package ship

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/pkg/audit"
)

// offsetFile is where the shipped offset of one audit log is kept.
func offsetFile(stateDir, auditPath string) string {
	sum := sha256.Sum256([]byte(auditPath))
	return filepath.Join(stateDir, "shipped-"+hex.EncodeToString(sum[:8])+".json")
}

type offsetState struct {
	Path string `json:"path"`
	// File identifies the file Offset is in (fileID), so the log is found
	// after a rename even when nothing was read from it. It is empty in state
	// saved before ship recorded it.
	File   string `json:"file,omitempty"`
	Offset int64  `json:"offset"`
	// Head is the SHA-256 of the log's first min(Offset, headBytes) bytes,
	// so a log replaced by one that has already grown past Offset is still
	// recognized as new.
	Head string `json:"head"`
	// Stats are the running totals every batch carries. They are saved with
	// the offset, so the lines behind it are counted exactly once.
	Stats audit.Stats `json:"stats"`
	// Counted are the logs Stats.LogsLost already counts while a rotation is
	// being finished: compressed logs' file IDs and lostKey of an old log
	// that wasn't found. A run that fails and is retried finds them again.
	Counted []string `json:"counted,omitempty"`
}

// lostKey names the log st points into for Counted.
func (st offsetState) lostKey() string {
	if st.File != "" {
		return st.File
	}
	return "head:" + st.Head
}

// loadOffset reads the saved offset of auditPath. A missing file means
// nothing has been shipped yet. A file that doesn't belong to auditPath or
// can't be parsed is an error, so shipping never restarts from the wrong
// place without someone removing it.
func loadOffset(path, auditPath string) (offsetState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return offsetState{Path: auditPath}, nil
	}
	if err != nil {
		return offsetState{}, err
	}
	var st offsetState
	if err := json.Unmarshal(data, &st); err != nil || st.Path != auditPath || st.Offset < 0 || st.Stats.LogsLost < 0 || st.Stats.LinesSkipped < 0 {
		return offsetState{}, fmt.Errorf("%s is corrupt; remove it to ship the audit log from the start", path)
	}
	sum, err := hex.DecodeString(st.Head)
	if err != nil || len(sum) != sha256.Size || hex.EncodeToString(sum) != st.Head {
		return offsetState{}, fmt.Errorf("%s has an invalid log fingerprint; remove it to ship the audit log from the start", path)
	}
	return st, nil
}

// headBytes is how much of the log's start fingerprints it. With the file ID,
// the fingerprint tells a log replaced or truncated in place from the one
// shipped, and finds copytruncate's copy, which starts as the log did.
const headBytes = 4096

// head returns the SHA-256 of f's first min(off, headBytes) bytes.
func head(f *os.File, off int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, min(off, headBytes))); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameLog reports whether f, whose file ID is id, is still the log st.Offset
// points into: the same file, at least that long, starting as it did.
func sameLog(f *os.File, size int64, id string, st offsetState) (bool, error) {
	if st.File != "" && id != "" && id != st.File || size < st.Offset {
		return false, nil
	}
	if st.Offset == 0 {
		return true, nil
	}
	h, err := head(f, st.Offset)
	return h == st.Head, err
}

// saveOffset replaces the offset file atomically.
func saveOffset(path, auditPath string, f *os.File, id string, off int64, stats audit.Stats, counted []string) error {
	h, err := head(f, off)
	if err != nil {
		return err
	}
	return writeState(path, offsetState{Path: auditPath, File: id, Offset: off, Head: h, Stats: stats, Counted: counted})
}

func writeState(path string, st offsetState) error {
	data, _ := json.Marshal(st)
	return atomicfile.Write(path, append(data, '\n'), 0o600)
}

// rotated is a file next to the audit log whose name starts with the log's
// (audit.jsonl.1, audit.jsonl-20261030): a log rotated away, or its copy.
type rotated struct {
	f   *os.File
	id  string
	mod time.Time
}

// siblings opens the files rotated away from auditPath, other than the file
// whose ID is current. The caller closes them.
func siblings(auditPath, current string) ([]rotated, error) {
	dir, base := filepath.Split(auditPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []rotated
	for _, e := range entries {
		if e.Name() == base || !strings.HasPrefix(e.Name(), base) || !e.Type().IsRegular() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		id, err := fileID(f)
		fi, serr := f.Stat()
		if err != nil || serr != nil || id != "" && id == current {
			f.Close()
			continue
		}
		out = append(out, rotated{f: f, id: id, mod: fi.ModTime()})
	}
	return out, nil
}

// findOldLog returns the sibling that st points into, after that log was
// rotated away: the same file (st.File), or one that starts as the log did,
// as copytruncate's copy does. Either is at least st.Offset long and not
// compressed, since a deleted log's file ID may be reused at once. ok is
// false when there is none, as when the old log was deleted, compressed or
// truncated in place.
func findOldLog(sibs []rotated, st offsetState) (old rotated, ok bool, err error) {
	is := func(s rotated, id string) (bool, error) {
		fi, err := s.f.Stat()
		if err != nil {
			return false, err
		}
		same, err := sameLog(s.f, fi.Size(), id, st)
		return same && !compressed(s.f), err
	}
	for _, s := range sibs {
		if st.File == "" || s.id != st.File {
			continue
		}
		if same, err := is(s, s.id); err != nil || same {
			return s, same, err
		}
	}
	if st.Offset == 0 {
		return rotated{}, false, nil // nothing was shipped from it, so no copy can be told from another log
	}
	for _, s := range sibs {
		if same, err := is(s, ""); err != nil || same {
			return s, same, err
		}
	}
	return rotated{}, false, nil
}

// rotationSlack is how much older than the old log a log rotated in after
// it may look, as when a line reached the old log just after it was renamed.
// An older log within it is sent again, which the console's event IDs make
// harmless, rather than a newer one being missed.
const rotationSlack = 2 * time.Second

// rotatedSince returns, oldest first, the siblings other than old written
// since since: the logs rotated in and out between two runs, as when the log
// was rotated twice. unreadable are the file IDs of the compressed ones, whose
// lines can't be sent.
func rotatedSince(sibs []rotated, old string, since time.Time) (logs []rotated, unreadable []string) {
	for _, s := range sibs {
		if s.id != "" && s.id == old || s.mod.Before(since.Add(-rotationSlack)) {
			continue
		}
		if compressed(s.f) {
			unreadable = append(unreadable, s.id)
			continue
		}
		logs = append(logs, s)
	}
	slices.SortStableFunc(logs, func(a, b rotated) int { return a.mod.Compare(b.mod) })
	return logs, unreadable
}

// compressed reports a file that starts as gzip, bzip2, xz or zstd data does.
func compressed(f *os.File) bool {
	var b [6]byte
	n, _ := f.ReadAt(b[:], 0)
	p := b[:n]
	for _, magic := range []string{"\x1f\x8b", "BZh", "\xfd7zXZ\x00", "\x28\xb5\x2f\xfd"} {
		if strings.HasPrefix(string(p), magic) {
			return true
		}
	}
	return false
}
