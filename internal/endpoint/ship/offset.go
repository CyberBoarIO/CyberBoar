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
	"strings"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/pkg/audit"
)

// offsetFile is where the shipped offset of one audit log is kept.
func offsetFile(stateDir, auditPath string) string {
	sum := sha256.Sum256([]byte(auditPath))
	return filepath.Join(stateDir, "shipped-"+hex.EncodeToString(sum[:8])+".json")
}

type offsetState struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	// Head is the SHA-256 of the log's first min(Offset, headBytes) bytes,
	// so a log replaced by one that has already grown past Offset is still
	// recognized as new.
	Head string `json:"head"`
	// Stats are the running totals every batch carries. They are saved with
	// the offset, so the lines behind it are counted exactly once.
	Stats audit.Stats `json:"stats"`
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

// headBytes is how much of the log's start identifies it
// Every audit line starts with a nanosecond timestamp, so two logs don't share it.
const headBytes = 4096

// head returns the SHA-256 of f's first min(off, headBytes) bytes.
func head(f *os.File, off int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, min(off, headBytes))); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameLog reports whether f is still the log st.Offset points into, which
// means it is at least that long and starts as it did.
func sameLog(f *os.File, size int64, st offsetState) (bool, error) {
	if size < st.Offset {
		return false, nil
	}
	if st.Offset == 0 {
		return true, nil
	}
	h, err := head(f, st.Offset)
	return h == st.Head, err
}

// saveOffset replaces the offset file atomically.
func saveOffset(path, auditPath string, f *os.File, off int64, stats audit.Stats) error {
	h, err := head(f, off)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(offsetState{Path: auditPath, Offset: off, Head: h, Stats: stats})
	return atomicfile.Write(path, append(data, '\n'), 0o600)
}

// findOldLog looks next to auditPath for the log that st points into, after
// that log was rotated away: a file whose name starts with the log's (such as
// audit.jsonl.1 or audit.jsonl-20261030), at least st.Offset long, that
// starts as the log did. It returns nil when there is none, as when the old
// log was deleted, compressed or truncated in place.
func findOldLog(auditPath string, st offsetState) (*os.File, error) {
	if st.Offset == 0 {
		return nil, nil // nothing was shipped from it, so nothing can be missing
	}
	dir, base := filepath.Split(auditPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == base || !strings.HasPrefix(e.Name(), base) || !e.Type().IsRegular() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err == nil {
			if same, err := sameLog(f, fi.Size(), st); err == nil && same {
				return f, nil
			}
		}
		f.Close()
	}
	return nil, nil
}
