// Package osfs maps the engine's paths to the operating system's
//
// The engine and the shell analyzer work in one path space on every OS:
// absolute paths separated by "/". On POSIX systems that is the OS's own
// form. On Windows the drive path C:\Users is /c/Users there, and every
// filesystem call goes through FS, which turns it back into C:\Users
package osfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// FS reaches the filesystem for engine paths
// The zero value is the POSIX mapping: an engine path is the OS path
type FS struct {
	// Windows says engine paths are /x/... for drive X
	Windows bool
	// Drives maps a lower-case drive letter to the OS directory that stands
	// for it. Nil means the real drives (X:\). A drive not in a non-nil map can't be reached.
	Drives map[string]string
}

// OSPath returns the operating system's name for the engine path p
func (f FS) OSPath(p string) (string, error) {
	if !f.Windows {
		return p, nil
	}
	drive, rest, ok := SplitDrive(p)
	if !ok {
		return "", fmt.Errorf("%s is not on a drive", p)
	}
	root := strings.ToUpper(drive) + `:\`
	if f.Drives != nil {
		if root, ok = f.Drives[drive]; !ok {
			return "", fmt.Errorf("drive %s: is not available", strings.ToUpper(drive))
		}
	}
	if rest == "" {
		return root, nil
	}
	return filepath.Join(root, filepath.FromSlash(rest)), nil
}

// Show returns the engine path p the way messages name it
// On Windows that is the Windows path (/c/x is C:\x), whatever Drives maps the drive to
func (f FS) Show(p string) string {
	if !f.Windows {
		return p
	}
	drive, rest, ok := SplitDrive(p)
	if !ok {
		return p
	}
	return strings.ToUpper(drive) + `:\` + strings.ReplaceAll(rest, "/", `\`)
}

// SplitDrive splits a Windows engine path /x/rest into its lower-case drive letter and rest
// ok is false when p doesn't start with a drive
func SplitDrive(p string) (drive, rest string, ok bool) {
	s, found := strings.CutPrefix(p, "/")
	if !found || len(s) == 0 || s[0] >= 0x80 {
		return "", "", false
	}
	d, rest, _ := strings.Cut(s, "/")
	if len(d) != 1 || !('a' <= d[0] && d[0] <= 'z' || 'A' <= d[0] && d[0] <= 'Z') {
		return "", "", false
	}
	return strings.ToLower(d), rest, true
}

// LongName returns the long form of the last name in engine path p, which must exist
// On Windows, an 8.3 short name such as ENV~1 may stand for
// .env. Elsewhere, and when there is no other form, it returns the name as is
func (f FS) LongName(p string) (string, error) {
	op, err := f.OSPath(p)
	if err != nil {
		return "", err
	}
	return longName(op)
}

// Lstat is os.Lstat for an engine path
func (f FS) Lstat(p string) (fs.FileInfo, error) {
	op, err := f.OSPath(p)
	if err != nil {
		return nil, err
	}
	return os.Lstat(op)
}

// Stat is os.Stat for an engine path
func (f FS) Stat(p string) (fs.FileInfo, error) {
	op, err := f.OSPath(p)
	if err != nil {
		return nil, err
	}
	return os.Stat(op)
}

// MaxDirEntries bounds the allocation for one directory enumeration
const MaxDirEntries = 50000

// ReadDir returns entries in name order, refusing directories over MaxDirEntries
func (f FS) ReadDir(p string) ([]fs.DirEntry, error) {
	op, err := f.OSPath(p)
	if err != nil {
		return nil, err
	}
	dir, err := os.Open(op)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(MaxDirEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > MaxDirEntries {
		return nil, ErrTooLarge
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

// Readlink returns the target of the symbolic link at engine path p, as the OS stores it
func (f FS) Readlink(p string) (string, error) {
	op, err := f.OSPath(p)
	if err != nil {
		return "", err
	}
	return os.Readlink(op)
}

// ErrTooLarge means a file or directory exceeds its resource limit
var ErrTooLarge = errors.New("filesystem input too large")

// ReadFile returns the contents of the regular file at engine path p, as
// the agent's tools would read it (symbolic links followed), or exists
// false when there is no file there. Anything but a regular file is an
// error (a FIFO would block, a device never end), and so is a file longer
// than limit bytes
func (f FS) ReadFile(p string, limit int64) (content string, exists bool, err error) {
	op, err := f.OSPath(p)
	if err != nil {
		return "", false, err
	}
	fi, err := os.Stat(op)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !fi.Mode().IsRegular() {
		return "", true, fmt.Errorf("%s is not a regular file", p)
	}
	if fi.Size() > limit {
		return "", true, ErrTooLarge
	}
	file, err := os.Open(op) // #nosec G304 -- the hook reads the file the agent is about to write
	if err != nil {
		return "", true, err
	}
	defer func() { _ = file.Close() }()
	// Check again on what was opened, since the path may have changed in between
	if fi, err = file.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "", true, fmt.Errorf("%s is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", true, err
	}
	if int64(len(b)) > limit {
		return "", true, ErrTooLarge
	}
	return string(b), true, nil
}
