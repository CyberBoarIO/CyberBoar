package pull

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrBusy means another process is committing a policy to this destination.
// The caller can retry the pull; no part of this install was written.
var ErrBusy = errors.New("another policy install is in progress")

// lockInstall resolves directory aliases and holds a persistent lock inode.
// Neither the lock nor its directory is removed on release: unlinking a locked
// file would let another writer acquire a different inode under the same name.
func lockInstall(out string) (canonical string, unlock func(), err error) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", nil, err
	}
	// #nosec G301 G703 -- the destination is locally configured, not bundle input; other users' hooks read it
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", nil, err
	}
	canonical = filepath.Join(dir, filepath.Base(abs))
	// #nosec G703 -- this is the explicit local destination, not a path supplied by the server
	if info, err := os.Lstat(canonical); err == nil {
		if !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("installed policy file %s is not regular", canonical)
		}
		// On Windows this also expands an existing 8.3 leaf and normalizes
		// its case, so aliases cannot select independent signature floors
		canonical, err = filepath.EvalSymlinks(canonical)
		if err != nil {
			return "", nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", nil, err
	}
	path := canonical + ".lock"
	// #nosec G703 -- the lock is next to the explicit local destination, not a server-supplied path
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", nil, err
	}
	if err == nil && !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("policy lock %s is not a regular file", path)
	}
	f, err := openInstallLock(path)
	if err != nil {
		return "", nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if err := tryInstallLock(f); err != nil {
		return "", nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	// #nosec G703 -- recheck the locally configured lock name against its opened identity
	info, err = os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(opened, info) || !singleLink(f, opened) {
		return "", nil, errors.New("policy lock was replaced or has another link")
	}
	// Atomic replacement targets the leaf name. Refuse aliases at that leaf
	// rather than use a different signature/floor for the symlink's target
	for _, p := range []string{canonical, canonical + ".sig"} {
		// #nosec G703 -- these are the locally configured policy and signature paths
		info, err := os.Lstat(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", nil, err
		}
		if err == nil && !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("installed policy file %s is not regular", p)
		}
	}
	ok = true
	return canonical, func() { f.Close() }, nil
}
