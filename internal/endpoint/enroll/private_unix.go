//go:build unix

package enroll

import (
	"fmt"
	"os"
	"syscall"
)

// securePath makes path private to the current user (0700 for a directory,
// 0600 for a file) and refuses one another user owns. fi may be nil.
func securePath(path string, fi os.FileInfo) error {
	if fi == nil {
		var err error
		if fi, err = os.Lstat(path); err != nil {
			return err
		}
	}
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi.IsDir() {
		mode = 0o700
	}
	if fi.Mode().Perm() != mode {
		return os.Chmod(path, mode)
	}
	return nil
}

// checkPrivate refuses a file or directory another user owns, a file others
// may read or write, and a directory others may write to (they could swap
// the files in it).
func checkPrivate(path string, fi os.FileInfo) error {
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	others := os.FileMode(0o077)
	if fi.IsDir() {
		others = 0o022
	}
	if fi.Mode().Perm()&others != 0 {
		return fmt.Errorf("%s is accessible to other users (mode %04o); it must be private to its owner", path, fi.Mode().Perm())
	}
	return nil
}

// checkOwner refuses a path owned by a user other than the one running.
func checkOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: its owner can't be read", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		// A root service must not trust a key or console address a user
		// could have put there.
		return fmt.Errorf("%s is owned by user %d, not by this user (%d)", path, st.Uid, uid)
	}
	return nil
}
