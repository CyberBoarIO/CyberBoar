// Package atomicfile replaces files so that a reader, or the next run after
// a crash, finds either the old contents or the new, never part of either.
package atomicfile

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Write replaces the file at path with data, which gets permissions perm.
// The directory must exist.
func Write(path string, data []byte, perm fs.FileMode) error {
	tmp, err := Stage(filepath.Dir(path), filepath.Base(path), data, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Stage writes data to a new hidden file in dir, named after name, synced to
// disk and with permissions perm, and returns its path.
// Renaming it over the final name is the caller's step, so that several files can be staged
// before any is replaced. On error nothing is left behind.
func Stage(dir, name string, data []byte, perm fs.FileMode) (string, error) {
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return "", err
	}
	_, err = tmp.Write(data)
	// Without Sync, a crash soon after the rename can leave an empty file
	// under the final name on file systems that don't order the two
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), perm)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// WriteNew creates path, which must not exist, with data and permissions perm.
// The data is synced before path becomes visible.
// The filesystem must support hard links. Creating an existing file fails
// with an error that matches fs.ErrExist; on any other error nothing is left behind.
func WriteNew(path string, data []byte, perm fs.FileMode) error {
	tmp, err := Stage(filepath.Dir(path), filepath.Base(path), data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	// Linking publishes the complete file without replacing an existing path
	return os.Link(tmp, path)
}
