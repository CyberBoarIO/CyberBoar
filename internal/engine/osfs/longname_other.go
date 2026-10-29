//go:build !windows

package osfs

import "path/filepath"

// longName returns the last name of op, since other systems have no short names.
func longName(op string) (string, error) { return filepath.Base(op), nil }
