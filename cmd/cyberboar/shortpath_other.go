//go:build !windows

package main

import "errors"

// shortPathName has no short names to find outside Windows.
func shortPathName(string) (string, error) {
	return "", errors.New("8.3 short names exist only on Windows")
}
