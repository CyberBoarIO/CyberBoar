//go:build !windows

package gitbash

import "errors"

func windowsDirectory() (string, error) {
	return "", errors.New("the Windows directory is unavailable")
}
