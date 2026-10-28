//go:build windows

package main

import "syscall"

// shortPathName returns the 8.3 short form of an existing path, which has no
// spaces where the volume keeps short names (C:\PROGRA~1)
func shortPathName(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	size := uint32(syscall.MAX_PATH)
	for {
		buf := make([]uint16, size)
		n, err := syscall.GetShortPathName(p, &buf[0], size)
		if err != nil {
			return "", err
		}
		if n < size {
			return syscall.UTF16ToString(buf[:n]), nil
		}
		size = n // the size needed
	}
}
