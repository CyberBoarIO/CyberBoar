package gitbash

import "golang.org/x/sys/windows"

func windowsDirectory() (string, error) { return windows.GetWindowsDirectory() }
