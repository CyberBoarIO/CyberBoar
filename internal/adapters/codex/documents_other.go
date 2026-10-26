//go:build !windows

package codex

// documentsDir returns "": the Documents folder matters only on Windows
func documentsDir() string { return "" }
