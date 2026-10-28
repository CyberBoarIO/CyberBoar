//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/codex"
)

// apply falls back to the 8.3 short name for a Codex hook program whose path
// has a space, such as one under C:\Program Files
func TestShortPathName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(dir, "prog.exe")
	if err := os.WriteFile(program, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	short, err := shortPathName(program)
	if err != nil {
		t.Fatal(err)
	}
	if short == program {
		t.Skipf("the volume of %s keeps no 8.3 names", program)
	}
	if !codex.BareWindowsProgram(short) {
		t.Fatalf("short name %q can't go into a Codex hook line", short)
	}
	a, errA := os.Stat(program)
	b, errB := os.Stat(short)
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Fatalf("short name %q is not %q (%v, %v)", short, program, errA, errB)
	}
}
