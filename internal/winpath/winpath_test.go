package winpath_test

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/winpath"
)

func TestPath(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		abs     bool
		refused bool
	}{
		{in: `C:\Users\dev`, out: "/c/Users/dev", abs: true},
		{in: `c:/Users/dev/`, out: "/c/Users/dev", abs: true},
		{in: `D:\`, out: "/d", abs: true},
		{in: `D:`, refused: true}, // D's current directory
		{in: `C:\a\..\b`, out: "/c/a/../b", abs: true},
		{in: `C:\\a\.\b`, out: "/c/a/./b", abs: true},
		{in: `src\main.go`, out: "src/main.go"},
		{in: `..\x`, out: "../x"},
		{in: `~\.ssh`, out: "~/.ssh"},
		{in: `.env. . `, out: ".env"},
		{in: `dir. \file`, out: "dir/file"},
		{in: `console.txt`, out: "console.txt"},
		{in: `com10`, out: "com10"},
		{in: `\\server\share\x`, refused: true},
		{in: `//server/share`, refused: true},
		{in: `\\?\C:\x`, refused: true},
		{in: `\\.\C:\x`, refused: true},
		{in: `\??\C:\x`, refused: true},
		{in: `\x`, refused: true},
		{in: `/c/x`, refused: true},
		{in: `C:x`, refused: true},
		{in: `1:\x`, refused: true},
		{in: `x::$DATA`, refused: true},
		{in: `x:stream`, refused: true},
		{in: `...`, refused: true},
		{in: `a\ \b`, refused: true},
		{in: `NUL`, refused: true},
		{in: `nul.txt`, refused: true},
		{in: `Aux .log`, refused: true},
		{in: `x\COM3\y`, refused: true},
		{in: `LPT²`, refused: true},
		{in: `CONOUT$`, refused: true},
	} {
		out, abs, err := winpath.Path(tc.in)
		if tc.refused {
			if err == nil {
				t.Errorf("Path(%q) = %q, want refused", tc.in, out)
			}
			continue
		}
		if err != nil || out != tc.out || abs != tc.abs {
			t.Errorf("Path(%q) = %q, %v, %v; want %q, %v", tc.in, out, abs, err, tc.out, tc.abs)
		}
	}
}

func TestTarget(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		abs     bool
		refused bool
	}{
		{in: `C:\ProgramData`, out: "/c/ProgramData", abs: true},
		{in: `\??\D:\data`, out: "/d/data", abs: true},
		{in: `\\?\D:\data`, out: "/d/data", abs: true},
		{in: `\ProgramData\x`, out: "/e/ProgramData/x", abs: true},
		{in: `..\x`, out: "../x"},
		{in: `\\?\Volume{0b1c}\x`, refused: true},
		{in: `\??\UNC\server\share`, refused: true},
		{in: `\\server\share`, refused: true},
		{in: `\\?\C:`, refused: true},
	} {
		out, abs, err := winpath.Target(tc.in, "e")
		if tc.refused {
			if err == nil {
				t.Errorf("Target(%q) = %q, want refused", tc.in, out)
			}
			continue
		}
		if err != nil || out != tc.out || abs != tc.abs {
			t.Errorf("Target(%q) = %q, %v, %v; want %q, %v", tc.in, out, abs, err, tc.out, tc.abs)
		}
	}
}

func TestAbs(t *testing.T) {
	if _, err := winpath.Abs(`repo`); err == nil {
		t.Error("Abs accepted a relative path")
	}
	if got, err := winpath.Abs(`C:\repo`); err != nil || got != "/c/repo" {
		t.Errorf("Abs = %q, %v", got, err)
	}
}
