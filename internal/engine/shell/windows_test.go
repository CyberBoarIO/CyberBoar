package shell

import (
	"os/user"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
)

// On Windows, ~user is a run-time directory even when the OS knows the user:
// Git Bash's idea of that home may differ.
func TestWindowsOtherUserHomeIsUnknown(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("no current user to look up: %v", err)
	}
	if _, ok := lookupHome(u.Username); !ok || strings.ContainsAny(u.Username, `\ `) {
		t.Skipf("%q is not a name ~ can take", u.Username)
	}
	an, err := AnalyzeWith("cat ~"+u.Username+"/.ssh/id_rsa", "/c/Users/dev", Options{Cwd: "/c/Users/dev/repo", FS: osfs.FS{Windows: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range an.Files {
		if f.Certain {
			t.Errorf("certain path %q from ~admin", f.Path)
		}
	}
}

func TestReadWinWord(t *testing.T) {
	for _, tc := range []struct {
		in         string
		kind       winKind
		path, msys string
	}{
		{`/c/Users/x`, winDrive, "/c/Users/x", "/c/Users/x"},
		{`/C`, winDrive, "/c", "/C"},
		{`/cygdrive/D/x`, winDrive, "/d/x", "/cygdrive/D/x"},
		{`C:\Users\x`, winDrive, "/c/Users/x", ""},
		{`c:/`, winDrive, "/c", ""},
		{`file:///C:/x`, winRel, "file///C/x", ""},
		{`/C:/x`, winDrive, "/c/x", ""},
		{`C:x`, winDriveRel, "", ""},
		{`//host/share/x`, winUNC, "", ""},
		{`\\host\share`, winUNC, "", ""},
		{`//c`, winUNC, "", ""},
		{`/tmp/a.txt.`, winMount, "", "/tmp/a.txt"},
		{`/`, winMount, "", "/"},
		{`a\b. \c:s`, winRel, "a/b/c", ""},
		{`..\x`, winRel, "../x", ""},
		{`...`, winRel, ".", ""},
		{`a/. ./b`, winRel, "a/./b", ""},
		{`/tmp/...`, winMount, "", "/tmp/."},
		{`:$I30:$INDEX_ALLOCATION\x`, winRel, "./x", ""},
		{`::$DATA`, winRel, "::$DATA", ""},
		{`::x`, winRel, "::x", ""},
	} {
		if w := readWinWord(tc.in, winNames); w.kind != tc.kind || w.path != tc.path || w.msys != tc.msys {
			t.Errorf("readWinWord(%q) = %+v, want %v %q %q", tc.in, w, tc.kind, tc.path, tc.msys)
		}
	}
}

func TestMSYSAbsResolvesMounts(t *testing.T) {
	a := &analyzer{windows: true, mounts: map[string]string{"/": "/c/Git", "/tmp": "/c/Temp", "/usr/bin": "/c/Git/usr/bin", "/opt": ""}}
	for in, want := range map[string]string{
		"/":             "/c/Git",
		"/etc/x":        "/c/Git/etc/x",
		"/tmp":          "/c/Temp",
		"/TMP/x":        "/c/Temp/x",
		"/tmpx/y":       "/c/Git/tmpx/y",
		"/usr/bin/ls":   "/c/Git/usr/bin/ls",
		"/usr/lib/x":    "/c/Git/usr/lib/x",
		"/tmp/../etc":   "/c/Git/etc",
		"/c/../etc":     "/c/Git/etc",
		"/c/x/../y":     "/c/y",
		"/cygdrive/d/x": "/d/x",
	} {
		if got, refused := a.msysAbs(in); got != want || refused != "" {
			t.Errorf("msysAbs(%q) = %q, %q; want %q", in, got, refused, want)
		}
	}
	for _, in := range []string{"/opt", "/opt/x"} {
		if got, refused := a.msysAbs(in); refused == "" {
			t.Errorf("msysAbs(%q) = %q, want refused (unknown mount directory)", in, got)
		}
	}
	a.mounts = nil
	if got, refused := a.msysAbs("/etc/x"); refused == "" {
		t.Errorf("without mounts: %q, want refused", got)
	}
	if got, refused := a.msysAbs("/c/x"); refused != "" || got != "/c/x" {
		t.Errorf("without mounts, a drive: %q, %q", got, refused)
	}
}

func TestWinProgramDropsExecutableSuffix(t *testing.T) {
	for in, want := range map[string]string{
		`bash.exe`: "bash", `BASH.EXE`: "BASH", `C:\Git\bin\bash.exe`: "bash", `/usr/bin/env`: "env",
		`x.com`: "x", `.exe`: ".exe", `run.bat`: "run.bat", `python3.12`: "python3.12",
	} {
		if got := winProgram(in); got != want {
			t.Errorf("winProgram(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitBashNamesRoundTrip(t *testing.T) {
	for in, want := range map[string]string{
		`k|y`:        "ky",
		`a/b./c`:     "a/b/c",
		`x. . /./..`: "x/./..",
		`...`:        "",
		`"*:<>?`:     "",
		`.env`:       ".env",
		"tab\there":  "tabhere",
		`ünï.code`:   `ünï.code`,
	} {
		got := gitBashNames(in)
		if got != want {
			t.Errorf("gitBashNames(%q) = %q, want %q", in, got, want)
		}
		for n := range strings.SplitSeq(got, "/") {
			if back := gitBashView(n); gitBashNames(back) != n {
				t.Errorf("gitBashView(%q) = %q does not map back", n, back)
			}
		}
	}
}
