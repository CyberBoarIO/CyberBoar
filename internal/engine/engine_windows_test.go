package engine_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
)

// These run only on Windows, against NTFS itself: what the corpus can't build on other systems

func windowsFixture(t *testing.T) (c *engine.Compiled, home, repo string) {
	t.Helper()
	p, err := policy.Load([]byte(`apiVersion: cyberboar.dev/v1
kind: Policy
metadata: {name: w}
spec:
  files:
    deny: ["**/.env*", "~/.ssh/**"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if c, err = engine.Compile(p); err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(t.TempDir(), "home")
	repo = filepath.Join(home, "repo")
	for _, f := range []string{`.ssh\id_rsa`, `repo\.env`, `repo\README.md`} {
		full := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return c, home, repo
}

func evalWindows(c *engine.Compiled, home, repo, path string) engine.Verdict {
	return engine.Evaluate(context.Background(), c, engine.Action{Tool: engine.ToolRead, Path: path, Cwd: repo, Home: home,
		Workspaces: []string{repo}, Platform: engine.PlatformWindows})
}

func TestWindowsAllowsPlainRead(t *testing.T) {
	c, home, repo := windowsFixture(t)
	if v := evalWindows(c, home, repo, filepath.Join(repo, "README.md")); v.Decision != engine.Allow {
		t.Fatalf("README.md: %+v", v)
	}
}

func TestWindowsShortName(t *testing.T) {
	c, home, repo := windowsFixture(t)
	long := filepath.Join(repo, ".env")
	p, _ := syscall.UTF16PtrFromString(long)
	buf := make([]uint16, 512)
	n, err := syscall.GetShortPathName(p, &buf[0], uint32(len(buf)))
	short := syscall.UTF16ToString(buf[:n])
	if err != nil || filepath.Base(short) == ".env" {
		t.Skipf("no 8.3 name for %s on this volume (%v)", long, err)
	}
	t.Logf("short name: %s", short)
	if v := evalWindows(c, home, repo, short); v.Decision != engine.Deny || v.Rule != "files.deny[0]" {
		t.Fatalf("%s: %+v", short, v)
	}
	if v := evalWindows(c, home, repo, filepath.Base(short)); v.Decision != engine.Deny {
		t.Fatalf("relative %s: %+v", filepath.Base(short), v)
	}
}

// An administrator can give a file any 8.3 name, one without "~" too.
func TestWindowsShortNameWithoutTilde(t *testing.T) {
	c, home, repo := windowsFixture(t)
	out, err := exec.Command("fsutil", "file", "setshortname", filepath.Join(repo, ".env"), "NOTES.TXT").CombinedOutput()
	if err != nil {
		t.Skipf("fsutil file setshortname (needs admin and 8.3 names on the volume): %v: %s", err, out)
	}
	for _, p := range []string{filepath.Join(repo, "NOTES.TXT"), "notes.txt", filepath.Join(home, "repo", "NOTES.TXT")} {
		if v := evalWindows(c, home, repo, p); v.Decision != engine.Deny || v.Rule != "files.deny[0]" {
			t.Errorf("%s: %+v", p, v)
		}
	}
}

func TestWindowsJunction(t *testing.T) {
	c, home, repo := windowsFixture(t)
	docs := filepath.Join(repo, "docs")
	if err := os.Mkdir(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(docs, "keys"), filepath.Join(home, ".ssh")).CombinedOutput()
	if err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if v := evalWindows(c, home, repo, `docs\keys\id_rsa`); v.Decision != engine.Deny || v.Rule != "files.deny[1]" {
		t.Fatalf("a file through a junction: %+v", v)
	}
	// Reading docs walks it and must see through the junction
	if v := evalWindows(c, home, repo, "docs"); v.Decision != engine.Deny || v.Rule != "files.deny[1]" {
		t.Fatalf("a directory holding a junction: %+v", v)
	}
}

func TestWindowsSymlink(t *testing.T) {
	c, home, repo := windowsFixture(t)
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_rsa"), filepath.Join(repo, "key")); err != nil {
		t.Skipf("symlinks need developer mode or admin: %v", err)
	}
	if v := evalWindows(c, home, repo, "key"); v.Decision != engine.Deny || v.Rule != "files.deny[1]" {
		t.Fatalf("key: %+v", v)
	}
}

func TestWindowsCaseAndTrailingDots(t *testing.T) {
	c, home, repo := windowsFixture(t)
	for _, p := range []string{`.ENV`, `.env.`, `.env  `, filepath.Join(home, `.SSH.`, `ID_RSA`)} {
		if v := evalWindows(c, home, repo, p); v.Decision != engine.Deny {
			t.Errorf("%q: %+v", p, v)
		}
	}
}
