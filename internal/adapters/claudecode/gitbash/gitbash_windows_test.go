package gitbash_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode/gitbash"
)

// The real Git for Windows: its mount table must read, with the root and /tmp known.
func TestRealGitForWindows(t *testing.T) {
	if _, err := exec.LookPath("git.exe"); err != nil {
		t.Skip("no git.exe on PATH")
	}
	m, err := gitbash.Mounts(gitbash.System(os.Getenv))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mounts: %v", m)
	if m["/"] == "" || m["/tmp"] == "" {
		t.Errorf("root or /tmp unknown: %v", m)
	}
}

func TestRealTempDirectory(t *testing.T) {
	if _, err := exec.LookPath("git.exe"); err != nil {
		t.Skip("no git.exe on PATH")
	}
	for _, source := range []string{"TMP", "TEMP", "USERPROFILE", "Windows"} {
		t.Run(source, func(t *testing.T) {
			directory, alternate := t.TempDir(), t.TempDir()
			for _, name := range []string{"TMP", "TEMP", "USERPROFILE"} {
				// On Windows "" still defines the variable, which GetTempPathW then uses
				t.Setenv(name, "")
				os.Unsetenv(name)
			}
			if source != "Windows" {
				t.Setenv(source, directory)
			}
			if source == "TMP" {
				t.Setenv("TEMP", alternate)
			}
			var buf [windows.MAX_PATH + 1]uint16
			n, err := windows.GetTempPath(uint32(len(buf)), &buf[0])
			if err != nil || n == 0 || n >= uint32(len(buf)) {
				t.Fatalf("GetTempPathW returned %d, %v", n, err)
			}
			want := strings.TrimRight(windows.UTF16ToString(buf[:n]), `\/`)
			got, err := gitbash.Mounts(gitbash.System(os.Getenv))
			if err != nil || !strings.EqualFold(strings.TrimRight(got["/tmp"], `\/`), want) {
				t.Fatalf("/tmp = %q, error %v; GetTempPathW returned %q", got["/tmp"], err, want)
			}
		})
	}
}
