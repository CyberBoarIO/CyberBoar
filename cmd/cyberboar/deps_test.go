package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/brand"
)

// TestBinaryLinksNoTestCode fails if the command depends on the testing
// package, on net/http/httptest, or on any package of this module whose path
// ends in "test" (the test helpers). Test helpers are written for test runs,
// not for an endpoint: linking one into the shipped command would put its code
// on the path every tool call takes. Build constraints choose different files
// for each GOOS, so the list is taken for each platform the binary ships on
func TestBinaryLinksNoTestCode(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list once per platform")
	}
	mod, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	module := strings.TrimSpace(string(mod))
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", ".")
		// The child inherits GOFLAGS and the toolchain
		// GOOS already in the environment is overridden, because exec keeps the last of duplicates
		cmd.Env = append(os.Environ(), "GOOS="+goos)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("GOOS=%s: go list -deps: %v\n%s", goos, err, stderr.Bytes())
		}
		for _, dep := range strings.Fields(string(out)) {
			if testCode(module, dep) {
				t.Errorf("GOOS=%s: the %s command links test code: %s", goos, brand.Name, dep)
			}
		}
	}
}

// testCode reports whether an import path is test code that a shipped binary
// must not link: the testing packages, httptest, or a helper of module
func testCode(module, pkg string) bool {
	if pkg == "testing" || strings.HasPrefix(pkg, "testing/") || pkg == "net/http/httptest" {
		return true
	}
	return strings.HasPrefix(pkg, module+"/") && strings.HasSuffix(pkg, "test")
}
