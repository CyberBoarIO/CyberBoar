package adapters_test

import (
	"slices"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
)

// Codex takes the path after "MARKER " as it is, and opencode takes the
// trimmed text after "MARKER". PatchPaths returns both readings
func TestPatchPaths(t *testing.T) {
	for _, tc := range []struct {
		patch string
		want  []string
	}{
		{"*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch", []string{"a.txt"}},
		{"*** Begin Patch\n*** Add File:.env\n+x\n*** End Patch", []string{".env"}},
		{"*** Begin Patch\n*** Add File:  /home/dev/.ssh/x\n+x\n*** End Patch", []string{" /home/dev/.ssh/x", "/home/dev/.ssh/x"}},
		{"*** Begin Patch\n*** Delete File:\t/k\n*** End Patch", []string{"/k"}},
		{"*** Begin Patch\n*** Update File:a\n*** Move to:b\n@@\n-x\n+y\n*** End Patch", []string{"a", "b"}},
		{"*** Begin Patch\n*** Update File: a\n*** Move to:  b\n@@\n-x\n+y\n*** End Patch", []string{"a", " b", "b"}},
		{"*** Begin Patch\n+*** Add File:x\n*** End Patch", nil},
		{"*** Begin Patch\n*** Update File: a\n*** Move to: b\n@@\n-x\n+y\n*** Update File: a\n*** End Patch", []string{"a", "b"}},
		{"*** Begin Patch\n*** Delete File: /abs/k\n*** End Patch", []string{"/abs/k"}},
		{"no patch at all", nil},
	} {
		if got, env := adapters.PatchPaths(tc.patch); env || !slices.Equal(got, tc.want) {
			t.Errorf("PatchPaths(%q) = %q, %v; want %q", tc.patch, got, env, tc.want)
		}
	}
}
