package shell_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

// Unknown code in a bare assignment creates a command too. Count it against
// the same budget as ordinary commands, including inside inline shell code.
func TestCommandLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  func(int) string
	}{
		{"ordinary", func(n int) string { return strings.Repeat("true;", n) }},
		{"bare assignments", func(n int) string { return strings.Repeat("LD_PRELOAD=x;", n) }},
		{"export declarations", func(n int) string { return strings.Repeat("export LD_PRELOAD=x;", n) }},
		{"mixed", func(n int) string { return strings.Repeat("true;", n-1) + "LD_PRELOAD=x;" }},
		{"nested assignments", func(n int) string {
			return "sh -c '" + strings.Repeat("LD_PRELOAD=x;", n-1) + "'"
		}},
		{"unknown layers", func(n int) string { return strings.Repeat("python -c x;", n) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, n := range []int{shell.MaxCommands - 1, shell.MaxCommands, shell.MaxCommands + 1} {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					an, err := shell.Analyze(tc.src(n), "/home/dev", "/work/repo")
					if n > shell.MaxCommands {
						if !errors.Is(err, shell.ErrTooComplex) || an != nil {
							t.Fatalf("want nil analysis and ErrTooComplex, got nil=%v, error=%v", an == nil, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if len(an.Commands) != n {
						t.Fatalf("got %d commands, want %d", len(an.Commands), n)
					}
				})
			}
		})
	}
}

func TestKnownAssignmentsDoNotConsumeCommandBudget(t *testing.T) {
	an, err := shell.Analyze(strings.Repeat("DEMO=x;", shell.MaxCommands+1), "/home/dev", "/work/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(an.Commands) != 0 {
		t.Fatalf("known assignments created %d commands", len(an.Commands))
	}
}
