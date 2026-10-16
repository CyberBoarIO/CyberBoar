package shell_test

import (
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

func BenchmarkAnalyze(b *testing.B) {
	for _, tc := range []struct{ name, src string }{
		{"simple", "go test ./..."},
		{"pipeline4", "printf x | cat | sort | head -1"},
		{"pipeline256", strings.Repeat("printf x | ", shell.MaxCommands-1) + "cat"},
		{"sequential256", strings.Repeat("true;", shell.MaxCommands)},
		{"wrappers", "timeout 5 nice env -S 'printf x'"},
		{"fixedpoint", "HOME=/tmp; shopt -s dotglob; alias ll='printf x'; ll; cat ~/.config/x"},
		{"substitutions", "printf '%s' \"$(printf x | cat)\" <(printf y | sort) | cat"},
		{"nested shells", "printf x | sh -c 'cat | sh -c \"cat | sort\"' | head -1"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := shell.Analyze(tc.src, "/home/dev", "/work/repo"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
