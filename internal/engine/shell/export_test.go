package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellDependent reports whether a command line has a $'…' escape that
// shells read differently (see ansiC), which the analyzer treats as a
// run-time word instead of any one shell's reading.
// The bash differential (differential_test.go) uses it.
func ShellDependent(src string) bool {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return false
	}
	found := false
	syntax.Walk(f, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok {
			for i, p := range w.Parts {
				if q, ok := p.(*syntax.SglQuoted); ok {
					if _, ok := ansiC(q, i == len(w.Parts)-1); !ok {
						found = true
					}
				}
			}
		}
		return !found
	})
	return found
}
