package pwsh

import (
	"errors"
	"testing"
	"unicode/utf16"

	"cyberboar.dev/cyberboar/internal/engine/shell/limits"
)

// FuzzParsePowerShell checks that Parse fails closed on anything: it never
// panics, an error is always an *Error the engine treats as unparseable or
// over a limit, and a tree it returns is well formed (every extent inside
// the input) and the same on every call. TestPowerShellDifferential takes what
// the fuzzer finds further, against PowerShell's own parser.
func FuzzParsePowerShell(f *testing.F) {
	for _, in := range pwshInputs(f) {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		sb, err := Parse(in)
		if err != nil {
			var pe *Error
			if !errors.As(err, &pe) || !(errors.Is(err, limits.ErrUnparseable) || errors.Is(err, limits.ErrTooLarge) || errors.Is(err, limits.ErrTooComplex)) {
				t.Fatalf("%q: error %T %v", in, err, err)
			}
			return
		}
		n := len(utf16.Encode([]rune(in)))
		Inspect(sb, func(nd Node) bool {
			if e := nd.Span(); e.Start < 0 || e.Start > e.End || e.End > n {
				t.Fatalf("%q: %T has extent %v outside 0-%d", in, nd, e, n)
			}
			return true
		})
		again, err := Parse(in)
		if err != nil || dump(again) != dump(sb) {
			t.Fatalf("%q: a second parse differs: %v", in, err)
		}
	})
}
