package pwsh_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/engine/shell/pwsh"
)

// Parsing costs time and memory in proportion to the input, so that a
// command line at the size limit can't hold the hook past its deadline. Each
// shape below once cost in proportion to the square of its length, which
// came to seconds of CPU or hundreds of megabytes at the limit. Wall-clock
// time depends on the machine and its load, so the test compares a quarter of
// the limit with the whole of it and keeps the fastest of a few runs
// Linearcost gives a ratio near 4 and quadratic cost one near 16
func TestParseCostIsLinear(t *testing.T) {
	for _, tc := range []struct{ name, prefix, unit, suffix string }{
		{"empty script blocks", "f ", "{}", ""},
		{"quotes dropped from a subexpression", `"$(`, "a ", ` """")"`},
		{"many subexpressions with dropped quotes", `"`, `$(<#""#>)`, `"`},
	} {
		line := func(size int) string {
			n := (size - len(tc.prefix) - len(tc.suffix)) / len(tc.unit)
			return tc.prefix + strings.Repeat(tc.unit, n) + tc.suffix
		}
		small, large := line(shell.MaxBytes/4), line(shell.MaxBytes)
		var smallTime, largeTime time.Duration
		var smallBytes, largeBytes uint64
		for i := range 3 {
			d, b := parseCost(t, small)
			if i == 0 || d < smallTime {
				smallTime = d
			}
			smallBytes = b
			d, b = parseCost(t, large)
			if i == 0 || d < largeTime {
				largeTime = d
			}
			largeBytes = b
		}
		if largeTime > 10*smallTime {
			t.Errorf("%s: %d bytes took %v, %d bytes took %v", tc.name, len(large), largeTime, len(small), smallTime)
		}
		if largeBytes > 6*smallBytes {
			t.Errorf("%s: %d bytes allocated %d, %d bytes allocated %d", tc.name, len(large), largeBytes, len(small), smallBytes)
		}
	}
}

// parseCost parses line, which must parse, and returns the time it took and
// the bytes it allocated
func parseCost(t *testing.T, line string) (time.Duration, uint64) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := pwsh.Parse(line)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("%.40q...: %v", line, err)
	}
	return took, after.TotalAlloc - before.TotalAlloc
}
