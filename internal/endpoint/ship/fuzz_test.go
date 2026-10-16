package ship

import (
	"bufio"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/audit"
)

// FuzzReadBatch: reading never panics, never moves past the input, and only
// returns lines the console would accept
func FuzzReadBatch(f *testing.F) {
	f.Add(line(1, "deny") + "junk\n" + line(2, "ask") + `{"decision":`)
	f.Add("\n\n\r\n")
	f.Add(strings.Repeat("x", 100))
	f.Fuzz(func(t *testing.T, in string) {
		r := bufio.NewReaderSize(strings.NewReader(in), 64)
		events, next, _, err := readBatch(r, 0)
		if err != nil {
			t.Fatal(err)
		}
		if next < 0 || next > int64(len(in)) || next > 0 && in[next-1] != '\n' {
			t.Fatalf("offset %d for %q", next, in)
		}
		for _, e := range events {
			if _, err := audit.ParseLine(e); err != nil {
				t.Fatalf("returned an invalid line %q: %v", e, err)
			}
		}
	})
}
