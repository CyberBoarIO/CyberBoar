package audit_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/audit"
)

// FuzzParseLine: parsing never panics, and a line ParseLine accepts also passes CheckKeys inside a batch.
func FuzzParseLine(f *testing.F) {
	// A fixed epoch keeps the seed corpus reproducible
	timestamp := time.Unix(0, 0).UTC().Format(time.RFC3339)
	f.Add([]byte(`{"time":"` + timestamp + `","decision":"deny","actions":[{"tool":"read","path":"/w"}]}`))
	f.Add([]byte(`{"time":"` + timestamp + `","decision":"deny","Decision":"allow"}`))
	files, _ := filepath.Glob("../../testdata/protocol/events/*.json")
	for _, file := range files {
		if data, err := os.ReadFile(file); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		if _, err := audit.ParseLine(line); err != nil {
			return
		}
		batch := append([]byte(`{"endpoint":{"id":"3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24","version":"v1"},"events":[`), line...)
		batch = append(batch, "]}"...)
		if err := audit.CheckKeys(batch, audit.Batch{}); err != nil {
			t.Errorf("ParseLine accepts %q, its batch fails: %v", line, err)
		}
	})
}
