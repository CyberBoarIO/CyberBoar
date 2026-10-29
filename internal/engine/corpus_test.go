package engine_test

import (
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/corpustest"
)

// TestCorpus runs the specification: every case in testdata/corpus against the engine.
func TestCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "corpus", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files found (err=%v)", err)
	}
	for _, path := range files {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".yaml"), func(t *testing.T) {
			f, err := corpustest.LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			corpustest.Run(t, f)
		})
	}
}
