package shell_test

import (
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/corpustest"
	"cyberboar.dev/cyberboar/internal/engine/shell"
)

func TestLinkFileCorpusMatchesReference(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(corpusDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("missing corpus: %v", err)
	}
	var compared int
	for _, path := range files {
		fixture, err := corpustest.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range fixture.Cases {
			action, err := fixture.Action(c, "/nonexistent/graph-test")
			if err != nil || action.Tool != "shell" || action.Command == "" {
				continue
			}
			t.Run(filepath.Base(path)+"/"+c.Name, func(t *testing.T) {
				shell.CheckFeedGraph(t, action.Command)
				compared++
			})
		}
	}
	t.Logf("compared graph relations for %d parseable corpus commands", compared)
}
