package adapters_test

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite docs/capability-matrix.md")

const matrixDoc = "../../docs/capability-matrix.md"

const matrixHeader = `# Capability matrix

Coverage for tool calls that reach each adapter. File checks through shell commands
are best effort on the command's arguments: what a launched program opens itself is not
seen, and CyberBoar is not an OS sandbox. See [Agent setup](agents.md) for installation
and [Security model](security-model.md) for shared limitations.

The table compares the agents at a glance. Each agent's section below it holds what
the table leaves out: tool names, versions, guarded paths and known gaps.

This reference is generated from ` + "`" + `internal/adapters/matrix_data_test.go` + "`" + ` with
` + "`" + `go test ./internal/adapters -update` + "`" + `; edit the source rather than this page.

`

// This checks document freshness against manually maintained Matrix prose.
// Behavioral adapter tests establish the capability claims.
func TestMatrixDocUpToDate(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(matrixHeader)
	if err := WriteMatrix(&b); err != nil {
		t.Fatal(err)
	}
	if *update {
		os.WriteFile(matrixDoc, b.Bytes(), 0o644)
	}
	got, err := os.ReadFile(matrixDoc)
	if err != nil || !bytes.Equal(got, b.Bytes()) {
		t.Errorf("%s is out of date (run go test ./internal/adapters -update): %v", matrixDoc, err)
	}
	for _, c := range Matrix {
		for i, x := range c.Cells {
			if strings.TrimSpace(x.Short) == "" {
				t.Errorf("row %q has an empty cell for %s", c.What, Agents[i].Name)
			}
		}
	}
}
