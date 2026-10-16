package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
)

// Hook latency: every agent tool call pays for one Evaluate
func BenchmarkEvaluate(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "baseline.yaml"))
	if err != nil {
		b.Fatal(err)
	}
	p, err := policy.Load(data)
	if err != nil {
		b.Fatal(err)
	}
	c, err := engine.Compile(p)
	if err != nil {
		b.Fatal(err)
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		b.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	for _, bc := range []struct{ name, tool, arg string }{
		{"read file", "read", "internal/engine/engine.go"},
		{"read repo dir", "read", "."},
		{"shell simple", "shell", "go test ./..."},
		{"shell pipeline", "shell", "cd internal && grep -n TODO engine/*.go | sort | head -20"},
		{"shell recursive grep", "shell", "grep -rn TODO ."},
	} {
		a := engine.Action{Tool: engine.Tool(bc.tool), Cwd: repo, Home: home, Workspaces: []string{repo}}
		if bc.tool == "read" {
			a.Path = bc.arg
		} else {
			a.Command = bc.arg
		}
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				engine.Evaluate(context.Background(), c, a)
			}
		})
	}
	b.Run("load and compile policy", func(b *testing.B) {
		for b.Loop() {
			p, _ := policy.Load(data)
			_, _ = engine.Compile(p)
		}
	})
}
