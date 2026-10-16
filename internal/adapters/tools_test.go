package adapters_test

import (
	"errors"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters"
)

func TestLoadTools(t *testing.T) {
	type spec struct {
		Read []string `yaml:"read"`
	}
	valid := func(_ string, s spec) error {
		if len(s.Read) == 0 {
			return errors.New("no fields")
		}
		return nil
	}
	tools, err := adapters.LoadTools([]byte("version: 1\ntools:\n  View: {read: [path]}\n"), valid)
	if err != nil || len(tools) != 1 || tools["View"].Read[0] != "path" {
		t.Fatalf("LoadTools = %v, %v", tools, err)
	}
	for data, want := range map[string]string{
		"version: 2\ntools: {}\n":                         "tools.yaml version 2, want 1",
		"version: 1\ntools:\n  View: {}\n":                "tools.yaml: View: no fields",
		"version: 1\ntools:\n  View: {read: [p], x: 1}\n": "unknown field",
	} {
		if _, err := adapters.LoadTools([]byte(data), valid); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LoadTools(%q) = %v, want an error containing %q", data, err, want)
		}
	}
}
