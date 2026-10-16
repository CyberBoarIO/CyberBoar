package adapters

import (
	"fmt"

	"github.com/goccy/go-yaml"
)

// LoadTools reads an adapter's tools.yaml, a version and a table of tool
// names to specs, and checks each spec with valid
func LoadTools[S any](data []byte, valid func(name string, spec S) error) (map[string]S, error) {
	var t struct {
		Version int          `yaml:"version"`
		Tools   map[string]S `yaml:"tools"`
	}
	if err := yaml.UnmarshalWithOptions(data, &t, yaml.Strict()); err != nil {
		return nil, err
	}
	if t.Version != 1 {
		return nil, fmt.Errorf("tools.yaml version %d, want 1", t.Version)
	}
	for name, spec := range t.Tools {
		if err := valid(name, spec); err != nil {
			return nil, fmt.Errorf("tools.yaml: %s: %w", name, err)
		}
	}
	return t.Tools, nil
}

// ClassificationFailed returns the denial of every tool when an adapter's tools.yaml didn't load
func ClassificationFailed(err error) *Error {
	return &Error{Rule: RuleUnclassifiedTool, Msg: fmt.Sprintf("the tool classification failed to load (%v), so every tool is blocked", err)}
}

// Unclassified returns the denial of a tool the adapter doesn't know
func Unclassified(tool string) *Error {
	return &Error{Rule: RuleUnclassifiedTool, Msg: fmt.Sprintf(
		"the tool %s is not classified yet, so policy can't tell what it touches and it is blocked; do not attempt to reach the same result with another tool", tool)}
}
