package policy

import "fmt"

// Warning is an advisory finding. Warnings never affect policy validity or enforcement
type Warning struct {
	Path    string
	Message string
}

// Lint detects only exact duplicates and exact cross-list conflicts
// It does not attempt to infer overlaps between nonidentical patterns or globs
func Lint(p *Policy) []Warning {
	if p == nil {
		return nil
	}
	var warnings []Warning
	for _, group := range []struct {
		prefix string
		rules  Rules
	}{
		{"spec.files", p.Spec.Files.Rules},
		{"spec.commands", p.Spec.Commands.Rules},
		{"spec.mcp", p.Spec.MCP},
	} {
		type prior struct{ path, decision string }
		seen := make(map[string]prior)
		for _, list := range ruleLists(group.prefix, group.rules) {
			decision := list.path[len(group.prefix)+1:]
			for i, pattern := range list.patterns {
				where := fmt.Sprintf("%s[%d]", list.path, i)
				if prev, ok := seen[pattern]; ok {
					message := "duplicates " + prev.path
					if prev.decision != decision {
						message = "also appears at " + prev.path + "; deny takes precedence over ask and allow, and ask takes precedence over allow"
					}
					warnings = append(warnings, Warning{Path: where, Message: message})
				} else {
					seen[pattern] = prior{where, decision}
				}
			}
		}
	}
	return warnings
}
