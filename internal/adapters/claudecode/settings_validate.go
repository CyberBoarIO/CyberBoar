package claudecode

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// validateSettings checks retained hook and permission structures before merging
// Unknown fields and events are preserved
func validateSettings(settings map[string]any) error {
	if value, present := settings["hooks"]; present {
		hooks, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("hooks is not an object")
		}
		for _, event := range slices.Sorted(maps.Keys(hooks)) {
			groups, ok := hooks[event].([]any)
			if !ok {
				return fmt.Errorf("hooks.%s is not a list", event)
			}
			for i, value := range groups {
				where := fmt.Sprintf("hooks.%s[%d]", event, i)
				group, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("%s is not an object", where)
				}
				if matcher, present := group["matcher"]; present {
					if _, ok := matcher.(string); !ok {
						return fmt.Errorf("%s.matcher is not a string", where)
					}
				}
				handlers, ok := group["hooks"].([]any)
				if !ok {
					return fmt.Errorf("%s.hooks is not a list", where)
				}
				for j, value := range handlers {
					where := fmt.Sprintf("%s.hooks[%d]", where, j)
					handler, ok := value.(map[string]any)
					if !ok {
						return fmt.Errorf("%s is not an object", where)
					}
					if err := validateHandler(handler, where); err != nil {
						return err
					}
				}
			}
		}
	}
	if value, present := settings["permissions"]; present {
		permissions, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("permissions is not an object")
		}
		for _, field := range []string{"allow", "ask", "deny"} {
			if value, present := permissions[field]; present {
				if err := stringList(value, "permissions."+field); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateHandler(handler map[string]any, where string) error {
	kind, _ := handler["type"].(string)
	var required []string
	switch kind {
	case "command":
		required = []string{"command"}
	case "http":
		required = []string{"url"}
	case "mcp_tool":
		required = []string{"server", "tool"}
	case "prompt", "agent":
		required = []string{"prompt"}
	default:
		return fmt.Errorf("%s.type %q is unsupported", where, kind)
	}
	for _, field := range required {
		text, ok := handler[field].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("%s.%s must be a nonempty string", where, field)
		}
	}
	for _, field := range []string{"statusMessage", "if", "model", "shell", "onFailure"} {
		if value, present := handler[field]; present {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s.%s is not a string", where, field)
			}
		}
	}
	for field, allowed := range map[string][]string{"shell": {"bash", "powershell"}, "onFailure": {"continue", "block"}} {
		if value, present := handler[field]; present && !slices.Contains(allowed, value.(string)) {
			return fmt.Errorf("%s.%s %q is unsupported", where, field, value)
		}
	}
	if value, present := handler["timeout"]; present {
		switch value.(type) {
		case json.Number, int:
		default:
			return fmt.Errorf("%s.timeout is not a number", where)
		}
	}
	for _, field := range []string{"async", "asyncRewake", "once"} {
		if value, present := handler[field]; present {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s.%s is not a boolean", where, field)
			}
		}
	}
	for _, field := range []string{"args", "allowedEnvVars"} {
		if value, present := handler[field]; present {
			if err := stringList(value, where+"."+field); err != nil {
				return err
			}
		}
	}
	if value, present := handler["headers"]; present {
		headers, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.headers is not an object", where)
		}
		for key, value := range headers {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s.headers.%s is not a string", where, key)
			}
		}
	}
	return nil
}

func stringList(value any, where string) error {
	list, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s is not a list", where)
	}
	for i, value := range list {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s[%d] is not a string", where, i)
		}
	}
	return nil
}
