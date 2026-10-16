package copilot

import (
	"bytes"
	"encoding/json"
	"errors"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// PolicyDir is where Copilot CLI reads machine-wide hooks on Linux and macOS.
// They load before every other hook, disableAllHooks can't switch them off,
// and Copilot requires them to be owned by root
const PolicyDir = "/etc/github-copilot/policy.d"

// Scope is where Copilot hook configuration lives. Each is a file CyberBoar
// owns entirely, since Copilot reads every *.json in its hooks directories
type Scope string

const (
	ScopeUser    Scope = "user"    // ~/.copilot/hooks/cyberboar.json (or COPILOT_HOME)
	ScopeProject Scope = "project" // <repo>/.github/hooks/cyberboar.json (committed)
	ScopeManaged Scope = "managed" // /etc/github-copilot/policy.d/cyberboar.json
)

// HookTimeout is the hook timeout in seconds. Copilot lets a call through
// when its hook times out, which fails open (seen in 1.0.91), so the hook's
// own deadline must stay well below it
const HookTimeout = 15

// HooksOff reports whether Copilot CLI settings, such as a user's
// config.json or a repository's .github/copilot/settings.json, set
// disableAllHooks, which switches off every user and repository hook.
// Copilot writes config.json with // comments (seen in 1.0.97), so comments
// and trailing commas are allowed. Settings that aren't a JSON object are an
// error, because then it can't be told whether they do
func HooksOff(settings []byte) (bool, error) {
	settings = jsonc(settings)
	if len(bytes.TrimSpace(settings)) == 0 {
		return false, nil
	}
	var s map[string]any
	if err := json.Unmarshal(settings, &s); err != nil || s == nil {
		return false, errors.New("the settings are not a JSON object")
	}
	v, ok := s["disableAllHooks"]
	return ok && v != nil && v != false, nil
}

// jsonc returns data without the // and /* */ comments and the trailing
// commas JSONC allows outside strings, so that encoding/json reads it. A
// comment is replaced by a space, so it still separates what is around it
func jsonc(data []byte) []byte {
	var out []byte
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			c = '\n'
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return append(out, data[i:]...) // unterminated: left for the decoder to refuse
			}
			i += end + 3
			c = ' '
		case c == '}' || c == ']':
			// A comma before the closing bracket, with only space between, goes
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
		}
		if i < len(data) || c == '\n' {
			out = append(out, c)
		}
	}
	return out
}

// FileName is the name of the hooks file CyberBoar writes in each scope
const FileName = brand.Name + ".json"

// FragmentOptions describe the hook command to install
type FragmentOptions struct {
	Scope    Scope
	Command  string // cyberboar executable, as an absolute path or a name on PATH
	Policy   string // policy path, relative to the repository root for ScopeProject
	Audit    string
	State    string // the hook's --state, or "" for its default
	PubKey   string // policy signing public key, or ""
	Deadline string
	Briefing bool // install the sessionStart briefing (the policy's spec.session.briefing)
}

// HookArgs returns the arguments of the preToolUse hook command. Copilot
// runs hooks in the repository root, or in the session directory outside a
// git repository, and a project-scope policy path is relative to it
func HookArgs(o FragmentOptions) []string {
	return adapters.HookArgs("copilot-cli", o.Policy, o.Audit, o.State, o.PubKey, o.Deadline)
}

// BriefArgs returns the arguments of the sessionStart briefing command
func BriefArgs(o FragmentOptions) []string {
	return adapters.BriefArgs("copilot-cli", o.Policy, o.PubKey)
}

// HooksFile returns the hooks file for a scope. The command is run directly
// (exec and args), never through a shell, so no path needs quoting
// The hook has no matcher, so it runs for every tool, MCP tools included
func HooksFile(o FragmentOptions) ([]byte, error) {
	hooks := map[string]any{
		"preToolUse": []any{map[string]any{"type": "command", "exec": o.Command, "args": HookArgs(o), "timeoutSec": HookTimeout}},
	}
	if o.Briefing {
		hooks["sessionStart"] = []any{map[string]any{"type": "command", "exec": o.Command, "args": BriefArgs(o), "timeoutSec": HookTimeout}}
	}
	out, err := json.MarshalIndent(map[string]any{"version": 1, "hooks": hooks}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// SessionStartOutput returns Copilot's sessionStart answer, which has
// additionalContext at the top level. Empty text gives no output
func (Adapter) SessionStartOutput(text string) []byte {
	if text == "" {
		return nil
	}
	out, _ := json.Marshal(map[string]any{"additionalContext": text})
	return append(out, '\n')
}
