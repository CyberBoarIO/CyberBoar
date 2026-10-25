// Package adapters holds the parsed form of one hook call, the hook's answer
// and the helpers for tool inputs that every agent adapter shares
package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// Rule IDs for decisions an adapter makes before the engine is involved
const (
	RuleInvalidInput     = "error.invalidInput"
	RuleUnclassifiedTool = "adapter.unclassifiedTool"
	// RulePowerShell denies every call of an agent's PowerShell tool, whatever
	// the policy says, where the engine doesn't analyze PowerShell: outside
	// native Windows
	RulePowerShell = "builtin.powershell"
)

// PowerShell returns the denial of a call to an agent's PowerShell tool
// outside native Windows, and what the user is told about it. tool is the
// agent's name for that tool, and bash names the tool the agent should use
// instead, such as "the Bash tool"
func PowerShell(tool, bash string) (err *Error, notice string) {
	name := brand.DisplayName
	err = &Error{Rule: RulePowerShell, Msg: fmt.Sprintf("%s checks PowerShell only on native Windows, so here every command for the %s tool is blocked, whatever it does. "+
		"Run the command with %s instead, where it is checked. If it can't be done there, stop and tell the user that %s blocks PowerShell here",
		name, tool, bash, name)}
	notice = fmt.Sprintf("%s blocked a command for the %s tool: %s checks PowerShell only on native Windows, so here every PowerShell command is blocked. "+
		"The agent was told to use %s instead, where commands are checked.", name, tool, name, bash)
	return err, notice
}

// Error is a hook input an adapter refuses. The hook denies it with Rule
type Error struct {
	Rule string
	Msg  string
}

// Error returns the message
func (e *Error) Error() string { return e.Msg }

// Invalid returns an Error for malformed input
func Invalid(format string, args ...any) *Error {
	return &Error{Rule: RuleInvalidInput, Msg: fmt.Sprintf(format, args...)}
}

// Call is one parsed hook invocation
type Call struct {
	// These fields are for the audit event
	Session, ToolUseID, AgentID, AgentType, Mode, Cwd, Project, Tool string

	// Actions are the engine actions to evaluate. When Err is set the call is
	// denied with Err's rule instead (once a policy has loaded)
	Actions []engine.Action
	Err     error
	// Notice, when set, is told to the user as well as the agent when the call
	// is denied (engine.Verdict.Notice)
	Notice string
}

// Output is a hook's answer to the agent
type Output struct {
	Stdout []byte
	Stderr string
	Exit   int
}

// Briefer is implemented by an Adapter whose agent reads the SessionStart
// briefing in its own shape
// Other agents get briefing.SessionStartOutput
type Briefer interface {
	// SessionStartOutput returns the hook answer that adds text to the agent's context
	// Empty text gives no output
	SessionStartOutput(text string) []byte
}

// Adapter speaks one agent's PreToolUse hook protocol
type Adapter interface {
	// Name returns the agent's ID in flags and audit events, such as "claude-code"
	Name() string
	// Parse decodes a hook input
	// An error means the input itself is unusable
	// Problems with the tool call go in Call.Err
	Parse(data []byte, getenv func(string) string) (*Call, error)
	// Respond turns a verdict into the agent's hook output
	// It must never answer "allow" in a way that skips the user's own approval
	Respond(v engine.Verdict, prefix string) Output
}

// Extract returns the strings at a field path such as "a", "a[]", "a.*" or"a.*.b"
// It skips values that aren't strings, which CheckFields refuses first
func Extract(v any, path string) []string {
	return extract(v, strings.Split(path, "."))
}

func extract(v any, segs []string) []string {
	if len(segs) == 0 {
		if s, ok := v.(string); ok {
			return []string{s}
		}
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	seg, rest := segs[0], segs[1:]
	var out []string
	switch {
	case seg == "*":
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, extract(obj[k], rest)...)
		}
	case strings.HasSuffix(seg, "[]"):
		arr, _ := obj[strings.TrimSuffix(seg, "[]")].([]any)
		for _, el := range arr {
			out = append(out, extract(el, rest)...)
		}
	default:
		out = extract(obj[seg], rest)
	}
	return out
}

// ToolInputObject decodes an agent's tool input, preserving JSON numbers,
// and checks required fields and the shapes of fields that carry paths
// Missing optional fields remain valid; each adapter checks its other types
func ToolInputObject(tool string, data json.RawMessage, required, fields []string) (map[string]any, error) {
	var input map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil || input == nil {
		return nil, Invalid("the %s tool input is not a JSON object", tool)
	}
	for _, f := range required {
		if v, ok := input[f]; !ok || v == nil {
			return nil, Invalid("the %s tool input has no %q", tool, f)
		}
	}
	if err := CheckFields(input, fields); err != nil {
		return nil, Invalid("the %s tool input is malformed: %v", tool, err)
	}
	return input, nil
}

// CheckFields reports a value at one of the field paths (as Extract reads
// them) that Extract would skip although it is there, such as a number where
// a path should be, or an array or object that no other path in fields reads into
// Extract skips such values, so without this check a tool input whose path
// has an unexpected type would be checked as touching nothing
func CheckFields(v any, fields []string) error {
	for _, f := range fields {
		if err := checkField(v, f, "", fields); err != nil {
			return err
		}
	}
	return nil
}

func checkField(v any, path, prefix string, fields []string) error {
	if v == nil {
		return nil
	}
	if path == "" {
		if _, ok := v.(string); ok {
			return nil
		}
		return unread(v, prefix, fields)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return unread(v, prefix, fields)
	}
	seg, rest, _ := strings.Cut(path, ".")
	join := func(s string) string {
		if prefix == "" {
			return s
		}
		return prefix + "." + s
	}
	switch {
	case seg == "*":
		for _, el := range obj {
			if err := checkField(el, rest, join("*"), fields); err != nil {
				return err
			}
		}
	case strings.HasSuffix(seg, "[]"):
		name := strings.TrimSuffix(seg, "[]")
		el := obj[name]
		arr, ok := el.([]any)
		if !ok {
			if el == nil {
				return nil
			}
			return unread(el, join(name), fields)
		}
		for _, el := range arr {
			if err := checkField(el, rest, join(seg), fields); err != nil {
				return err
			}
		}
	default:
		return checkField(obj[seg], rest, join(seg), fields)
	}
	return nil
}

// unread returns an error for v at prefix unless another field path reads it
// A string is read if prefix itself is a path, and an array or object if a path goes on below prefix
func unread(v any, prefix string, fields []string) error {
	for _, f := range fields {
		switch v.(type) {
		case string:
			if f == prefix {
				return nil
			}
		case []any:
			if strings.HasPrefix(f, prefix+"[]") {
				return nil
			}
		case map[string]any:
			if strings.HasPrefix(f, prefix+".") {
				return nil
			}
		}
	}
	return fmt.Errorf("field %q holds a %s, which is not read as a path", prefix, typeName(v))
}

func typeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case []any:
		return "list"
	case map[string]any:
		return "object"
	case bool:
		return "boolean"
	}
	return "number"
}

// ShellQuote quotes s as one POSIX shell word
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SplitMCP returns every (server, tool) reading of the part of an MCP tool
// name after "mcp__". Callers evaluate every reading and keep the strictest
// verdict, so a server named "a__b" can't hide behind the split (a, b__tool)
func SplitMCP(rest string) []engine.MCPCall {
	var out []engine.MCPCall
	for i := 0; i+2 <= len(rest); i++ {
		if rest[i:i+2] == "__" && i > 0 && i+2 < len(rest) {
			out = append(out, engine.MCPCall{Server: rest[:i], Tool: rest[i+2:]})
		}
	}
	return out
}

// Guard adds paths, the files that install the hook, to the Guarded list of
// every file and shell action, so that the agent may not change them
// (builtin.guarded). Empty paths are skipped
func Guard(actions []engine.Action, paths ...string) {
	for i := range actions {
		if actions[i].Tool == engine.ToolMCP {
			continue
		}
		for _, p := range paths {
			if p != "" {
				actions[i].Guarded = append(actions[i].Guarded, p)
			}
		}
	}
}

// Under joins names below dir with the separator of the platform's paths
// It returns "" when dir is empty, which means the hook doesn't know it
func Under(windows bool, dir string, names ...string) string {
	if dir == "" {
		return ""
	}
	sep := "/"
	if windows {
		sep = `\`
		dir = strings.TrimRight(dir, `\/`)
	} else {
		dir = strings.TrimRight(dir, "/")
	}
	return dir + sep + strings.Join(names, sep)
}

// IsDir reports whether path names an existing directory
// It follows symbolic links, so a link to a directory lists that directory
// The engine resolves the path itself and checks where it really leads, so this only chooses
// between listing and reading. An empty path, or one that can't be examined,
// is not a directory. That is the stricter reading, because the path is then
// checked as a read
func IsDir(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// DecodeHookInput decodes a hook's input, which must be exactly one JSON
// object. Fields v has no place for are ignored, because agents add them over time
func DecodeHookInput(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return Invalid("the hook input is not a JSON object: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Invalid("the hook input has data after the JSON object")
	}
	return nil
}

// ShellCommand returns cmd as the engine should read it when the agent runs it with shell
// It is unchanged for bash, sh, dash and zsh. For any other
// shell it is wrapped as foreign code, as PowerShell or else as fish, which
// the analyzer doesn't read as bash
func ShellCommand(shell, cmd string) string {
	name := strings.ToLower(filepath.Base(shell))
	switch strings.TrimSuffix(name, ".exe") {
	case "bash", "sh", "dash", "zsh":
		return cmd
	}
	if strings.HasPrefix(name, "pwsh") || strings.HasPrefix(name, "powershell") {
		return "pwsh -Command " + ShellQuote(cmd)
	}
	return "fish -c " + ShellQuote(cmd)
}
