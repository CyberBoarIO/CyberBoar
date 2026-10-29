package cursor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"cyberboar.dev/cyberboar/internal/adapters"
)

// ManagedFiles are the machine-wide hooks.json files Cursor reads first, on
// Linux and on macOS. Cursor runs commands in PowerShell on native Windows,
// where it is denied, so C:\ProgramData\Cursor\hooks.json is not written.
var ManagedFiles = []string{path.Join(ManagedDir("linux"), "hooks.json"), path.Join(ManagedDir("darwin"), "hooks.json")}

// ManagedDir is the directory of the machine-wide hooks.json on goos.
func ManagedDir(goos string) string {
	if goos == "darwin" {
		return "/Library/Application Support/Cursor"
	}
	return "/etc/cursor"
}

// Scope is where a hooks.json lives.
type Scope string

// The scopes apply installs into, by the settings file each one writes.
const (
	ScopeUser    Scope = "user"    // ~/.cursor/hooks.json
	ScopeProject Scope = "project" // <project>/.cursor/hooks.json (committed)
	ScopeManaged Scope = "managed" // /etc/cursor/hooks.json, /Library/Application Support/Cursor/hooks.json
)

// HookTimeout is the hook timeout in seconds. Hooks are installed with
// failClosed, so a timeout denies.
// The hook's deadline stays below it, so that the hook gives its reason instead.
const HookTimeout = 15

// FragmentOptions describe the hook command to install.
type FragmentOptions struct {
	Command  string // cyberboar executable, as an absolute path or a name on PATH
	Policy   string // policy path, relative to the project root for ScopeProject
	Audit    string
	State    string // the hook's --state, or "" for its default
	PubKey   string // policy signing public key, or ""
	Deadline string
	Briefing bool // install the sessionStart briefing (the policy's spec.session.briefing)
}

// HookArgs returns the arguments of the hook command.
func HookArgs(o FragmentOptions) []string {
	return adapters.HookArgs("cursor", o.Policy, o.Audit, o.State, o.PubKey, o.Deadline)
}

// BriefArgs returns the arguments of the sessionStart briefing command.
func BriefArgs(o FragmentOptions) []string {
	return adapters.BriefArgs("cursor", o.Policy, o.PubKey)
}

// commandLine returns a hook command line. Cursor runs it through a shell,
// so every word is quoted. Cursor silently ignores a whole hooks.json in which
// any command holds a URL, so one is refused.
func commandLine(exe string, args []string) (string, error) {
	words := []string{adapters.ShellQuote(exe)}
	for _, a := range args {
		words = append(words, adapters.ShellQuote(a))
	}
	line := strings.Join(words, " ")
	if strings.Contains(line, "://") {
		return "", fmt.Errorf("the hook command %s holds \"://\", which makes Cursor ignore the whole hooks.json", line)
	}
	return line, nil
}

// ours reports whether a hook entry runs CyberBoar for Cursor, so it is
// replaced rather than duplicated. The command is read as shell words, so an
// entry written by hand as the docs show it counts as well as one apply wrote.
func ours(entry map[string]any) bool {
	if kind, ok := entry["type"]; ok && kind != "command" {
		return false
	}
	cmd, _ := entry["command"].(string)
	words := commandWords(cmd)
	for i := range words {
		if words[i] != "hook" && words[i] != "brief" {
			continue
		}
		rest := words[i+1:]
		switch {
		case len(rest) >= 2 && (rest[0] == "--agent" || rest[0] == "-agent") && rest[1] == "cursor",
			len(rest) >= 1 && (rest[0] == "--agent=cursor" || rest[0] == "-agent=cursor"):
			return true
		}
	}
	return false
}

// commandWords returns the words of a one-command line, unquoted, with ""
// for a word that isn't a plain literal. A line that isn't one simple
// command gives none.
func commandWords(line string) []string {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(line), "")
	if err != nil || len(f.Stmts) != 1 {
		return nil
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	var out []string
	for _, w := range call.Args {
		lit := ""
		if len(w.Parts) == 1 {
			switch p := w.Parts[0].(type) {
			case *syntax.Lit:
				if !strings.Contains(p.Value, `\`) {
					lit = p.Value
				}
			case *syntax.SglQuoted:
				if !p.Dollar {
					lit = p.Value
				}
			case *syntax.DblQuoted:
				if l, ok := onlyLit(p.Parts); ok && !strings.ContainsAny(l, `\$`+"`") {
					lit = l
				}
			}
		}
		out = append(out, lit)
	}
	return out
}

// MergeHooks adds the hook to a hooks.json, keeping every other hook in it
// and replacing an earlier CyberBoar entry. Cursor has one hooks.json per
// scope, so the file is shared. existing may be empty. The hook has no
// matcher, so it runs for every tool, MCP tools included. failClosed makes
// Cursor deny when the hook crashes or times out instead of running the tool.
func MergeHooks(existing []byte, o FragmentOptions) ([]byte, error) {
	doc := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(existing))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("not a JSON object: %w", err)
		}
		if doc == nil {
			return nil, errors.New("hooks.json is null, not a JSON object")
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, errors.New("data after the JSON object")
		}
		if v, ok := doc["version"]; ok && fmt.Sprint(v) != "1" {
			return nil, fmt.Errorf("hooks.json version %v, want 1", v)
		}
	}
	doc["version"] = 1
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		if _, ok := doc["hooks"]; ok {
			return nil, errors.New("hooks is not an object")
		}
		hooks = map[string]any{}
	}
	if err := validateHooks(hooks); err != nil {
		return nil, err
	}
	hookCmd, err := commandLine(o.Command, HookArgs(o))
	if err != nil {
		return nil, err
	}
	briefCmd, err := commandLine(o.Command, BriefArgs(o))
	if err != nil {
		return nil, err
	}
	install := map[string]string{}
	for _, e := range Events {
		install[e] = hookCmd
	}
	if o.Briefing {
		install["sessionStart"] = briefCmd
	}
	for _, event := range append(append([]string{}, Events...), "sessionStart") {
		var list []any
		if hooks[event] != nil {
			l, ok := hooks[event].([]any)
			if !ok {
				return nil, fmt.Errorf("hooks.%s is not a list", event)
			}
			list = l
		}
		var kept []any
		if cmd, ok := install[event]; ok {
			h := map[string]any{"command": cmd, "timeout": HookTimeout}
			if event != "sessionStart" {
				h["failClosed"] = true // the briefing decides nothing
			}
			kept = append(kept, h)
		}
		for _, h := range list {
			if m, ok := h.(map[string]any); ok && ours(m) {
				continue
			}
			kept = append(kept, h)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	doc["hooks"] = hooks
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// validateHooks checks existing definitions before they are retained in the merged file.
// Unknown events and properties are preserved, including their number representations.
func validateHooks(hooks map[string]any) error {
	for _, event := range slices.Sorted(maps.Keys(hooks)) {
		list, ok := hooks[event].([]any)
		if !ok {
			return fmt.Errorf("hooks.%s is not a list", event)
		}
		for i, value := range list {
			where := fmt.Sprintf("hooks.%s[%d]", event, i)
			entry, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s is not an object", where)
			}
			for _, field := range []string{"type", "command", "prompt", "matcher", "model"} {
				if v, present := entry[field]; present {
					if _, ok := v.(string); !ok {
						return fmt.Errorf("%s.%s is not a string", where, field)
					}
				}
			}
			kind := "command"
			if v, present := entry["type"]; present {
				kind = v.(string)
			}
			required := "command"
			switch kind {
			case "command":
			case "prompt":
				required = "prompt"
			default:
				return fmt.Errorf("%s.type %q is not command or prompt", where, kind)
			}
			text, _ := entry[required].(string)
			if strings.TrimSpace(text) == "" {
				return fmt.Errorf("%s.%s must be a nonempty string", where, required)
			}
			for _, field := range []string{"timeout", "loop_limit"} {
				if v, present := entry[field]; present {
					if field == "loop_limit" && v == nil {
						continue
					}
					if _, ok := v.(json.Number); !ok {
						return fmt.Errorf("%s.%s is not a number", where, field)
					}
				}
			}
			if v, present := entry["failClosed"]; present {
				if _, ok := v.(bool); !ok {
					return fmt.Errorf("%s.failClosed is not a boolean", where)
				}
			}
		}
	}
	return nil
}

// SessionStartOutput returns Cursor's sessionStart answer, which puts the
// text in additional_context. Empty text gives no output.
func (Adapter) SessionStartOutput(text string) []byte {
	if text == "" {
		return nil
	}
	out, _ := json.Marshal(map[string]any{"additional_context": text})
	return append(out, '\n')
}

func onlyLit(parts []syntax.WordPart) (string, bool) {
	if len(parts) != 1 {
		return "", false
	}
	l, ok := parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return l.Value, true
}
