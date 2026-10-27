// Package cursor maps Cursor's agent hook inputs to engine actions and engine
// verdicts to hook output. It covers the Cursor editor's agent and the
// Cursor CLI (cursor-agent), which share hooks.json
//
// One hook command answers several events, which hook_event_name tells
// apart. They are preToolUse for every tool, and beforeShellExecution,
// beforeMCPExecution, beforeReadFile and beforeTabFileRead, which Cursor
// fires as well, with inputs it documents more precisely
// A call checked twice is only ever stricter
package cursor

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/engine"
)

// Adapter speaks Cursor's hook protocol
type Adapter struct{}

// Name returns "cursor", the agent name used on the command line and in audit events
func (Adapter) Name() string { return "cursor" }

// Events are the hook events the adapter answers
// The apply command installs a hook for each
var Events = []string{"preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeTabFileRead"}

// Input is a hook input
// It holds the fields every event carries and those of the events in Events
type Input struct {
	Event          string   `json:"hook_event_name"`
	ConversationID string   `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Cwd            string   `json:"cwd"`

	// Fields of preToolUse. beforeMCPExecution has tool_name and tool_input
	// too, with tool_input as a JSON-encoded string
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`

	// beforeShellExecution
	Command *string `json:"command"`

	// beforeMCPExecution
	MCPServerName string `json:"mcp_server_name"`

	// beforeReadFile, beforeTabFileRead
	FilePath    string `json:"file_path"`
	Attachments []struct {
		FilePath string `json:"file_path"`
	} `json:"attachments"`
}

// ParseInput decodes exactly one JSON object naming one of Events
func ParseInput(data []byte) (*Input, error) {
	var in Input
	if err := adapters.DecodeHookInput(data, &in); err != nil {
		return nil, err
	}
	for _, e := range Events {
		if in.Event == e {
			return &in, nil
		}
	}
	return nil, adapters.Invalid("the hook input's hook_event_name %q is not one this hook answers", in.Event)
}

// Env is what the adapter takes from the hook's environment
type Env struct {
	// ProjectDir is CURSOR_PROJECT_DIR, the workspace root Cursor sets for every hook
	ProjectDir string
	Home       string
	// Shell is SHELL, the shell Cursor's agent runs commands in
	Shell  string
	CDPath bool
}

// Parse decodes a hook input into engine actions
func (Adapter) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	env := Env{ProjectDir: getenv("CURSOR_PROJECT_DIR"), Home: getenv("HOME"), Shell: getenv("SHELL"), CDPath: getenv("CDPATH") != ""}
	c := &adapters.Call{Session: in.ConversationID, ToolUseID: in.ToolUseID, Cwd: in.Cwd, Project: env.ProjectDir, Tool: toolLabel(in)}
	c.Actions, c.Err = Actions(in, env)
	adapters.Guard(c.Actions, SettingsFiles(env, in.WorkspaceRoots)...)
	adapters.Guard(c.Actions, adapters.StartupFiles(false, env.Home, getenv)...)
	return c, nil
}

// toolLabel names the call in audit events
// It is the tool for preToolUse and MCP calls, and the event otherwise
func toolLabel(in *Input) string {
	if in.ToolName != "" {
		return in.ToolName
	}
	return in.Event
}

// SettingsFiles returns the files that install, change or switch off the
// hook, which agents may not change (builtin.guarded). They are hooks.json in
// every scope with the hook scripts beside it, the CLI's configuration, the
// editor's user settings, and Claude Code's settings, whose hooks Cursor also runs
func SettingsFiles(env Env, roots []string) []string {
	var out []string
	if env.Home != "" {
		cursor := adapters.Under(false, env.Home, ".cursor")
		out = append(out, cursor+"/hooks.json", cursor+"/hooks", cursor+"/cli-config.json",
			adapters.Under(false, env.Home, ".config", "Cursor", "User"),
			adapters.Under(false, env.Home, "Library", "Application Support", "Cursor", "User"),
			adapters.Under(false, env.Home, ".claude", "settings.json"))
	}
	for _, dir := range projectDirs(env, roots) {
		out = append(out, adapters.Under(false, dir, ".cursor", "hooks.json"), adapters.Under(false, dir, ".cursor", "hooks"),
			adapters.Under(false, dir, ".claude", "settings.json"), adapters.Under(false, dir, ".claude", "settings.local.json"))
	}
	return append(out, ManagedFiles...)
}

func projectDirs(env Env, roots []string) []string {
	dirs := append([]string{env.ProjectDir}, roots...)
	sort.Strings(dirs)
	var out []string
	for i, d := range dirs {
		if d != "" && (i == 0 || d != dirs[i-1]) {
			out = append(out, d)
		}
	}
	return out
}

// Respond turns a verdict into hook output, which is a JSON permission answer
// on stdout and exit status 0. Cursor ignores "ask" from preToolUse and runs
// the tool, and preToolUse comes first, so ask is answered as deny
// Allow is "{}", with no decision, which leaves Cursor's own approval flow in charge
// An empty answer would be invalid JSON, which blocks
func (Adapter) Respond(v engine.Verdict, prefix string) adapters.Output {
	var reason string
	switch v.Decision {
	case engine.Allow:
		return adapters.Output{Stdout: []byte("{}\n")}
	case engine.Ask:
		reason = prefix + v.Reason + " (Cursor hooks can't ask for confirmation before every tool, so it is blocked; the user can run it themselves)"
	default:
		reason = prefix + v.Reason
	}
	body, _ := json.Marshal(map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason})
	return adapters.Output{Stdout: append(body, '\n'), Stderr: reason + "\n"}
}

// Actions maps a hook input to the engine actions to evaluate
// No actions and no error means the call touches nothing CyberBoar governs
func Actions(in *Input, env Env) ([]engine.Action, error) {
	base := engine.Action{Cwd: in.Cwd, Home: env.Home, CDPath: env.CDPath}
	base.Workspaces = projectDirs(env, in.WorkspaceRoots)
	if len(base.Workspaces) == 0 {
		return nil, adapters.Invalid("the hook has neither CURSOR_PROJECT_DIR nor workspace_roots, so the project is unknown")
	}
	if base.Cwd == "" {
		// File tools resolve relative paths against the workspace
		base.Cwd = env.ProjectDir
		for _, r := range in.WorkspaceRoots {
			if base.Cwd != "" {
				break
			}
			base.Cwd = r
		}
	}
	file := func(tool engine.Tool, paths ...string) []engine.Action {
		var out []engine.Action
		for _, p := range paths {
			a := base
			a.Tool, a.Path = tool, p
			out = append(out, a)
		}
		return out
	}

	switch in.Event {
	case "beforeShellExecution":
		if in.Command == nil {
			return nil, adapters.Invalid("the beforeShellExecution input has no command")
		}
		return []engine.Action{shellAction(base, *in.Command, in.Cwd, env)}, nil
	case "beforeMCPExecution":
		tool := strings.TrimPrefix(in.ToolName, "MCP:")
		if in.MCPServerName == "" || tool == "" {
			return nil, adapters.Invalid("the beforeMCPExecution input has no mcp_server_name or tool_name")
		}
		a := base
		a.Tool, a.MCP, a.Content = engine.ToolMCP, engine.MCPCall{Server: in.MCPServerName, Tool: tool}, adapters.JSONText(in.ToolInput)
		return []engine.Action{a}, nil
	case "beforeReadFile", "beforeTabFileRead":
		if in.FilePath == "" {
			return nil, adapters.Invalid("the %s input has no file_path", in.Event)
		}
		paths := []string{in.FilePath}
		for _, att := range in.Attachments {
			if att.FilePath != "" {
				paths = append(paths, att.FilePath)
			}
		}
		return file(engine.ToolRead, paths...), nil
	}
	return toolActions(in, base, env, file)
}

// preToolUse maps the tool names Cursor documents for preToolUse matchers to how they are checked
// A tool not listed is denied, because new tools are never trusted by default
var preToolUse = map[string]struct {
	tool     engine.Tool // "" for the shell
	required bool        // a path must be found
}{
	"Shell":  {},
	"Read":   {engine.ToolRead, true},
	"Write":  {engine.ToolWrite, true},
	"Delete": {engine.ToolWrite, true},
	"Grep":   {engine.ToolRead, false}, // searches contents, and with no path the working directory
}

func toolActions(in *Input, base engine.Action, env Env, file func(engine.Tool, ...string) []engine.Action) ([]engine.Action, error) {
	if in.ToolName == "" {
		return nil, adapters.Invalid("the preToolUse input has no tool_name")
	}
	switch {
	case in.ToolName == "Task":
		// Task starts a subagent, whose own tool calls come through these hooks
		return nil, nil
	case strings.HasPrefix(in.ToolName, "MCP:"):
		// preToolUse doesn't name the server
		// beforeMCPExecution, which Cursor fires for the same call, does, and the call is checked there
		return nil, nil
	}
	spec, ok := preToolUse[in.ToolName]
	if !ok {
		return nil, adapters.Unclassified(in.ToolName)
	}
	var input map[string]any
	dec := json.NewDecoder(bytes.NewReader(in.ToolInput))
	dec.UseNumber()
	if err := dec.Decode(&input); err != nil || input == nil {
		return nil, adapters.Invalid("the %s tool input is not a JSON object", in.ToolName)
	}
	if spec.tool == "" {
		cmd, ok := input["command"].(string)
		if !ok {
			return nil, adapters.Invalid("the %s tool input has no command string", in.ToolName)
		}
		cwd := in.Cwd
		for _, k := range []string{"cwd", "working_directory"} {
			if s, ok := input[k].(string); ok && s != "" {
				cwd = s
			}
		}
		return []engine.Action{shellAction(base, cmd, cwd, env)}, nil
	}
	paths := pathValues(input)
	if len(paths) == 0 {
		if spec.required {
			return nil, adapters.Invalid("the %s tool input names no file this hook recognizes, so it is blocked", in.ToolName)
		}
		paths = []string{"."}
	}
	out := file(spec.tool, paths...)
	if spec.tool == engine.ToolWrite {
		// Cursor doesn't document what a write's input holds, so all of its
		// text is checked for secrets, and none counts as already in the file
		content := adapters.ValuesText(input)
		for i := range out {
			out[i].Content = content
		}
	}
	return out, nil
}

// pathValues returns every string, at any depth, under a key that names a
// file or directory. Cursor documents the tool names but not their inputs,
// so the keys are matched loosely and every match is checked, since an extra
// path can only make the verdict stricter. Directories a tool runs in rather
// than acts on, such as cwd, are left out, because the project root would
// read as a directory holding every protected file
func pathValues(v any) []string {
	var out []string
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch v := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(k, v[k])
			}
		case []any:
			for _, e := range v {
				walk(key, e)
			}
		case string:
			if pathKey(key) && v != "" {
				out = append(out, v)
			}
		}
	}
	walk("", v)
	return out
}

func pathKey(key string) bool {
	k := strings.ToLower(key)
	for _, not := range []string{"cwd", "working_dir", "workdir", "content", "text", "string", "pattern", "glob", "query"} {
		if strings.Contains(k, not) {
			return false
		}
	}
	for _, is := range []string{"path", "file", "dir", "target"} {
		if strings.Contains(k, is) {
			return true
		}
	}
	return false
}

// shellAction returns the action for a command run in the user's shell. A
// command for a shell other than bash, sh, dash or zsh is foreign code to the
// analyzer. A call with no directory starts in an unknown one
// The agent's shell persists between calls (cd, variables and aliases
// carry over, seen in the CLI 2026.10.14), so the action says so
func shellAction(base engine.Action, cmd, cwd string, env Env) engine.Action {
	a := base
	a.Tool, a.Command = engine.ToolShell, adapters.ShellCommand(env.Shell, cmd)
	a.ShellPersists = true
	a.Cwd = cwd
	if cwd == "" {
		a.CwdUnknown = true
	}
	return a
}
