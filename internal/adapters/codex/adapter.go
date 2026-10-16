// Package codex maps Codex CLI's PreToolUse hook input to engine actions and
// engine verdicts to hook output
//
// Codex differs from Claude Code in ways that make it weaker to govern:
//   - The hook sees a command's text but not the directory it starts in or
//     the shell that runs it. Both are read from the call in the session
//     transcript, and a call that can't be found there is denied.
//   - Codex doesn't support "ask" and runs the tool anyway, so an ask
//     becomes a deny
package codex

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
)

// RuleRemoteEnvironment denies a call that runs in a remote environment,
// where local paths mean nothing
const RuleRemoteEnvironment = "adapter.remoteEnvironment"

// RuleInteractiveSession denies a command started with a terminal (tty).
// Codex then lets the model type into it with write_stdin, which no hook
// sees, and programs such as more, less and vi run shell commands typed there
const RuleInteractiveSession = "adapter.interactiveSession"

// Input is the part of the PreToolUse hook input CyberBoar uses
type Input struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	TurnID         string          `json:"turn_id"`
	ToolUseID      string          `json:"tool_use_id"`
	PermissionMode string          `json:"permission_mode"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	TranscriptPath *string         `json:"transcript_path"`
}

// ParseInput decodes exactly one JSON object
func ParseInput(data []byte) (*Input, error) {
	var in Input
	if err := adapters.DecodeHookInput(data, &in); err != nil {
		return nil, err
	}
	if in.HookEventName != "PreToolUse" {
		return nil, adapters.Invalid("hook event %q: this hook handles PreToolUse only", in.HookEventName)
	}
	if in.ToolName == "" {
		return nil, adapters.Invalid("the hook input has no tool_name")
	}
	return &in, nil
}

// Adapter speaks Codex CLI's hook protocol
type Adapter struct{}

// Name returns "codex", the agent name used on the command line and in audit events
func (Adapter) Name() string { return "codex" }

// Parse uses the session cwd from the hook input as the workspace root.
// Codex sets it when the session starts, and the model can't change it. The
// model's per-command `workdir` is a different thing, which the hook input
// doesn't carry
func (Adapter) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	c := &adapters.Call{Session: in.SessionID, ToolUseID: in.ToolUseID, AgentID: in.AgentID, AgentType: in.AgentType,
		Mode: in.PermissionMode, Cwd: in.Cwd, Project: in.Cwd, Tool: in.ToolName}
	c.Actions, c.Err = Actions(in, getenv("HOME"), getenv("SHELL"), getenv("CDPATH") != "")
	codexHome := getenv("CODEX_HOME")
	if codexHome == "" {
		codexHome = adapters.Under(false, getenv("HOME"), ".codex")
	}
	adapters.Guard(c.Actions, ConfigFiles(codexHome, in.Cwd)...)
	// The transcript supplies trusted command arguments, so it must stay read-only
	// It may live outside CODEX_HOME, for example when resuming a moved session
	if in.TranscriptPath != nil {
		adapters.Guard(c.Actions, *in.TranscriptPath)
	}
	return c, nil
}

// ConfigFiles returns the Codex paths agents may not change (builtin.guarded)
// They include the user's session transcripts, hook settings in the user's and
// project's Codex directories, and the managed directory
func ConfigFiles(codexHome, project string) []string {
	var out []string
	for _, dir := range []string{codexHome, adapters.Under(false, project, ".codex")} {
		out = append(out, adapters.Under(false, dir, "hooks.json"), adapters.Under(false, dir, "config.toml"))
	}
	return append(out, adapters.Under(false, codexHome, "sessions"), adapters.Under(false, codexHome, "archived_sessions"), ManagedDir)
}

// Respond turns a verdict into hook output. Codex treats an "ask" answer as a
// failed hook and runs the tool, so ask is answered as deny. Allow produces
// no output, leaving Codex's own approval flow in charge
// A verdict's Notice is sent as systemMessage, Codex's message for the user
func (Adapter) Respond(v engine.Verdict, prefix string) adapters.Output {
	var reason string
	switch v.Decision {
	case engine.Allow:
		return adapters.Output{}
	case engine.Ask:
		reason = prefix + v.Reason + " (Codex hooks can't ask for confirmation, so it is blocked; the user can run it themselves)"
	default:
		reason = prefix + v.Reason
	}
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}}
	if v.Notice != "" {
		out["systemMessage"] = v.Notice // for the user
	}
	body, _ := json.Marshal(out)
	return adapters.Output{Stdout: append(body, '\n'), Stderr: reason + "\n", Exit: 2}
}

//go:embed tools.yaml
var toolsYAML []byte

type toolSpec struct {
	Shell       string   `yaml:"shell"`
	Patch       string   `yaml:"patch"`
	Read        []string `yaml:"read"`
	Write       []string `yaml:"write"`
	List        []string `yaml:"list"`
	MCPResource string   `yaml:"mcpResource"`
	Forbid      []string `yaml:"forbid"`
	Required    []string `yaml:"required"`
	Passthrough bool     `yaml:"passthrough"`
}

func (s toolSpec) valid() error {
	acts := s.Shell != "" || s.Patch != "" || s.MCPResource != "" || len(s.Read)+len(s.Write)+len(s.List) > 0
	switch {
	case s.Passthrough && acts:
		return errors.New("passthrough together with fields")
	case !s.Passthrough && !acts:
		return errors.New("neither passthrough nor fields")
	}
	return nil
}

var classification = sync.OnceValues(func() (map[string]toolSpec, error) {
	return adapters.LoadTools(toolsYAML, func(_ string, s toolSpec) error { return s.valid() })
})

// Actions maps a hook input to the engine actions to evaluate
// No actions and no error means the tool touches nothing CyberBoar governs
// userShell is the hook's $SHELL, which is the shell Codex uses when the model names none
func Actions(in *Input, home, userShell string, cdPath bool) ([]engine.Action, error) {
	base := engine.Action{Cwd: in.Cwd, Home: home, Workspaces: []string{in.Cwd}}
	mcp := func(server, tool string) engine.Action {
		a := base
		a.Tool, a.MCP, a.Content = engine.ToolMCP, engine.MCPCall{Server: server, Tool: tool}, adapters.JSONText(in.ToolInput)
		return a
	}
	if rest, ok := strings.CutPrefix(in.ToolName, "mcp__"); ok {
		// Codex doesn't say where the server name ends, so every split is
		// evaluated and the strictest verdict wins. Codex writes both names
		// with "_" for other characters, "-" among them (seen in 0.155)
		var out []engine.Action
		for _, c := range adapters.SplitMCP(rest) {
			a := mcp(c.Server, c.Tool)
			a.MCP.Names = engine.NamesCodex
			out = append(out, a)
		}
		if len(out) == 0 {
			return nil, adapters.Invalid("the MCP tool name %s has no server and tool part", in.ToolName)
		}
		return out, nil
	}
	tools, err := classification()
	if err != nil {
		return nil, adapters.ClassificationFailed(err)
	}
	spec, ok := tools[in.ToolName]
	if !ok {
		return nil, adapters.Unclassified(in.ToolName)
	}
	if spec.Passthrough {
		return nil, nil
	}

	input, err := adapters.ToolInputObject(in.ToolName, in.ToolInput, spec.Required, slices.Concat(spec.Read, spec.Write, spec.List))
	if err != nil {
		return nil, err
	}
	for _, f := range spec.Forbid {
		if v, ok := input[f]; ok && v != nil {
			return nil, &adapters.Error{Rule: RuleRemoteEnvironment, Msg: fmt.Sprintf(
				"the %s call targets another environment (%s), whose files the policy can't check, so it is blocked", in.ToolName, f)}
		}
	}
	str := func(field string) (string, error) {
		s, ok := input[field].(string)
		if !ok {
			return "", adapters.Invalid("the %s tool input field %q is not a string", in.ToolName, field)
		}
		return s, nil
	}

	var out []engine.Action
	add := func(tool engine.Tool, path string) {
		a := base
		a.Tool, a.Path = tool, path
		out = append(out, a)
	}
	if spec.Shell != "" {
		cmd, err := str(spec.Shell)
		if err != nil {
			return nil, err
		}
		actions, err := shellActions(in, cmd, base, userShell, cdPath)
		if err != nil {
			return nil, err
		}
		out = append(out, actions...)
	}
	if spec.Patch != "" {
		patch, err := str(spec.Patch)
		if err != nil {
			return nil, err
		}
		if err := checkPatchEnvironment(patch); err != nil {
			return nil, err
		}
		out = append(out, adapters.PatchWrites(patch, base)...)
	}
	for _, pf := range []struct {
		tool   engine.Tool
		fields []string
	}{{engine.ToolRead, spec.Read}, {engine.ToolWrite, spec.Write}, {engine.ToolList, spec.List}} {
		for _, field := range pf.fields {
			for _, p := range adapters.Extract(input, field) {
				add(pf.tool, p)
			}
		}
	}
	if spec.MCPResource != "" {
		server, err := str(spec.MCPResource)
		if err != nil {
			return nil, err
		}
		out = append(out, mcp(server, in.ToolName))
	}
	return out, nil
}

func shellActions(in *Input, cmd string, base engine.Action, userShell string, cdPath bool) ([]engine.Action, error) {
	call, err := lookupExecCall(in, cmd)
	if err != nil {
		return nil, err
	}
	if call.Cmd != cmd {
		return nil, callError("the command in the transcript differs from the hook input")
	}
	if call.EnvironmentID != nil && *call.EnvironmentID != "" {
		return nil, &adapters.Error{Rule: RuleRemoteEnvironment, Msg: "the command runs in another environment, whose files the policy can't check, so it is blocked"}
	}
	if call.Tty != nil && *call.Tty {
		return nil, &adapters.Error{Rule: RuleInteractiveSession, Msg: "the command asks for a terminal (tty), and what is typed into it later (write_stdin) never reaches the hook, " +
			"so it is blocked; run the command without tty and give it its input as arguments or files"}
	}
	cwd := base.Cwd
	if call.Workdir != nil && *call.Workdir != "" {
		if filepath.IsAbs(*call.Workdir) {
			cwd = *call.Workdir
		} else {
			cwd = base.Cwd + "/" + *call.Workdir // not cleaned, because the engine resolves it like the kernel
		}
	}
	shell := userShell
	if call.Shell != nil && *call.Shell != "" {
		shell = *call.Shell
	}
	a := base
	a.Tool, a.Cwd, a.Command, a.CDPath = engine.ToolShell, cwd, adapters.ShellCommand(shell, cmd), cdPath
	writes, err := shellPatchActions(cmd, base, cwd)
	if err != nil {
		return nil, err
	}
	return append([]engine.Action{a}, writes...), nil
}

func shellPatchActions(cmd string, base engine.Action, cwd string) ([]engine.Action, error) {
	// Codex itself applies `apply_patch <<EOF ...` run through the shell,
	// in the command's directory or, after `cd DIR &&`, in DIR
	if strings.Contains(cmd, beginPatch) {
		if err := checkPatchEnvironment(cmd); err != nil {
			return nil, err
		}
		w := base
		w.Cwd = cwd
		patch, dir, ok := edits.ShellPatch(cmd)
		switch {
		case ok && strings.HasPrefix(dir, "/"):
			w.Cwd = dir
		case ok && dir != "":
			w.Cwd = cwd + "/" + dir // not cleaned, because the engine resolves it like the kernel
		case !ok:
			// Codex doesn't apply this form itself, so the paths are
			// checked, but what the patch would leave in the files can't be
			patch = cmd
		}
		writes := adapters.PatchWrites(patch, w)
		for i := range writes {
			if !ok {
				writes[i].Rewrite = func(string, bool) ([]string, error) {
					return nil, errors.New("the patch isn't in a form Codex applies itself (`apply_patch <<'EOF'`, alone or after `cd DIR &&`)")
				}
			}
			writes[i].Content = "" // the command line is checked whole
		}
		return writes, nil
	}
	return nil, nil
}
