// Package claudecode maps Claude Code's PreToolUse hook input to engine
// actions and engine verdicts to hook output
package claudecode

import (
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode/gitbash"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/winpath"
)

// Adapter speaks Claude Code's hook protocol
type Adapter struct{}

// Name returns "claude-code", the agent name used on the command line and in audit events
func (Adapter) Name() string { return "claude-code" }

// Parse reads the workspace root from CLAUDE_PROJECT_DIR, which Claude Code
// sets and the model's shell can't change
func (Adapter) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	return parse(data, getenv, runtime.GOOS, gitbash.System(getenv))
}

// parse is Parse for the operating system goos, a runtime.GOOS value
// Git Bash is read only on Windows, and gitBash reads the hook's environment
// through its Getenv
func parse(data []byte, getenv func(string) string, goos string, gitBash gitbash.Env) (*adapters.Call, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	env := Env{ProjectDir: getenv("CLAUDE_PROJECT_DIR"), Home: getenv("HOME"), CDPath: getenv("CDPATH") != ""}
	c := &adapters.Call{Session: in.SessionID, ToolUseID: in.ToolUseID, AgentID: in.AgentID, AgentType: in.AgentType,
		Mode: in.PermissionMode, Cwd: in.Cwd, Project: env.ProjectDir, Tool: in.ToolName}
	if goos == "windows" {
		if env, c.Err = windowsEnv(env, getenv, gitBash); c.Err != nil {
			return c, nil
		}
	}
	c.Actions, c.Err = Actions(in, env)
	if tools, err := classification(); err == nil && tools[in.ToolName].PowerShell != "" && c.Err == nil && !env.Windows {
		// The engine reads PowerShell with Windows semantics only. The command
		// stays in Actions for the audit log
		c.Err, c.Notice = adapters.PowerShell(in.ToolName, "the Bash tool")
	}
	configDir := getenv("CLAUDE_CONFIG_DIR")
	if env.Windows {
		configDir = winpath.FromGitBash(configDir)
	}
	adapters.Guard(c.Actions, SettingsFiles(env, configDir, goos)...)
	adapters.Guard(c.Actions, adapters.StartupFiles(env.Windows, env.Home, getenv)...)
	return c, nil
}

// SettingsFiles returns the Claude Code files that can install, change or
// switch off the hook, or run hooks of their own, which agents may not
// change (builtin.guarded). They are the user's settings and plugins in
// ~/.claude or CLAUDE_CONFIG_DIR, the project's shared and local settings,
// the managed settings directory on goos, a runtime.GOOS value, and the
// custom agents, skills and commands of the user and of every folder
// projectDirs returns
func SettingsFiles(env Env, configDir, goos string) []string {
	w := env.Windows
	var out []string
	for _, dir := range []string{adapters.Under(w, env.Home, ".claude"), configDir, adapters.Under(w, env.ProjectDir, ".claude")} {
		out = append(out, adapters.Under(w, dir, "settings.json"), adapters.Under(w, dir, "settings.local.json"))
	}
	if w {
		out = append(out, ManagedDir("windows"), legacyManagedDir)
	} else {
		out = append(out, ManagedDir(goos))
	}
	// An enabled plugin's hooks/hooks.json runs after /reload-plugins
	for _, dir := range []string{adapters.Under(w, env.Home, ".claude"), configDir} {
		out = append(out, adapters.Under(w, dir, "plugins"))
		out = append(out, customizations(w, dir)...)
	}
	for _, dir := range projectDirs(env) {
		out = append(out, customizations(w, adapters.Under(w, dir, ".claude"))...)
	}
	return out
}

// customizations returns the folders of a .claude directory whose custom
// agents, skills and commands can declare hooks in their frontmatter.
// Claude Code picks up changes there during the session and runs those
// hooks when the model starts the agent or invokes the skill
func customizations(windows bool, dir string) []string {
	return []string{adapters.Under(windows, dir, "agents"), adapters.Under(windows, dir, "skills"),
		adapters.Under(windows, dir, "commands")}
}

// projectDirs returns the folders whose .claude agents, skills and commands
// Claude Code loads: the project directory, where it started, and every
// folder above it up to the git work tree holding it. Outside a work tree
// it is the project directory alone
func projectDirs(env Env) []string {
	if env.ProjectDir == "" {
		return nil
	}
	start := path.Clean(env.ProjectDir)
	if env.Windows {
		start = strings.TrimRight(env.ProjectDir, `\`)
	}
	var walked []string
	for d := start; d != ""; d = parent(env.Windows, d) {
		walked = append(walked, d)
		if _, err := os.Lstat(adapters.Under(env.Windows, d, ".git")); err == nil {
			return walked
		}
	}
	return walked[:1]
}

// parent returns the folder holding dir, or "" when dir is the root (on
// Windows, of a drive or a share)
func parent(windows bool, dir string) string {
	if !windows {
		if p := path.Dir(dir); p != dir {
			return p
		}
		return ""
	}
	dir = strings.TrimRight(dir, `\`)
	i := strings.LastIndexByte(dir, '\\')
	switch {
	case i < 0, strings.HasPrefix(dir, `\\`) && (i < 2 || !strings.Contains(dir[2:i], `\`)):
		return ""
	case i == 2 && dir[1] == ':':
		return dir[:3]
	}
	return dir[:i]
}

// windowsEnv reads the environment on native Windows. Git Bash expands ~
// with HOME and native tools use USERPROFILE, so when both are set they must
// name one directory, or the hook can't tell which home a path under ~ means.
// Directories may come in Git Bash's form, such as /c/Users/dev
func windowsEnv(env Env, getenv func(string) string, gitBash gitbash.Env) (Env, error) {
	env.Windows = true
	env.ProjectDir = winpath.FromGitBash(env.ProjectDir)
	home, profile := winpath.FromGitBash(env.Home), getenv("USERPROFILE")
	switch {
	case profile == "":
		env.Home = home
	case home != "" && !winpath.SameDir(home, profile):
		return env, adapters.Invalid("HOME (%s) and USERPROFILE (%s) name different directories, so paths under ~ can't be checked", env.Home, profile)
	default:
		env.Home = profile
	}
	// Without the table the engine refuses Git Bash's paths outside the
	// drives (/tmp, /usr), so a failure here needs no answer of its own
	env.Mounts, _ = gitbash.Mounts(gitBash)
	return env, nil
}

// Respond turns a verdict into hook output (see the package-level Respond)
func (Adapter) Respond(v engine.Verdict, prefix string) adapters.Output { return Respond(v, prefix) }

// Input is the part of the PreToolUse hook input CyberBoar uses
type Input struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	ToolUseID      string          `json:"tool_use_id"`
	PermissionMode string          `json:"permission_mode"`
	AgentID        string          `json:"agent_id"`
	AgentType      string          `json:"agent_type"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	MCPServer      *struct {
		Name   string `json:"name"`
		Source string `json:"source"`
	} `json:"mcp_server"`
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

// Env is what the adapter takes from the hook's environment
type Env struct {
	// ProjectDir is the workspace root from CLAUDE_PROJECT_DIR, which Claude
	// Code sets and the model's shell can't change
	ProjectDir string
	Home       string
	CDPath     bool // CDPATH is set in the hook's (and so the agent's) environment
	// Windows reports whether the hook runs on native Windows, where paths
	// are Windows paths and commands run in Git Bash
	Windows bool
	// Mounts is Git Bash's mount table (engine.Action.Mounts)
	// It is nil if the table couldn't be read
	Mounts map[string]string
}

//go:embed tools.yaml
var toolsYAML []byte

type toolSpec struct {
	Shell       string             `yaml:"shell"`
	PowerShell  string             `yaml:"powershell"`
	Read        []string           `yaml:"read"`
	Write       []string           `yaml:"write"`
	List        []string           `yaml:"list"`
	ListPattern string             `yaml:"listPattern"`
	Content     []string           `yaml:"content"`
	Edit        *adapters.EditSpec `yaml:"edit"`
	Required    []string           `yaml:"required"`
	DefaultCwd  bool               `yaml:"defaultCwd"`
	Passthrough bool               `yaml:"passthrough"`
}

func (s toolSpec) valid() error {
	acts := s.Shell != "" || s.PowerShell != "" || len(s.Read)+len(s.Write)+len(s.List) > 0
	switch {
	case s.Passthrough && acts:
		return errors.New("passthrough together with fields")
	case !s.Passthrough && !acts:
		return errors.New("neither passthrough nor fields")
	case (len(s.Content) > 0 || s.Edit != nil) && len(s.Write) == 0:
		return errors.New("content without a write field")
	case s.Edit != nil && s.Edit.Valid() != nil:
		return s.Edit.Valid()
	}
	return nil
}

// classification is the embedded tools.yaml. If it doesn't load, every tool
// is unclassified and denied
var classification = sync.OnceValues(func() (map[string]toolSpec, error) {
	return adapters.LoadTools(toolsYAML, func(_ string, s toolSpec) error { return s.valid() })
})

// Actions maps a hook input to the engine actions to evaluate
// No actions and no error means the tool touches nothing CyberBoar governs
func Actions(in *Input, env Env) ([]engine.Action, error) {
	base := engine.Action{Cwd: in.Cwd, Home: env.Home, CDPath: env.CDPath}
	if env.Windows {
		base.Platform = engine.PlatformWindows
		base.Cwd = winpath.FromGitBash(in.Cwd)
		base.Mounts = env.Mounts
	}
	if env.ProjectDir != "" {
		base.Workspaces = []string{env.ProjectDir}
	}
	if strings.HasPrefix(in.ToolName, "mcp__") {
		mb := base
		mb.Content = adapters.JSONText(in.ToolInput)
		return mcpActions(in, mb)
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

	fields := slices.Concat(spec.Read, spec.Write, spec.List, spec.Content)
	if spec.ListPattern != "" {
		fields = append(fields, spec.ListPattern)
	}
	input, err := adapters.ToolInputObject(in.ToolName, in.ToolInput, spec.Required, fields)
	if err != nil {
		return nil, err
	}

	var out []engine.Action
	add := func(tool engine.Tool, set func(*engine.Action)) {
		a := base
		a.Tool = tool
		set(&a)
		out = append(out, a)
	}
	// The PowerShell tool runs each command in a new process, like Bash: only
	// the working directory carries over, and it comes as the input's cwd
	for _, sf := range []struct {
		field, shell string
	}{{spec.Shell, ""}, {spec.PowerShell, engine.ShellPowerShell}} {
		if sf.field == "" {
			continue
		}
		switch v := input[sf.field].(type) {
		case nil: // optional and absent (a WebSocket Monitor)
		case string:
			add(engine.ToolShell, func(a *engine.Action) { a.Command, a.Shell = v, sf.shell })
		default:
			return nil, adapters.Invalid("the %s tool input field %q is not a string", in.ToolName, sf.field)
		}
	}
	content, rewrite, err := adapters.WriteText(input, spec.Content, spec.Edit)
	if err != nil {
		return nil, adapters.Invalid("the %s tool input is malformed: %v", in.ToolName, err)
	}
	paths := 0
	for _, pf := range []struct {
		tool   engine.Tool
		fields []string
	}{{engine.ToolRead, spec.Read}, {engine.ToolWrite, spec.Write}, {engine.ToolList, spec.List}} {
		for _, field := range pf.fields {
			for _, p := range adapters.Extract(input, field) {
				paths++
				add(pf.tool, func(a *engine.Action) {
					a.Path = p
					if pf.tool == engine.ToolWrite {
						a.Content, a.Rewrite = content, rewrite
					}
				})
			}
		}
	}
	if spec.ListPattern != "" {
		for _, pattern := range adapters.Extract(input, spec.ListPattern) {
			if dir, ok := globBase(pattern, env.Windows); ok {
				paths++
				add(engine.ToolList, func(a *engine.Action) { a.Path = dir })
			}
		}
	}
	if paths == 0 && spec.DefaultCwd {
		tool := engine.ToolRead
		if len(spec.Read) == 0 {
			tool = engine.ToolList
		}
		add(tool, func(a *engine.Action) { a.Path = "." })
	}
	return out, nil
}

// globBase returns the directory that Claude Code's Glob tool searches when
// pattern is absolute, in which case the tool ignores its path field. Claude
// Code cuts the pattern at the last separator before its first *, ?, [ or {,
// and takes the parent directory of a pattern that has none of them. On
// Windows both separators count, and a pattern is absolute when it starts
// with one, or with a drive letter, a colon and one
func globBase(pattern string, windows bool) (dir string, ok bool) {
	seps, root := "/", 1
	if windows {
		seps = `/\`
	}
	switch {
	case pattern != "" && strings.IndexByte(seps, pattern[0]) >= 0:
	case windows && len(pattern) > 2 && isLetter(pattern[0]) && pattern[1] == ':' && strings.IndexByte(seps, pattern[2]) >= 0:
		root = 3
	default:
		return "", false
	}
	head := strings.TrimRight(pattern, seps)
	if i := strings.IndexAny(pattern, "*?[{"); i >= 0 {
		head = pattern[:i]
	}
	if cut := strings.LastIndexAny(head, seps); cut >= root {
		return pattern[:cut], true
	}
	return pattern[:root], true
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// mcpNameChars matches the characters of a server name that Claude Code
// replaces with "_" in tool names
var mcpNameChars = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// mcpActions splits mcp__<server>__<tool>. If the input has mcp_server.name,
// the split is known
// Otherwise every split is evaluated and the strictest verdict wins, so
// a server named "a__b" can't hide behind the split (a, b__tool)
func mcpActions(in *Input, base engine.Action) ([]engine.Action, error) {
	rest := strings.TrimPrefix(in.ToolName, "mcp__")
	mk := func(server, tool string) engine.Action {
		a := base
		a.Tool = engine.ToolMCP
		a.MCP = engine.MCPCall{Server: server, Tool: tool, Names: engine.NamesClaudeCode}
		return a
	}
	if in.MCPServer != nil && in.MCPServer.Name != "" {
		name := in.MCPServer.Name
		for _, prefix := range []string{name, mcpNameChars.ReplaceAllString(name, "_")} {
			if tool, ok := strings.CutPrefix(rest, prefix+"__"); ok && tool != "" {
				return []engine.Action{mk(name, tool)}, nil
			}
		}
		return nil, adapters.Invalid("the MCP tool %s does not belong to the server %q named in the hook input", in.ToolName, name)
	}
	var out []engine.Action
	for _, c := range adapters.SplitMCP(rest) {
		out = append(out, mk(c.Server, c.Tool))
	}
	if len(out) == 0 {
		return nil, adapters.Invalid("the MCP tool name %s has no server and tool part", in.ToolName)
	}
	return out, nil
}

// Output is the hook's response to Claude Code
type Output = adapters.Output

// Respond turns a verdict into hook output. Deny exits 2 (which blocks even
// if Claude Code can't parse the JSON) and also puts the reason on stderr.
// Allow produces no output, because a hook "allow" would skip the user's own
// permission prompt, which CyberBoar must never do
// A verdict's Notice is shown to the user as systemMessage
func Respond(v engine.Verdict, prefix string) Output {
	reason := prefix + v.Reason
	var decision string
	switch v.Decision {
	case engine.Allow:
		return Output{}
	case engine.Ask:
		decision = "ask"
	default:
		decision = "deny"
	}
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
	}}
	if v.Notice != "" {
		// Claude Code shows systemMessage to the user as a warning, and it
		// reads the JSON on exit 2 too
		out["systemMessage"] = v.Notice
	}
	body, _ := json.Marshal(out)
	body = append(body, '\n')
	if decision == "ask" {
		return Output{Stdout: body}
	}
	return Output{Stdout: body, Stderr: reason + "\n", Exit: 2}
}
