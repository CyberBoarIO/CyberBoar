// Package opencode maps the input of CyberBoar's opencode plugin shim to
// engine actions and engine verdicts to the shim's answer
//
// opencode has no command hooks. It loads JavaScript plugins in its own
// process, and a plugin whose tool.execute.before hook throws blocks the tool
// call. The shim (cyberboar.js, written by apply) runs the hook command with
// the call as JSON on stdin and throws unless the hook answers exactly
// {"decision":"none"} with exit status 0, so a missing binary, a crash, a
// timeout or any other answer blocks the call too
package opencode

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/engine"
)

// Adapter speaks the plugin shim's protocol
type Adapter struct{}

// Name returns "opencode", the agent name used on the command line and in
// audit events
func (Adapter) Name() string { return "opencode" }

// Input is what the shim sends for one tool call
// It holds the tool.execute.before input and arguments, the plugin's directory and
// worktree, and what the config plugin hook reported
type Input struct {
	Tool      string          `json:"tool"`
	SessionID string          `json:"sessionID"`
	CallID    string          `json:"callID"`
	Args      json.RawMessage `json:"args"`
	// Directory is the session directory, where tools resolve relative paths
	// and start commands
	Directory string `json:"directory"`
	// Worktree is the git worktree root, or "/" outside a git repository
	Worktree string `json:"worktree"`
	// Shell is the config's shell setting, or "" if it is unset. If nil, the
	// config hook never ran, and the shell is unknown
	Shell *string `json:"shell"`
	// MCPServers are the configured MCP server names. If nil, they are unknown
	MCPServers *[]string `json:"mcpServers"`
}

// ParseInput decodes exactly one JSON object with only the shim's fields
func ParseInput(data []byte) (*Input, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var in Input
	if err := dec.Decode(&in); err != nil {
		return nil, adapters.Invalid("the plugin input is not the JSON object the %s plugin sends: %v", "opencode", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, adapters.Invalid("the plugin input has data after the JSON object")
	}
	switch {
	case in.Tool == "":
		return nil, adapters.Invalid("the plugin input has no tool")
	case in.SessionID == "":
		return nil, adapters.Invalid("the plugin input has no sessionID")
	case in.Directory == "" || in.Worktree == "":
		return nil, adapters.Invalid("the plugin input has no directory or worktree")
	case in.Shell == nil || in.MCPServers == nil:
		// The config hook runs before any tool can. Without it, the shell
		// and the MCP servers are unknown
		return nil, adapters.Invalid("the plugin input has no shell or mcpServers: the plugin never saw opencode's configuration")
	}
	return &in, nil
}

// Env is what the adapter takes from the hook's environment, which the shim
// passes on from opencode's
type Env struct {
	Home          string
	XDGConfigHome string
	XDGCacheHome  string
	// Config, ConfigDir and TUIConfig are OPENCODE_CONFIG,
	// OPENCODE_CONFIG_DIR and OPENCODE_TUI_CONFIG, which are more places
	// opencode loads configuration and plugins from
	Config, ConfigDir, TUIConfig string
	// UserShell is $SHELL, which opencode runs commands in when the config names no shell
	UserShell string
	CDPath    bool
}

// EnvFrom reads Env from the hook's environment
func EnvFrom(getenv func(string) string) Env {
	return Env{Home: getenv("HOME"), XDGConfigHome: getenv("XDG_CONFIG_HOME"), XDGCacheHome: getenv("XDG_CACHE_HOME"),
		Config: getenv("OPENCODE_CONFIG"), ConfigDir: getenv("OPENCODE_CONFIG_DIR"), TUIConfig: getenv("OPENCODE_TUI_CONFIG"),
		UserShell: getenv("SHELL"), CDPath: getenv("CDPATH") != ""}
}

// Parse decodes the shim's input
func (Adapter) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	env := EnvFrom(getenv)
	c := &adapters.Call{Session: in.SessionID, ToolUseID: in.CallID, Cwd: in.Directory, Project: Workspace(in), Tool: in.Tool}
	c.Actions, c.Err = Actions(in, env)
	adapters.Guard(c.Actions, ConfigFiles(in, env)...)
	adapters.Guard(c.Actions, adapters.StartupFiles(false, env.Home, getenv)...)
	return c, nil
}

// Workspace returns the project root. That is the git worktree, or the
// session directory outside a git repository, where opencode reports the
// worktree as "/"
func Workspace(in *Input) string {
	if in.Worktree != "/" {
		return in.Worktree
	}
	return in.Directory
}

// ManagedDirs are where opencode reads managed (machine-wide) configuration
// on Linux and macOS. On macOS that includes the ai.opencode.managed profiles
// MDM installs in /Library/Managed Preferences and its per-user directories
var ManagedDirs = []string{"/etc/opencode", "/Library/Application Support/opencode", "/Library/Managed Preferences"}

// ConfigFiles returns the opencode files and directories that can load,
// change or switch off the plugin shim, which agents may not change
// (builtin.guarded). They are every directory opencode loads plugins, custom
// tools and configuration from (the user's config directory, ~/.opencode,
// each .opencode from the session directory up to the worktree,
// OPENCODE_CONFIG_DIR), every configuration file that can list plugins
// (opencode.json, opencode.jsonc, tui.json and tui.jsonc on the same walk,
// OPENCODE_CONFIG, OPENCODE_TUI_CONFIG, the managed directories), and the
// cache that holds plugin packages
func ConfigFiles(in *Input, env Env) []string {
	var out []string
	abs := func(p string) string {
		if p == "" || path.IsAbs(p) {
			return p
		}
		// opencode resolves it against its own working directory, which is
		// the session directory
		return path.Join(in.Directory, p)
	}
	for _, p := range []string{
		adapters.Under(false, env.Home, ".config", "opencode"), adapters.Under(false, env.XDGConfigHome, "opencode"),
		adapters.Under(false, env.Home, ".cache", "opencode"), adapters.Under(false, env.XDGCacheHome, "opencode"),
		adapters.Under(false, env.Home, ".opencode"),
		abs(env.Config), abs(env.ConfigDir), abs(env.TUIConfig),
	} {
		if p != "" && path.IsAbs(p) {
			out = append(out, p)
		}
	}
	stop := in.Worktree
	if in.Directory != stop && !strings.HasPrefix(in.Directory, strings.TrimSuffix(stop, "/")+"/") {
		stop = "/"
	}
	// Actions refuses a relative directory, and the walk skips one, because
	// it would never reach the root
	for dir := in.Directory; path.IsAbs(dir); dir = path.Dir(dir) {
		for _, name := range []string{".opencode", "opencode.json", "opencode.jsonc", "tui.json", "tui.jsonc"} {
			out = append(out, path.Join(dir, name))
		}
		if dir == stop || dir == "/" {
			break
		}
	}
	return append(out, ManagedDirs...)
}

// Respond turns a verdict into the shim's answer. Only exit 0 with
// {"decision":"none"} lets the call through, leaving opencode's own
// permissions in charge. Deny exits 2 with the reason in the JSON and on
// stderr. opencode plugins can't ask the user, so ask is answered as deny
func (Adapter) Respond(v engine.Verdict, prefix string) adapters.Output {
	var reason string
	switch v.Decision {
	case engine.Allow:
		return adapters.Output{Stdout: []byte(`{"decision":"none"}` + "\n")}
	case engine.Ask:
		reason = prefix + v.Reason + " (opencode plugins can't ask for confirmation, so it is blocked; the user can run it themselves)"
	default:
		reason = prefix + v.Reason
	}
	body, _ := json.Marshal(map[string]any{"decision": "deny", "reason": reason})
	return adapters.Output{Stdout: append(body, '\n'), Stderr: reason + "\n", Exit: 2}
}

//go:embed tools.yaml
var toolsYAML []byte

type toolSpec struct {
	Shell       string             `yaml:"shell"`
	Workdir     string             `yaml:"workdir"`
	Read        []string           `yaml:"read"`
	Write       []string           `yaml:"write"`
	Content     []string           `yaml:"content"`
	Edit        *adapters.EditSpec `yaml:"edit"`
	List        []string           `yaml:"list"`
	View        []string           `yaml:"view"`
	Patch       string             `yaml:"patch"`
	MCPResource string             `yaml:"mcpResource"`
	Required    []string           `yaml:"required"`
	RequirePath bool               `yaml:"requirePath"`
	DefaultCwd  bool               `yaml:"defaultCwd"`
	Passthrough bool               `yaml:"passthrough"`
}

func (s toolSpec) valid() error {
	paths := len(s.Read)+len(s.Write)+len(s.List)+len(s.View) > 0
	acts := s.Shell != "" || s.Patch != "" || s.MCPResource != "" || paths
	switch {
	case s.Passthrough && acts:
		return errors.New("passthrough together with fields")
	case !s.Passthrough && !acts:
		return errors.New("neither passthrough nor fields")
	case (len(s.Content) > 0 || s.Edit != nil) && len(s.Write) == 0:
		return errors.New("content without a write field")
	case s.Edit != nil && s.Edit.Valid() != nil:
		return s.Edit.Valid()
	case s.Workdir != "" && s.Shell == "":
		return errors.New("workdir without shell")
	case (s.RequirePath || s.DefaultCwd) && !paths:
		return errors.New("requirePath or defaultCwd without path fields")
	case s.RequirePath && s.DefaultCwd:
		return errors.New("requirePath together with defaultCwd")
	}
	return nil
}

var classification = sync.OnceValues(func() (map[string]toolSpec, error) {
	return adapters.LoadTools(toolsYAML, func(_ string, s toolSpec) error { return s.valid() })
})

// Actions maps the shim's input to the engine actions to evaluate. No actions
// and no error means the tool touches nothing CyberBoar governs
func Actions(in *Input, env Env) ([]engine.Action, error) {
	// Checked here rather than in ParseInput, so that on an unsupported
	// platform (Windows paths) the hook explains the platform instead
	for _, p := range []string{in.Directory, in.Worktree} {
		if !path.IsAbs(p) {
			return nil, adapters.Invalid("the plugin input's directory or worktree %q is not an absolute path", p)
		}
	}
	base := engine.Action{Cwd: in.Directory, Home: env.Home, Workspaces: []string{Workspace(in)}}
	tools, err := classification()
	if err != nil {
		return nil, adapters.ClassificationFailed(err)
	}
	var args map[string]any
	dec := json.NewDecoder(bytes.NewReader(in.Args))
	dec.UseNumber()
	if err := dec.Decode(&args); err != nil || args == nil {
		return nil, adapters.Invalid("the %s tool arguments are not a JSON object", in.Tool)
	}

	// An MCP tool is <server>_<tool> with nothing to tell it from a built-in
	// or custom tool, and opencode registers MCP tools after its own, so a
	// listed name that also reads as an MCP tool is checked both ways
	mb := base
	mb.Content = adapters.JSONText(in.Args)
	mcp := mcpActions(in.Tool, *in.MCPServers, mb)
	spec, listed := tools[in.Tool]
	if !listed {
		if len(mcp) == 0 {
			return nil, adapters.Unclassified(in.Tool)
		}
		return mcp, nil
	}
	out, err := specActions(in, env, spec, args, base)
	if err != nil {
		return nil, err
	}
	return append(out, mcp...), nil
}

func specActions(in *Input, env Env, spec toolSpec, args map[string]any, base engine.Action) ([]engine.Action, error) {
	if spec.Passthrough {
		return nil, nil
	}
	for _, f := range spec.Required {
		if v, ok := args[f]; !ok || v == nil {
			return nil, adapters.Invalid("the %s tool arguments have no %q", in.Tool, f)
		}
	}
	if err := adapters.CheckFields(args, slices.Concat(spec.Read, spec.Write, spec.List, spec.View, spec.Content)); err != nil {
		return nil, adapters.Invalid("the %s tool arguments are malformed: %v", in.Tool, err)
	}
	str := func(field string) (string, bool, error) {
		switch v := args[field].(type) {
		case nil:
			return "", false, nil
		case string:
			return v, true, nil
		default:
			return "", false, adapters.Invalid("the %s tool argument %q is not a string", in.Tool, field)
		}
	}
	var out []engine.Action
	add := func(tool engine.Tool, set func(*engine.Action)) {
		a := base
		a.Tool = tool
		set(&a)
		out = append(out, a)
	}

	if spec.Shell != "" {
		cmd, ok, err := str(spec.Shell)
		if err != nil || !ok {
			return nil, adapters.Invalid("the %s tool argument %q is not a string", in.Tool, spec.Shell)
		}
		workdir, _, err := str(spec.Workdir)
		if err != nil {
			return nil, err
		}
		cwd := in.Directory
		switch {
		case strings.HasPrefix(workdir, "/"):
			cwd = workdir
		case workdir != "":
			cwd = strings.TrimSuffix(in.Directory, "/") + "/" + workdir // not cleaned, because the engine resolves it like the kernel
		}
		if !bashLike(RunShell(*in.Shell, env.UserShell)) {
			// The shell doesn't read bash syntax, so the engine treats the
			// command as foreign code
			cmd = "fish -c " + adapters.ShellQuote(cmd)
		}
		add(engine.ToolShell, func(a *engine.Action) { a.Command, a.Cwd, a.CDPath = cmd, cwd, env.CDPath })
	}
	if spec.Patch != "" {
		patch, ok, err := str(spec.Patch)
		if err != nil || !ok {
			return nil, adapters.Invalid("the %s tool argument %q is not a patch text", in.Tool, spec.Patch)
		}
		_, environment := adapters.PatchPaths(patch)
		if environment {
			return nil, adapters.Invalid("the %s patch names an environment, which opencode's apply_patch doesn't define", in.Tool)
		}
		out = append(out, adapters.PatchWrites(patch, base)...)
	}
	if spec.MCPResource != "" {
		server, ok, err := str(spec.MCPResource)
		if err != nil {
			return nil, err
		}
		servers := []string{server}
		if !ok {
			// Without a server the tool reaches every configured one
			servers = *in.MCPServers
		}
		if len(servers) == 0 {
			return nil, adapters.Invalid("the %s tool names no MCP server and none is configured", in.Tool)
		}
		content := adapters.JSONText(in.Args)
		for _, s := range servers {
			add(engine.ToolMCP, func(a *engine.Action) {
				a.MCP = engine.MCPCall{Server: s, Tool: in.Tool}
				a.Content = content
			})
		}
	}

	content, rewrite, err := adapters.WriteText(args, spec.Content, spec.Edit)
	if err != nil {
		return nil, adapters.Invalid("the %s tool arguments are malformed: %v", in.Tool, err)
	}
	paths := 0
	for _, pf := range []struct {
		tool   engine.Tool
		fields []string
		view   bool
	}{
		{engine.ToolRead, spec.Read, false},
		{engine.ToolWrite, spec.Write, false},
		{engine.ToolList, spec.List, false},
		{engine.ToolRead, spec.View, true},
	} {
		for _, field := range pf.fields {
			for _, p := range adapters.Extract(args, field) {
				paths++
				tool := pf.tool
				if pf.view && adapters.IsDir(resolve(in.Directory, p)) {
					tool = engine.ToolList
				}
				add(tool, func(a *engine.Action) {
					a.Path = p
					if tool == engine.ToolWrite {
						a.Content, a.Rewrite = content, rewrite
					}
				})
			}
		}
	}
	switch {
	case paths == 0 && spec.RequirePath:
		return nil, adapters.Invalid("the %s tool arguments name no path", in.Tool)
	case paths == 0 && spec.DefaultCwd:
		tool := engine.ToolRead
		if len(spec.Read) == 0 {
			tool = engine.ToolList
		}
		add(tool, func(a *engine.Action) { a.Path = "." })
	}
	return out, nil
}

// RunShell returns the shell opencode runs a command in. That is the config's
// shell, or else $SHELL, or else bash. opencode refuses fish and nu, so for
// them it is bash too. A shell that doesn't exist also falls back to bash in
// opencode. The hook can't tell, so it takes the named one, which is the
// stricter reading
func RunShell(config, user string) string {
	sh := config
	if sh == "" {
		sh = user
	}
	if n := shellName(sh); sh == "" || n == "fish" || n == "nu" {
		return "bash"
	}
	return sh
}

func shellName(sh string) string {
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(sh, `\`, "/"))), ".exe")
}

// bashLike reports whether the engine can analyze the shell's commands as
// bash. opencode runs bash and zsh as login shells that read ~/.bashrc or
// ~/.zshrc first, aliases included. The apply command warns about the
// settings there that change what a command line means
func bashLike(sh string) bool {
	switch shellName(sh) {
	case "bash", "sh", "dash", "zsh":
		return true
	}
	return false
}

// resolve makes p absolute against dir, for the directory test only. The
// engine does its own resolution
func resolve(dir, p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return dir + "/" + p
}

// sanitize sanitizes an MCP server name as opencode does, replacing every
// UTF-16 code unit outside [A-Za-z0-9_-] with "_"
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case utf16.RuneLen(r) == 2:
			b.WriteString("__")
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// mcpActions reads name as <server>_<tool> for every configured server whose
// sanitized name and an underscore start it. Server names may contain
// underscores and may be prefixes of each other, so every match is evaluated
// and the strictest verdict wins. An allowed server "github" then can't cover
// a server "github_evil". opencode sanitizes the tool name too, and the
// original can't be recovered, so the call says how the names were written
func mcpActions(name string, servers []string, base engine.Action) []engine.Action {
	var out []engine.Action
	for _, s := range servers {
		prefix := sanitize(s) + "_"
		if tool, ok := strings.CutPrefix(name, prefix); ok && tool != "" {
			a := base
			a.Tool, a.MCP = engine.ToolMCP, engine.MCPCall{Server: s, Tool: tool, Names: engine.NamesOpencode}
			out = append(out, a)
		}
	}
	return out
}
