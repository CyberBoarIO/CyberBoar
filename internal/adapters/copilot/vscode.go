package copilot

// VS Code's Local agent reads Copilot's hook files too: the repository's
// .github/hooks and the user's ~/.copilot/hooks. It runs a hook's bash
// command (an exec and args hook it skips) with input of its own: the
// VS Code-compatible form with tool_use_id, naming VS Code's tools, such as
// read_file and run_in_terminal (seen in VS Code 1.142 with GitHub Copilot
// Chat 0.70). It reads hookSpecificOutput's answer, which Respond adds, and
// counts every exit but 0 and 2 as a warning that lets the tool run

import (
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
)

// RuleUncheckedTool denies a VS Code tool that does something the hook
// can't check, such as typing into a running terminal.
const RuleUncheckedTool = "adapter.uncheckedTool"

//go:embed vscode-tools.yaml
var vscodeToolsYAML []byte

type vscodeSpec struct {
	Read         []string           `yaml:"read"`
	Write        []string           `yaml:"write"`
	List         []string           `yaml:"list"`
	Content      []string           `yaml:"content"`
	Edit         *adapters.EditSpec `yaml:"edit"`
	Replacements string             `yaml:"replacements"`
	Patch        string             `yaml:"patch"`
	Shell        string             `yaml:"shell"`
	Task         bool               `yaml:"task"`
	URLs         []string           `yaml:"urls"`
	Memory       []string           `yaml:"memory"`
	Workspace    string             `yaml:"workspace"`
	DefaultCwd   string             `yaml:"defaultCwd"`
	SQL          string             `yaml:"sql"`
	Required     []string           `yaml:"required"`
	Deny         string             `yaml:"deny"`
	Passthrough  bool               `yaml:"passthrough"`
}

func (s vscodeSpec) valid() error {
	acts := len(s.Read)+len(s.Write)+len(s.List)+len(s.URLs)+len(s.Memory) > 0 || s.Replacements != "" || s.Patch != "" ||
		s.Shell != "" || s.Task || s.Workspace != "" || s.SQL != ""
	pathOrAction := func(v string) bool { return v == "" || v == "read" || v == "list" }
	switch {
	case s.Passthrough && (acts || s.Deny != ""), s.Deny != "" && acts:
		return errors.New("passthrough or deny together with other fields")
	case !s.Passthrough && s.Deny == "" && !acts:
		return errors.New("neither passthrough, deny nor fields")
	case (len(s.Content) > 0 || s.Edit != nil) && len(s.Write) == 0:
		return errors.New("content without a write field")
	case s.Edit != nil && s.Edit.Valid() != nil:
		return s.Edit.Valid()
	case !pathOrAction(s.Workspace) || !pathOrAction(s.DefaultCwd):
		return errors.New("workspace and defaultCwd take read or list")
	case s.DefaultCwd != "" && len(s.Read)+len(s.Write)+len(s.List) == 0:
		return errors.New("defaultCwd without path fields")
	case s.SQL != "" && s.SQL != "duckdb":
		return fmt.Errorf("sql %q: want duckdb", s.SQL)
	}
	return nil
}

var vscodeClassification = sync.OnceValues(func() (map[string]vscodeSpec, error) {
	return adapters.LoadTools(vscodeToolsYAML, func(name string, s vscodeSpec) error {
		if err := s.valid(); err != nil {
			return err
		}
		if strings.HasPrefix(name, vscodeMCPPrefix) {
			return errors.New("a built-in tool name starting with " + vscodeMCPPrefix + " would read as an MCP tool")
		}
		return nil
	})
})

// vscodeMCPPrefix starts the name of every MCP tool VS Code offers the model.
const vscodeMCPPrefix = engine.VSCodeMCPPrefix

// vscodePrefixMax is the longest prefix VS Code puts before an MCP tool's
// name: "mcp_", the server's label, a number when labels collide, and "_",
// with the label cut to fit (McpToolName.MaxPrefixLen, McpPrefixGenerator).
const vscodePrefixMax = 18

// vscodeUserDirs are where VS Code keeps user settings, under the home
// directory: the desktop app's on Linux and macOS, VS Code Server's, and
// Codespaces'. Each holds settings.json, and profiles/<id>/settings.json
// for every other profile.
var vscodeUserDirs = []string{
	".config/Code/User", ".config/Code - Insiders/User",
	"Library/Application Support/Code/User", "Library/Application Support/Code - Insiders/User",
	".vscode-server/data/User", ".vscode-server-insiders/data/User", ".vscode-remote/data/User",
}

// vscodeMachineDirs are where VS Code Server and Codespaces keep the remote
// machine's settings, under the home directory.
var vscodeMachineDirs = []string{".vscode-server/data/Machine", ".vscode-server-insiders/data/Machine", ".vscode-remote/data/Machine"}

// VSCodeSettingsFiles returns the VS Code settings that can switch the hook
// off (chat.useHooks, chat.hookFilesLocations): the workspace's, and the
// user's (every profile's) and machine's where VS Code keeps them on this
// machine. With chat.useClaudeHooks on, VS Code also runs the hooks in
// Claude Code's settings files, so those are returned too, and so are the
// places of agents and agent plugins, which can declare hooks of their own.
func VSCodeSettingsFiles(env Env) []string {
	out := vscodeProjectFiles(env.ProjectDir)
	if env.Home == "" {
		return out
	}
	under := func(dir string, names ...string) string {
		return adapters.Under(false, env.Home, append(strings.Split(dir, "/"), names...)...)
	}
	// Agent plugins, in a profile's agent-plugins, can hold agents and hooks
	for _, d := range vscodeUserDirs {
		out = append(out, under(d, "settings.json"), under(d, "profiles"), under(d, "agent-plugins"))
	}
	for _, d := range vscodeMachineDirs {
		out = append(out, under(d, "settings.json"))
	}
	return append(out, adapters.Under(false, env.Home, ".claude", "settings.json"), adapters.Under(false, env.Home, ".claude", "agents"))
}

// vscodeProjectFiles returns a folder's files that can switch the hook off
// in VS Code or add hooks of their own: its settings, Claude Code's
// settings, whose hooks VS Code runs with chat.useClaudeHooks on, and
// Claude Code's agents, whose hooks VS Code runs when the model starts the
// agent (runSubagent with agentName).
func vscodeProjectFiles(dir string) []string {
	return []string{adapters.Under(false, dir, ".vscode", "settings.json"),
		adapters.Under(false, dir, ".claude", "settings.json"),
		adapters.Under(false, dir, ".claude", "settings.local.json"),
		adapters.Under(false, dir, ".claude", "agents")}
}

// guardFiles returns every file that installs, changes or switches off the
// hook for Copilot CLI and VS Code alike, since both read the same hook
// files: the user's, and those of every folder projectDirs returns.
func guardFiles(env Env, cwd string) []string {
	dirs := projectDirs(cwd, env.ProjectDir)
	env.ProjectDir = ""
	out := append(SettingsFiles(env), VSCodeSettingsFiles(env)...)
	for _, d := range dirs {
		out = append(out, copilotProjectFiles(d)...)
		out = append(out, vscodeProjectFiles(d)...)
	}
	return out
}

// projectDirs returns the folders whose hook files and settings apply to a
// session in cwd: the project directory, and cwd and every folder above it
// up to the git work tree holding it, since Copilot CLI reads the work
// tree's hooks and VS Code reads the workspace folder's, and its parent
// repository's with chat.useCustomizationsInParentRepositories on. Outside
// a work tree, they are cwd and the folders up to the project directory
// when it holds cwd.
func projectDirs(cwd, projectDir string) []string {
	var out []string
	if projectDir != "" {
		out = append(out, path.Clean(projectDir))
	}
	if !path.IsAbs(cwd) {
		return out
	}
	var walked []string
	for d := path.Clean(cwd); ; d = path.Dir(d) {
		walked = append(walked, d)
		if _, err := os.Lstat(path.Join(d, ".git")); err == nil {
			return append(out, walked...)
		}
		if path.Dir(d) == d {
			break
		}
	}
	for i, d := range walked {
		if len(out) > 0 && d == out[0] {
			return append(out, walked[:i]...)
		}
	}
	return append(out, walked[0])
}

// parseVSCode reads a Local agent call. VS Code runs the hook in the
// workspace folder, which is the input's cwd, and doesn't set
// COPILOT_PROJECT_DIR. Its input names no other folder, so in a multi-root
// workspace only this one is known.
func parseVSCode(in *Input, env Env) *adapters.Call {
	env.ProjectDir = ""
	c := &adapters.Call{Session: in.SessionID, ToolUseID: in.ToolUseID, Cwd: in.Cwd, Project: in.Cwd, Tool: *in.ToolNameVSCode}
	c.Actions, c.Err = VSCodeActions(in, env)
	adapters.Guard(c.Actions, guardFiles(env, in.Cwd)...)
	return c
}

// VSCodeActions maps a Local agent call to the engine actions to evaluate.
// No actions and no error means the tool touches nothing CyberBoar governs.
func VSCodeActions(in *Input, env Env) ([]engine.Action, error) {
	name := *in.ToolNameVSCode
	base := engine.Action{Cwd: in.Cwd, Home: env.Home}
	if in.Cwd != "" {
		base.Workspaces = []string{in.Cwd}
	}
	tools, err := vscodeClassification()
	if err != nil {
		return nil, adapters.ClassificationFailed(err)
	}
	spec, ok := tools[name]
	if !ok {
		if strings.HasPrefix(name, vscodeMCPPrefix) {
			mb := base
			mb.Content = adapters.JSONText(in.ToolInput)
			return vscodeMCPActions(name, mb)
		}
		return nil, adapters.Unclassified(name)
	}
	switch {
	case spec.Passthrough:
		return nil, nil
	case spec.Deny != "":
		return nil, &adapters.Error{Rule: RuleUncheckedTool, Msg: fmt.Sprintf("the %s tool %s, so it is blocked", name, spec.Deny)}
	}

	fields := slices.Concat(spec.Read, spec.Write, spec.List, spec.Content, spec.URLs, spec.Memory)
	for _, f := range []string{spec.Shell, spec.Patch} {
		if f != "" {
			fields = append(fields, f)
		}
	}
	if spec.Replacements != "" {
		fields = append(fields, spec.Replacements+"[].filePath", spec.Replacements+"[].oldString", spec.Replacements+"[].newString")
	}
	input, err := adapters.ToolInputObject(name, in.ToolInput, spec.Required, fields)
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
	if spec.Shell != "" {
		cmd, _, err := inputString(name, input, spec.Shell)
		if err != nil {
			return nil, err
		}
		// The agent's terminal keeps its directory, variables and aliases
		// between calls, and the user can type in it too
		add(engine.ToolShell, func(a *engine.Action) {
			a.Command, a.CDPath, a.ShellPersists = cmd, env.CDPath, true
			a.Cwd, a.CwdUnknown = "", true
		})
	}
	if spec.Task {
		acts, err := taskActions(input, base, env)
		if err != nil {
			return nil, err
		}
		out = append(out, acts...)
	}
	if spec.Patch != "" {
		patch, _, err := inputString(name, input, spec.Patch)
		if err != nil {
			return nil, err
		}
		if _, environment := adapters.PatchPaths(patch); environment {
			return nil, adapters.Invalid("the %s patch names an environment, which VS Code's apply_patch doesn't define", name)
		}
		out = append(out, adapters.PatchWrites(patch, base)...)
	}
	if spec.Replacements != "" {
		acts, err := replacementWrites(name, input[spec.Replacements], base)
		if err != nil {
			return nil, err
		}
		out = append(out, acts...)
	}
	if spec.SQL != "" {
		q, _, err := inputString(name, input, "query")
		if err != nil {
			return nil, err
		}
		if why := sqlFileAccess(spec.SQL, q); why != "" {
			return nil, &adapters.Error{Rule: RuleSQLFileAccess, Msg: fmt.Sprintf(
				"the %s query uses %s, which can read or write files outside the policy's view, so it is blocked; query the session's own tables instead", name, why)}
		}
	}

	content, rewrite, err := adapters.WriteText(input, spec.Content, spec.Edit)
	if err != nil {
		return nil, adapters.Invalid("the %s tool input is malformed: %v", name, err)
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
	// Memory paths name files in VS Code's own storage; one that could leave
	// /memories/ might name any file
	for _, field := range spec.Memory {
		for _, p := range adapters.Extract(input, field) {
			inside := p == strings.TrimSuffix(memoriesRoot, "/") || strings.HasPrefix(p, memoriesRoot)
			if !inside || strings.Contains(p, "\\") || slices.Contains(strings.Split(p, "/"), "..") {
				return nil, adapters.Invalid("the %s tool path %q is not inside %s", name, p, memoriesRoot)
			}
		}
	}
	for _, field := range spec.URLs {
		for _, u := range adapters.Extract(input, field) {
			p, local, err := urlPath(u)
			if err != nil {
				return nil, adapters.Invalid("the %s tool input field %q: %v", name, field, err)
			}
			if local {
				add(engine.ToolRead, func(a *engine.Action) { a.Path = p })
			}
		}
	}
	whole := func(how string) {
		tool := engine.ToolRead
		if how == "list" {
			tool = engine.ToolList
		}
		add(tool, func(a *engine.Action) { a.Path = "." })
	}
	if spec.Workspace != "" {
		whole(spec.Workspace)
	}
	if paths == 0 && spec.DefaultCwd != "" {
		whole(spec.DefaultCwd)
	}
	for i := range out {
		if t := out[i].Tool; t == engine.ToolRead || t == engine.ToolWrite || t == engine.ToolList {
			p, err := vscodePath(out[i].Path)
			if err != nil {
				return nil, adapters.Invalid("the %s tool path: %v", name, err)
			}
			out[i].Path = p
		}
	}
	return out, nil
}

// uriLike is how VS Code's file tools tell a URI from a path: a string that
// isn't absolute and holds this anywhere is parsed as a URI (Copilot Chat
// 0.70's resolveFilePath).
var uriLike = regexp.MustCompile(`\w[\w\d+.-]*:\S`)

// vscodePath returns the path VS Code's file tools reach for p. An absolute
// path is itself and a file: URI is its path. Any other URI is an error,
// and so is a string VS Code would read as a URI with no scheme, which it
// makes absolute ("a/b:c" is /a/b:c). Other relative paths, which the tools
// refuse, are left to the engine.
func vscodePath(p string) (string, error) {
	if strings.HasPrefix(p, "/") || !uriLike.MatchString(p) {
		return p, nil
	}
	if u, err := url.Parse(p); err != nil || u.Scheme == "" {
		return "", fmt.Errorf("%q reads as a URI without a scheme, whose file the hook can't tell", p)
	}
	local, isLocal, err := urlPath(p)
	switch {
	case err != nil:
		return "", err
	case !isLocal:
		return "", fmt.Errorf("the URL %q names no file on this machine", p)
	}
	return local, nil
}

// memoriesRoot is the root of the memory tool's paths.
const memoriesRoot = "/memories/"

// remoteSchemes are URL schemes that name nothing on this machine's disk.
var remoteSchemes = map[string]bool{"http": true, "https": true, "about": true, "data": true}

// urlPath returns the local file a URL names: a file: URL's path, or a
// string with no scheme, read as a path. http, https, about and data URLs
// name nothing local. Any other scheme is an error, since VS Code may map it
// to a file (vscode-remote:, vscode-userdata:, …), and so is a file: URL
// with a host, even localhost: VS Code's file tools read file://localhost/p
// as //localhost/p, which is /localhost/p, while a browser reads /p.
func urlPath(s string) (string, bool, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return s, true, nil
	}
	scheme := strings.ToLower(u.Scheme)
	if remoteSchemes[scheme] {
		return "", false, nil
	}
	if scheme != "file" {
		return "", false, fmt.Errorf("the URL %q has a scheme the hook can't check", s)
	}
	if u.Host != "" {
		return "", false, fmt.Errorf("the file URL %q names a host, whose file the hook can't tell; use file:///path", s)
	}
	if u.Path == "" {
		return "", false, fmt.Errorf("the file URL %q has no path", s)
	}
	return u.Path, true, nil
}

// replacementWrites returns one write per file that multi_replace_string_in_file
// edits, with that file's edits applied in order.
func replacementWrites(tool string, v any, base engine.Action) ([]engine.Action, error) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, adapters.Invalid("the %s tool input has no list of replacements", tool)
	}
	var order []string
	byPath := map[string][]edits.Replace{}
	for _, el := range list {
		obj, ok := el.(map[string]any)
		p, ok1 := obj["filePath"].(string)
		old, ok2 := obj["oldString"].(string)
		with, ok3 := obj["newString"].(string)
		if !ok || !ok1 || !ok2 || !ok3 {
			return nil, adapters.Invalid("the %s tool input has a replacement without filePath, oldString and newString strings", tool)
		}
		if _, seen := byPath[p]; !seen {
			order = append(order, p)
		}
		byPath[p] = append(byPath[p], edits.Replace{Old: old, New: with})
	}
	out := make([]engine.Action, 0, len(order))
	for _, p := range order {
		a := base
		a.Tool, a.Path = engine.ToolWrite, p
		a.Content, a.Rewrite = adapters.EditText(byPath[p]), edits.StringsMatching(byPath[p], edits.Loose)
		out = append(out, a)
	}
	return out, nil
}

// taskKeys are the task properties the hook can check. Any other one may
// change what runs or where: options.env and options.shell, per-platform
// overrides (linux: {command: …}), dependsOn, or runOptions, which can run
// the task again whenever the folder opens.
var taskKeys = map[string]bool{"label": true, "type": true, "command": true, "args": true, "isBackground": true,
	"problemMatcher": true, "group": true, "detail": true, "options": true}

// plainWord matches a task argument that the shell reads the same whether
// VS Code quotes it or not.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./=:,@%+-]+$`)

// taskActions reads create_and_run_task's input: it saves a shell task in
// the workspace folder's .vscode/tasks.json, then runs it in a new shell in
// that folder, or in the task's options.cwd. The folder must be the one the
// hook runs in, the only one it is told. VS Code quotes a task's arguments
// as it sees fit, so with arguments, the command and every argument must be
// a plain word, which reads the same either way; a command line goes in the
// command alone. VS Code substitutes ${…} variables in tasks, and
// ${command:…} runs a command, so a task holding one is refused.
func taskActions(input map[string]any, base engine.Action, env Env) ([]engine.Action, error) {
	const tool = "create_and_run_task"
	folder, ok := input["workspaceFolder"].(string)
	task, ok2 := input["task"].(map[string]any)
	if !ok || !ok2 || folder == "" {
		return nil, adapters.Invalid("the %s tool input has no workspaceFolder string or task object", tool)
	}
	if base.Cwd == "" || path.Clean(folder) != path.Clean(base.Cwd) {
		return nil, adapters.Invalid("the %s task's workspaceFolder %q is not the folder the hook runs in (%q), "+
			"the only one VS Code tells it; run the command with run_in_terminal instead", tool, folder, base.Cwd)
	}
	for k := range task {
		if !taskKeys[k] {
			return nil, adapters.Invalid("the %s task has %q, which the hook can't check; run the command with run_in_terminal instead", tool, k)
		}
	}
	for _, s := range append(adapters.Extract(task, "command"), adapters.Extract(task, "args[]")...) {
		if strings.Contains(s, "${") {
			return nil, adapters.Invalid("the %s task uses a ${…} variable, which VS Code substitutes after the hook; run the command with run_in_terminal instead", tool)
		}
	}
	if typ, _ := task["type"].(string); typ != "shell" {
		return nil, adapters.Invalid("the %s task is of type %v, not shell", tool, task["type"])
	}
	cmd, ok := task["command"].(string)
	if !ok || cmd == "" {
		return nil, adapters.Invalid("the %s task has no command string", tool)
	}
	words := []string{cmd}
	if args, ok := task["args"]; ok {
		list, ok := args.([]any)
		if !ok {
			return nil, adapters.Invalid("the %s task's args is not a list", tool)
		}
		for _, a := range list {
			s, ok := a.(string)
			if !ok {
				return nil, adapters.Invalid("the %s task has an argument that is not a string", tool)
			}
			words = append(words, s)
		}
		for _, w := range words {
			if !plainWord.MatchString(w) {
				return nil, adapters.Invalid("the %s task has %q in its command or arguments, which VS Code may quote; "+
					"put the whole command line in command, without args", tool, w)
			}
		}
	}
	cwd := folder
	if opts, ok := task["options"]; ok {
		obj, ok := opts.(map[string]any)
		if !ok {
			return nil, adapters.Invalid("the %s task's options is not an object", tool)
		}
		for k := range obj {
			if k != "cwd" {
				return nil, adapters.Invalid("the %s task has options.%s, which the hook can't check; run the command with run_in_terminal instead", tool, k)
			}
		}
		switch d := obj["cwd"].(type) {
		case nil:
		case string:
			if strings.HasPrefix(d, "/") {
				cwd = d
			} else {
				cwd = strings.TrimRight(folder, "/") + "/" + d
			}
		default:
			return nil, adapters.Invalid("the %s task's options.cwd is not a string", tool)
		}
	}
	if strings.Contains(cwd, "${") {
		return nil, adapters.Invalid("the %s task's directory %q uses a variable the hook can't resolve", tool, cwd)
	}
	tasks := strings.TrimRight(folder, "/") + "/.vscode/tasks.json"
	save := base
	save.Tool, save.Path, save.Content = engine.ToolWrite, tasks, adapters.ValuesText(task)
	run := base
	run.Tool, run.Command, run.Cwd, run.CDPath = engine.ToolShell, strings.Join(words, " "), cwd, env.CDPath
	return []engine.Action{save, run}, nil
}

// vscodeMCPActions reads mcp_<prefix>_<tool>. The prefix comes from the
// server's label, which can hold "_", so every split within the prefix's
// length is evaluated and the strictest verdict wins. The engine matches
// the tool of any server (engine.NamesVSCode).
func vscodeMCPActions(name string, base engine.Action) ([]engine.Action, error) {
	var out []engine.Action
	last := min(vscodePrefixMax, len(name)-1)
	for i := len(vscodeMCPPrefix) + 1; i < last; i++ {
		if name[i] == '_' {
			a := base
			a.Tool, a.MCP = engine.ToolMCP, engine.MCPCall{Server: name[len(vscodeMCPPrefix):i], Tool: name[i+1:], Names: engine.NamesVSCode}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, adapters.Invalid("the MCP tool name %s has no server and tool part", name)
	}
	return out, nil
}
