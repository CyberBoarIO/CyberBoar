// Package copilot maps GitHub Copilot's preToolUse hook input to engine
// actions and engine verdicts to hook output, for Copilot CLI, the Copilot
// session target of VS Code (which runs Copilot CLI's runtime) and VS Code's
// Local agent, which all read the same hook files
//
// The hook is installed under the camelCase event name preToolUse, whose
// input from Copilot names its own tools, such as bash, powershell and view.
// Copilot's VS Code-compatible PreToolUse form reports bash and powershell
// both as Bash, so the adapter refuses it. VS Code's Local agent sends that
// form with a tool_use_id and its own tools (vscode.go)
package copilot

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
)

// RuleSQLFileAccess denies a query to one of Copilot's SQL tools that could
// read or write a file
// Copilot runs the query itself, so the files it would touch never reach the engine
const RuleSQLFileAccess = "adapter.sqlFileAccess"

// Adapter speaks Copilot CLI's hook protocol
type Adapter struct{}

// Name returns "copilot-cli", the agent name used on the command line and in audit events
func (Adapter) Name() string { return "copilot-cli" }

// Input is the preToolUse hook input
type Input struct {
	SessionID string          `json:"sessionId"`
	Cwd       string          `json:"cwd"`
	ToolName  string          `json:"toolName"`
	ToolArgs  json.RawMessage `json:"toolArgs"`
	// The VS Code-compatible form's fields. VS Code's Local agent sends this
	// form with a tool_use_id and Copilot sends it without one
	ToolNameVSCode *string         `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
	SessionIDVS    string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
}

// Local reports whether the input is from VS Code's Local agent
func (in *Input) Local() bool { return in.ToolNameVSCode != nil }

// ParseInput decodes exactly one JSON object
func ParseInput(data []byte) (*Input, error) {
	var in Input
	if err := adapters.DecodeHookInput(data, &in); err != nil {
		return nil, err
	}
	if in.ToolNameVSCode != nil {
		switch {
		case in.ToolUseID == "" || in.HookEventName != "PreToolUse":
			return nil, adapters.Invalid("the hook input is in the VS Code-compatible PreToolUse form, which reports bash and powershell alike; install the hook under preToolUse")
		case in.ToolName != "":
			return nil, adapters.Invalid("the hook input has both toolName and tool_name")
		case *in.ToolNameVSCode == "":
			return nil, adapters.Invalid("the hook input has no tool_name")
		}
		in.SessionID = in.SessionIDVS
		return &in, nil
	}
	if in.ToolName == "" {
		return nil, adapters.Invalid("the hook input has no toolName")
	}
	return &in, nil
}

// Env is what the adapter takes from the hook's environment
type Env struct {
	// ProjectDir is COPILOT_PROJECT_DIR, which Copilot sets for hooks to the
	// git root, or else to the session directory
	// The model can't change it
	ProjectDir string
	Home       string
	// CopilotHome is COPILOT_HOME, where Copilot keeps the user's settings when it is set
	// The default is ~/.copilot
	CopilotHome string
	CDPath      bool
}

// Parse reads the workspace root from COPILOT_PROJECT_DIR
func (Adapter) Parse(data []byte, getenv func(string) string) (*adapters.Call, error) {
	in, err := ParseInput(data)
	if err != nil {
		return nil, err
	}
	env := Env{ProjectDir: getenv("COPILOT_PROJECT_DIR"), Home: getenv("HOME"), CopilotHome: getenv("COPILOT_HOME"),
		CDPath: getenv("CDPATH") != ""}
	if in.Local() {
		return parseVSCode(in, env), nil
	}
	c := &adapters.Call{Session: in.SessionID, Cwd: in.Cwd, Project: env.ProjectDir, Tool: in.ToolName}
	c.Actions, c.Err = Actions(in, env)
	// VS Code reads the same hook files, so its settings can switch the hook off as well
	adapters.Guard(c.Actions, guardFiles(env, in.Cwd)...)
	return c, nil
}

// SettingsFiles returns the Copilot files and directories that can install,
// change or switch off the hook (disableAllHooks), which agents may not
// change (builtin.guarded). They are the user's config and hooks, the
// repository's hooks and settings, and the machine-wide policy directory
func SettingsFiles(env Env) []string {
	var out []string
	for _, dir := range []string{adapters.Under(false, env.Home, ".copilot"), env.CopilotHome} {
		if dir != "" {
			// Custom agents can declare hooks, which VS Code runs for them
			out = append(out, adapters.Under(false, dir, "config.json"), adapters.Under(false, dir, "settings.json"),
				adapters.Under(false, dir, "hooks"), adapters.Under(false, dir, "agents"))
		}
	}
	out = append(out, copilotProjectFiles(env.ProjectDir)...)
	return append(out, PolicyDir)
}

// copilotProjectFiles returns a folder's Copilot hook files and settings,
// and its custom agents, whose hooks VS Code runs when the agent runs
func copilotProjectFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	return []string{adapters.Under(false, dir, ".github", "hooks"), adapters.Under(false, dir, ".github", "copilot"),
		adapters.Under(false, dir, ".github", "agents")}
}

// Respond turns a verdict into hook output. Deny exits 2, which blocks even
// if Copilot can't parse the JSON, and puts the reason on stderr too. Copilot
// still shows the JSON reason. Allow produces no output, because CyberBoar
// never answers "allow" and leaves Copilot's own permission flow in charge
// The answer is in both shapes: Copilot reads the top-level fields and
// ignores hookSpecificOutput, which VS Code's Local agent reads (seen in
// Copilot CLI 1.0.98 and VS Code 1.142)
func (Adapter) Respond(v engine.Verdict, prefix string) adapters.Output {
	reason := prefix + v.Reason
	var decision string
	switch v.Decision {
	case engine.Allow:
		return adapters.Output{}
	case engine.Ask:
		decision = "ask"
	default:
		decision = "deny"
	}
	body, _ := json.Marshal(map[string]any{"permissionDecision": decision, "permissionDecisionReason": reason,
		"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}})
	body = append(body, '\n')
	if decision == "ask" {
		// Without a user to ask (copilot -p), Copilot denies
		return adapters.Output{Stdout: body}
	}
	return adapters.Output{Stdout: body, Stderr: reason + "\n", Exit: 2}
}

//go:embed tools.yaml
var toolsYAML []byte

type toolSpec struct {
	Shell           string             `yaml:"shell"`
	ShellUnknownCwd string             `yaml:"shellUnknownCwd"`
	PowerShell      string             `yaml:"powershell"`
	Read            []string           `yaml:"read"`
	Write           []string           `yaml:"write"`
	Content         []string           `yaml:"content"`
	Edit            *adapters.EditSpec `yaml:"edit"`
	Editor          bool               `yaml:"editor"`
	List            []string           `yaml:"list"`
	View            []string           `yaml:"view"`
	Patch           bool               `yaml:"patch"`
	SQL             string             `yaml:"sql"`
	Required        []string           `yaml:"required"`
	DefaultCwd      bool               `yaml:"defaultCwd"`
	Passthrough     bool               `yaml:"passthrough"`
}

func (s toolSpec) valid() error {
	acts := s.Shell != "" || s.PowerShell != "" || s.Patch || s.SQL != "" || len(s.Read)+len(s.Write)+len(s.List)+len(s.View) > 0
	switch {
	case s.Passthrough && acts:
		return errors.New("passthrough together with fields")
	case !s.Passthrough && !acts:
		return errors.New("neither passthrough nor fields")
	case s.SQL != "" && s.SQL != "sqlite" && s.SQL != "duckdb":
		return fmt.Errorf("sql %q: want sqlite or duckdb", s.SQL)
	case (len(s.Content) > 0 || s.Edit != nil || s.Editor) && len(s.Write) == 0:
		return errors.New("content without a write field")
	case s.Editor && (len(s.Content) > 0 || s.Edit != nil):
		return errors.New("editor together with content or edit")
	case s.Edit != nil && s.Edit.Valid() != nil:
		return s.Edit.Valid()
	case s.ShellUnknownCwd != "" && s.Shell == "":
		return errors.New("shellUnknownCwd without shell")
	}
	return nil
}

var classification = sync.OnceValues(func() (map[string]toolSpec, error) {
	return adapters.LoadTools(toolsYAML, func(name string, s toolSpec) error {
		if err := s.valid(); err != nil {
			return err
		}
		if strings.Contains(name, "-") {
			return errors.New("a built-in tool name with a dash would read as an MCP tool")
		}
		return nil
	})
})

// Actions maps a hook input to the engine actions to evaluate
// No actions and no error means the tool touches nothing CyberBoar governs
func Actions(in *Input, env Env) ([]engine.Action, error) {
	base := engine.Action{Cwd: in.Cwd, Home: env.Home}
	if env.ProjectDir != "" {
		base.Workspaces = []string{env.ProjectDir}
	}
	tools, err := classification()
	if err != nil {
		return nil, adapters.ClassificationFailed(err)
	}
	spec, ok := tools[in.ToolName]
	if !ok {
		// Copilot names an MCP tool <server>-<tool>. No classified tool has
		// a dash in its name, because the classification refuses one, so an
		// unclassified name with a dash is read as an MCP tool
		if strings.Contains(in.ToolName, "-") {
			mb := base
			mb.Content = adapters.JSONText(in.ToolArgs)
			return mcpActions(in.ToolName, mb)
		}
		return nil, adapters.Unclassified(in.ToolName)
	}
	if spec.Passthrough {
		return nil, nil
	}

	var out []engine.Action
	add := func(tool engine.Tool, set func(*engine.Action)) {
		a := base
		a.Tool = tool
		set(&a)
		out = append(out, a)
	}
	if spec.Patch {
		var patch string
		if err := json.Unmarshal(in.ToolArgs, &patch); err != nil {
			return nil, adapters.Invalid("the %s tool input is not a patch text", in.ToolName)
		}
		_, environment := adapters.PatchPaths(patch)
		if environment {
			return nil, adapters.Invalid("the %s patch names an environment, which Copilot's apply_patch doesn't define", in.ToolName)
		}
		return adapters.PatchWrites(patch, base), nil
	}

	input, err := adapters.ToolInputObject(in.ToolName, in.ToolArgs, spec.Required, slices.Concat(spec.Read, spec.Write, spec.List, spec.View, spec.Content))
	if err != nil {
		return nil, err
	}
	actions, err := shellActions(in.ToolName, input, spec, base, env.CDPath)
	if err != nil {
		return nil, err
	}
	out = append(out, actions...)
	// Copilot runs a query itself, against its own databases. A query that
	// can't reach a file touches nothing the engine checks, so it adds no action
	if spec.SQL != "" {
		q, ok, err := inputString(in.ToolName, input, "query")
		if err != nil || !ok {
			return nil, adapters.Invalid("the %s tool input field %q is not a string", in.ToolName, "query")
		}
		if why := sqlFileAccess(spec.SQL, q); why != "" {
			return nil, &adapters.Error{Rule: RuleSQLFileAccess, Msg: fmt.Sprintf(
				"the %s query uses %s, which can read or write files outside the policy's view, so it is blocked; query the session's own tables instead", in.ToolName, why)}
		}
	}

	content, rewrite, err := writeText(input, spec)
	if err != nil {
		return nil, adapters.Invalid("the %s tool input is malformed: %v", in.ToolName, err)
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
			for _, p := range adapters.Extract(input, field) {
				paths++
				tool := pf.tool
				if pf.view && adapters.IsDir(resolve(in.Cwd, p)) {
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
	if paths == 0 && spec.DefaultCwd {
		tool := engine.ToolRead
		if len(spec.Read) == 0 {
			tool = engine.ToolList
		}
		add(tool, func(a *engine.Action) { a.Path = "." })
	}
	return out, nil
}

// resolve makes p absolute against cwd, for the directory test only. The
// engine does its own resolution. An unusable cwd gives "", which is not a
// directory, so the path is checked as a read, the stricter reading
func resolve(cwd, p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	if !strings.HasPrefix(cwd, "/") {
		return ""
	}
	return cwd + "/" + p
}

// mcpActions splits <server>-<tool>. Server and tool names may both contain
// dashes and the hook input doesn't say where the server ends, so every split
// is evaluated and the strictest verdict wins
// An allowed server "github" then can't cover a server "github-evil"
// Copilot writes both names with "-" for other punctuation, punycode for
// non-ASCII parts, and cuts the whole at 64 characters (seen in 1.0.97), so
// the calls say the names are Copilot's
func mcpActions(name string, base engine.Action) ([]engine.Action, error) {
	var out []engine.Action
	for i := 1; i < len(name)-1; i++ {
		if name[i] == '-' {
			a := base
			a.Tool, a.MCP = engine.ToolMCP, engine.MCPCall{Server: name[:i], Tool: name[i+1:], Names: engine.NamesCopilot}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, adapters.Invalid("the MCP tool name %s has no server and tool part", name)
	}
	return out, nil
}

// These patterns match SQL that reaches files. SQLite, which holds Copilot's
// session database, can attach databases, write one with VACUUM INTO and load
// extensions. DuckDB, the session store, also reads and writes files through
// table functions, COPY, EXPORT and file names used as tables. query and
// query_table can construct SQL or file names at runtime, so they are refused
// The lists over-approximate, and a false match only denies a query the model
// can phrase another way
var (
	sqliteFile = regexp.MustCompile(`(?i)\b(attach|vacuum|load_extension|readfile|writefile|fsdir|zipfile|sqlar\w*|(temp|data)_store_directory)\b|\bedit\s*\(`)
	duckdbFile = regexp.MustCompile(`(?i)\b(copy|export|import|install|load|force|read_\w+|\w+_scan|sniff_csv|parquet_\w+|delta_\w+|iceberg_\w+|query(_table)?|glob|secret|httpfs)\b`)
	// quotedPath matches a quoted name or string that looks like a path or
	// file name, because DuckDB reads FROM 'x.csv' and FROM "x.csv" as files
	quotedPath = regexp.MustCompile(`'[^']*[/\\~][^']*'|"[^"]*[/\\~][^"]*"|'[^']*\.[A-Za-z]\w*'|"[^"]*\.[A-Za-z]\w*"`)
)

// sqlFileAccess names the construct that makes a query unsafe, or ""
func sqlFileAccess(dialect, q string) string {
	if m := sqliteFile.FindString(q); m != "" {
		return strings.ToUpper(strings.TrimSpace(strings.TrimSuffix(m, "(")))
	}
	if dialect != "duckdb" {
		return ""
	}
	if m := duckdbFile.FindString(q); m != "" {
		return strings.ToUpper(m)
	}
	if m := quotedPath.FindString(q); m != "" {
		return "a file name (" + m + ")"
	}
	return ""
}

// writeText returns what a write tool puts in its file, and how it changes
// the file (adapters.WriteText). str_replace_editor, Anthropic's text editor
// tool, uses the fields its command names. create writes file_text,
// str_replace replaces old_str with new_str, and insert puts new_str after
// line insert_line. A command that writes nothing may not carry text
func writeText(input map[string]any, spec toolSpec) (string, engine.Rewrite, error) {
	if !spec.Editor {
		return adapters.WriteText(input, spec.Content, spec.Edit)
	}
	str := func(k string) (string, bool) { s, ok := input[k].(string); return s, ok }
	cmd, _ := str("command")
	switch cmd {
	case "create":
		text, ok := str("file_text")
		if !ok {
			return "", nil, errors.New("create without file_text")
		}
		return text, nil, nil
	case "str_replace":
		return adapters.WriteText(input, nil, &adapters.EditSpec{Old: "old_str", New: "new_str"})
	case "insert":
		text, ok := str("new_str")
		num, isNum := input["insert_line"].(json.Number)
		n, err := num.Int64()
		if !ok || !isNum || err != nil || n < 0 || n > math.MaxInt32 {
			return "", nil, errors.New("insert without new_str or a line number")
		}
		return text, edits.Insert(int(n), text), nil
	}
	for _, k := range []string{"file_text", "new_str"} {
		if _, ok := input[k]; ok {
			return "", nil, fmt.Errorf("command %q with %s", cmd, k)
		}
	}
	return "", nil, nil
}

func inputString(tool string, input map[string]any, field string) (string, bool, error) {
	switch v := input[field].(type) {
	case nil:
		return "", false, nil
	case string:
		return v, true, nil
	default:
		return "", false, adapters.Invalid("the %s tool input field %q is not a string", tool, field)
	}
}

func shellActions(tool string, input map[string]any, spec toolSpec, base engine.Action, cdPath bool) ([]engine.Action, error) {
	var out []engine.Action

	if spec.Shell != "" {
		cmd, ok, err := inputString(tool, input, spec.Shell)
		if err != nil || !ok {
			return nil, adapters.Invalid("the %s tool input field %q is not a string", tool, spec.Shell)
		}
		_, reused, err := inputString(tool, input, spec.ShellUnknownCwd)
		if err != nil {
			return nil, err
		}
		// A command sent to an existing shell runs in the directory that
		// shell was created in, which the hook isn't told
		a := base
		a.Tool = engine.ToolShell
		a.Command, a.CDPath = cmd, cdPath
		if reused {
			a.Cwd, a.CwdUnknown = "", true
		}
		out = append(out, a)
	}
	if spec.PowerShell != "" {
		cmd, ok, err := inputString(tool, input, spec.PowerShell)
		if err != nil || !ok {
			return nil, adapters.Invalid("the %s tool input field %q is not a string", tool, spec.PowerShell)
		}
		a := base
		a.Tool, a.Command = engine.ToolShell, "pwsh -Command "+adapters.ShellQuote(cmd)
		out = append(out, a)
	}
	return out, nil
}
