package engine

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/winpath"
)

// Tool is the kind of action an agent wants to take, after adapter normalization.
type Tool string

// The tools an action can use.
const (
	ToolShell Tool = "shell"
	ToolRead  Tool = "read"
	ToolWrite Tool = "write"
	// ToolList reads only the names under a path, as Glob and LS do
	// The path is checked, but not what a directory contains (files.containing).
	ToolList Tool = "list"
	ToolMCP  Tool = "mcp"
)

// Action is an agent's tool-call intent in agent-neutral form.
// Adapters build it from each agent's hook input.
type Action struct {
	Tool    Tool
	Command string  // shell
	Path    string  // read, write, list
	MCP     MCPCall // mcp
	// Content is checked for secrets. For a write, it is the text the write
	// adds to the file when the agent's tool says: a whole file, an edit's
	// new text or a patch's added lines. For an MCP call, it is what the call
	// sends, the strings in its arguments. Other tools must leave it empty.
	Content string
	// Rewrite is set for a write that changes a file rather than replacing
	// it whole, such as an edit or a patch. The secrets check then reads the
	// file and checks what it would hold after the write. Other tools must
	// leave it nil.
	Rewrite Rewrite
	// RewriteMoves says the rewritten contents are moved to another path.
	// Treat credentials already in the source as new credentials in the destination.
	RewriteMoves bool
	// Cwd, Home and at least one workspace root, all absolute, are required
	// for every tool but MCP. Workspaces must come from the agent harness
	// (e.g. the project directory), never from cwd, which the agent can change.
	Cwd string
	// CwdUnknown says the harness lets the model choose the directory a shell
	// command starts in without telling the hook (a Cursor terminal call that
	// reports no directory). Cwd must then be empty, and the command is analyzed as if it
	// began with `cd "$DIR"`, so relative paths are only possible paths. Only
	// shell actions may set it.
	CwdUnknown bool
	// ShellPersists says the command runs in a shell that earlier commands
	// ran in, which the hook didn't see change (Cursor's agent shell). Their
	// cd, variables, shell options and aliases carry over, so HOME, CDPATH
	// and glob options are unknown, and an alias the command defines is
	// checked as if a later command passed it any arguments. Only shell
	// actions may set it.
	ShellPersists bool
	// Shell is the language Command is written in: "" for bash and the
	// shells that read it (sh, zsh, Git Bash), or ShellPowerShell. Only
	// shell actions may set it.
	Shell string
	// CDPath says CDPATH is set where the command runs, so `cd NAME` may go
	// elsewhere than ./NAME.
	// Adapters read it from the hook's environment.
	CDPath     bool
	Home       string
	Workspaces []string
	// Protected are the absolute paths of CyberBoar's own directories and
	// files, such as the hook's tripwire counts and shipping offsets, and the
	// audit log. Paths inside them are denied whatever the policy says
	// (builtin.self), as are their rotated copies, the paths beside them
	// whose names start with theirs (audit.jsonl.1), and touching the
	// contents of a directory that holds one. They are optional, and only file and shell actions use them.
	Protected []string
	// Guarded are the absolute paths of the files that decide whether and how
	// CyberBoar runs (builtin.guarded): the agent's settings files that
	// install the hook, the policy, its signature and key, the hook binary,
	// the audit log, and the startup files the agent's shell runs outside
	// the hook. They need not exist. The agent's file tools may read
	// them but not write them. The shell may not touch them at all, nor
	// delete, move or replace a directory holding one. They are optional, and
	// only file and shell actions use them.
	Guarded []string
	// Platform names the path semantics of every path in the action: "" for
	// POSIX, or "windows", where paths are Windows paths (C:\Users\dev) that
	// the engine reads into its own form.
	Platform string
	// Drives maps drive letters to OS directories for Windows actions, as osfs.FS.Drives does
	// If nil, the real drives are used, as adapters do.
	Drives map[string]string
	// Mounts is Git Bash's mount table on Windows. It maps each mount point,
	// such as /, /tmp or /usr/bin, to the Windows directory behind it, or to
	// "" when that is unknown. Nil means the table couldn't be read, and shell
	// paths outside a drive are then refused. Adapters read it from Git's installation.
	Mounts map[string]string

	display string // Path as the agent wrote it, when fromPlatform rewrote it
}

// Rewrite returns every content a file may hold after a write, given old,
// what it holds before. When there is no file, exists is false and old is
// "". It returns several contents when the agent's tool may leave any of
// them and the engine can't tell which. It returns an error when the tool
// would refuse the write, such as an edit whose old text is not in the
// file. Package edits builds Rewrite functions for each agent's tools.
type Rewrite func(old string, exists bool) ([]string, error)

// ErrRewriteTooLarge means an edit would exceed the secret scanner's size limit.
var ErrRewriteTooLarge = errors.New("the edited file is too large to check for secrets")

// PlatformWindows is Action.Platform for native Windows.
const PlatformWindows = "windows"

// ShellPowerShell is Action.Shell for PowerShell: Windows PowerShell 5.1 or
// PowerShell 7 (pwsh), read as package shell's AnalyzePowerShell reads them.
const ShellPowerShell = "powershell"

// MCPCall names the MCP server and tool an action calls.
type MCPCall struct {
	Server string
	Tool   string
	// Names says how the agent rewrote the names it reports. Deny and ask
	// rules then also match the names in that form.
	Names MCPNames
}

// MCPNames is how an agent rewrites the MCP names it reports.
type MCPNames int

const (
	// NamesAsConfigured are the server and tool names as configured.
	NamesAsConfigured MCPNames = iota
	// NamesOpencode has the server as configured and the tool with every
	// UTF-16 code unit outside [A-Za-z0-9_-] replaced by "_", as opencode
	// writes it.
	NamesOpencode
	// NamesCopilot has both names as Copilot CLI writes them: characters
	// outside [A-Za-z0-9_-] replaced by "-", a part holding a non-ASCII
	// character in punycode (xn--…), and server-tool cut at 64 characters.
	NamesCopilot
	// NamesCodex has both names as Codex writes them: characters outside
	// [A-Za-z0-9_] replaced by "_", and "_" and 12 hex digits added to a
	// name that collides or is cut short.
	NamesCodex
	// NamesClaudeCode has both names with every UTF-16 code unit outside
	// [A-Za-z0-9_-] replaced by "_", as Claude Code writes server names in
	// mcp__<server>__<tool>; the tool part is treated the same way.
	NamesClaudeCode
	// NamesVSCode has the server as part of VS Code's tool prefix, which comes
	// from the name the server reports for itself (or its label) cut to 13
	// characters, and the tool with every UTF-16 code unit outside
	// [A-Za-z0-9_-] replaced by "_", the whole mcp_<prefix>_<tool> cut at
	// 64 characters (seen in VS Code 1.142). The server can't be told from
	// the prefix, so deny and ask rules match the tool of any server, and
	// allow rules only cover a call when they allow every server ("*"),
	// and every tool when the name may have been cut.
	NamesVSCode
)

// validate rejects malformed and ambiguous actions. A field that doesn't belong
// to the tool is an error rather than ignored: it signals an adapter bug, and
// the engine must not guess which field the agent will actually use.
func (a Action) validate() error {
	// A NUL byte ends a string for the OS and for the programs the agent
	// runs, so they would read a different command or path than the one the engine checks
	for _, f := range []struct{ name, v string }{
		{"command", a.Command}, {"path", a.Path}, {"cwd", a.Cwd}, {"home", a.Home},
		{"mcp.server", a.MCP.Server}, {"mcp.tool", a.MCP.Tool},
		{"workspaces", strings.Join(a.Workspaces, "")},
		{"protected", strings.Join(a.Protected, "")},
		{"guarded", strings.Join(a.Guarded, "")},
	} {
		if strings.ContainsRune(f.v, 0) {
			return fmt.Errorf("%s contains a NUL byte", f.name)
		}
	}

	hasMCP := a.MCP != MCPCall{}
	if (a.Content != "" && a.Tool != ToolWrite && a.Tool != ToolMCP) ||
		(a.Rewrite != nil && a.Tool != ToolWrite) {
		return fmt.Errorf("%s action must not carry written content", a.Tool)
	}
	if a.RewriteMoves && a.Rewrite == nil {
		return errors.New("a moved write must have a rewrite")
	}
	if a.CwdUnknown && a.Tool != ToolShell {
		return fmt.Errorf("%s action can't have an unknown working directory", a.Tool)
	}
	if a.ShellPersists && a.Tool != ToolShell {
		return fmt.Errorf("%s action can't run in a persistent shell", a.Tool)
	}
	switch {
	case a.Shell != "" && a.Tool != ToolShell:
		return fmt.Errorf("%s action can't name a shell", a.Tool)
	case a.Shell != "" && a.Shell != ShellPowerShell:
		return fmt.Errorf("unknown shell %q", a.Shell)
	}
	switch a.Tool {
	case ToolShell:
		if a.Command == "" {
			return errors.New("shell action has no command")
		}
		if a.Path != "" || hasMCP {
			return errors.New("shell action must not carry a path or MCP call")
		}
	case ToolRead, ToolWrite, ToolList:
		if a.Path == "" {
			return fmt.Errorf("%s action has no path", a.Tool)
		}
		if a.Command != "" || hasMCP {
			return fmt.Errorf("%s action must not carry a command or MCP call", a.Tool)
		}
	case ToolMCP:
		if a.MCP.Server == "" || a.MCP.Tool == "" {
			return errors.New("MCP action needs both server and tool")
		}
		// Rules name a call as server/tool, so a / in either name would make that ambiguous
		if strings.Contains(a.MCP.Server, "/") || strings.Contains(a.MCP.Tool, "/") {
			return errors.New("MCP server and tool names must not contain /")
		}
		if a.Command != "" || a.Path != "" {
			return errors.New("MCP action must not carry a command or path")
		}
		return nil // cwd and home are not needed
	case "":
		return errors.New("action has no tool")
	default:
		return fmt.Errorf("unknown tool %q", a.Tool)
	}

	// Every tool left reaches files, whose rules are anchored on the home
	// directory and the workspace roots. Without a root, every workspace
	// rule would match nothing, a deny rule among them included
	switch {
	case a.CwdUnknown && a.Cwd != "":
		return errors.New("cwd is given although the working directory is unknown")
	case !a.CwdUnknown && !path.IsAbs(a.Cwd):
		return fmt.Errorf("cwd %q is not an absolute path", a.Cwd)
	}
	if !path.IsAbs(a.Home) {
		return fmt.Errorf("home %q is not an absolute path", a.Home)
	}
	if len(a.Workspaces) == 0 {
		return errors.New("no workspace root given")
	}
	for _, ws := range a.Workspaces {
		if !path.IsAbs(ws) {
			return fmt.Errorf("workspace root %q is not an absolute path", ws)
		}
	}
	for _, p := range a.Protected {
		if !path.IsAbs(p) {
			return fmt.Errorf("protected directory %q is not an absolute path", p)
		}
	}
	for _, p := range a.Guarded {
		if !path.IsAbs(p) {
			return fmt.Errorf("guarded path %q is not an absolute path", p)
		}
	}
	return nil
}

// fs returns the filesystem mapping for the action's paths.
func (a Action) fs() osfs.FS {
	return osfs.FS{Windows: a.Platform == PlatformWindows, Drives: a.Drives}
}

// fromPlatform returns a with its paths in the engine's form. Windows paths
// the engine refuses to read deny as builtin.windowsPath when the agent
// chose them (the tool's path) and as an invalid action when the harness
// did (cwd, home, workspace roots).
func (a Action) fromPlatform() (Action, *Verdict) {
	switch a.Platform {
	case "":
		return a, nil
	case PlatformWindows:
	default:
		v := invalidAction(fmt.Errorf("unknown platform %q", a.Platform))
		return a, &v
	}
	if a.Tool == ToolMCP {
		// An MCP call involves no path, so its paths need not be valid here,
		// as validate doesn't ask for them on POSIX either
		return a, nil
	}
	invalid := func(what string, err error) (Action, *Verdict) {
		v := invalidAction(fmt.Errorf("%s: %v", what, err))
		return a, &v
	}
	drives := make(map[string]string, len(a.Drives))
	for d, dir := range a.Drives {
		if len(d) != 1 || !('a' <= d[0] && d[0] <= 'z' || 'A' <= d[0] && d[0] <= 'Z') {
			return invalid("drives", fmt.Errorf("%q is not a drive letter", d))
		}
		if _, dup := drives[strings.ToLower(d)]; dup {
			return invalid("drives", fmt.Errorf("drive %q is given twice", d))
		}
		drives[strings.ToLower(d)] = dir
	}
	if a.Drives != nil {
		a.Drives = drives
	}
	var err error
	if a.Cwd != "" {
		if a.Cwd, err = winpath.Abs(a.Cwd); err != nil {
			return invalid("cwd", err)
		}
	}
	if a.Home, err = winpath.Abs(a.Home); err != nil {
		return invalid("home", err)
	}
	conv := func(what string, ps []string) ([]string, *Verdict) {
		out := make([]string, len(ps))
		for i, p := range ps {
			if out[i], err = winpath.Abs(p); err != nil {
				_, v := invalid(what, err)
				return nil, v
			}
		}
		return out, nil
	}
	var v *Verdict
	if a.Workspaces, v = conv("workspace root", a.Workspaces); v != nil {
		return a, v
	}
	if a.Protected, v = conv("protected directory", a.Protected); v != nil {
		return a, v
	}
	if a.Guarded, v = conv("guarded path", a.Guarded); v != nil {
		return a, v
	}
	if a.Mounts != nil {
		mounts := make(map[string]string, len(a.Mounts))
		folded := map[string]bool{}
		for pt, dir := range a.Mounts {
			if !strings.HasPrefix(pt, "/") || path.Clean(pt) != pt || folded[strings.ToLower(pt)] {
				return invalid("mounts", fmt.Errorf("%q is not a clean, unique mount point", pt))
			}
			folded[strings.ToLower(pt)] = true
			if dir != "" {
				if dir, err = winpath.Abs(dir); err != nil {
					return invalid("mount "+pt, err)
				}
			}
			mounts[pt] = dir
		}
		a.Mounts = mounts
	}
	if a.Path != "" {
		a.display = a.Path
		if a.Path, _, err = winpath.Path(a.Path); err != nil {
			v := deny(RuleWindowsPath, fmt.Sprintf("the path %v, so access is blocked; %s", err, noRetry))
			return a, &v
		}
	}
	return a, nil
}
