package adapters_test

import (
	"fmt"
	"io"
	"strings"
)

// Capability is one row of the capability matrix: what each agent adapter
// can and can't enforce. Maintainers describe the tested behavior and known
// limitations here; docs/capability-matrix.md is generated from this prose
type Capability struct {
	What       string
	ClaudeCode string
	Codex      string
	Copilot    string
	Cursor     string
	Opencode   string
}

// Matrix is the capability matrix. Keep it in step with the adapters and
// their case files; docs/capability-matrix.md is generated from it
var Matrix = []Capability{
	{"Validation coverage",
		"Claude Code 2.1.220: captured inputs and real-agent harness.",
		"Codex 0.155: captured inputs and real denied reads/writes; scripted-model integration harness passed at 0.155 and 0.163.",
		"Copilot CLI: captured inputs/schema at 1.0.91, tool list at 1.0.97; local-model integration harness passed at 1.0.97.",
		"Cursor CLI 2026.10.14: captured inputs and real-agent harness. Cursor editor 3.13: documentation and captured payloads; real-agent validation pending.",
		"opencode: captured plugin inputs/schema at 1.18.34; local-model integration harness passed at 1.19.0."},
	{"Native Windows",
		"Claude Code with Git Bash. Mount-aware Windows path checks cover drives, trailing dots, streams, junctions and 8.3 names; UNC/device paths deny. PowerShell tool is hidden and denied (builtin.powershell). Local-scope real-agent testing does not cover every CPU or managed configuration.",
		"Denied; use the Linux build in WSL.",
		"Denied; use WSL or a Linux container.",
		"Denied; use WSL, Remote-WSL or a Linux container.",
		"Denied; use WSL or a Linux container."},
	{"Native file tools",
		"Read, Write, Edit, MultiEdit, NotebookEdit, Grep, Glob, LS and file-upload tools.",
		"apply_patch (every changed path), view_image. Reads otherwise use shell tools.",
		"view, create, edit, str_replace_editor, apply_patch (every changed path), grep, rg and glob.",
		"Read, Write, Delete and Grep through preToolUse; loosely matched path fields, missing paths deny. beforeReadFile covers prompt attachments; beforeTabFileRead covers Tab reads.",
		"read, write, edit, apply_patch (every changed path), grep and glob."},
	{"Shell file rules",
		"Best effort on inferred arguments. Launched programs' internal file access is opaque.",
		"Best effort. Working directory is recovered from the session transcript; code mode requires plain literal tool calls. Missing or unmatched calls deny.",
		"Best effort. Each call starts in the session directory and keeps no cd or variables; relative paths in reused shells (shellId) ask, since such a shell starts where it was created.",
		"Best effort. The agent shell persists between calls; a call without a working directory leaves relative paths unknown (ask, so denied) unless the command starts with an absolute cd. HOME, glob options and aliases from earlier calls are treated as unknown. Shells outside bash/sh/dash/zsh are foreign code.",
		"Best effort using the call's workdir."},
	{"Command rules",
		"Parsed Bash commands.",
		"Parsed Bash; selected shell is recovered from the transcript. Shells outside bash/sh/zsh are foreign code.",
		"Parsed Bash; the powershell tool is foreign code.",
		"Parsed Bash through preToolUse and beforeShellExecution.",
		"Parsed Bash; config, $SHELL or the Bash default selects the shell. Shells outside bash/sh/dash/zsh are foreign code."},
	{"MCP rules",
		"Server name from the hook input; deny and ask rules also match names with characters outside A-Z, a-z, 0-9, _ and - written as _.",
		"All possible server/tool name splits; deny and ask rules also match Codex's rewritten names (characters outside A-Z, a-z, 0-9 and _ as _, hash suffixes); resource access maps to its server.",
		"All possible server/tool name splits; deny and ask rules also match Copilot's rewritten names (punctuation as -, punycode, 64-character cut).",
		"beforeMCPExecution, the event supplying the server name.",
		"Configured server names and all possible splits; resource calls map to a known server or every server when ambiguous."},
	{"ask",
		"Native user confirmation.",
		"Converted to deny; a hook ask would let the tool run.",
		"Native confirmation; headless (-p) denies.",
		"Converted to deny; preToolUse ask would let the tool run.",
		"Converted to deny; plugins cannot request confirmation."},
	{"Unclassified tools",
		"Denied.",
		"Denied, including code-mode exec and plugin installation. write_stdin is not hooked, so commands that ask for a terminal (tty) are denied.",
		"Denied, including write_bash/write_powershell and unknown tools.",
		"Denied outside Shell, Read, Write, Delete, Grep, Task and MCP.",
		"Denied, including custom tools, experimental lsp and code-mode execute."},
	{"Hook visibility limits",
		"No unhooked calls known.",
		"Hosted tools (such as web search) and hook opt-outs are outside coverage. Input typed into running commands (write_stdin) is not hooked; commands with a terminal are denied, and others get no stdin.",
		"Internal sql/session_store_sql queries are checked conservatively and refused when file access is possible (ATTACH, read_csv, quoted paths).",
		"Cloud-agent MCP calls lack beforeMCPExecution. Events that fire no hook, such as AskQuestion, are outside coverage.",
		"No unhooked calls known; another plugin can alter arguments after the check."},
	{"Subagents",
		"Hooked.",
		"Hooked.",
		"Hooked.",
		"Task passes; subagent calls are checked.",
		"Hooked with separate sessionID."},
	{"Tripwire",
		"Per session_id.",
		"Per session_id; converted asks do not count.",
		"Per sessionId.",
		"Per conversation_id; converted asks do not count.",
		"Per sessionID; subagents count separately."},
	{"Session briefing",
		"SessionStart additionalContext for startup, resume, clear and compact.",
		"SessionStart additionalContext; invocation verified, delivery of briefing text unverified.",
		"sessionStart additionalContext; delivery verified.",
		"sessionStart additional_context in editor/CLI; unavailable in cloud agents.",
		"System prompt through experimental.chat.system.transform; delivery verified."},
	{"Hook execution failure",
		"Claude Code 2.1.295+ blocks missing binary, crash and timeout with onFailure: block. Earlier versions may fail open; native deny/ask fallback covers translatable literal file, command and MCP rules.",
		"Can fail open. Managed prefix_rules cover translatable literal command rules.",
		"Timeout or invalid output can fail open. Crashes/other exits deny; no native fallback.",
		"failClosed blocks crashes/timeouts; invalid output also blocks.",
		"Plugin denies missing binary, crash, timeout and unexpected answers. Plugin-load failure or --pure skips enforcement."},
	{"Configuration guards",
		"Guards settings, policy, key, audit and binary (builtin.guarded), plus native Edit denies. Indirect writes by launched programs and branch switches remain possible.",
		"Guards hooks.json/config.toml under CODEX_HOME/project, /etc/codex and shared policy/key/audit/binary paths; indirect-write gaps remain.",
		"Guards COPILOT_HOME or ~/.copilot, repository .github/hooks and .github/copilot, /etc/github-copilot/policy.d and shared protected paths; indirect-write gaps remain.",
		"Guards user/workspace/machine hooks and scripts, cli-config.json, editor user settings, Claude settings and shared protected paths; indirect-write gaps remain.",
		"Guards XDG config/cache, ~/.opencode, project .opencode, opencode.json(c)/tui.json(c), environment-selected config, /etc/opencode and shared protected paths; indirect-write gaps remain."},
	{"Trust before activation",
		"Not required.",
		"User/project hooks require trust in /hooks. Managed hooks do not.",
		"Not required.",
		"Not required.",
		"Not required."},
	{"Managed locking",
		"Managed settings with allowManagedHooksOnly (Team/Enterprise, MDM). Other scopes are advisory.",
		"requirements.toml with allow_managed_hooks_only. Other scopes are advisory.",
		"Root-owned /etc/github-copilot/policy.d, unaffected by disableAllHooks. Other scopes are advisory.",
		"Machine-wide root-owned hooks run before user hooks. apply cannot configure dashboard team hooks; other scopes are advisory.",
		"No CyberBoar managed scope. --pure/OPENCODE_PURE=1 skips plugins; configuration is advisory outside OpenCode Console controls."},
	{"Network egress",
		"Not governed.",
		"Not governed.",
		"Not governed.",
		"Not governed.",
		"Not governed."},
}

// WriteMatrix renders the matrix as a Markdown table
func WriteMatrix(w io.Writer) error {
	cell := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
	if _, err := fmt.Fprintln(w, "| Capability | Claude Code | Codex CLI | Copilot CLI | Cursor | opencode |\n|---|---|---|---|---|---|"); err != nil {
		return err
	}
	for _, c := range Matrix {
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", cell(c.What), cell(c.ClaudeCode), cell(c.Codex), cell(c.Copilot), cell(c.Cursor), cell(c.Opencode)); err != nil {
			return err
		}
	}
	return nil
}
