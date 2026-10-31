package adapters_test

import (
	"fmt"
	"io"
	"strings"
)

// Agent is one column of the capability matrix and one section below it.
type Agent struct {
	Name string
	// Links points to the agent's setup and limitations in other documents.
	Links string
}

// Agents are the matrix's columns, in the order of Capability.Cells.
var Agents = [...]Agent{
	{"Claude Code", "[Setup](agents.md#claude-code), [extension](editor-integrations.md#claude-code-extension), [PowerShell](powershell.md)"},
	{"Codex CLI", "[Setup](agents.md#codex-cli), [Windows](agents.md#codex-on-windows), [extension](editor-integrations.md#codex-extension), [PowerShell](powershell.md)"},
	{"GitHub Copilot (CLI, VS Code)", "[Setup](agents.md#github-copilot-cli), [VS Code](editor-integrations.md#copilot-in-vs-code)"},
	{"Cursor", "[Setup](agents.md#cursor), [editor](editor-integrations.md#cursor-editor)"},
	{"opencode", "[Setup](agents.md#opencode), [extension](editor-integrations.md#opencode-extension)"},
}

// Cell is what one agent's adapter does for one capability. Short goes in
// the table. Detail, if the short form leaves anything out, is the whole
// statement and goes in the agent's section.
type Cell struct {
	Short, Detail string
}

// Capability is one row of the capability matrix: what each agent adapter
// can and can't enforce. Maintainers describe the tested behavior and known
// limitations here; docs/capability-matrix.md is generated from this prose.
type Capability struct {
	What  string
	Cells [len(Agents)]Cell
}

// Matrix is the capability matrix. Keep it in step with the adapters and
// their case files; docs/capability-matrix.md is generated from it.
var Matrix = []Capability{
	{"Validated with", [...]Cell{
		{"2.1.220, real agent.", "Claude Code 2.1.220: captured inputs and real-agent harness."},
		{"0.155 and 0.163, scripted model.", "Codex 0.155: captured inputs and real denied reads and writes; the scripted-model integration harness passed at 0.155 and 0.163."},
		{"CLI 1.0.97 and 1.0.98, local model; VS Code 1.142, scripted model.", "Copilot CLI: captured inputs and schema at 1.0.91, tool list at 1.0.97; the local-model integration harness passed at 1.0.97 and 1.0.98. " +
			"VS Code 1.142 with Copilot Chat 0.70: the Copilot target runs the CLI runtime (captured inputs); the Local agent has captured inputs and tool list, and a scripted-model run checked its decisions."},
		{"CLI 2026.10.14, real agent. Editor: not yet.", "Cursor CLI 2026.10.14: captured inputs and real-agent harness. Cursor editor 3.13: documentation and captured payloads; real-agent validation is pending."},
		{"1.19.0, local model.", "opencode: captured plugin inputs and schema at 1.18.34; the local-model integration harness passed at 1.19.0."},
	}},
	{"Native Windows", [...]Cell{
		{"Yes: Bash (Git Bash) and PowerShell tools.", "The Bash tool with Git Bash, and the PowerShell tool, which is the only shell without Git Bash. Mount-aware Windows path checks cover drives, trailing dots, streams, junctions and 8.3 names; UNC and device paths deny. " +
			"Local-scope real-agent testing does not cover every CPU or managed configuration; the PowerShell tool's real-agent testing is limited."},
		{"Yes: PowerShell. User and managed scope.", "PowerShell, with the same Windows path checks; the user's PowerShell profiles run and are guarded. User and managed scope; project scope is not supported. Real-agent testing is limited."},
		{"No: use WSL or a Linux container.", "Denied; use WSL or a Linux container (in VS Code, open the folder there)."},
		{"No: use WSL, Remote-WSL or a Linux container.", ""},
		{"No: use WSL or a Linux container.", ""},
	}},
	{"Native file tools", [...]Cell{
		{"All built-in file tools.", "Read, Write, Edit, MultiEdit, NotebookEdit, Grep, Glob, LS and the file-upload tools."},
		{"apply_patch, view_image; other reads go through the shell.", "apply_patch (every changed path) and view_image. Reads otherwise use shell tools."},
		{"CLI and VS Code Local file tools.", "view, create, edit, str_replace_editor, apply_patch (every changed path), grep, rg and glob. " +
			"VS Code Local: read_file, list_dir, view_image, create_file, replace_string_in_file, multi_replace_string_in_file, insert_edit_into_file, apply_patch, create_directory and the notebook tools; grep_search, semantic_search and the symbol searches check the whole workspace. " +
			"A file: URI in a path is read as its path; other URIs are refused."},
		{"Read, Write, Delete, Grep, attachments, Tab reads.", "Read, Write, Delete and Grep through preToolUse; path fields are matched loosely, and a missing path denies. beforeReadFile covers prompt attachments; beforeTabFileRead covers Tab reads."},
		{"read, write, edit, apply_patch, grep, glob.", "read, write, edit, apply_patch (every changed path), grep and glob."},
	}},
	{"Shell file rules", [...]Cell{
		{"Best effort.", ""},
		{"Best effort; directory from the transcript.", "Best effort. The working directory is recovered from the session transcript; code mode requires plain literal tool calls. Missing or unmatched calls deny."},
		{"Best effort; some relative paths ask.", "Best effort. Each call starts in the session directory and keeps no cd or variables; relative paths in reused shells (shellId) ask, since such a shell starts where it was created. " +
			"VS Code Local: the agent terminal persists and its directory is not reported, so relative paths ask unless the command starts with an absolute cd; the terminal is read as bash or zsh."},
		{"Best effort; some relative paths deny.", "Best effort. The agent shell persists between calls; a call without a working directory leaves relative paths unknown (ask, so denied) unless the command starts with an absolute cd. " +
			"HOME, glob options and aliases from earlier calls are treated as unknown. Shells outside bash, sh, dash and zsh are foreign code."},
		{"Best effort, in the call's workdir.", ""},
	}},
	{"Command rules", [...]Cell{
		{"Bash; PowerShell on native Windows.", "Parsed Bash. On native Windows the PowerShell tool's commands are parsed PowerShell (a checked subset); elsewhere that tool is denied (builtin.powershell)."},
		{"Bash; PowerShell on native Windows.", "Parsed Bash; the shell the model selected is recovered from the transcript. Shells outside bash, sh, dash and zsh are foreign code. " +
			"On native Windows commands are parsed PowerShell (a checked subset), and other shells deny (adapter.windowsShell)."},
		{"Bash; PowerShell is foreign code.", "Parsed Bash; the powershell tool is foreign code. " +
			"VS Code Local: run_in_terminal and create_and_run_task commands; a task must run in the hook's workspace folder, and a task with arguments may hold only plain words, since VS Code quotes them."},
		{"Bash.", "Parsed Bash, through preToolUse and beforeShellExecution."},
		{"Bash; other shells are foreign code.", "Parsed Bash; the configuration, $SHELL or the Bash default selects the shell. Shells outside bash, sh, dash and zsh are foreign code."},
	}},
	{"MCP rules", [...]Cell{
		{"Server name from the hook input.", "The server name comes from the hook input; deny and ask rules also match names with characters outside A-Z, a-z, 0-9, _ and - written as _."},
		{"Every server/tool split of the name.", "Every possible server/tool split of the name is checked; deny and ask rules also match Codex's rewritten names (characters outside A-Z, a-z, 0-9 and _ as _, hash suffixes). Resource access maps to its server."},
		{"Every split; VS Code Local matches by tool.", "Every possible server/tool split of the name is checked; deny and ask rules also match Copilot's rewritten names (punctuation as -, punycode, a 64-character cut). " +
			"VS Code Local names tools `mcp_<label>_<tool>` with a label the server reports, cut at 64 characters: deny and ask rules match the tool of any server (a whole-server deny covers every VS Code MCP tool), and only `*/tool` allow rules cover a call. " +
			"A cut name matches deny and ask rules whose tool could start with it, and only allow rules whose tool pattern ends in `*`."},
		{"Server name from beforeMCPExecution.", "beforeMCPExecution, the event that supplies the server name."},
		{"Configured server names.", "Configured server names and every possible split; resource calls map to a known server, or to every server when ambiguous."},
	}},
	{"ask", [...]Cell{
		{"Asks the user.", ""},
		{"Denies.", "Converted to deny: a hook's ask would let the tool run."},
		{"Asks the user; headless (-p) denies.", "Native confirmation in Copilot CLI and VS Code; headless (-p) denies."},
		{"Denies.", "Converted to deny: a preToolUse ask would let the tool run."},
		{"Denies.", "Converted to deny: plugins can't ask for confirmation."},
	}},
	{"Unclassified tools", [...]Cell{
		{"Denied.", ""},
		{"Denied.", "Denied, including code-mode exec and plugin installation. write_stdin is not hooked, so commands that ask for a terminal (tty) are denied."},
		{"Denied.", "Denied, including write_bash, write_powershell and unknown tools. " +
			"VS Code Local: extension tools are denied, but one named `mcp_…` is checked as an MCP tool; send_to_terminal, run_task, runTests, run_notebook_cell, run_vscode_command, install_extension, run_playwright_code and vscode_renameSymbol are denied (adapter.uncheckedTool)."},
		{"Denied.", "Denied outside Shell, Read, Write, Delete, Grep, Task and MCP."},
		{"Denied.", "Denied, including custom tools, experimental lsp and code-mode execute."},
	}},
	{"Calls the hook doesn't see", [...]Cell{
		{"None known.", "No unhooked calls are known. A call that one of apply's native deny rules blocks never reaches the hook, so it leaves no audit event and no tripwire count."},
		{"Hosted tools, input to running commands.", "Hosted tools (such as web search) and hook opt-outs are outside coverage. Input typed into running commands (write_stdin) is not hooked; commands with a terminal are denied, and others get no stdin."},
		{"VS Code memory, other workspace folders.", "Internal sql and session_store_sql queries are checked conservatively and refused when file access is possible (ATTACH, read_csv, quoted paths). VS Code's memory files live in its own storage and are not governed. " +
			"VS Code's hook input names only the folder the hook runs in: in a multi-root workspace, workspace-wide searches are checked against that folder only and other folders' settings are not guarded. " +
			"terminal_last_command and terminal_selection may return output of commands the user typed; insert_edit_into_file is checked for secrets in its sketch, not the text another model writes from it."},
		{"Cloud-agent MCP calls, events without hooks.", "Cloud-agent MCP calls lack beforeMCPExecution. Events that fire no hook, such as AskQuestion, are outside coverage."},
		{"None known.", "No unhooked calls are known; another plugin can change the arguments after the check."},
	}},
	{"Subagents", [...]Cell{
		{"Checked.", ""},
		{"Checked.", ""},
		{"Checked.", ""},
		{"Checked.", "Task passes; the subagent's calls are checked."},
		{"Checked, as their own session.", "Checked, with a separate sessionID."},
	}},
	{"Tripwire counts", [...]Cell{
		{"Per session.", "Per session_id."},
		{"Per session; converted asks don't count.", "Per session_id; asks converted to deny don't count."},
		{"Per session.", "Per sessionId (VS Code: session_id)."},
		{"Per conversation; converted asks don't count.", "Per conversation_id; asks converted to deny don't count."},
		{"Per session; subagents separately.", "Per sessionID; subagents count separately."},
	}},
	{"Session briefing", [...]Cell{
		{"Delivered.", "SessionStart additionalContext for startup, resume, clear and compact."},
		{"Runs; delivery unverified.", "SessionStart additionalContext; the hook is invoked, but delivery of the briefing text is unverified."},
		{"Delivered.", "sessionStart additionalContext; delivery verified in Copilot CLI and VS Code's Local agent."},
		{"Editor and CLI; not cloud agents.", "sessionStart additional_context in the editor and CLI; unavailable in cloud agents."},
		{"Delivered.", "In the system prompt, through experimental.chat.system.transform; delivery verified."},
	}},
	{"Hook failure", [...]Cell{
		{"Blocks, from 2.1.295.", "Claude Code 2.1.295 and later blocks the call on a missing binary, a crash and a timeout (onFailure: block). Earlier versions may fail open; the native deny and ask rules apply writes cover translatable literal file, command and MCP rules."},
		{"Can fail open.", "Can fail open. Managed prefix_rules cover translatable literal command rules."},
		{"A timeout can fail open.", "A timeout or invalid output can fail open. Crashes and other exits deny; there is no native fallback. " +
			"VS Code lets a tool run on a timeout or an exit other than 0 and 2, so the installed command ends in `|| exit 2`: a missing binary or a crash denies."},
		{"Blocks.", "failClosed blocks crashes and timeouts; invalid output also blocks."},
		{"Blocks, unless the plugin fails to load.", "The plugin denies a missing binary, a crash, a timeout and unexpected answers. A plugin that fails to load, or --pure, skips enforcement."},
	}},
	{"Configuration guards", [...]Cell{
		{"Settings, plugins, agents, skills, commands.", "Guards the settings, installed plugins, and custom agents, skills and commands (.claude/agents, .claude/skills and .claude/commands in ~/.claude, CLAUDE_CONFIG_DIR, the project and every folder above it up to its git work tree), whose hooks Claude Code runs; " +
			"shell startup files; and the policy, key, audit log and binary (builtin.guarded). Native Edit denies cover these folders at any depth too. " +
			"Gaps: shell writes to .claude/skills or .claude/commands below the project, folders added with --add-dir or /add-dir, indirect writes by launched programs, and branch switches."},
		{"hooks.json, config.toml, transcripts.", "Guards hooks.json and config.toml under CODEX_HOME and the project, /etc/codex (Windows: %ProgramData%\\OpenAI\\Codex), session transcripts, shell startup files, on Windows the PowerShell profile and module folders, and the shared policy, key, audit and binary paths. Indirect writes remain a gap."},
		{"Hook files, settings, custom agents.", "Guards COPILOT_HOME or ~/.copilot; .github/hooks, .github/copilot and VS Code's workspace settings in the session's folder and every folder up to its git work tree; /etc/github-copilot/policy.d; " +
			"the user settings of every profile and remote machine settings, Codespaces' included (chat.useHooks, chat.hookFilesLocations); Claude settings (chat.useClaudeHooks); custom agents (.github/agents, .claude/agents, ~/.copilot/agents, ~/.claude/agents) and agent plugins, whose hooks VS Code runs; " +
			"shell startup files; and the shared protected paths. Gaps: *.code-workspace files, .vscode/mcp.json, agent locations added with chat.agentFilesLocations, and indirect writes."},
		{"Hooks, CLI and editor settings.", "Guards user, workspace and machine hooks and their scripts, cli-config.json, the editor's user settings, Claude settings, shell startup files and the shared protected paths. Indirect writes remain a gap."},
		{"opencode configuration and plugins.", "Guards the XDG config and cache, ~/.opencode, the project's .opencode, opencode.json(c) and tui.json(c), configuration that environment variables select, /etc/opencode, shell startup files and the shared protected paths. Indirect writes remain a gap."},
	}},
	{"Trust before hooks run", [...]Cell{
		{"Not needed.", ""},
		{"Needed, except managed hooks.", "User and project hooks need trust in /hooks; managed hooks don't."},
		{"CLI: not needed. VS Code: trusted workspace.", "Not needed in Copilot CLI. VS Code runs workspace hooks only in a trusted workspace."},
		{"Not needed.", ""},
		{"Not needed.", ""},
	}},
	{"Managed locking", [...]Cell{
		{"allowManagedHooksOnly.", "Managed settings with allowManagedHooksOnly (Team or Enterprise, MDM). Other scopes are advisory."},
		{"allow_managed_hooks_only.", "requirements.toml with allow_managed_hooks_only. Other scopes are advisory."},
		{"Root-owned policy.d; not VS Code Local.", "The root-owned /etc/github-copilot/policy.d, which disableAllHooks doesn't affect; VS Code's Local agent reads neither it nor a user hook under COPILOT_HOME. Other scopes are advisory."},
		{"Machine-wide hooks.", "Machine-wide root-owned hooks run before user hooks. apply can't configure dashboard team hooks; other scopes are advisory."},
		{"None.", "No CyberBoar managed scope. --pure and OPENCODE_PURE=1 skip plugins; configuration is advisory outside OpenCode Console controls."},
	}},
	{"Network egress", [...]Cell{
		{"Not governed.", ""},
		{"Not governed.", ""},
		{"Not governed.", ""},
		{"Not governed.", ""},
		{"Not governed.", ""},
	}},
}

// WriteMatrix renders the matrix as a Markdown table, followed by each
// agent's section with the details the table leaves out.
func WriteMatrix(w io.Writer) error {
	cell := func(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
	var b strings.Builder
	b.WriteString("| Capability |")
	for _, a := range Agents {
		b.WriteString(" " + a.Name + " |")
	}
	b.WriteString("\n|---|" + strings.Repeat("---|", len(Agents)) + "\n")
	for _, c := range Matrix {
		b.WriteString("| " + cell(c.What) + " |")
		for _, x := range c.Cells {
			b.WriteString(" " + cell(x.Short) + " |")
		}
		b.WriteString("\n")
	}
	for i, a := range Agents {
		fmt.Fprintf(&b, "\n## %s\n\n%s.\n\n", a.Name, a.Links)
		for _, c := range Matrix {
			if d := c.Cells[i].Detail; d != "" {
				fmt.Fprintf(&b, "- **%s:** %s\n", c.What, d)
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
