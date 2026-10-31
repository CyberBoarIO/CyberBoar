# Capability matrix

Coverage for tool calls that reach each adapter. File checks through shell commands
are best effort on the command's arguments: what a launched program opens itself is not
seen, and CyberBoar is not an OS sandbox. See [Agent setup](agents.md) for installation
and [Security model](security-model.md) for shared limitations.

The table compares the agents at a glance. Each agent's section below it holds what
the table leaves out: tool names, versions, guarded paths and known gaps.

This reference is generated from `internal/adapters/matrix_data_test.go` with
`go test ./internal/adapters -update`; edit the source rather than this page.

| Capability | Claude Code | Codex CLI | GitHub Copilot (CLI, VS Code) | Cursor | opencode |
|---|---|---|---|---|---|
| Validated with | 2.1.220, real agent. | 0.155 and 0.163, scripted model. | CLI 1.0.97 and 1.0.98, local model; VS Code 1.142, scripted model. | CLI 2026.10.14, real agent. Editor: not yet. | 1.19.0, local model. |
| Native Windows | Yes: Bash (Git Bash) and PowerShell tools. | Yes: PowerShell. User and managed scope. | No: use WSL or a Linux container. | No: use WSL, Remote-WSL or a Linux container. | No: use WSL or a Linux container. |
| Native file tools | All built-in file tools. | apply_patch, view_image; other reads go through the shell. | CLI and VS Code Local file tools. | Read, Write, Delete, Grep, attachments, Tab reads. | read, write, edit, apply_patch, grep, glob. |
| Shell file rules | Best effort. | Best effort; directory from the transcript. | Best effort; some relative paths ask. | Best effort; some relative paths deny. | Best effort, in the call's workdir. |
| Command rules | Bash; PowerShell on native Windows. | Bash; PowerShell on native Windows. | Bash; PowerShell is foreign code. | Bash. | Bash; other shells are foreign code. |
| MCP rules | Server name from the hook input. | Every server/tool split of the name. | Every split; VS Code Local matches by tool. | Server name from beforeMCPExecution. | Configured server names. |
| ask | Asks the user. | Denies. | Asks the user; headless (-p) denies. | Denies. | Denies. |
| Unclassified tools | Denied. | Denied. | Denied. | Denied. | Denied. |
| Calls the hook doesn't see | None known. | Hosted tools, input to running commands. | VS Code memory, other workspace folders. | Cloud-agent MCP calls, events without hooks. | None known. |
| Subagents | Checked. | Checked. | Checked. | Checked. | Checked, as their own session. |
| Tripwire counts | Per session. | Per session; converted asks don't count. | Per session. | Per conversation; converted asks don't count. | Per session; subagents separately. |
| Session briefing | Delivered. | Runs; delivery unverified. | Delivered. | Editor and CLI; not cloud agents. | Delivered. |
| Hook failure | Blocks, from 2.1.295. | Can fail open. | A timeout can fail open. | Blocks. | Blocks, unless the plugin fails to load. |
| Configuration guards | Settings, plugins, agents, skills, commands. | hooks.json, config.toml, transcripts. | Hook files, settings, custom agents. | Hooks, CLI and editor settings. | opencode configuration and plugins. |
| Trust before hooks run | Not needed. | Needed, except managed hooks. | CLI: not needed. VS Code: trusted workspace. | Not needed. | Not needed. |
| Managed locking | allowManagedHooksOnly. | allow_managed_hooks_only. | Root-owned policy.d; not VS Code Local. | Machine-wide hooks. | None. |
| Network egress | Not governed. | Not governed. | Not governed. | Not governed. | Not governed. |

## Claude Code

[Setup](agents.md#claude-code), [extension](editor-integrations.md#claude-code-extension), [PowerShell](powershell.md).

- **Validated with:** Claude Code 2.1.220: captured inputs and real-agent harness.
- **Native Windows:** The Bash tool with Git Bash, and the PowerShell tool, which is the only shell without Git Bash. Mount-aware Windows path checks cover drives, trailing dots, streams, junctions and 8.3 names; UNC and device paths deny. Local-scope real-agent testing does not cover every CPU or managed configuration; the PowerShell tool's real-agent testing is limited.
- **Native file tools:** Read, Write, Edit, MultiEdit, NotebookEdit, Grep, Glob, LS and the file-upload tools.
- **Command rules:** Parsed Bash. On native Windows the PowerShell tool's commands are parsed PowerShell (a checked subset); elsewhere that tool is denied (builtin.powershell).
- **MCP rules:** The server name comes from the hook input; deny and ask rules also match names with characters outside A-Z, a-z, 0-9, _ and - written as _.
- **Calls the hook doesn't see:** No unhooked calls are known. A call that one of apply's native deny rules blocks never reaches the hook, so it leaves no audit event and no tripwire count.
- **Tripwire counts:** Per session_id.
- **Session briefing:** SessionStart additionalContext for startup, resume, clear and compact.
- **Hook failure:** Claude Code 2.1.295 and later blocks the call on a missing binary, a crash and a timeout (onFailure: block). Earlier versions may fail open; the native deny and ask rules apply writes cover translatable literal file, command and MCP rules.
- **Configuration guards:** Guards the settings, installed plugins, and custom agents, skills and commands (.claude/agents, .claude/skills and .claude/commands in ~/.claude, CLAUDE_CONFIG_DIR, the project and every folder above it up to its git work tree), whose hooks Claude Code runs; shell startup files; and the policy, key, audit log and binary (builtin.guarded). Native Edit denies cover these folders at any depth too. Gaps: shell writes to .claude/skills or .claude/commands below the project, folders added with --add-dir or /add-dir, indirect writes by launched programs, and branch switches.
- **Managed locking:** Managed settings with allowManagedHooksOnly (Team or Enterprise, MDM). Other scopes are advisory.

## Codex CLI

[Setup](agents.md#codex-cli), [Windows](agents.md#codex-on-windows), [extension](editor-integrations.md#codex-extension), [PowerShell](powershell.md).

- **Validated with:** Codex 0.155: captured inputs and real denied reads and writes; the scripted-model integration harness passed at 0.155 and 0.163.
- **Native Windows:** PowerShell, with the same Windows path checks; the user's PowerShell profiles run and are guarded. User and managed scope; project scope is not supported. Real-agent testing is limited.
- **Native file tools:** apply_patch (every changed path) and view_image. Reads otherwise use shell tools.
- **Shell file rules:** Best effort. The working directory is recovered from the session transcript; code mode requires plain literal tool calls. Missing or unmatched calls deny.
- **Command rules:** Parsed Bash; the shell the model selected is recovered from the transcript. Shells outside bash, sh, dash and zsh are foreign code. On native Windows commands are parsed PowerShell (a checked subset), and other shells deny (adapter.windowsShell).
- **MCP rules:** Every possible server/tool split of the name is checked; deny and ask rules also match Codex's rewritten names (characters outside A-Z, a-z, 0-9 and _ as _, hash suffixes). Resource access maps to its server.
- **ask:** Converted to deny: a hook's ask would let the tool run.
- **Unclassified tools:** Denied, including code-mode exec and plugin installation. write_stdin is not hooked, so commands that ask for a terminal (tty) are denied.
- **Calls the hook doesn't see:** Hosted tools (such as web search) and hook opt-outs are outside coverage. Input typed into running commands (write_stdin) is not hooked; commands with a terminal are denied, and others get no stdin.
- **Tripwire counts:** Per session_id; asks converted to deny don't count.
- **Session briefing:** SessionStart additionalContext; the hook is invoked, but delivery of the briefing text is unverified.
- **Hook failure:** Can fail open. Managed prefix_rules cover translatable literal command rules.
- **Configuration guards:** Guards hooks.json and config.toml under CODEX_HOME and the project, /etc/codex (Windows: %ProgramData%\OpenAI\Codex), session transcripts, shell startup files, on Windows the PowerShell profile and module folders, and the shared policy, key, audit and binary paths. Indirect writes remain a gap.
- **Trust before hooks run:** User and project hooks need trust in /hooks; managed hooks don't.
- **Managed locking:** requirements.toml with allow_managed_hooks_only. Other scopes are advisory.

## GitHub Copilot (CLI, VS Code)

[Setup](agents.md#github-copilot-cli), [VS Code](editor-integrations.md#copilot-in-vs-code).

- **Validated with:** Copilot CLI: captured inputs and schema at 1.0.91, tool list at 1.0.97; the local-model integration harness passed at 1.0.97 and 1.0.98. VS Code 1.142 with Copilot Chat 0.70: the Copilot target runs the CLI runtime (captured inputs); the Local agent has captured inputs and tool list, and a scripted-model run checked its decisions.
- **Native Windows:** Denied; use WSL or a Linux container (in VS Code, open the folder there).
- **Native file tools:** view, create, edit, str_replace_editor, apply_patch (every changed path), grep, rg and glob. VS Code Local: read_file, list_dir, view_image, create_file, replace_string_in_file, multi_replace_string_in_file, insert_edit_into_file, apply_patch, create_directory and the notebook tools; grep_search, semantic_search and the symbol searches check the whole workspace. A file: URI in a path is read as its path; other URIs are refused.
- **Shell file rules:** Best effort. Each call starts in the session directory and keeps no cd or variables; relative paths in reused shells (shellId) ask, since such a shell starts where it was created. VS Code Local: the agent terminal persists and its directory is not reported, so relative paths ask unless the command starts with an absolute cd; the terminal is read as bash or zsh.
- **Command rules:** Parsed Bash; the powershell tool is foreign code. VS Code Local: run_in_terminal and create_and_run_task commands; a task must run in the hook's workspace folder, and a task with arguments may hold only plain words, since VS Code quotes them.
- **MCP rules:** Every possible server/tool split of the name is checked; deny and ask rules also match Copilot's rewritten names (punctuation as -, punycode, a 64-character cut). VS Code Local names tools `mcp_<label>_<tool>` with a label the server reports, cut at 64 characters: deny and ask rules match the tool of any server (a whole-server deny covers every VS Code MCP tool), and only `*/tool` allow rules cover a call. A cut name matches deny and ask rules whose tool could start with it, and only allow rules whose tool pattern ends in `*`.
- **ask:** Native confirmation in Copilot CLI and VS Code; headless (-p) denies.
- **Unclassified tools:** Denied, including write_bash, write_powershell and unknown tools. VS Code Local: extension tools are denied, but one named `mcp_…` is checked as an MCP tool; send_to_terminal, run_task, runTests, run_notebook_cell, run_vscode_command, install_extension, run_playwright_code and vscode_renameSymbol are denied (adapter.uncheckedTool).
- **Calls the hook doesn't see:** Internal sql and session_store_sql queries are checked conservatively and refused when file access is possible (ATTACH, read_csv, quoted paths). VS Code's memory files live in its own storage and are not governed. VS Code's hook input names only the folder the hook runs in: in a multi-root workspace, workspace-wide searches are checked against that folder only and other folders' settings are not guarded. terminal_last_command and terminal_selection may return output of commands the user typed; insert_edit_into_file is checked for secrets in its sketch, not the text another model writes from it.
- **Tripwire counts:** Per sessionId (VS Code: session_id).
- **Session briefing:** sessionStart additionalContext; delivery verified in Copilot CLI and VS Code's Local agent.
- **Hook failure:** A timeout or invalid output can fail open. Crashes and other exits deny; there is no native fallback. VS Code lets a tool run on a timeout or an exit other than 0 and 2, so the installed command ends in `|| exit 2`: a missing binary or a crash denies.
- **Configuration guards:** Guards COPILOT_HOME or ~/.copilot; .github/hooks, .github/copilot and VS Code's workspace settings in the session's folder and every folder up to its git work tree; /etc/github-copilot/policy.d; the user settings of every profile and remote machine settings, Codespaces' included (chat.useHooks, chat.hookFilesLocations); Claude settings (chat.useClaudeHooks); custom agents (.github/agents, .claude/agents, ~/.copilot/agents, ~/.claude/agents) and agent plugins, whose hooks VS Code runs; shell startup files; and the shared protected paths. Gaps: *.code-workspace files, .vscode/mcp.json, agent locations added with chat.agentFilesLocations, and indirect writes.
- **Trust before hooks run:** Not needed in Copilot CLI. VS Code runs workspace hooks only in a trusted workspace.
- **Managed locking:** The root-owned /etc/github-copilot/policy.d, which disableAllHooks doesn't affect; VS Code's Local agent reads neither it nor a user hook under COPILOT_HOME. Other scopes are advisory.

## Cursor

[Setup](agents.md#cursor), [editor](editor-integrations.md#cursor-editor).

- **Validated with:** Cursor CLI 2026.10.14: captured inputs and real-agent harness. Cursor editor 3.13: documentation and captured payloads; real-agent validation is pending.
- **Native file tools:** Read, Write, Delete and Grep through preToolUse; path fields are matched loosely, and a missing path denies. beforeReadFile covers prompt attachments; beforeTabFileRead covers Tab reads.
- **Shell file rules:** Best effort. The agent shell persists between calls; a call without a working directory leaves relative paths unknown (ask, so denied) unless the command starts with an absolute cd. HOME, glob options and aliases from earlier calls are treated as unknown. Shells outside bash, sh, dash and zsh are foreign code.
- **Command rules:** Parsed Bash, through preToolUse and beforeShellExecution.
- **MCP rules:** beforeMCPExecution, the event that supplies the server name.
- **ask:** Converted to deny: a preToolUse ask would let the tool run.
- **Unclassified tools:** Denied outside Shell, Read, Write, Delete, Grep, Task and MCP.
- **Calls the hook doesn't see:** Cloud-agent MCP calls lack beforeMCPExecution. Events that fire no hook, such as AskQuestion, are outside coverage.
- **Subagents:** Task passes; the subagent's calls are checked.
- **Tripwire counts:** Per conversation_id; asks converted to deny don't count.
- **Session briefing:** sessionStart additional_context in the editor and CLI; unavailable in cloud agents.
- **Hook failure:** failClosed blocks crashes and timeouts; invalid output also blocks.
- **Configuration guards:** Guards user, workspace and machine hooks and their scripts, cli-config.json, the editor's user settings, Claude settings, shell startup files and the shared protected paths. Indirect writes remain a gap.
- **Managed locking:** Machine-wide root-owned hooks run before user hooks. apply can't configure dashboard team hooks; other scopes are advisory.

## opencode

[Setup](agents.md#opencode), [extension](editor-integrations.md#opencode-extension).

- **Validated with:** opencode: captured plugin inputs and schema at 1.18.34; the local-model integration harness passed at 1.19.0.
- **Native file tools:** read, write, edit, apply_patch (every changed path), grep and glob.
- **Command rules:** Parsed Bash; the configuration, $SHELL or the Bash default selects the shell. Shells outside bash, sh, dash and zsh are foreign code.
- **MCP rules:** Configured server names and every possible split; resource calls map to a known server, or to every server when ambiguous.
- **ask:** Converted to deny: plugins can't ask for confirmation.
- **Unclassified tools:** Denied, including custom tools, experimental lsp and code-mode execute.
- **Calls the hook doesn't see:** No unhooked calls are known; another plugin can change the arguments after the check.
- **Subagents:** Checked, with a separate sessionID.
- **Tripwire counts:** Per sessionID; subagents count separately.
- **Session briefing:** In the system prompt, through experimental.chat.system.transform; delivery verified.
- **Hook failure:** The plugin denies a missing binary, a crash, a timeout and unexpected answers. A plugin that fails to load, or --pure, skips enforcement.
- **Configuration guards:** Guards the XDG config and cache, ~/.opencode, the project's .opencode, opencode.json(c) and tui.json(c), configuration that environment variables select, /etc/opencode, shell startup files and the shared protected paths. Indirect writes remain a gap.
- **Managed locking:** No CyberBoar managed scope. --pure and OPENCODE_PURE=1 skip plugins; configuration is advisory outside OpenCode Console controls.
