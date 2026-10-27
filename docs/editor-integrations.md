# Editor integrations

CyberBoar supports the official Claude Code, Codex and opencode editor extensions,
the Cursor editor, and GitHub Copilot in VS Code: both its Copilot session target and
its Local agent. These integrations reuse the agents' existing hooks or plugins;
CyberBoar runs in the agent's execution environment, not as a VS Code extension of
its own.

**Active testing:** Copilot in VS Code has been verified end to end from editor
sessions; the other editor integrations are under active testing. This support status
is not a claim that every editor tool, version or platform has been verified:
CLI/runtime tests do not establish editor-session coverage. Confirm an allowed and a
policy-denied tool call from the editor before relying on a setup.
See the [capability matrix](capability-matrix.md) for tested versions and limitations.

## Choose the integration

| Agent surface | Extension or editor | Support status | CyberBoar configuration |
|---|---|---|---|
| Claude Code | `anthropic.claude-code` | Supported; active testing | `--agent claude-code`; existing `.claude/settings.json` or `.claude/settings.local.json` |
| Codex | `openai.chatgpt` | Supported; active testing | `--agent codex`; existing `.codex/hooks.json` |
| opencode | `sst-dev.opencode` | Supported; active testing | `--agent opencode`; existing `.opencode/plugin/cyberboar.js` |
| Cursor | Cursor editor, not a separate VS Code extension | Supported; real-agent validation pending | `--agent cursor`; existing `.cursor/hooks.json` |
| Copilot in VS Code, Copilot session target | GitHub Copilot Chat, built into VS Code | Supported; validated with VS Code 1.142 | `--agent copilot-cli`; `.github/hooks/cyberboar.json` |
| Copilot in VS Code, Local agent | GitHub Copilot Chat, built into VS Code | Supported; validated with VS Code 1.142 | `--agent copilot-cli`; the same `.github/hooks/cyberboar.json` |

Selecting a Claude or OpenAI **model** in Copilot does not select the Claude Code or
Codex runtime. Choose the actual extension/session target. VS Code documents these
differences in [Choose the hook implementation for your
session](https://code.visualstudio.com/docs/agent-customization/hooks#choose-the-hook-implementation-for-your-session).

## Keep execution and configuration together

Install the binary, policy and hook configuration where the agent executes. With
WSL, Remote-SSH or a dev container, this may be the remote Linux environment rather
than the desktop host. A host path such as `C:\Users\...` is not a Linux policy path.

Use the Linux binary inside WSL or a Linux container. Native Windows support covers
Claude Code (Git Bash and its PowerShell tool) and Codex CLI; see [system
requirements](system-requirements.md) and [PowerShell support](powershell.md). Opening
an editor on Windows does not make its other agents run natively there.

GUI extensions may inherit a different `PATH` from your terminal. The examples below
pin the binary's absolute path with `--command`. Do not point them at a temporary
build you will later remove. Preview every change before adding `--write`; merge
manually rather than replacing unrelated hooks if you use [manual configuration](agents.md#manual-hook-configuration).

Run each example from the root of a project with a validated `.cyberboar/policy.yaml`:

```sh
cyberboar_bin=$(command -v cyberboar)
test -n "$cyberboar_bin" || { echo 'Install cyberboar on PATH first.'; exit 1; }
```

`cyberboar_bin` must be an absolute executable path, not an alias or a shell function.
If necessary, set it to the full path of your installed binary.

## Claude Code extension

Install **Claude Code** (`anthropic.claude-code`) in the environment hosting your
agent. The extension shares Claude Code settings with the CLI; see the [official
VS Code settings guide](https://code.claude.com/docs/en/vs-code#configure-settings).
Use extension version **2.1.295 or later** for the installed `onFailure: block`
behavior; the extension bundles its own Claude Code version.

Preview local project settings, then repeat with `--write`:

```sh
"$cyberboar_bin" apply --agent claude-code --scope local --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
```

This creates `.claude/settings.local.json`, not a new editor extension. Open that
project in VS Code and start a **new Claude Code extension conversation**. Review the
loaded handlers through Claude Code's hooks interface. Keep normal permissions
enabled and verify from the extension conversation, not only the `claude` CLI.

For native Windows, use the [Claude Code installation](getting-started.md) and a
stable absolute `cyberboar.exe` path instead of this Linux/macOS shell example.

## Codex extension

Install **Codex** (`openai.chatgpt`). The CLI and extension share configuration
layers; see [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-basic)
and the [IDE settings guide](https://learn.chatgpt.com/docs/ide/settings).

Preview project hooks, then repeat with `--write`:

```sh
"$cyberboar_bin" apply --agent codex --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
```

This creates `.codex/hooks.json`. **Trust the project and the exact hook definitions**
before testing. Open `codex` in this project and review/trust the handlers in `/hooks`,
then start a fresh local Codex extension conversation in the same project and execution
environment. Edited definitions require trust review again. Do not bypass hook trust.
See the [official trust documentation](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks).

CyberBoar recovers a shell call's working directory and shell from the Codex session
transcript. A missing or unmatched call denies. Include an ordinary shell read in the
editor test; file-patch success alone does not verify this path. Cloud-delegated tasks
are a separate execution environment and are not covered by a local installation.
Check the extension's bundled runtime version as well as any standalone CLI version;
an extension update can introduce a runtime newer than the one in the capability matrix.

## opencode extension

Install the official **opencode** extension (`sst-dev.opencode`), not an unofficial
chat wrapper. It opens opencode in an integrated terminal; it still needs the
`opencode` executable and your provider setup in that environment. See the [official
IDE guide](https://opencode.ai/docs/ide/).

Preview the project plugin, then repeat with `--write`:

```sh
"$cyberboar_bin" apply --agent opencode --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
```

This creates `.opencode/plugin/cyberboar.js`. Do not add a second copy under
`.opencode/plugins/`. Start a fresh session through the extension in this project
and confirm the plugin loads. Do not use `--pure` or `OPENCODE_PURE`, which skip
plugins. A plugin that fails to load cannot enforce policy. See [plugin
configuration](agents.md#opencode) and the [official plugin reference](https://opencode.ai/docs/plugins/).

## Cursor editor

Cursor is its own editor. Use its existing `--agent cursor` setup and [Cursor
demo](quick-demos.md#cursor); no additional CyberBoar extension is required.
Keep every installed pre-tool handler, including the separate shell, MCP, file-read
and Tab-read checks. Real-agent validation of the Cursor editor remains pending. See
[Cursor hooks](https://cursor.com/docs/hooks).

## Copilot in VS Code

GitHub Copilot Chat is built into VS Code. Its **Copilot** session target runs Copilot
CLI's runtime, and its **Local** agent runs VS Code's own tools. Both read Copilot's
hook files, so one installation covers them and Copilot CLI:

```sh
"$cyberboar_bin" apply --agent copilot-cli --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
```

This creates `.github/hooks/cyberboar.json`; `--scope user` writes
`~/.copilot/hooks/cyberboar.json` instead. The hook is a shell command, which both
surfaces run (the Local agent skips Copilot's `exec` form), and it ends in
`|| exit 2`: VS Code lets a tool run when a hook exits with anything but 0 or 2, such
as when the binary is missing. If you installed with CyberBoar 1.0.0-rc.1, run
`apply` again; its hook does not run in the Local agent.

VS Code runs workspace hooks only in a **trusted workspace**, and only while
`chat.useHooks` is on (the default). Run **Chat: Configure Hooks** to see the files
VS Code found, and the **GitHub Copilot Chat Hooks** output channel to see each run.
CyberBoar blocks agent changes to the settings that can switch hooks off: the
workspace's `.vscode/settings.json`, your user settings in every profile and a remote
machine's settings, including a Codespace's. Hook files and workspace settings are
guarded in the workspace folder and every folder above it up to its git work tree,
which VS Code also reads with `chat.useCustomizationsInParentRepositories` on. A
`*.code-workspace` file can hold the same settings and is not guarded.

The Local agent reads `.github/hooks` and `~/.copilot/hooks`. It doesn't read the
managed directory (`--scope managed`), or a user hook installed while `COPILOT_HOME`
points elsewhere; `apply` says so when that is the case.

What the Local agent's hook checks differs from Copilot CLI's:

- **Terminal:** the agent terminal keeps its directory between commands and VS Code
  doesn't tell the hook which it is, so a command reaching a relative path asks for
  confirmation, which VS Code shows. Commands that start with `cd /absolute/dir &&`
  are checked fully. The terminal is read as bash or zsh: keep its profile on one of
  those. `send_to_terminal`, which types into a running program, is denied.
- **Searches:** `grep_search`, `semantic_search` and symbol searches can read every
  file in the workspace, so a workspace holding a protected file blocks them; agents
  then read files by name.
- **Tools the hook can't check** are denied: running saved tasks, tests through an
  extension or notebook cells, VS Code commands, installing extensions, browser code
  and symbol renames across files. Tools contributed by other extensions are denied
  as unclassified. A new task (`create_and_run_task`) may set only its command,
  arguments and working directory; environment, shell, per-platform commands,
  dependencies, automatic runs and `${…}` variables are refused. Its workspace
  folder must be the one the hook runs in, and because VS Code decides how to quote
  a task's arguments, a task with arguments may hold only plain words (letters,
  digits and `_ . / = : , @ % + -`); a command line goes in the command alone.
- **MCP tools** are named `mcp_<label>_<tool>`, where the label is the name the server
  reports for itself, not the name you configured, and the whole name is cut at 64
  characters. Deny and ask rules therefore match the tool of any server, so a rule
  denying a whole server (`github`) denies every MCP tool in VS Code, and only allow
  rules for every server (`*/search`) cover a call. When a name was cut, deny and ask
  rules match if their tool could start with what is left, and only an allow rule
  whose tool pattern ends in `*` (`*/search*`) covers it. A tool from another
  extension whose name starts with `mcp_` can't be told from an MCP tool, so it is
  checked as one instead of being denied.
- **Output and edits:** `terminal_last_command` and `terminal_selection` return what
  a terminal shows, which may be a command you typed yourself, not one the hook
  checked. `insert_edit_into_file` sends a sketch of the change that another model
  turns into the written text, so secrets are looked for in the sketch, not in what
  is finally written.
- **Custom agents:** an agent file can declare hooks, which VS Code runs when the
  model starts that agent as a subagent. CyberBoar therefore blocks agent changes to
  custom agents and agent plugins: `.github/agents` and `.claude/agents` (in the same
  folders as the hook files), `~/.copilot/agents`, `~/.claude/agents` and each
  profile's `agent-plugins`. Edit agent files yourself.
- **Not covered:** the hook guards the files above, but not other files VS Code runs
  from later: `.vscode/mcp.json` servers, `.vscode/tasks.json`, or hook and agent
  locations added with `chat.hookFilesLocations` and `chat.agentFilesLocations`. VS Code tells the hook only the folder it runs in,
  so in a multi-root workspace the other folders are unknown: searches are checked
  against that folder only, and the other folders' `.vscode/settings.json` and
  `.github/hooks` are not guarded. Keep protected files out of multi-root workspaces.

See the [capability matrix](capability-matrix.md) for the full comparison and the
[Local hooks reference](https://code.visualstudio.com/docs/agents/reference/hooks-reference).

## Verify from the editor

Use a new disposable project and fake data from [Before the clock
starts](quick-demos.md#before-the-clock-starts). Install the configuration above for
one agent only, then start that agent **through its editor integration**.

1. Send the two [demo prompts](quick-demos.md#demo-prompts) separately: an ordinary
   `demo.txt` read and one attempted `.env.cyberboar-demo` read.
2. In a human terminal, [check the audit log](quick-demos.md#verify-the-result).
   Require the expected agent ID, an `allow` for `demo.txt` and a `deny` with
   `files.deny[0]` for the fake secret. A model's refusal without a hook event is not
   evidence of enforcement.
3. Check the file and shell tools separately. In the disposable project, request
   `cat demo.txt`, then `cat .env.cyberboar-demo`, with no alternative after a denial.
   Require the corresponding allowed and denied command events.
4. Record the editor, extension and bundled runtime versions, operating system,
   execution host and policy scope. Do not reuse a CLI test result as an editor result.

This smoke test verifies those calls, not every tool or failure mode. Full validation
also needs blocked writes, MCP decisions, subagents where available, hook failures,
trust/loading checks and reviewed tool schemas. Editor-provided selections, attached
context and inline completions are not automatically governed by a pre-tool hook.
Read the [security model](security-model.md) and keep the agent's own sandbox and
permissions enabled. Close the disposable session when finished.
