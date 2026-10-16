# Editor integrations

CyberBoar supports the official Claude Code, Codex and opencode editor extensions,
and the Cursor editor. These integrations reuse the agents' existing hooks or
plugins; CyberBoar runs in the agent's execution environment, not as a VS Code
extension of its own. **Copilot editor support is experimental**; its Agent Host
and Local session targets have different requirements, described below.

**Active testing:** Editor integrations for all five supported agents are under
active testing. This support status is not a claim that every editor tool, version
or platform has been verified: CLI/runtime tests do not establish editor-session
coverage, and end-to-end editor-session verification is still pending. Confirm an
allowed and a policy-denied tool call from the editor before relying on a setup.
See the [capability matrix](capability-matrix.md) for tested versions and limitations.

## Choose the integration

| Agent surface | Extension or editor | Support status | CyberBoar configuration |
|---|---|---|---|
| Claude Code | `anthropic.claude-code` | Supported; active testing | `--agent claude-code`; existing `.claude/settings.json` or `.claude/settings.local.json` |
| Codex | `openai.chatgpt` | Supported; active testing | `--agent codex`; existing `.codex/hooks.json` |
| opencode | `sst-dev.opencode` | Supported; active testing | `--agent opencode`; existing `.opencode/plugin/cyberboar.js` |
| Cursor | Cursor editor, not a separate VS Code extension | Supported; real-agent validation pending | `--agent cursor`; existing `.cursor/hooks.json` |
| Copilot on VS Code Agent Host | GitHub Copilot Chat (`GitHub.copilot-chat`); select the Copilot session target | Experimental; active testing | CLI hook implementation can be reused in principle; editor-session verification pending |
| Copilot in VS Code's Local agent | GitHub Copilot Chat (`GitHub.copilot-chat`); select the Local session target | Experimental; adapter planned | Not supported by the current `copilot-cli` adapter; separate adapter work is planned |

Selecting a Claude or OpenAI **model** in Copilot does not select the Claude Code or
Codex runtime. Choose the actual extension/session target. VS Code documents these
differences in [Choose the hook implementation for your
session](https://code.visualstudio.com/docs/agent-customization/hooks#choose-the-hook-implementation-for-your-session).

## Keep execution and configuration together

Install the binary, policy and hook configuration where the agent executes. With
WSL, Remote-SSH or a dev container, this may be the remote Linux environment rather
than the desktop host. A host path such as `C:\Users\...` is not a Linux policy path.

Use the Linux binary inside WSL or a Linux container. Native Windows support is
limited to Claude Code using Git Bash; see [system requirements](system-requirements.md)
and [PowerShell status](powershell.md). Opening an editor on Windows does not imply
native Windows execution or PowerShell analysis.

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

For native Windows, use the [Claude Code/Git Bash installation](getting-started.md)
and a stable absolute `cyberboar.exe` path instead of this Linux/macOS shell example.

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

**Experimental support:** Copilot editor integration is under active testing and
development. Do not treat it as equivalent to the existing Copilot CLI integration.

VS Code's **Copilot Agent Host** and **Local** session targets do not have identical
tool payloads. Agent Host uses the Copilot SDK hook implementation shared with the
CLI, but this editor workflow still needs verification against the selected VS Code
version. Existing [Copilot CLI configuration](agents.md#github-copilot-cli) is a reuse
candidate; experimental status does not mean this editor workflow is validated.

The **Local** agent sends VS Code-specific tools and `tool_name`/`tool_input` fields.
The current `copilot-cli` adapter deliberately rejects that input. Loading the same
JSON file, changing its event capitalization, or selecting a different model does
not make it supported. Do not install the CLI hook as a Local-agent workaround.
Separate adapter work must verify file, terminal and MCP mapping, output decisions,
configuration guards and execution failures. See the [Local hooks
reference](https://code.visualstudio.com/docs/agents/reference/hooks-reference).

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
