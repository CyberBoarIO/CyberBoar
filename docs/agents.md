# Agent setup

Choose automatic installation with `cyberboar apply`, or [configure the hooks
manually](#manual-hook-configuration). Both run the same `cyberboar hook` policy engine;
`apply` is a configuration helper, not a prerequisite for enforcement. Preview its
settings first; add `--write` to install them. Keep the binary at its installed path and
back up settings. For a complete first installation, follow [Getting
started](getting-started.md).

For a short allowed/denied test with each integration, follow the
[60-second agent demos](quick-demos.md).
The official Claude Code, Codex and opencode editor extensions are supported and under
active testing. The Cursor editor is supported, with real-agent validation pending.
The Copilot CLI setup below also covers Copilot in VS Code, both its Copilot session
target and its Local agent. See [Editor integrations](editor-integrations.md) for
setup and current validation limits.

## Choose an integration

| Agent (`--agent`) | macOS / Linux | Native Windows | `ask` behavior |
|---|---|---|---|
| Claude Code (`claude-code`) | Available | Git Bash and the PowerShell tool | Native confirmation |
| Codex CLI (`codex`) | Available | PowerShell; user and managed scope | Deny |
| GitHub Copilot CLI and Copilot in VS Code (`copilot-cli`) | Available | Use WSL or a Linux container | Native confirmation; deny in headless mode |
| Cursor (`cursor`) | Available; CLI validated with a real agent, editor validation pending | Use WSL / Remote-WSL or a Linux container | Deny |
| opencode (`opencode`) | Available through a plugin | Use WSL or a Linux container | Deny |

For the other agents on Windows, use the Linux binary inside WSL or a Linux container.
PowerShell commands are analyzed as a [checked subset](powershell.md).

## Select a scope

| Scope | Use | Agents |
|---|---|---|
| `local` | One Claude Code project, outside shared project settings | Claude Code |
| `project` | Shared project configuration; policy must be inside the project | All five |
| `user` (default) | Configuration for the current user | All five |
| `managed` | Machine-wide configuration installed by an administrator | All except opencode |

At user, local and managed scope, `apply` records the executable's own path. Project
scope uses `cyberboar` on `PATH` unless `--command` specifies a path. Each developer
using shared settings needs the binary available there. `--dir` selects the project for
local/project scope.

## Preview and install

Run from a project with a validated `.cyberboar/policy.yaml`. These are previews:

```sh
cyberboar apply --agent claude-code --scope local --policy .cyberboar/policy.yaml
cyberboar apply --agent codex --scope project --policy .cyberboar/policy.yaml
cyberboar apply --agent copilot-cli --scope project --policy .cyberboar/policy.yaml
cyberboar apply --agent cursor --scope project --policy .cyberboar/policy.yaml
cyberboar apply --agent opencode --scope project --policy .cyberboar/policy.yaml
```

Choose the agent you use, inspect the target files and warnings, then repeat its command
with `--write`. For decision logging, include `--audit` in both commands. The `.bak`
produced by `apply` can be replaced on later runs, so retain an independent pre-install
backup.

Reload or restart the agent. **Codex user/project hooks must also be trusted in `/hooks`
before enforcement starts.** Test a policy-denied call and confirm its audit event when
logging is enabled. An agent refusing a request on its own does not prove the hook ran.

## Manual hook configuration

The examples below are project-level configurations for macOS/Linux, or for the Linux
binary inside WSL/a Linux container. Start with a validated `.cyberboar/policy.yaml` in
the project root and `cyberboar` on the agent's `PATH`. On native Windows, use an
executable path to `cyberboar.exe`; for Codex see [Codex on Windows](#codex-on-windows).

Back up existing files. **Merge these handlers into existing hook arrays; do not replace
unrelated hooks or settings.** Use only one CyberBoar installation per scope to avoid
duplicate checks and audit events. The examples include an optional session briefing:
remove only its session-start handler if you do not want the advice. Never make the
pre-tool check asynchronous or ignore its exit status.

For a user-level installation, use the user configuration location listed below and
absolute binary/policy paths instead of the project-relative paths. To require signed
policies, add `--pubkey /absolute/path/policy-signing.pub` to both `hook` and `brief`.
For logging/tripwire state, add `--audit /absolute/path/audit.jsonl` and
`--state /absolute/path/hook-state` to `hook` only. The parent directories must be
accessible to the account running the agent. Do not let project environment variables
choose these protected paths. See the [CLI reference](cli.md#cyberboar-hook).

Manual hook configuration does **not** reproduce all of `apply`'s native permission
fallbacks or managed locking. Protect configuration ownership separately; use the
[managed deployment guide](deploy-mdm.md) for administrator-enforced installations.

### Claude Code

Official reference: [Claude Code hooks](https://code.claude.com/docs/en/hooks).

Merge into `.claude/settings.json` (shared project), or
`.claude/settings.local.json` (local project). User configuration is
`~/.claude/settings.json`. The exec-form `args` avoid shell quoting, and Claude Code
substitutes `${CLAUDE_PROJECT_DIR}` in each argument. Use Claude Code **2.1.295 or
later** for `onFailure: block`; older versions can run tools when the hook fails.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "cyberboar",
            "args": ["hook", "--policy", "${CLAUDE_PROJECT_DIR}/.cyberboar/policy.yaml", "--deadline", "5s"],
            "timeout": 10,
            "onFailure": "block"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "cyberboar",
            "args": ["brief", "--policy", "${CLAUDE_PROJECT_DIR}/.cyberboar/policy.yaml"],
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The hook checks Claude Code's `PowerShell` tool on native Windows and denies it
elsewhere. If your settings deny any `Bash(…)` command, also add a `PowerShell(…)` rule
(such as the same command), or Claude Code turns the PowerShell tool off; `apply` writes
these rules for you. Ensure no active settings set `disableAllHooks`. Review the handlers in `/hooks`, restart/reload Claude
Code as required, and test enforcement in a new session.

### Codex CLI

Official reference: [Codex hooks](https://learn.chatgpt.com/docs/hooks).

Merge into `.codex/hooks.json`; user configuration is `~/.codex/hooks.json`, or
`$CODEX_HOME/hooks.json` when `CODEX_HOME` is set.
This example assumes Codex starts from the project root. Hook commands run from the
session's working directory, so `.cyberboar/policy.yaml` is relative to that directory.
If you start Codex from a subdirectory, use an absolute policy path or the Git-root
alternative below.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "cyberboar hook --agent codex --policy .cyberboar/policy.yaml --deadline 5s",
            "timeout": 10
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "cyberboar brief --agent codex --policy .cyberboar/policy.yaml",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

No matcher means all tool calls are checked. **Trust the project and review/trust the
handlers in `/hooks` after creating or changing them.** Until trusted, Codex skips
non-managed hooks. `ask` decisions deny; a hook that cannot launch can fail open.
Codex does not hook `write_stdin`, which types into a running command, so a command that
asks for a terminal (`tty`) is denied; without one, a command gets no input.

**Optional Git-root path:** OpenAI recommends Git-root resolution for repo-local
hooks that must work when Codex starts from a subdirectory. In both commands above,
replace `.cyberboar/policy.yaml` with
`\"$(git rev-parse --show-toplevel)/.cyberboar/policy.yaml\"` inside the JSON string.
This requires Git and a Git worktree; the escaped quotes preserve paths with spaces.
See the [official hook configuration notes](https://learn.chatgpt.com/docs/hooks#config-shape).

#### Codex on Windows

On native Windows, Codex runs hook commands with `cmd.exe` and the model's commands in
PowerShell. Use the user scope (`%USERPROFILE%\.codex\hooks.json`, or under
`CODEX_HOME`) or the managed scope (`%ProgramData%\OpenAI\Codex\requirements.toml`);
the Git-root form above needs a POSIX shell, so `apply` refuses `--scope project`
there. Write absolute paths in double quotes, and give the same line as
`commandWindows`:

```json
{
  "type": "command",
  "command": "\"C:\\Tools\\cyberboar.exe\" hook --agent codex --policy \"C:\\Users\\dev\\.cyberboar\\policy.yaml\" --deadline \"5s\"",
  "commandWindows": "\"C:\\Tools\\cyberboar.exe\" hook --agent codex --policy \"C:\\Users\\dev\\.cyberboar\\policy.yaml\" --deadline \"5s\"",
  "timeout": 10
}
```

A path can't contain `"` or `%` (which cmd.exe expands) or end in `\`. Codex starts
PowerShell with the user's profiles unless the model asks otherwise; the hook guards the
PowerShell profile and module folders (see [Profiles and
modules](powershell.md#profiles-and-modules)), and denies commands sent to another
shell, such as `cmd.exe` or Git Bash.

### GitHub Copilot CLI

Official reference: [GitHub Copilot hooks
reference](https://docs.github.com/en/copilot/reference/hooks-reference).

Create `.github/hooks/cyberboar.json`; user configuration is
`~/.copilot/hooks/cyberboar.json` (or under `COPILOT_HOME`). Copilot CLI, VS Code's
Copilot session target and VS Code's Local agent all read these files. Repository
hooks run from the repository root (VS Code: the workspace folder).

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "'cyberboar' 'hook' '--agent' 'copilot-cli' '--policy' '.cyberboar/policy.yaml' '--deadline' '5s' || exit 2",
        "powershell": "[Console]::Error.WriteLine('cyberboar: GitHub Copilot on native Windows is not supported, so the tool call is blocked; use WSL or a Linux dev container'); exit 2",
        "timeoutSec": 15
      }
    ],
    "sessionStart": [
      {
        "type": "command",
        "bash": "'cyberboar' 'brief' '--agent' 'copilot-cli' '--policy' '.cyberboar/policy.yaml'",
        "timeoutSec": 15
      }
    ]
  }
}
```

Use `bash`, not Copilot's `exec` form: VS Code's Local agent skips `exec` hooks.
Keep `|| exit 2`, so that VS Code denies when the binary is missing or crashes; it
lets a tool run on any other failing exit. The `powershell` command denies every call
on native Windows, where neither surface is supported. This doesn't cover Copilot's
cloud agent. Ensure the scope's settings do not set `disableAllHooks`, and that VS
Code's `chat.useHooks` is on. Reload Copilot or start a new VS Code chat, and test a
denied call. Keep the 5-second decision deadline below the 15-second timeout:
timeouts can fail open.

### Cursor

Official reference: [Cursor hooks](https://cursor.com/docs/hooks).

Merge into `.cursor/hooks.json`; user configuration is `~/.cursor/hooks.json`.
Project hooks run from the project root. Keep all five pre-tool handlers: the general
handler does not replace the separate file-read, tab-read, shell and MCP checks.

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {"command": "cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s", "timeout": 15, "failClosed": true}
    ],
    "beforeShellExecution": [
      {"command": "cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s", "timeout": 15, "failClosed": true}
    ],
    "beforeMCPExecution": [
      {"command": "cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s", "timeout": 15, "failClosed": true}
    ],
    "beforeReadFile": [
      {"command": "cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s", "timeout": 15, "failClosed": true}
    ],
    "beforeTabFileRead": [
      {"command": "cyberboar hook --agent cursor --policy .cyberboar/policy.yaml --deadline 5s", "timeout": 15, "failClosed": true}
    ],
    "sessionStart": [
      {"command": "cyberboar brief --agent cursor --policy .cyberboar/policy.yaml", "timeout": 15}
    ]
  }
}
```

`failClosed` blocks execution failures/timeouts. CyberBoar maps `ask` to denial.
Install only hooks you trust: Cursor runs every matching hook, a later `preToolUse` hook
can replace a tool's input after CyberBoar checked it, and a `sessionStart` hook can set
environment variables for every later hook.

The agent's shell keeps its directory, variables and aliases between calls. When the
agent leaves the Shell tool's working directory empty, the Cursor CLI does not tell the
hook which directory the shell is in, so a command with a relative path is denied unless
it starts with `cd` to an absolute directory (`cd /absolute/path/to/project && go test
./...`); the denial tells the agent so. A call that sets the working directory is checked
in it. Paths under `~` are always unknown, since an earlier call may have changed `HOME`.

Restart/reload Cursor, inspect its hook diagnostics, and test the real agent before
relying on this integration. The Cursor CLI has passed the [real-agent
harness](capability-matrix.md); the Cursor editor has not been validated yet.

### opencode

Official reference: [opencode plugins and hook
events](https://opencode.ai/docs/plugins/).

opencode uses a JavaScript plugin, **not** `hooks.json`. It loads project plugins from
`.opencode/plugin/` or `.opencode/plugins/`, and user plugins from the same directories
under `~/.config/opencode/` (or `XDG_CONFIG_HOME`). CyberBoar uses the singular
`plugin/`, so `apply` replaces a manual copy instead of adding a second one. Keep one
copy only.

From a verified CyberBoar source checkout matching your binary, copy the complete
[tested project plugin](../internal/adapters/opencode/testdata/apply/project-plugin.js)
to a **new** `.opencode/plugin/cyberboar.js` in your project. For example, from the
checkout root:

```sh
mkdir -p /absolute/path/to/project/.opencode/plugin
cp -i internal/adapters/opencode/testdata/apply/project-plugin.js /absolute/path/to/project/.opencode/plugin/cyberboar.js
```

Leave its implementation intact. Configure the constants at the top of your copy:

```js
const name = "cyberboar";
const command = "cyberboar";
const hookArgs = ["hook", "--agent", "opencode", "--policy", ".cyberboar/policy.yaml", "--deadline", "5s"];
const briefArgs = ["brief", "--agent", "opencode", "--policy", ".cyberboar/policy.yaml"];
const timeoutMs = 15000;
```

Keep the existing project-root `cwd` expression. For a user plugin, use absolute
binary/policy paths and set `const cwd = undefined;` instead. Set `briefArgs = null` if
you do not want the optional briefing. Add signing/logging/state arguments to these
arrays as described above; they are passed directly, not through a shell.

The complete shim preserves config-derived shell/MCP context, per-call working
directory, the 15-second process timeout, output-size limits and strict response
validation. It throws to block a call unless the hook exits `0` with exactly
`{"decision":"none"}`. A shortened shell wrapper that checks only the exit status is
not equivalent. It also wires the optional briefing into the system prompt.

Restart opencode after editing. Do not use `--pure` or `OPENCODE_PURE=1`, which skip
plugins; a plugin load failure also leaves calls unchecked. Check startup diagnostics
and test a denied call. Install only trusted plugins: another plugin can change a call
after CyberBoar checked it.

### Verify a manual installation

In a throwaway project, create `.env.cyberboar-demo` containing dummy data and deny
`**/.env*` in the policy. Ask the agent to read it, then to run a harmless permitted
command. Confirm the CyberBoar rule/reason for the denial and, if `--audit` is configured,
both decision events. For shell/JSON hook diagnostics and recovery, see
[Troubleshooting](troubleshooting.md). `cyberboar explain` alone does not prove the
agent loaded a manual hook.

## Failure behavior

CyberBoar denies invalid input and decision errors. The agent determines what happens
when its hook never runs:

- Claude Code 2.1.295 and later honors `onFailure: block` installed by `apply`.
  Earlier versions can fail open; native fallback rules cover only literal rules
  that `apply` can translate.
- Codex can fail open when the hook cannot launch. Managed prefix rules provide
  a limited fallback for literal command rules.
- Copilot CLI can fail open on timeout or invalid JSON; other failures deny.
  VS Code's Local agent fails open on timeout and on exits other than 0 and 2; the
  installed `|| exit 2` turns a missing binary or a crash into a deny.
- Cursor hooks are installed with `failClosed`. Cursor CLI passed the real-agent
  harness; Cursor editor sessions remain unverified.
- The opencode plugin denies execution failures. A plugin that fails to load is
  skipped; `--pure` and `OPENCODE_PURE=1` skip plugins entirely.

The [capability matrix](capability-matrix.md) lists verified versions, tool coverage,
missing working-directory information and hook visibility.

## Managed enforcement

User/project installations are advisory to a user who can change them. Managed
deployments need OS ownership and permissions protecting the binary, signing key, policy
and agent configuration.

`--lock` requires managed scope and supports only Claude Code and Codex. Copilot uses
its root-owned policy directory. Cursor supports machine-wide hooks, but `apply` cannot
configure dashboard-managed team hooks. opencode has no managed scope in CyberBoar. See
[MDM deployment](deploy-mdm.md).

## Updates and removal

Re-run `apply` with the original scope/options to change hook commands. Keep older
binaries while sessions still reference them. Restore or carefully edit settings before
deleting a binary. There is no uninstall subcommand; the [local removal
procedure](getting-started.md#6-remove-cyberboar-or-roll-back) illustrates how to
preserve unrelated configuration.
