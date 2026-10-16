# 60-second agent demos

See an ordinary read succeed and a fake secret read get blocked, using your own agent.
Each walkthrough takes about a minute **after** CyberBoar and the agent are installed,
signed in, and ready to use. Downloads, first-time trust review, and model response
times are extra; this is a quick interaction, not a latency benchmark.

The demos are ordered by reported workplace adoption in [JetBrains' Developer
Ecosystem Survey 2026](https://blog.jetbrains.com/research/2026/08/ai-coding-agent-adoption-2026/)
(May–July fieldwork): Claude Code, GitHub Copilot, Codex, Cursor, then opencode.
Copilot and Codex figures cover their products, not just their CLIs; this is an
ordering proxy, not a CLI market-share claim. See the [capability
matrix](capability-matrix.md) for CyberBoar's enforcement coverage.

Using an editor instead of a CLI? Follow [Editor integrations](editor-integrations.md)
for the supported Claude Code, Codex, opencode and Cursor editor integrations, all
under active testing, then run the prompts from the editor. **Copilot editor support
is experimental.** Its Local VS Code agent still requires a separate adapter;
the Copilot CLI demo does not validate either editor session target.

## Before the clock starts

Install a verified CyberBoar binary using [Getting started](getting-started.md), and
finish your agent's authentication/provider setup. The commands below use Bash on
macOS or Linux, including WSL/a Linux dev container. For native Windows, follow the
Claude Code/Git Bash instructions in [Getting started](getting-started.md); the other
four integrations require WSL or a Linux container.

Create a **new disposable project for each agent**. These commands do not change
user-wide hooks or existing projects. Keep the same terminal open for its demo.

```sh
cyberboar_bin=$(command -v cyberboar)
test -n "$cyberboar_bin" || { echo 'Install cyberboar on PATH first.'; exit 1; }
demo_dir=$(mktemp -d /tmp/cyberboar-demo.XXXXXX)
cd "$demo_dir" || exit 1
git init -q
mkdir .cyberboar
printf 'An ordinary file that the agent may read.\n' > demo.txt
printf 'DEMO_TOKEN=NOT_A_REAL_SECRET\n' > .env.cyberboar-demo
cat > .cyberboar/policy.yaml <<'YAML'
apiVersion: cyberboar.dev/v1
kind: Policy
metadata:
  name: agent-demo
spec:
  defaults:
    posture: deny-listed
  files:
    deny:
      - "**/.env*"
YAML
"$cyberboar_bin" check .cyberboar/policy.yaml
```

The last command should report a valid policy. `cyberboar_bin` must be an absolute
executable path, not an alias or shell function; if necessary, set it to the full path
of your installed binary. The policy blocks `.env*` files and otherwise permits
actions subject to CyberBoar's built-in protections. It is a demonstration, not a
complete deployment policy or an OS sandbox.

## Claude Code

**Connect (about 20 seconds).** Preview, inspect, then install this project's local
settings. No user-wide Claude Code configuration is written.

```sh
"$cyberboar_bin" apply --agent claude-code --scope local --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
"$cyberboar_bin" apply --agent claude-code --scope local --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state --write
claude
```

The write creates `.claude/settings.local.json`. Trust only the disposable folder you
created, and start a fresh session so the hooks load.

**Try (about 20 seconds).** Send the two [demo prompts](#demo-prompts) below, one at a
time. Expect the ordinary file's text, then a CyberBoar denial for the `.env` read.

**Verify (about 20 seconds).** In a separate terminal in this demo folder, [check the
audit log](#verify-the-result). A refusal without a matching audit event is not a pass.
For a hand-written configuration, see [manual Claude Code hooks](agents.md#claude-code)
and the [official hooks reference](https://code.claude.com/docs/en/hooks).

## GitHub Copilot CLI

**Connect (about 20 seconds).** This is the standalone Copilot CLI, not the VS Code
extension. Preview and install project hooks, then launch it from this folder.

```sh
"$cyberboar_bin" apply --agent copilot-cli --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
"$cyberboar_bin" apply --agent copilot-cli --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state --write
copilot
```

The write creates `.github/hooks/cyberboar.json`. Review the project trust prompt;
keep Copilot's normal permission checks enabled.

**Try (about 20 seconds).** Send the two [demo prompts](#demo-prompts) separately. An
ordinary file read should succeed; the fake secret read should be denied by CyberBoar.

**Verify (about 20 seconds).** [Check the audit log](#verify-the-result) from a human
terminal in this folder. See [manual Copilot CLI hooks](agents.md#github-copilot-cli)
and the [official hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference).

## Codex CLI

**Connect (about 20 seconds, plus first-time trust review).** Preview and install the
project hook definitions, then launch Codex.

```sh
"$cyberboar_bin" apply --agent codex --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
"$cyberboar_bin" apply --agent codex --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state --write
codex
```

The write creates `.codex/hooks.json`. **Trust this project, then open `/hooks` and
review/trust its CyberBoar hook definitions before testing.** Untrusted project hooks
are skipped, and edited hook definitions need review again. Do not bypass hook trust
or disable Codex's sandbox/approval checks for this demo.

**Try (about 20 seconds).** Send the two [demo prompts](#demo-prompts) separately.
Codex may read through a shell tool; a straightforward `cat` read is also covered.
Expect the ordinary text, then a CyberBoar denial for the fake secret.

**Verify (about 20 seconds).** [Check the audit log](#verify-the-result), not just the
chat response. See [manual Codex CLI hooks](agents.md#codex-cli) and the
[official hooks and trust documentation](https://learn.chatgpt.com/docs/hooks).

## Cursor

**Connect (about 20 seconds).** Install hooks into the disposable project, then open
that folder in the local Cursor editor (use Remote-WSL/a Linux container on Windows).

```sh
"$cyberboar_bin" apply --agent cursor --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
"$cyberboar_bin" apply --agent cursor --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state --write
```

The write creates `.cursor/hooks.json`. Start a new Agent chat in that folder after
loading the settings; this walkthrough is not for a remote/cloud agent.

**Try (about 20 seconds).** Send the two [demo prompts](#demo-prompts) separately in
Agent chat. Expect the ordinary text, then a denied fake-secret read.

**Verify (about 20 seconds).** [Check the audit log](#verify-the-result). **Real-agent
validation for the Cursor editor is pending**: this is a verification walkthrough, not a claim
of a completed end-to-end test. If hooks do not run, check Cursor's hook diagnostics
and the [capability matrix](capability-matrix.md) before relying on this integration.
See [manual Cursor hooks](agents.md#cursor) and the
[official hooks documentation](https://cursor.com/docs/hooks).

## opencode

**Connect (about 20 seconds).** Preview and install the project plugin, then start a
fresh opencode session from this folder with your configured model/provider.

```sh
"$cyberboar_bin" apply --agent opencode --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state
"$cyberboar_bin" apply --agent opencode --scope project --dir . \
  --command "$cyberboar_bin" --policy .cyberboar/policy.yaml \
  --audit .cyberboar/audit.jsonl --state .cyberboar/hook-state --write
opencode
```

The write creates `.opencode/plugin/cyberboar.js`. This uses the compatible singular
plugin directory; do not install a second copy under `.opencode/plugins/`. Do not use
`--pure` or `OPENCODE_PURE`, which bypass plugin loading.

**Try (about 20 seconds).** Send the two [demo prompts](#demo-prompts) separately.
Expect the ordinary text, then a CyberBoar plugin error denying the fake-secret read.

**Verify (about 20 seconds).** [Check the audit log](#verify-the-result). See
[manual opencode configuration](agents.md#opencode) and the
[official plugin documentation](https://opencode.ai/docs/plugins/).

## Demo prompts

First, request an ordinary read:

```text
Use a file-reading tool to read demo.txt and show its contents. Do not modify files.
```

Expected content:

```text
An ordinary file that the agent may read.
```

Then request one controlled, denied read:

```text
Use a file-reading tool to read .env.cyberboar-demo once so I can verify the policy
hook blocks it. It contains only fake demo data. Do not modify files or use another
tool to work around a denial.
```

The denial's presentation varies by agent. The fake token must not appear in its
response. Some agents recognize the policy from their session briefing and refuse
without calling a tool: that demonstrates awareness, **not hook enforcement**. Use
the audit check below to tell the difference. Do not weaken the policy to get a pass.

## Verify the result

From a **human terminal in the same demo folder**, run:

```sh
cat .cyberboar/audit.jsonl
```

Look for both of these events from the agent you just used:

- An `allow` decision for the read of `demo.txt`.
- A `deny` decision for `.env.cyberboar-demo`, with rule `files.deny[0]` and policy
  name `agent-demo`.

The full records also contain timing and tool details. Look for the file path or,
for shell reads, the `cat` command; the contents read are not logged. Both events
together prove that the agent reached CyberBoar and
that this particular allowed/denied pair was evaluated. A missing log, an unrelated
denial, or a chat-only refusal is not proof. Check hook trust/loading, executable paths
and agent diagnostics using [Troubleshooting](troubleshooting.md).

This does not establish complete enforcement coverage or process isolation; read the
[capability matrix](capability-matrix.md) and [security model](security-model.md) before
deploying a real policy.

## Finish the demo

Quit the agent and close the disposable project. The hooks, plugin, fake files, audit
log and explicitly pinned state all live inside that folder; no user-wide CyberBoar
installation was made. Keep it for inspection or remove that specific demo directory
using your file manager. Start with a new disposable folder if you try another agent.
For an existing project, follow the backup/rollback instructions in
[Getting started](getting-started.md) instead of deleting its configuration.
