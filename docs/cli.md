# CyberBoar command-line reference

Commands, flags, environment variables and exit statuses for the `cyberboar` binary. See
[Compatibility](#compatibility) for the v1 contract. For installation, follow [Getting
started](getting-started.md). For policy fields, use the [Policy reference](policy.md).

Repository tests check the command and flag tables against the implementation.

- [Conventions](#conventions) · [Exit status](#exit-status) · [Environment](#environment) ·
  [Compatibility](#compatibility) · [Policy sync settings](#policy-sync-settings)
- Agents: [`hook`](#cyberboar-hook) · [`brief`](#cyberboar-brief) · [`unlock`](#cyberboar-unlock)
- Set-up: [`apply`](#cyberboar-apply) · [`check`](#cyberboar-check) ·
  [`explain`](#cyberboar-explain) · [`test`](#cyberboar-test)
- Signing: [`keygen`](#cyberboar-keygen) · [`sign`](#cyberboar-sign) ·
  [`verify`](#cyberboar-verify) · [`bundle`](#cyberboar-bundle)
- Fleet: [`enroll`](#cyberboar-enroll) · [`ship`](#cyberboar-ship) · [`pull`](#cyberboar-pull)
- [`version`](#cyberboar-version) · [Command examples](#command-examples)

## Conventions

- `cyberboar COMMAND [FLAGS] [ARGUMENTS]`. `cyberboar help`, `--help` and `-h` list the
  commands on stdout.
- Long flags are written as `--name VALUE` or `--name=VALUE` in examples. Go's `flag`
  parser also accepts the `-name` spelling; both have identical behavior.
  A boolean flag is `--name` or `--name=false`, never `--name false`. Flags come before arguments:
  parsing stops at the first argument that isn't a flag. A flag given twice keeps the last value.
- `--help` (or `-h`) after a command prints its flags on stderr.
- **Env** is the environment variable a flag falls back to when it isn't given. The flag wins.
- In flag tables, none means no environment fallback, an empty default, or `false`
  for a boolean flag.
- Durations are Go durations: `90s`, `10m`, `720h`. There is no unit for days.
- Paths are relative to the working directory unless a flag says it needs an absolute path.
- Transport uses TLS 1.3 and does not follow redirects. `--insecure-skip-verify`
  disables server-certificate verification while retaining encryption; it must
  be specified explicitly and warns on every run. It has no environment fallback.
  There is no option that makes CyberBoar decision errors fail open.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Done. `--help` on a command, `help`, `version` |
| 1 | The command ran and failed, or found what it checks invalid (`check`, `verify`) |
| 2 | Usage error: unknown command, bad flag, missing or extra argument. **For `hook`: deny** |

Command-specific behavior:

- `hook` exits 0 (no objection, or an answer in the agent's JSON) or 2 (deny), never 1. Every
  error, a bad flag and `--help` included, is a deny with exit 2: any other status lets the agent run
  the tool. With `--agent cursor` a policy deny is a JSON answer with exit 0, which is what Cursor
  reads; set-up errors still exit 2. With `--agent codex` every deny, set-up errors included, is
  a JSON answer with exit 0: on Windows, Codex runs hooks in PowerShell, which turns exit 2 into 1.
- `brief` always exits 0: a briefing is advice and must never stop a session from starting.
- `explain` exits 0 whatever the decision; read it from the output or `--json`.
- `ship` and `pull` with a nonzero interval, from `--every` or the policy, run until SIGINT or
  SIGTERM and then exit 0; a failed round is
  retried at the next interval, or for `ship` later if the console sent a `Retry-After` (at most
  an hour).

## Environment

Variables the binary reads for its own configuration. Each one stands in for a flag
where the command tables say so; `CYBERBOAR_ENROLL_TOKEN` has no flag, since a flag
value is visible to every user in the process list.

| Variable | Read by |
|---|---|
| `CYBERBOAR_AUDIT` | `ship --audit` |
| `CYBERBOAR_CA` | `enroll`, `ship`, `pull` `--ca` |
| `CYBERBOAR_CONSOLE_KEY` | `enroll --console-key` |
| `CYBERBOAR_ENROLL_TOKEN` | `enroll`, when there is no `--token-file` |
| `CYBERBOAR_KEY_STORAGE` | `enroll --key-storage` |
| `CYBERBOAR_POLICY` | `--policy` of `explain`, `apply`, `ship`; `pull --out` |
| `CYBERBOAR_PUBKEY` | `pull`, `verify`, `bundle` `--pubkey` |
| `CYBERBOAR_SERVER` | `enroll --server`, `pull --server` |
| `CYBERBOAR_SIGNING_KEY` | `sign --key` |
| `CYBERBOAR_SINK` | `ship --sink` |
| `CYBERBOAR_STATE` | `enroll`, `ship`, `pull` `--state` |

Without `--state` (or `CYBERBOAR_STATE` where a command reads it) the state directory is
`$XDG_STATE_HOME/cyberboar` when `XDG_STATE_HOME` is an absolute path, else
`%LOCALAPPDATA%\cyberboar` on Windows, else `$HOME/.local/state/cyberboar`. `explain`
and `apply` read `HOME` (`USERPROFILE` on Windows), and `apply` the agents' own
variables for where their settings live (`CODEX_HOME`, `COPILOT_HOME`,
`XDG_CONFIG_HOME`, …). `hook` reads the variables of the agent's hook protocol
(`CLAUDE_PROJECT_DIR`, `CURSOR_PROJECT_DIR`, `SHELL`, …); those belong to the agents and
are listed in [capability-matrix.md](capability-matrix.md).

**`hook`, `brief` and `unlock` read no `CYBERBOAR_*` variable.** The agent's environment can come
from the project the agent opened (an agent's project settings can set variables), so
nothing in it may choose the hook's policy, key, audit log or state directory: they come
from the command line `apply` wrote. `unlock` follows the hook, so the two always agree
on the state directory. The hook's default state directory still follows
`XDG_STATE_HOME` and `HOME`, which a project could steer to reset the tripwire's counts;
`apply --state` pins it.

## Compatibility

Within v1 (from `v1.0.0` until `v2`):

- No command, flag or environment variable on this page is removed or renamed, and none changes
  its meaning, its default or its exit statuses.
- Commands, flags and environment variables may be added. A new flag doesn't change what a
  command line without it does.
- A hook command line that `apply` wrote keeps working with every later v1 binary. `apply`
  writes flags using `--name`; both the single-dash and double-dash spellings remain accepted.
- **Fixes that refuse or deny more are not breaking changes.** A command line that a security
  fix makes `hook` deny, or `pull`, `sign` or `apply` refuse, is not a compatibility promise.
- The machine-readable output is: the exit status; what `hook` and `brief` print, which is the
  agent's own protocol; `explain --json`; and the files `apply`, `keygen`, `sign` and `bundle`
  write (the bundle site is in [protocol](protocol/README.md); the audit log is the audit event
  schema). Everything else on stdout and all of stderr is for people and may change. Scripts
  should branch on exit statuses, not on messages.
- The policy format, the protocol and the audit schema are contracts of their own.

## Policy sync settings

The policy can supply the intervals for both commands. These settings do not start
services:

```yaml
spec:
  audit:
    sink: https://console.example.test/api/v1/events
  sync:
    shipEvery: 5s
    pullEvery: 4h
```

Start `cyberboar ship --policy FILE --audit LOG --state DIR` and `cyberboar pull --out
FILE --pubkey KEY --state DIR` as supervised services. The commands stay running and
forward new audit events or refresh the policy at its configured intervals. An explicit
`--every` overrides the corresponding policy setting, including `--every 0s` for one
run. An omitted setting or `0s` means one run. Positive intervals must be at least `1s`
for shipping or `10s` for pulling, and use Go durations such as `5s`, `10m`, or `4h`.

`ship` reloads its `--policy` before every round and checks the sink against the
enrolled console. Invalid or unreadable policies and sink mismatches prevent that round
from sending events; an already running service retries at its last valid interval.
`pull` reads the interval only from its installed policy after checking its signature
with `--pubkey`, its name and its expiry. It can start without a local policy: the first
successfully installed bundle supplies the interval. An existing valid signed policy
supplies the retry interval if the first request fails. After successful pulls, new
settings take effect on the next round; invalid local files cannot change the interval
or prevent a recovery pull. When a valid policy sets the interval to `0s` or removes it,
the command completes the current round and exits.

These settings configure running services; they do not start a process from a hook. Keep
the policy and service definitions writable only by the administrator. Audit delivery
still needs a compatible console and enrollment; static-site policy refresh does not.

---

## `cyberboar hook`

Answers one tool call from an agent's pre-tool hook: the hook input on stdin, the answer
on stdout and stderr, exit 2 for deny (see [Exit status](#exit-status)). An allowed
action produces no objection (empty output; `{}` for Cursor, `{"decision":"none"}` for
the opencode plugin), leaving the agent's own approval system in control. Input larger
than 32 MiB is denied. `apply` can write this command line into the agent's settings, or
you can [configure the hook manually](agents.md#manual-hook-configuration). Outside an
agent, supply a complete test payload and its project context, as in the [hook
example](#hook).

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--agent NAME` | none | `claude-code` | Hook protocol to speak: `claude-code`, `codex`, `copilot-cli`, `cursor`, `opencode`. Anything else denies |
| `--policy FILE` | none | none | The policy. None, or one that doesn't load, denies every call |
| `--pubkey FILE` | none | none | Require a valid, unexpired `POLICY.sig` from this ed25519 key; otherwise deny every call |
| `--audit FILE` | none | none | Append one JSON line per decision. Must be absolute; a log that can't be written denies |
| `--deadline DURATION` | none | `5s` | Deny if the decision takes longer. Keep it below the agent's hook timeout |
| `--state DIR` | none | the state directory ([Environment](#environment)) | Tripwire counts. Must be absolute; agents may not touch it |

Policy, signature and signing-key reads share the decision deadline. These inputs must
be regular files (symlinks to regular files are accepted); policies are capped at 1 MiB
and PEM keys at 4 KiB. The signed expiry is checked again before the hook answers.

No arguments.

## `cyberboar brief`

Answers a session-start hook with the policy's briefing for the agent: what is denied,
what needs confirmation, and to stop rather than look for another way. Stdin is read and
ignored. Advice only: every failure becomes a short "the briefing is unavailable" text,
exit 0. When this binary does not meet the policy's `minimumVersion`, the briefing tells
the agent that every tool call is blocked until CyberBoar is upgraded.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--agent NAME` | none | `claude-code` | Agent whose answer shape to print (as for `hook`) |
| `--policy FILE` | none | none | The policy |
| `--pubkey FILE` | none | none | Brief only on a policy validly signed with this key |

No arguments.

## `cyberboar unlock`

Lists the sessions the tripwire tracks, or unlocks one or all. For the user, never the
agent: `hook` denies agents any access to the state directory.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--state DIR` | none | the state directory | The hook's state directory: give the same `--state` as the hook |
| `--session ID` | none | none | Unlock this session (the ID as in the audit log) |
| `--agent NAME` | none | `claude-code` | The agent of `--session` |
| `--all` | none | none | Unlock every session. Not with `--session` |

No arguments. Without `--session` or `--all` it lists the sessions, locked or still
counting.

## `cyberboar apply`

Installs the hook (and `brief`, when the policy's briefing is on) into an agent's
settings. It prints what it would write unless `--write` is given. It checks the policy
first, and `--write` refuses to install where the hook would deny every call (an agent
on a platform it doesn't support). It also refuses to install where the agent would
never run the hook: into Claude Code settings that set `disableAllHooks`, or for Copilot
CLI when its settings for that scope set it. It doesn't remove the key, which is the
user's own setting.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--agent NAME` | none | `claude-code` | `claude-code`, `codex`, `copilot-cli`, `cursor` or `opencode` |
| `--policy FILE` | `CYBERBOAR_POLICY` | none | The policy the hook will read |
| `--scope SCOPE` | none | `user` | `user`, `project`, `local` (Claude Code only) or `managed` (not opencode). `project` needs the policy inside the project, and isn't available for Codex on Windows |
| `--dir DIR` | none | the working directory | The project, for `project` and `local` |
| `--managed-dir DIR` | none | the agent's machine-wide directory, e.g. `/etc/claude-code`, `/etc/codex`, on Windows `%ProgramData%\OpenAI\Codex` for Codex | Where `managed` writes |
| `--command FILE` | none | this binary; `cyberboar` on `PATH` for `project` | The executable the hook runs |
| `--audit FILE` | none | none | The hook's audit log (made absolute) |
| `--state DIR` | none | none | The hook's `--state` (made absolute); without it the hook uses its default |
| `--pubkey FILE` | none | none | The hook then refuses unsigned, altered or expired policies. Required for `managed` |
| `--allow-unsigned` | none | none | `managed` without `--pubkey` |
| `--deadline DURATION` | none | `5s` | The hook's `--deadline`; with the audit write it must stay below the agent's hook timeout |
| `--lock` | none | none | Stop users adding or switching off hooks (Claude Code, Codex). Needs `--scope managed`; refused otherwise, and for the other agents |
| `--write` | none | none | Write the settings (keeping a `.bak` of what was there) instead of printing them |

No arguments.

## `cyberboar check`

Validates policy files: each one must load against the schema and compile.
It also reports advisory warnings for exact duplicate patterns and rules appearing in multiple decision lists. Warnings never change evaluation or the exit status. One line per
file, `ok` or `invalid` with the error. Exit 1 if any is invalid. Under an `ok` line, an
indented line names each rule in `secrets.ignore` this version doesn't have, and another
says when this version is older than the policy's `minimumVersion`, so its hook would
block every tool call; neither is an error.

No flags. Arguments: `POLICY...`, at least one.

## `cyberboar test`

Runs YAML regression cases using the same policy evaluator as `explain`, without invoking an agent. A case selects exactly one read, write, list, command or MCP action, and specifies its expected allow/ask/deny decision. Case files are capped at 1 MiB and 1000 cases. All cases are validated before running. This is not an end-to-end agent hook test. Exit 0 if all pass, 1 on validation failure or mismatches, and 2 for usage errors.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--policy FILE` | none | none | Policy to evaluate |
| `--cases FILE` | none | none | YAML case file |

See [Policy regression tests](policy-tests.md).

## `cyberboar explain`

Shows the decision the policy makes for one action, and the rule that made it. Give
exactly one of `--command`, `--read`, `--write`, `--list`, `--mcp`.

`explain` doesn't know the files the hook protects for itself and for the agent: its
audit log and state (`builtin.self`) and the agent's settings, hooks and shell startup
files (`builtin.guarded`). The hook can deny such an action, or name one of those rules
where `explain` names a policy rule: `Select-String -Path *` in a folder that holds the
audit log is `builtin.self` in the hook and `files.deny[0]` in `explain` if `*` also
matches `.env`.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--policy FILE` | `CYBERBOAR_POLICY` | none | The policy. Required |
| `--command LINE` | none | none | A shell command line |
| `--shell NAME` | none | `""` (bash) | The language of `--command`: empty for bash, or `powershell` ([PowerShell support](powershell.md)) |
| `--read PATH` | none | none | A path the agent reads |
| `--write PATH` | none | none | A path the agent writes |
| `--list PATH` | none | none | A path whose names the agent lists |
| `--mcp SERVER/TOOL` | none | none | An MCP tool call |
| `--cwd DIR` | none | the working directory | The agent's working directory |
| `--workspace DIR` | none | none | The workspace root; without it, `--cwd` |
| `--home DIR` | none | `$HOME` (`%USERPROFILE%` on Windows) | The home directory |
| `--platform NAME` | none | `""` (POSIX); `windows` on Windows | Path semantics: empty for POSIX, or `windows` |
| `--json` | none | none | Print the verdict as JSON (below) |
| `--verbose` | none | none | Also print what the shell analysis found (`--command`); with `--json`, on stderr |
| `-v` | none | none | Alias for `--verbose`; `--v` is also accepted |

No arguments. `--json` prints one object:

| Field | Value |
|---|---|
| `decision` | `allow`, `ask` or `deny` |
| `reason` | Why, as the agent is told |
| `rule` | What decided: a policy rule such as `files.deny[0]`, or a built-in such as `error.noPolicy` |
| `notice` | Only when set: what the user is told directly |

Fields may be added.

## `cyberboar keygen`

Creates an Ed25519 key pair for policy signing. Keys made with any other tool work as
well: the private key
must be unencrypted PKCS#8 PEM (`PRIVATE KEY`), and the public key must be PKIX/SPKI PEM
(`PUBLIC KEY`), both Ed25519. OpenSSH and encrypted private-key files are not accepted
directly. `sign` reads the private key from a file; it can't use an HSM or a remote
signer. Store the private key in your protected signing
environment and distribute only the public key. The policy-signing key is separate from
the endpoint identity key that `enroll` can create in the OS key store or TPM.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--private FILE` | none | `policy-signing.key` | Private key to create; an existing file is never overwritten |
| `--public FILE` | none | `policy-signing.pub` | Public key to create. An existing file is never overwritten either |

No arguments.

## `cyberboar sign`

Writes `POLICY.sig` for each policy, with a serial and an expiry, so a server can't roll
an endpoint back to an older policy or keep it on one forever. It refuses a policy that
doesn't load, and a lower serial, or an equal serial with different signature contents.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--key FILE` | `CYBERBOAR_SIGNING_KEY` | none | Private key. Required |
| `--serial N` | none | none | 1 to 2^63−1. Endpoints never install a lower serial than theirs: use one rising counter, e.g. `$(date +%s)`. Required |
| `--expires WHEN` | none | none | An RFC 3339 time or a duration from now, at most 366 days ahead; after it endpoints deny every call. `0` or `never`: no expiry (warns). Required |

Arguments: `POLICY...`, at least one.

## `cyberboar verify`

Checks each policy's `POLICY.sig`: `ok`, `invalid` or `expired`, one line per file. Exit
1 if any isn't `ok`.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--pubkey FILE` | `CYBERBOAR_PUBKEY` | none | Public key. Required |

Arguments: `POLICY...`, at least one.

## `cyberboar bundle`

Writes the signed bundles of a policy directory as a static site that `pull` reads
(`SITE/api/v1/bundles/NAME`, [protocol](protocol/README.md)). All or nothing: one policy
that doesn't load, isn't signed with the key or has expired means nothing is written,
and every bundle is written to a synced temporary file before any is renamed into place.
Then the bundles of policies no longer in `POLICYDIR` are removed; only files named like
a policy are touched.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--pubkey FILE` | `CYBERBOAR_PUBKEY` | none | Key the policies must be signed with. Required |
| `--out SITE` | none | none | The site's root directory. Required |

Arguments: `POLICYDIR`, exactly one.

## `cyberboar enroll`

**Requires a compatible console implementing the [protocol](protocol/README.md).**
This endpoint release does not include a console service. Enrollment registers identity
and policy assignment; it does not install hooks or enroll with a static website. Skip
it for local use and static bundle distribution.

Enrolls this machine with a console: creates the endpoint's key, gets a client
certificate and pins the console's key. On an enrolled machine it renews the certificate
when half its lifetime has passed, so it is safe to run on every MDM check-in; a renewal
that fails (a revoked endpoint, an unreachable console) exits 1.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--server URL` | `CYBERBOAR_SERVER` | none | The console, `https://…`. Required |
| `--token-file FILE` | none | read `CYBERBOAR_ENROLL_TOKEN` | File holding the enrollment token, `-` for stdin. Needed only to enroll |
| `--state DIR` | `CYBERBOAR_STATE` | the state directory | Where the key and enrollment live; machine-wide installs use one only root or SYSTEM can read ([deploy-mdm.md](deploy-mdm.md)) |
| `--console-key FILE` | `CYBERBOAR_CONSOLE_KEY` | none | PEM public key the console's answers must be signed with. Required with `--insecure-skip-verify` |
| `--key-storage WHERE` | `CYBERBOAR_KEY_STORAGE` | `auto` | Where a new endpoint key is made: `tpm` (Linux `/dev/tpmrm0`, Windows' Platform Crypto Provider), `os` (Windows' Software Key Storage Provider), `file`, or `auto`, the first of those that works. Any value but `auto` is an error when the store is missing, or when the endpoint already has a key elsewhere |
| `--ca FILE` | `CYBERBOAR_CA` | none | Trust only these CAs (PEM) for the console's certificate |
| `--insecure-skip-verify` | none | none | Don't verify the console's certificate. Still encrypted; warns every run |

No arguments. The key, wherever it is, is named by the file `endpoint.key` in the state
directory; `ship` and `pull` use the store that file names and fail if it can't be
reached. `auto` says on stderr when it passed a store over.

## `cyberboar ship`

Uploads new audit-log lines in authenticated batches to the console this machine is
enrolled with; only an enrolled endpoint ships. The interval comes from `--every`, or
from `spec.sync.shipEvery` in `--policy`. A running service continuously forwards new
events in batches, keeps unsent events locally for retry and stays silent on empty
rounds. `spec.audit.sink` checks the intended destination; setting it does not start a
background process. Delivery is at least once; consumers must tolerate duplicate events.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--audit FILE` | `CYBERBOAR_AUDIT` | none | The hook's audit log. Required |
| `--state DIR` | `CYBERBOAR_STATE` | the state directory | The enrollment and how far the log was shipped |
| `--sink URL` | `CYBERBOAR_SINK` | none | Only checked: must be the enrolled console's events URL |
| `--policy FILE` | `CYBERBOAR_POLICY` | none | Policy with `spec.sync.shipEvery`; always checked, even with `--sink` or `--every`. Its `spec.audit.sink`, if set, must match the enrolled console's events URL |
| `--every DURATION` | none | `0s` | Explicit value overrides `spec.sync.shipEvery`. Wait after each round, at least `1s`, longer for `Retry-After` (at most an hour). `0s`: once |
| `--ca FILE` | `CYBERBOAR_CA` | none | As for `enroll` |
| `--insecure-skip-verify` | none | none | As for `enroll` |

No arguments. When the audit log was truncated or replaced since the last run, `ship`
sends the new log from its start and warns on stderr that any lines the old log got
after the last run were not sent. Rotate the log only right after a `ship` run
([deploy-mdm.md](deploy-mdm.md#rotate-the-audit-log)).

## `cyberboar pull`

Installs the signed bundle for a policy where the hook reads it, only if its signature
verifies, its serial isn't lower than the installed one's and it hasn't expired.
Concurrent installs are serialized with a persistent `POLICY.lock` file; a competing
install returns an error and can be retried. The lock is released if a process exits,
and agents may not change it. Symlinks at the policy, signature or lock leaf are
refused; directory aliases share the same lock. An enrolled endpoint pulls the policy
its console assigned it; one that isn't pulls `--name` from the static site `--server`.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--out FILE` | `CYBERBOAR_POLICY` | none | Where the hook reads its policy. Required |
| `--pubkey FILE` | `CYBERBOAR_PUBKEY` | none | Key bundles must be signed with. Required |
| `--state DIR` | `CYBERBOAR_STATE` | the state directory | The enrollment, if any |
| `--server URL` | `CYBERBOAR_SERVER` | none | The static site, `https://…`. Enrolled: only checked against the console |
| `--name POLICY` | none | none | The policy's `metadata.name`. Enrolled: only checked against the assigned one |
| `--every DURATION` | none | `0s` | Explicit value overrides the signed installed policy's `spec.sync.pullEvery`. Keep running and pull at this interval, at least `10s`. `0s`: once |
| `--ca FILE` | `CYBERBOAR_CA` | none | As for `enroll` |
| `--insecure-skip-verify` | none | none | As for `enroll` |

No arguments. Not enrolled and without `--server` or `--name`: exit 2.

## `cyberboar version`

Prints `cyberboar VERSION (policy APIVERSION)`, e.g. `cyberboar v1.0.0 (policy
cyberboar.dev/v1)`. `--version` is the same. No flags or arguments.

---

## Command examples

These responses were captured from the CLI, including successful fleet commands against
an isolated TLS test console. JSON is formatted for readability. Temporary paths are
normalized to `/tmp/cyberboar-example` and the test-console URL to
`https://console.example.test`; substitute your own paths and service. Dates, endpoint
IDs, hashes and prose vary. Exit statuses below are annotations, not command output.

Use a disposable directory with `cyberboar` on `PATH`:

```sh
demo_dir=$(mktemp -d)
cd "$demo_dir"
mkdir policies
```

Save this as `policies/starter.yaml`:

```yaml
apiVersion: cyberboar.dev/v1
kind: Policy
metadata:
  name: starter
spec:
  defaults:
    posture: deny-listed
  files:
    deny:
      - "**/.env*"
```

The local/signing examples share this policy. They do not execute the proposed `cat`
command or change real agent settings. Signing examples create a **disposable test
key**: never deploy or commit it. Console examples additionally require a compatible
service, a token supplied by its operator, and its trusted CA for private TLS
certificates. Local hooks and static distribution do not need a console.

### `help`

```sh
cyberboar help
```

Stdout (exit `0`):

```text
usage: cyberboar <command> [flags]

  hook     answer one PreToolUse hook call on stdin (--agent claude-code, codex, copilot-cli, cursor, opencode)
  brief    answer a SessionStart hook with the policy's briefing for the agent
  check    validate policy files
  test     run YAML policy regression cases
  explain  show the decision for one action
  apply    install the hook into an agent's settings (dry run unless --write)
  enroll   enroll this machine with a compatible console, or renew its certificate
  ship     send the audit log to the console this machine is enrolled with
  pull     fetch a signed policy bundle from the console or a static site
  keygen   create the key pair that signs policies
  sign     sign policy files with a serial and an expiry (writes POLICY.sig)
  verify   check policy signatures
  bundle   write signed policy bundles as a static site for pull
  unlock   list sessions the tripwire tracks, or unlock one
  version  print the version

Run "cyberboar <command> --help" for a command's flags.
```

### `hook`

Claude Code normally supplies stdin and `CLAUDE_PROJECT_DIR`. To reproduce its denied
call manually, supply both:

```sh
printf '{"hook_event_name":"PreToolUse","session_id":"docs-demo","cwd":"%s","tool_name":"Bash","tool_input":{"command":"cat .env"}}\n' "$PWD" |
  CLAUDE_PROJECT_DIR="$PWD" cyberboar hook --agent claude-code --policy policies/starter.yaml --audit "$PWD/audit.jsonl" --state "$PWD/hook-state"
```

Stdout (exit `2`):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "cyberboar: access to .env is blocked by policy rule files.deny[0]; do not attempt alternative ways to read or modify it"
  }
}
```

Stderr:

```text
cyberboar: access to .env is blocked by policy rule files.deny[0]; do not attempt alternative ways to read or modify it
```

Changing the proposed command to `printf hello` produces no stdout or stderr, exit `0`:
no objection, not a permission grant. The denied example writes one local audit event
for `ship`. Do not add `|| true` to an installed hook.

### `test`

Run this example from the source checkout, which includes the policy and case files:

```sh
cyberboar test --policy examples/baseline.yaml --cases testdata/policy-cases/baseline.tests.yaml
```

Stdout (exit `0`):

```text
PASS Block env file: deny
PASS Require push approval: ask
PASS Block other MCP servers: deny
3 passed, 0 failed
```

### `brief`

```sh
cyberboar brief --agent claude-code --policy policies/starter.yaml
```

Stdout (exit `0`):

```json
{
  "hookSpecificOutput": {
    "additionalContext": "CyberBoar enforces the policy \"starter\" on every tool call in this session, including subagents.\n\nDenied:\n- files: **/.env*\n- inline code: sh -c, bash -c, eval, python -c, node -e and other interpreters given code on the command line or stdin\n- directories that contain a denied file, for commands that read or change what's inside (grep -r, tar, cp -r)\n\nIf a tool call is denied, do not try another way to do the same thing: no other tool, command, spelling, encoding, path, script or subagent. Stop, tell the user what you needed and why, and let them decide; only they can change the policy.\n",
    "hookEventName": "SessionStart"
  }
}
```

### `unlock`

```sh
cyberboar unlock --state "$PWD/hook-state"
```

Stdout (exit `0`):

```text
no sessions with denied calls
```

This policy has no tripwire configured, so the denied test did not create session
counts. After investigating denials, you can clear all tracked sessions:

```sh
cyberboar unlock --state "$PWD/hook-state" --all
```

Stdout (exit `0`):

```text
cleared 0 sessions
```

### `apply`

Preview a shared Copilot CLI configuration without changing settings:

```sh
cyberboar apply --agent copilot-cli --scope project --dir . --policy policies/starter.yaml --command cyberboar --audit "$PWD/audit.jsonl" --state "$PWD/hook-state"
```

Stdout (exit `0`):

```text
# /tmp/cyberboar-example/.github/hooks/cyberboar.json (dry run; add --write to apply)
{
  "hooks": {
    "preToolUse": [
      {
        "bash": "'cyberboar' 'hook' '--agent' 'copilot-cli' '--policy' 'policies/starter.yaml' '--audit' '/tmp/cyberboar-example/audit.jsonl' '--state' '/tmp/cyberboar-example/hook-state' '--deadline' '5s' || exit 2",
        "powershell": "[Console]::Error.WriteLine('cyberboar: GitHub Copilot on native Windows is not supported, so the tool call is blocked; use WSL or a Linux dev container'); exit 2",
        "timeoutSec": 15,
        "type": "command"
      }
    ],
    "sessionStart": [
      {
        "bash": "'cyberboar' 'brief' '--agent' 'copilot-cli' '--policy' 'policies/starter.yaml'",
        "timeoutSec": 15,
        "type": "command"
      }
    ]
  },
  "version": 1
}

Notes:
  - Copilot lets a tool call through when the hook times out or answers with invalid JSON; the hook answers within --deadline to stay clear of that
  - command, file and MCP rules are enforced only by the hook
  - VS Code's Copilot session target and Local agent run this hook too, in a trusted workspace while chat.useHooks is on; start a new chat to load it
  - users can switch user and repository hooks off (disableAllHooks); --scope managed can't be switched off and must be owned by root
```

Add `--write` only after inspecting the preview. See [Agent setup](agents.md) for all
five integrations and [manual configuration](agents.md#manual-hook-configuration)
without `apply`.

### `check`

```sh
cyberboar check policies/starter.yaml
```

Stdout (exit `0`):

```text
ok      policies/starter.yaml (starter)
```

### `explain`

```sh
cyberboar explain --policy policies/starter.yaml --command 'cat .env'
```

Stdout (exit `0`):

```text
DENY  (files.deny[0])
access to .env is blocked by policy rule files.deny[0]; do not attempt alternative ways to read or modify it
```

`explain` exits `0` even for a `DENY` decision. For a machine-readable response:

```sh
cyberboar explain --policy policies/starter.yaml --command 'cat .env' --json
```

Stdout (exit `0`):

```json
{
  "decision": "deny",
  "reason": "access to .env is blocked by policy rule files.deny[0]; do not attempt alternative ways to read or modify it",
  "rule": "files.deny[0]"
}
```

### `keygen`

```sh
cyberboar keygen --private policy-signing.key --public policy-signing.pub
```

Stdout (exit `0`):

```text
wrote policy-signing.key (secret: store it in CI, nowhere else) and policy-signing.pub
```

Existing keys are never overwritten. Keep deployment private keys in a protected signing
environment and distribute only the public key.

### `sign`

```sh
cyberboar sign --key policy-signing.key --serial 42 --expires 720h policies/starter.yaml
```

Stdout (exit `0`):

```text
signed  policies/starter.yaml (starter, serial 42, expires <UTC expiry>)
```

Creates `policies/starter.yaml.sig`. `<UTC expiry>` represents the expiry timestamp,
720 hours after your run. Increase the serial each time you sign again.

### `verify`

```sh
cyberboar verify --pubkey policy-signing.pub policies/starter.yaml
```

Stdout (exit `0`):

```text
ok      policies/starter.yaml (serial 42, expires <UTC expiry>)
```

### `bundle`

```sh
cyberboar bundle --pubkey policy-signing.pub --out site policies
```

Stdout (exit `0`):

```text
wrote   site/api/v1/bundles/starter (policy e2b177ad8e6ace0822a25caccee23fbd3b8a06e4220bce40560a134daae6a477, ETag "sha256-24035679d3c121839a4e1a86de6cee2a04f683b2115efb46e8de12e230b98850")
```

Serve `site` over HTTPS for [static policy
distribution](operations.md#publish-static-bundles). The policy digest reflects its
exact bytes; the bundle ETag also reflects its signature.

### `enroll`

**Console required.** Replace the example URL and provision `enrollment-token` and
`console-ca.pem` securely through the console operator. Omit `--ca` for a system-trusted
server certificate. This example uses a file-backed endpoint key; use your deployment's
approved storage in production.

```sh
cyberboar enroll --server https://console.example.test --token-file enrollment-token --state "$PWD/endpoint-state" --key-storage file --ca console-ca.pem
```

Stdout (exit `0`):

```text
enrolled: endpoint 1ae90403-e910-44d5-8be8-7b9ff15e0298 with https://console.example.test, policy starter; certificate valid until <UTC certificate expiry>; key in a file (state in /tmp/cyberboar-example/endpoint-state)
```

The endpoint creates and keeps its ID; the console assigns the policy and certificate
lifetime. Enrollment does not install hooks, and is not required for local hooks or
static distribution.

### `ship`

After enrollment, upload the one audit event from the denied `hook` example:

```sh
cyberboar ship --audit "$PWD/audit.jsonl" --state "$PWD/endpoint-state" --every 0s --ca console-ca.pem
```

Stdout (exit `0`):

```text
shipped 1 events in 1 batches, skipped 0 invalid lines
```

Counts depend on the log and acknowledged cursor. `--every 0s` completes one round; it
does not start an ongoing forwarding service.

### `pull`

The test console assigns `starter`, signed with the key used above. On first installation:

```sh
cyberboar pull --state "$PWD/endpoint-state" --out installed.yaml --pubkey policy-signing.pub --every 0s --ca console-ca.pem
```

Stdout (exit `0`):

```text
installed policy starter at installed.yaml
```

Without a console or enrollment, pull from the HTTPS static site written by `bundle`.
Obtain its trusted CA separately if needed:

```sh
cyberboar pull --server https://policies.example.test --name starter --state "$PWD/static-state" --out static.yaml --pubkey policy-signing.pub --every 0s --ca policies-ca.pem
```

Stdout (exit `0`):

```text
installed policy starter at static.yaml
```

The `.sig` is installed alongside the policy. An unchanged valid bundle produces no
output, exit `0`. Verification failure does not replace the installed policy.

### `version`

A build with no version recorded, such as one from a source tree outside version
control, reports `dev`:

```sh
cyberboar version
```

Stdout (exit `0`):

```text
cyberboar dev (policy cyberboar.dev/v1)
```

A release binary prints its installed version in place of `dev`. Without one, the
binary prints the module version Go recorded when it was built: the tag for
`go install cyberboar.dev/cyberboar/cmd/cyberboar@VERSION`, or a pseudo-version such as
`v1.0.0-rc.1.0.20261017113155-6b7a4d9d9640` for a build in a git checkout.
`--version` produces the same response.
