# Policy reference

A policy defines how CyberBoar evaluates file, command and MCP actions. Save it as YAML,
keep it in version control, and validate it with `cyberboar check` before installing it.
This page describes the `cyberboar.dev/v1` format.

## Document structure

```yaml
apiVersion: cyberboar.dev/v1
kind: Policy
metadata:
  name: baseline
  description: Rules for development workstations
spec:
  defaults:
    posture: deny-listed
  files:
    deny: ["**/.env*", "**/*.pem", "~/.ssh/**"]
    ask: ["**/terraform.tfstate"]
  commands:
    deny: ["terraform apply", "kubectl delete", "curl | sh"]
    ask: ["git push"]
  mcp:
    allow: ["github", "internal-docs/search"]
  session:
    tripwire:
      maxDenials: 3
```

`apiVersion`, `kind`, `metadata` and `spec` are required. `metadata.name` is a DNS label
of at most 63 characters: lowercase letters, digits and internal hyphens.
`metadata.description` is optional; `metadata.labels` is an optional map of strings.
Unknown fields are rejected. The [JSON Schema](../internal/policy/schema/policy.v1.json)
defines the structure; loading also validates patterns and durations.

## Decisions and defaults

| Decision | Result |
|---|---|
| `deny` | Block the proposed tool call. |
| `ask` | Require confirmation where the agent supports it; otherwise deny. |
| `allow` | No objection from CyberBoar; the agent's own permissions still apply. |

`spec.defaults.posture` defaults to `deny-listed`: unmatched actions have no objection.
`allow-listed` requires coverage by an allow or applicable ask rule. A nonempty `allow`
list restricts its own category even under `deny-listed` posture. For example,
`mcp.allow` restricts MCP calls without changing the default for files or commands.

A definite deny takes precedence over ask or allow. Actions inferred from one tool call
are combined conservatively: any denied action blocks the call. Runtime values that
cannot be resolved may require confirmation, and cannot establish an allow-list match.
A shell variable is resolved only when the same command line first sets it to a plain
value (`f=src/file.txt; cat "$f"`) and nothing on the line could change it again.
Built-in protections and evaluation errors can deny an action even when a policy allow
rule matches.

## File rules

`spec.files` accepts `deny`, `ask` and `allow` lists. Rules apply to native file tools
and paths inferred from shell commands; they do not distinguish reads from writes.

| Pattern | Anchor |
|---|---|
| `secrets/**` | Workspace root |
| `**/.env*` | Any matching path |
| `~/.ssh/**` | Developer's home directory |
| `/etc/shadow` | Absolute POSIX path |
| `C:/Users/*/.ssh/**` | Absolute Windows drive path |

Use `/` as the separator in portable patterns. `*` matches within one path component;
`**` spans directories. Quote patterns in YAML. Windows drive paths are supported;
backslashes outside drive paths are rejected because they would escape pattern
characters.

CyberBoar checks lexical paths, symlink traversal and resolved paths. Deny and ask
matching also accounts for case and Unicode aliases; allow matching preserves the
written case. Unresolvable or ambiguous paths are denied. Hard links, bind mounts and
changes between checking and execution remain outside this boundary.

`spec.files.containing` controls operations on a directory containing protected files,
such as recursive searches or archives:

| Value | Behavior |
|---|---|
| `deny` (default) | Deny a directory containing a denied file; ask rules still ask. |
| `ask` | Require confirmation for directory operations encountering protected files. |
| `ignore` | Do not apply policy deny/ask rules to descendants solely because the directory is accessed. Built-in protections still apply. |

Directory scans are bounded. Incomplete checks are denied in every mode, including
`ask` and `ignore`. This includes unreadable directories, unresolved links, directory
cycles that prevent policy checks, and scans that exceed resource limits. Listings
and operations that access contents have different coverage; inspect them with
`explain --list` or `explain --command`.

## Command rules

`spec.commands` accepts the same three lists. A pattern is one simple command or
pipeline, parsed as Bash syntax. Matching uses command words rather than substrings.
Write command names without paths.

| Pattern | Purpose |
|---|---|
| `git push` | Match a command prefix, including additional arguments. |
| `kubectl delete` | Deny/ask matching accounts for intervening options such as `kubectl -n prod delete`. |
| `curl \| sh` | Match a pipeline feeding curl output to sh. |
| `npm run deploy` | Govern a named task whose implementation is otherwise opaque. |

Unquoted wildcards in a command pattern match an argument; quoted shell text matches
literally. YAML quoting and shell quoting are separate. Patterns cannot contain
assignments, redirections, `;`, `&&` or command substitution. Allow rules require exact
prefixes; they do not skip options as deny/ask rules do.

`spec.commands.denyInterpreters` defaults to `true`. Inline foreign code such as `python
-c`, `node -e` and unresolved shell code is denied. Literal nested shell commands can be
analyzed. Setting this field to `false` permits opaque inline code unless another rule
denies it; file rules cannot inspect its behavior. Scripts, task runners and executable
entrypoints remain opaque. A pipeline rule such as `curl | sh` matches the pipe only:
`curl -o x URL && sh x` downloads and runs a script as two separate commands, which the
rule does not match.

## MCP rules

`spec.mcp` accepts the same three lists. A pattern names a server (`github`) or a
server/tool pair (`internal-docs/search`); glob patterns are supported in each part. A
server-only rule covers all of its tools. Use the server identifier from your agent
configuration, which may differ from a service's display name.

Some agents rewrite the names they report. opencode replaces every character in a tool
name outside `A-Z`, `a-z`, `0-9`, `_` and `-` with `_`, so `fs/write.file` arrives as
`fs/write_file`. Copilot CLI replaces such characters in both names with `-`, writes a
part with a non-ASCII character in punycode (`xn--…`) and cuts the whole name at 64
characters, so `fs.srv/write.file` arrives as `fs-srv/write-file`. Codex replaces every
character outside `A-Z`, `a-z`, `0-9` and `_` in both names with `_`, `-` included, and
adds `_` and 12 hex digits to a name that would collide or be too long, so `fs.srv` and
`github-mcp` arrive as `fs_srv` and `github_mcp`. Claude Code writes a server name in
`mcp__<server>__<tool>` with `_` for characters outside `A-Z`, `a-z`, `0-9`, `_` and
`-`. Deny and ask rules still match these names. Their wildcards may match more broadly
when rewriting changes character widths or punycode moves characters. Allow rules
match only the name as the agent reports it: to
allow such a tool, also list the agent's form (`fs/write_file` for opencode,
`fs-srv/write-file` for Copilot, `fs_srv/write_file` for Codex). The audit log shows the names as reported.

MCP policy rules govern server/tool names, not argument semantics or server behavior.
Secret detection also checks argument content supplied by adapters.

## Secret detection

`spec.secrets.action` defaults to `deny`. `ask` requests confirmation where supported;
`off` disables enforcement scanning. Audit redaction remains enabled independently.

Checks cover command text, credentials added by writes/edits, and MCP argument content
available to the adapter, including object keys and string values. Edits check the
complete resulting file; credentials already present may remain in place. A patch that
moves a file also checks credentials already in the source. Scan inputs, including the
resulting contents of an edited file, are limited to 4 MiB; larger inputs are blocked
when secret checks are enabled.
Commands that exceed shell expansion limits are blocked even with `action: ask`.
Audit logs redact these commands in full.
`spec.secrets.ignore` lists detection rule IDs to exclude.
`check` warns about IDs this build does not know without rejecting them. Review the
reported `secrets.<id>` before adding an exception. Detection does not replace file
rules or a credential manager; see the [security model](security-model.md).

## Session controls

The tripwire is disabled unless `spec.session.tripwire` is present. A present block
enables it unless `enabled: false` is set. `maxDenials` defaults to `3` and accepts
`1`–`1000`. Omit `window` to count the whole session, or use a duration such as `30m`
(at least one minute, integer `s`, `m` or `h`).

Once locked, the session remains blocked until a user runs `cyberboar unlock` with the
same state directory as the hook. Ask decisions converted to denials by an adapter do
not count as policy denials. Session and subagent behavior is listed in the [capability
matrix](capability-matrix.md).

The briefing is enabled by default. Set `spec.session.briefing.enabled: false` to
disable it, or supply `message` (1–2000 characters) for extra instructions. A briefing
is advice, not an enforcement rule. Run `apply` again after changing whether the
briefing hook should be installed.

## Version, audit and sync settings

| Field | Default | Meaning |
|---|---|---|
| `spec.minimumVersion` | No floor | Minimum release version, such as `1.0.0-rc.1`. An older or unversioned development binary denies all calls. |
| `spec.audit.sink` | Unset | Expected enrolled console events URL. Does not create a log or start shipping. |
| `spec.sync.shipEvery` | One run | Interval for `ship --policy FILE`; `0s` or at least `1s`. |
| `spec.sync.pullEvery` | One run | Interval for `pull` reading the signed installed policy; `0s` or at least `10s`. |

Use Go durations (`5s`, `10m`, `4h`), not days. Explicit `--every` overrides the policy.
Start pull/ship processes with a service manager. Enable local logging with `apply
--audit`, not `spec.audit.sink`.

## Policy lint and regression tests

`cyberboar check` reports non-failing warnings for exact duplicate/conflicting patterns; it does not attempt to infer overlaps between different globs. `cyberboar test --policy FILE --cases FILE` checks YAML fixtures with the existing policy evaluator. See [Policy regression tests](policy-tests.md). Neither command verifies that an agent installed or honored its hook.

## Test and install a change

```sh
cyberboar check .cyberboar/policy.yaml
cyberboar explain --policy .cyberboar/policy.yaml --read .env
cyberboar explain --policy .cyberboar/policy.yaml --command 'git push origin main' --verbose
cyberboar explain --policy .cyberboar/policy.yaml --mcp internal-docs/search
```

`check` validates the policy. `explain` does not run the action and exits `0` even for a
denial; use `--json` for scripts. Neither proves the agent invokes its hook. After
deployment, verify harmless allowed and denied calls in an actual session. Re-sign
signed updates with a higher serial; see [Operations](operations.md). The [rule
corpus](../testdata/corpus/) supplies executable matching examples.
