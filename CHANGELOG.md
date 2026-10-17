# Changelog

Release notes for CyberBoar packages: policy format, CLI, protocol, agent integrations
and enforcement. Stable releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting with `v1.0.0`. The v1 compatibility contract covers the policy format, CLI,
protocol, audit schema and public Go packages under `pkg/`.

## [Unreleased]

### Fixed

- A shell word only known at run time is named as written (`"$f"`) in
  decisions and `explain` output instead of `…`, with a hint that writing the
  path itself lets it be checked.
- A command-line word longer than a file name can be, such as a long `sed`
  script, is checked as a missing path instead of being denied as unresolvable.
- Draft releases take their notes from this changelog again.

## [v1.0.0-rc.1] - 2026-10-16

First public release candidate for CyberBoar 1.0. The package includes the CLI,
policy engine, agent adapters and endpoint clients. RC1 is a prerelease; the stable
v1 compatibility contract starts with `v1.0.0`.

### Package contents

- YAML policies in `cyberboar.dev/v1` controlling supported coding agents'
  file, shell-command and MCP tool calls. Decisions are deny, ask, or no objection;
  hook errors result in denial. No LLM participates in policy evaluation.
- Adapters for Claude Code, Codex CLI, GitHub Copilot CLI, Cursor and opencode,
  each with documented [hook limitations](docs/capability-matrix.md).
- Bash-style command parsing, symlink-aware path checks, secret detection,
  session tripwire, and redacted JSON audit events.
- The `check`, `explain`, `apply` and `test` commands for policy validation,
  decision inspection, hook installation and YAML policy regression cases.
  Policy checks report advisory duplicate or conflicting rule warnings.
- Signed, expiring policy bundles with serial rollback protection, plus endpoint
  clients for TLS 1.3 enrollment, authenticated policy pull and audit shipping.
- Policy-controlled endpoint intervals: `spec.sync.shipEvery` configures audit
  delivery and `spec.sync.pullEvery` configures signed policy refresh. Explicit
  `--every` values override the policy, including `0s` for one run. Running
  services pick up new intervals without restarting.
- Binary archives for Linux, macOS and Windows on x86-64 and ARM64;
  see [system requirements](docs/system-requirements.md).
- [Installation instructions](docs/getting-started.md), per-agent quick demos,
  manual hook configuration, editor integration guides, CLI and protocol references,
  a [policy regression test guide](docs/policy-tests.md), and starter MCP tool rules.
- CyberBoar's license and third-party license notices in release archives.

### Security and reliability

- Installation instructions verify the checksum manifest with Sigstore against
  the official repository, release workflow and tag before checking binary archives.
- Audit shipping advances its cursor only after a valid signed acknowledgment
  accepts every event in the batch. Malformed, partial and oversized responses
  retain events for retry. Services stay silent on rounds with no events.
- Endpoint JSON rejects duplicate keys and case aliases, including nested objects.
- Policy signatures and settings backups use atomic replacement rather than
  following an existing destination symlink or exposing a partial write.
- Invalid console URL errors omit embedded credentials.
- Unicode folding handles valid text following malformed UTF-8.
- MCP deny and ask rules also match the server and tool names that opencode,
  Copilot CLI, Codex and Claude Code rewrite, such as `fs.srv` reported as `fs_srv`.
  Allow rules match the name as the agent reports it.
- Codex commands that request a terminal (`tty`) are denied, because input typed
  into them later (`write_stdin`) never reaches the hook.
- In Cursor's agent shell, which keeps its state between calls, `HOME`, glob options
  and aliases from earlier calls are treated as unknown, and a command without a
  known working directory must start with `cd` to an absolute directory.
- opencode edits whose loose matching could change other text than the text checked
  for secrets are denied.
- Policy bundles skip a policy whose signature file links outside the policy
  directory, without reading it.
- `apply` installs Codex user hooks in `CODEX_HOME` when it is set, and reads the
  commented `config.json` that Copilot CLI writes.

### Known limitations

- CyberBoar is a **policy hook, not an OS sandbox**. Programs launched by an
  agent, network egress and operations outside an agent's hook visibility
  are not controlled.
- On native Windows only Claude Code with Git Bash is supported today.
  PowerShell is not enforced; other Windows agents' PowerShell calls are
  denied. In WSL, use the Linux build.
- Each agent's hook defines its actual enforcement coverage. The Cursor CLI has
  passed the real-agent harness; the Cursor editor has not been verified yet.
- Editor-session verification is pending. Copilot editor support is experimental;
  its Local session target requires a separate adapter.
- Native Intel macOS and Windows ARM64 tests passed, but not every
  real-agent/OS/CPU combination has been tested end-to-end.
- macOS Keychain/Secure Enclave support, Apple notarization and Windows
  Authenticode signing are not implemented yet. See system requirements.
