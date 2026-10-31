# Changelog

Release notes for CyberBoar packages: policy format, CLI, protocol, agent integrations
and enforcement. Stable releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting with `v1.0.0`. The v1 compatibility contract covers the policy format, CLI,
protocol, audit schema and public Go packages under `pkg/`.

## [Unreleased]

### Added

- Audit events: a shell action has `shell: powershell` when its command is read as
  PowerShell. Codex names its shell tool `Bash` on Windows too, so `tool` alone can't
  tell them apart.
- `explain --shell` and a policy test's `shell:` accept `bash`, the default, by name.
- Audit events have an `id`, a version 7 UUID, so a console can drop an event it
  already stored when a batch is sent again.
- `ship` finishes a rotated audit log: when the log was renamed (`audit.jsonl.1`) or
  copied and truncated, it sends the rest of the old log first, found next to the new
  one by how it starts. Before, lines the old log got after the last run were lost.
- Protocol: event batches carry `stats`, running totals of logs lost to rotation (the
  old log gone) and of invalid lines skipped, so a console can see lost events.
  Consoles must accept the field; older endpoints don't send it.

### Changed

- Errors from the packages under `pkg/` wrap their cause, so `errors.Is` and
  `errors.As` reach it.
- `bundle.Source` no longer has a `Policy` field, whose type was internal and so not
  something the v1 compatibility promise could cover. Parse `Source.Data` instead.

### Fixed

- Audit events: a Codex command the adapter refuses (another shell on Windows, a
  terminal, another environment, a call missing from the transcript) is listed in
  `actions`, which were empty before.
- A `cd` whose `..` leaves a symbolic link (`cd link/../other`) is followed as the
  shell follows it, to the directory holding the link, and also as the kernel and
  `cd -P` follow it, to the target's parent.
- Globs match with bash's grammar, including character classes (`token[[:digit:]].txt`),
  and by byte as in the C locale. A glob that the analysis can't match, with a collating
  symbol (`[[.1.]]`) or a bracket expression for a name that isn't ASCII, counts as any path.
- A `file:` URL is checked as the path curl opens: `%XX` decoded, the scheme in any case,
  `file:/path`, and without its query and fragment. Before, `file:///…/%74oken.txt`
  could read a denied `token.txt`.
- PowerShell: `Start-Process -Environment` is checked as `$env:` assignments are, so
  a variable that makes a program run code (`GIT_CONFIG_*`, `GIT_SSH_COMMAND`) is
  inline code; a map known only at run time is treated as inline code too.
- PowerShell: secrets are looked for in the strings as PowerShell reads them, so an
  escape (``gh`p_…``) or strings joined with `+`, `-join` or `-f` no longer hide a
  token from the check or from the audit log's redaction.
- PowerShell: `Invoke-WebRequest` and `Invoke-RestMethod` check a `-Uri` that names a
  local file, a `file:` URL or a drive path, which Windows PowerShell 5.1 reads. A
  `-Form` value that may be a file object (`Get-ChildItem`'s output, a variable) asks
  about the file it uploads.
- PowerShell: `New-Item` checks a link's target (`-Value`, `-Target`) with what it
  holds, as `ln`'s target is, so a link made and read in one command can't reach a
  protected file.
- PowerShell: a variable name given to `-OutVariable`, `-ErrorVariable` and the other
  parameters that name one is checked as a variable written: `env:` sets an environment
  variable and a drive path writes a file.
- A glob that matches nothing is read as any other word, so an unquoted
  `file:///…/token.txt?x` is checked as the file curl opens.
- `git grep` with no path searches the work tree (or, with `--no-index`, the
  directory), as `grep -r` does, so `git grep KEY` no longer reads a denied `.env`.
- On Windows and macOS a program named in other capitals is the program (`RM -rf
  .claude`, `Git grep KEY`), as their filesystems find it; what it does is checked as
  for the lower-case name.
- `xcopy` and `robocopy` are checked as copies: the files they write in the
  destination, and with `robocopy /MOVE` the source, so they can't replace a guarded
  file.
- PowerShell on Windows: an unquoted wildcard given to a program (`findstr KEY *`,
  each element of `a,*`) is matched as the program matches it, without case and with
  names that start with a dot. Before, it was taken as a name.
- PowerShell on Windows: an unquoted `~`, `~\…` or `~/…` given to a program is the
  home folder, as PowerShell 7.6 passes it, and a program run as `& ~\…` is in the
  home folder. When older versions' reading, a folder named `~`, may be another file,
  the command asks.
- PowerShell: a wildcard path under `~` (`Get-Content ~\.ssh\I*`) is matched in the
  home folder.

## [v1.0.0-rc.3] - 2026-10-28

Third release candidate for CyberBoar 1.0. It adds PowerShell analysis, checks
Claude Code's PowerShell tool and Codex CLI on native Windows, and guards shell
startup files for every agent. Claude Code users re-run `apply --agent claude-code`
to install the new native rules. Tested on Windows 11 with Claude Code 2.1.312,
Codex CLI 0.165.0 and PowerShell 7.4.22.

### Added

- PowerShell analysis: the engine reads a checked subset of PowerShell, the
  common file cmdlets and their aliases, programs, and the constructs that run
  code, and applies the same policy rules as for Bash. Anything outside the
  subset is treated as able to do anything. See [PowerShell support](docs/powershell.md).
- Claude Code's `PowerShell` tool is checked on native Windows, with or without
  Git Bash. Elsewhere it is still denied.
- Codex CLI on native Windows, whose commands run in PowerShell. A command sent
  to another shell, such as `cmd.exe` or Git Bash, is denied
  (`adapter.windowsShell`). `apply` writes the hook as a command line that
  works in both PowerShell, where Codex runs hooks in the session's shell, and
  `cmd.exe` (`command` and `commandWindows`). The program's path goes in without
  quotes, so a path with spaces needs an 8.3 short name. This covers the user and
  managed scopes; the project scope isn't available there. The hook guards Codex's managed directory
  (`%ProgramData%\OpenAI\Codex`) and the user's PowerShell profile and module
  folders, which Codex runs.
- `explain --shell powershell` reads a command as PowerShell, and a policy test
  case can set `shell: powershell`.

### Changed

- `apply --agent claude-code` no longer denies the whole `PowerShell` tool. It
  mirrors every native `Bash(…)` rule as a `PowerShell(…)` rule, which also keeps
  Claude Code from switching the tool off, and adds `PowerShell(Invoke-Expression *)`
  under `denyInterpreters`. Re-run `apply` to install them.
- `builtin.powershell` now denies Claude Code's PowerShell tool only outside
  native Windows, and the Windows session briefing no longer tells the agent to
  avoid it.
- Codex: the hook answers a deny as JSON with exit code 0 instead of exit code 2,
  for every deny including configuration errors. Under PowerShell, Codex sees
  exit code 2 as 1, a failed hook, and runs the tool call. Re-running `apply` is
  not needed for this change.
- Source builds need Go 1.27.3, whose release fixes vulnerabilities in
  `crypto/x509`; release binaries are built with it.

### Fixed

- Shell startup files are guarded for every agent: `~/.profile`, bash's and
  zsh's files (also in `$ZDOTDIR`), and the files `$BASH_ENV` and `$ENV` name.
  Agents' shells run them before commands or at session start, outside the
  hook's checks. Claude Code's native rules cover them too after `apply`.
  The `builtin.guarded` reason no longer calls every guarded file CyberBoar's
  configuration.
- Claude Code: custom agents, skills and commands, whose frontmatter can
  declare hooks that Claude Code runs without the CyberBoar hook seeing them,
  are guarded like settings files. That is `.claude/agents`, `.claude/skills`
  and `.claude/commands` in `~/.claude`, `CLAUDE_CONFIG_DIR`, the project and
  every folder above it up to its git work tree, and installed plugins in
  `~/.claude/plugins`. Claude's file tools may read them, but not change them,
  and the shell may not touch them. `apply`
  writes native `Edit` denies for these folders at any depth; re-run `apply`
  to install them. Skills in folders below the project and folders added with
  `--add-dir` are still not guarded against shell writes.
- On Windows, the reason for a refused workspace root, such as an agent started
  in the home folder, shows the path as `C:\Users\…` instead of `/c/Users/…` and
  says to start the agent in a project folder.

### Known limitations

- PowerShell support is new and its real-agent testing on Windows is limited.
  Windows PowerShell 5.1 commands are read with PowerShell 7's grammar.
- Codex runs the user's PowerShell profiles; CyberBoar trusts them as the user's configuration and keeps agents from changing them.
- Copilot CLI, Cursor and opencode remain unsupported on native Windows.

## [v1.0.0-rc.2] - 2026-10-20

Second release candidate for CyberBoar 1.0. It adds GitHub Copilot in VS Code and
fixes shell analysis found in RC1. Copilot users re-run `apply --agent copilot-cli`
to install the new hook form.

### Added

- GitHub Copilot in VS Code: the `copilot-cli` hook now covers VS Code's
  Copilot session target and its Local agent (verified with VS Code 1.142 and
  GitHub Copilot Chat 0.70). The Local agent's file, terminal, task, search, URL
  and MCP tools are classified. Tools the hook can't check (typing into
  a terminal or running VS Code commands), and extensions' tools are denied.
  VS Code's settings that can switch hooks off are guarded, in every profile.
  For Copilot CLI and VS Code, hook files and workspace settings are
  guarded in the session's folder and every folder above it up to its git work
  tree, and so are custom agents and agent plugins, whose hooks VS Code runs.
  `apply` informs when the Local agent won't read the installed hook (managed
  scope, or `COPILOT_HOME` set).

### Changed

- `apply --agent copilot-cli` writes the hook as a quoted `bash` command ending
  in `|| exit 2`, with a `powershell` command that denies every call on native Windows.
- Copilot hook answers carry `hookSpecificOutput`.

### Fixed

- A shell variable that the command line sets to a plain value before using
  it (`f=src/main.go; cat "$f"`) is resolved and checked as that path, instead
  of asking for confirmation. Lines where something else could change the
  variable, lines that use it in a form the analysis doesn't model (`$f:r`,
  `"$f[1,-2]"`, `$~f`, `[[ ]]`, `${f:=…}`), lines that assign a special variable
  (`IFS`, `PATH`, `HISTSIZE`), and shells that persist between tool calls, are
  unchanged.
- A value the shell evaluates as code or as a name (`${x@P}`, `${!x}`, arithmetic
  on a name that may hold something other than a number, a substring offset, an
  integer or name-reference declaration, a zsh integer parameter, and a subscripted
  name given to `test -v`, `printf -v`, `print -v`, `unset` or `read`) asks for
  confirmation. It is denied as inline code when the line itself holds that code,
  as in `y='$(cmd)'; : "${y@P}"`. Counters and loops over numbers, such as
  `n=$((n + 1))` and `for ((i=0; i<3; i++))`, are not asked about.
- `bash --version`, `zsh --version` and `--help` run no code and are allowed
  instead of being denied as inline code.
- The hint for an unresolved variable leaves out the `f=path` example in a
  persistent shell, where that form isn't followed.
- `ls ~/…` shows a directory only known at run time as `…/` instead of `*/`.
- A shell word only known at run time is named as written (`"$f"`) in
  decisions and `explain` output instead of `…`, with a hint on making the
  path checkable.
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
