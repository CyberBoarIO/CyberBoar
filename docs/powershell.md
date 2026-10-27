# PowerShell support

On native Windows, CyberBoar checks the PowerShell commands of **Claude Code's
`PowerShell` tool** and of **Codex CLI**. It reads a checked subset of PowerShell and
applies the same policy rules as for Bash. Anything outside that subset is treated as
able to do anything, so it is checked strictly. Support is new in `v1.0.0-rc.3`; see
[Validation status](#validation-status).

## Where PowerShell is checked

| Entry point | Result |
|---|---|
| Claude Code `PowerShell` tool on native Windows, with or without Git Bash | Analyzed. Each command runs in a new process; only the working directory carries over, and the hook input gives it. |
| Codex CLI on native Windows | Analyzed. Codex runs every command in PowerShell (`pwsh`, else Windows PowerShell). A command sent to another shell, such as `cmd.exe` or Git Bash, is denied (`adapter.windowsShell`). |
| Claude Code `PowerShell` tool on Linux or macOS | Denied (`builtin.powershell`); the agent is pointed to the Bash tool. |
| Copilot CLI, Cursor or opencode on native Windows | Denied (`error.unsupportedPlatform`). Use WSL or a Linux dev container. |
| `pwsh -Command`, `powershell -EncodedCommand` inside a Bash command | Inline foreign code, denied by default through `commands.denyInterpreters`. |

Setting `denyInterpreters: false` permits opaque inline code subject to the remaining
rules; it does not make nested PowerShell checkable.

## What the analysis reads

- **Programs** (`git`, `npm`, `.\build.ps1`) are read as in Bash: the name is matched
  against command rules and every argument is checked as a possible path.
- **Common cmdlets** are bound by parameter, so the engine knows which values are paths
  and whether they are read, listed, written or deleted. They are the file cmdlets
  (`Get-Content`, `Set-Content`, `Add-Content`, `Get-ChildItem`, `Copy-Item`,
  `Move-Item`, `Remove-Item`, `Rename-Item`, `New-Item`, `Test-Path`, `Out-File`,
  `Tee-Object`, `Select-String` and others), item properties, ACLs, CSV, CLIXML and
  archives, plus `Start-Process`, `Invoke-WebRequest` and `Invoke-RestMethod`.
  A cmdlet not in this set is read like a program.
- **Aliases** (`ls`, `cat`, `gc`, `rm`, `iex`) resolve to their cmdlets. A policy
  allow rule for an alias or its cmdlet allows both. `explain` on Linux or macOS reads
  `ls` and `cat` as the programs, as pwsh does there.
- **Windows paths** go through the same checks as Claude Code's Windows paths: drives,
  trailing dots, streams, junctions and 8.3 names. UNC and device paths are denied.
- **Bash started from PowerShell** (`bash -c '…'`) is read as Bash, with Git Bash's
  paths.

The following count as **inline code**, which `denyInterpreters` denies:
- `Invoke-Expression`;
- `[scriptblock]` casts;
- `Add-Type`, except for loading an assembly by name;
- `New-Object` with a COM object or a type outside a short list of harmless ones;
- a nested `pwsh -Command` or `-EncodedCommand`.

A script block run in place (`& { … }`, `ForEach-Object { … }`) is analyzed as part of
the command.

These leave the meaning only known at run time:
- variables;
- a command name built at run time;
- an alias defined on the command line (`Set-Alias`), which makes every later name
  unknown;
- a drive defined with `New-PSDrive`, which makes every drive path unknown.

As for Bash, a deny or ask rule that such a command might match asks for confirmation
(Codex, which can't ask, denies), and an allow list doesn't cover it.

Some syntax isn't read at all, and a command that uses it is denied as unparseable
(`error.unparseable`), whatever it does. That includes the ternary operator, `??` and
`??=`, null-conditional member access, `using` statements, `#Requires`, `--%`
(stop-parsing), `$using:` variables, loop labels, `clean` and `dynamicparam` blocks,
`switch -File`/`-Parallel`, generic method calls, number type suffixes and
assembly-qualified type names. Rewrite such a command in plainer PowerShell.

## Profiles and modules

Claude Code's PowerShell tool doesn't load PowerShell profiles. Codex starts PowerShell
as a login shell unless the model asks otherwise, which runs the user's profiles before
every command.

CyberBoar treats a profile as the user's own configuration, as it does Bash startup
files, and reads command names as PowerShell defines them. To keep an agent from adding
to them, the Codex hook guards the user's PowerShell folders
(`Documents\PowerShell` and `Documents\WindowsPowerShell`, wherever Windows has moved
the Documents folder). They hold the profiles and the user's modules, which load when
one of their commands is named. The all-users profiles under the PowerShell installation
directory need administrator rights to change.

## Native rules

`apply --agent claude-code` mirrors every native `Bash(…)` deny and ask rule as a
`PowerShell(…)` rule, and adds `PowerShell(Invoke-Expression *)` under
`denyInterpreters`. Claude Code switches the PowerShell tool off in a session whose
settings deny anything in Bash, unless a `PowerShell` rule exists, so the mirrored rules
also keep the tool available. Native rules are a fallback for when the hook can't run;
the hook does the checking.

## Testing a policy

`cyberboar explain --shell powershell --command '…'` shows how a PowerShell command
line is read and decided ([CLI reference](cli.md)). In [policy tests](policy-tests.md),
a case with `shell: powershell` checks a PowerShell command.

## Validation status

The parser is a port of PowerShell 7's, built with AI assistance. A differential test
against PowerShell's own parser, parser fixtures, fuzzing and resource-limit checks
cover it, and the engine has a PowerShell decision corpus. Windows PowerShell 5.1
commands are read with PowerShell 7's grammar; a construct that only PowerShell 7
accepts fails to run on 5.1.

Real-agent testing on Windows is limited. Report a command the analysis reads wrongly
as a [security issue](../SECURITY.md) if it lets an action through that the policy
denies.

See [System requirements](system-requirements.md), [Agent setup](agents.md) and the
[capability matrix](capability-matrix.md) for supported configurations.
