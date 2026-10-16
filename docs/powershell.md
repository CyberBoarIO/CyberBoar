# PowerShell support

**Experimental: PowerShell commands are not analyzed by the production engine.** The parser
exists as development work, but is not connected to policy evaluation. There is no
released policy opt-in or `explain --powershell` flag.

## Current behavior

| Entry point | Result |
|---|---|
| Claude Code `PowerShell` tool | Hidden by a native deny rule and denied as `builtin.powershell` if a call reaches the hook. Use Bash. |
| Codex, Copilot CLI, Cursor or opencode on native Windows | Unsupported; calls are denied. Use WSL or a Linux dev container. |
| `pwsh -Command` or `powershell -EncodedCommand` inside Bash | Treated as inline foreign code; denied by default through `commands.denyInterpreters`. |

Setting `denyInterpreters: false` does not enable PowerShell analysis: it permits opaque
code subject to the remaining rules. Do not use it as a substitute for shell support.

Native Windows currently means Claude Code with Git Bash. Use the Linux binary inside
WSL or a Linux container. A human can run installation commands from PowerShell without
enabling PowerShell enforcement for an agent.

## Validation status

The development parser was built with AI assistance and has not been thoroughly
validated as a security control. Parser fixtures and a differential against PowerShell's
own parser exercise syntax, not end-to-end agent enforcement.

Production support requires engine integration, adapter validation, file and command
matching tests, resource-limit checks and real-agent Windows testing. Proposed options
in development designs are not part of the current policy or CLI contract.

See [System requirements](system-requirements.md), [Agent setup](agents.md) and the
[capability matrix](capability-matrix.md) for supported configurations.
