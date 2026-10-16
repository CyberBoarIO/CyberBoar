# CyberBoar

**Define what coding agents can do. See what they try.**

[Documentation](https://cyberboar.dev/docs/)

CyberBoar evaluates coding-agent tool calls against a YAML policy on the developer's
machine. It checks file access, Bash commands and MCP server/tool names, then returns
`deny`, `ask` or no objection through the agent's hook interface. Optional local JSON
audit logs record its decisions. No LLM participates in policy evaluation.

Adapters are available for Claude Code, Codex CLI, GitHub Copilot CLI, Cursor and
opencode. Coverage and failure behavior depend on the agent; review [agent
setup](docs/agents.md) and the [capability matrix](docs/capability-matrix.md) before
deploying.

The official Claude Code, Codex and opencode editor extensions are supported and under
active testing. The Cursor editor is supported, with real-agent validation pending.
**Copilot editor support is experimental.**
See [editor integrations](docs/editor-integrations.md) for setup, validation status
and session-specific limitations.

## Start here

| Task | Documentation |
|---|---|
| Install, test and remove CyberBoar | [Getting started](docs/getting-started.md) |
| Try a one-minute policy test with your agent | [60-second agent demos](docs/quick-demos.md) |
| Choose a binary and supported shell | [System requirements](docs/system-requirements.md) |
| Write and test a policy | [Policy reference](docs/policy.md) · [Policy regression tests](docs/policy-tests.md) |
| Configure an agent | [Agent setup](docs/agents.md) |
| Configure and verify an editor integration | [Editor integrations](docs/editor-integrations.md) |
| Understand enforcement coverage | [Security model](docs/security-model.md) · [Capability matrix](docs/capability-matrix.md) |
| Sign policies and collect decisions | [Policy distribution and auditing](docs/operations.md) |
| Deploy managed endpoints | [MDM deployment](docs/deploy-mdm.md) |
| Diagnose a blocked call or broken hook | [Troubleshooting](docs/troubleshooting.md) |
| Look up flags and exit statuses | [CLI reference](docs/cli.md) |
| Implement a compatible service | [Protocol reference](docs/protocol/README.md) |

## Quick example

With Go 1.27.2 or later, run from the repository root on macOS or Linux:

```sh
mkdir -p "$HOME/.local/bin"
go build -trimpath -o "$HOME/.local/bin/cyberboar" ./cmd/cyberboar
"$HOME/.local/bin/cyberboar" check examples/baseline.yaml
"$HOME/.local/bin/cyberboar" explain --policy examples/baseline.yaml --command 'cat .env'
```

The last command reports `DENY` under `files.deny[0]`. `explain` evaluates the proposed
action without executing it or installing a hook. Follow [Getting
started](docs/getting-started.md) to verify enforcement in an actual agent session,
including native Windows installation.

A minimal policy blocks `.env` files:

```yaml
apiVersion: cyberboar.dev/v1
kind: Policy
metadata:
  name: starter
spec:
  defaults:
    posture: deny-listed
  files:
    deny: ["**/.env*"]
```

Use [baseline.yaml](examples/baseline.yaml) or
[advanced-baseline.yaml](examples/advanced-baseline.yaml) as a broader starting
point. Review each rule for your environment before installing it.

## How enforcement works

1. An agent sends a proposed tool call to its CyberBoar hook or plugin.
2. CyberBoar translates the call into actions and evaluates the policy.
3. The adapter returns the decision in the agent's protocol. If an audit path is
   configured, CyberBoar appends a redacted decision event locally.

`allow` means the action passed CyberBoar's checks. The agent's own permissions still
apply. Agents that cannot safely request confirmation receive a denial for `ask`
decisions. CyberBoar denies invalid inputs, unavailable policies and decision errors; an
agent that cannot launch its hook may have different failure behavior.

## What it does not do

CyberBoar is a policy hook, not an operating-system sandbox. It cannot observe every
file a launched program opens, govern network egress, or enforce calls the agent does
not send to a hook. Users who control their machine can disable an advisory
installation. Managed settings and OS permissions can protect deployment configuration;
an OS sandbox is needed for a process-level boundary.

See the [security model](docs/security-model.md) for path, shell, secret-detection and
deployment limits. On native Windows, use Claude Code with Git Bash. Other agents
require WSL or a Linux dev container; [PowerShell analysis](docs/powershell.md) is not
connected to the production engine.

## Fleet use

Signed policy bundles can be served from a static HTTPS host without a console.
Endpoints verify signatures, expiry and serial numbers before installing an update.
Audit logs can be collected with an existing log agent.

`enroll` and `ship` require a compatible service implementing the endpoint protocol.
This endpoint release does not include a console service. See [Policy distribution and
auditing](docs/operations.md) for both deployment options.

## Project information

- [Contributing](CONTRIBUTING.md): development workflow and contribution guidelines.
  Bug reports, proposals and patches are welcome. Patches require an accepted
  [CLA](docs/cla/README.md) before merging.
- [Security policy](SECURITY.md): report vulnerabilities privately by
  [email](mailto:security@cyberboar.io) or
  [GitHub](https://github.com/CyberBoarIO/CyberBoar/security/advisories/new).
- [Changelog](CHANGELOG.md): release changes and compatibility status.
- [License](LICENSE): `AGPL-3.0-only`. The protocol reference includes an additional
  permission for compatible implementations. The commercial console is a separate
  product.

Please use a distinct name for forks and do not imply official affiliation with or
endorsement by the CyberBoar project.
