# Policy distribution and auditing

Local hooks work without enrollment or a console. Signed bundles can distribute policies
from a static HTTPS host; an existing log agent can collect audit records. Enrollment
and `ship` require a compatible console service, which is not included in the endpoint
release.

## Choose a deployment

| Deployment | Policy source | Audit collection | Enrollment |
|---|---|---|---|
| Local | Local YAML file | Optional local JSON lines | Not needed |
| Static distribution | Signed bundles on HTTPS | Existing log agent / SIEM | Not needed |
| Compatible console | Assigned signed bundles | Authenticated `ship` batches | Required |

## Sign a policy

Keep the private Ed25519 key in a protected signing environment. Distribute only its
public key. `keygen` is optional: compatible PKCS#8 private and PKIX/SPKI public PEM
keys from other tools are accepted.

From the repository root:

```sh
mkdir -p policies
cp examples/baseline.yaml policies/baseline.yaml
cyberboar check policies/baseline.yaml
cyberboar keygen --private policy-signing.key --public policy-signing.pub
cyberboar sign --key policy-signing.key --serial 1 --expires 720h policies/baseline.yaml
cyberboar verify --pubkey policy-signing.pub policies/baseline.yaml
```

Do not commit the private key. Increase the serial for every subsequent signature, using
one counter across all policies in a deployment. Serialize signing jobs or use another
monotonic counter: Unix seconds alone can collide when jobs run together.

Expiry is a duration or RFC 3339 time, at most 366 days ahead. `0` or `never` disables
expiry with a warning and allows a distribution server to freeze a policy indefinitely.

To require signatures in a local Claude Code installation, preview this command, then
repeat with `--write`:

```sh
cyberboar apply --agent claude-code --scope local --policy policies/baseline.yaml --pubkey policy-signing.pub
```

## Publish static bundles

```sh
cyberboar bundle --pubkey policy-signing.pub --out site policies
```

Serve the contents of `site` over HTTPS at `/api/v1/bundles/<metadata.name>`. The host
must support TLS 1.3 and serve the paths directly, without redirects. Configure JSON
content types.

Keep the output directory between builds, or synchronize the published site with
deletion. `bundle` removes bundles deleted from the input directory; uploading only new
files can leave old policies on the host.

On an unenrolled endpoint:

```sh
cyberboar pull --server https://policies.example.test --name baseline --out ./policy.yaml --pubkey ./policy-signing.pub --every 0s
```

Replace the example URL and provision the trusted public key separately. Use `--every
10m` to keep pulling, supervised by a service manager. An enrolled endpoint uses its
assigned console and policy and cannot switch to an arbitrary static host through these
options.

## Refresh, expiry and rollback

- Sign on a schedule even without content changes. Choose an expiry longer than
  the expected offline period, and monitor refresh failures.
- Failed updates leave the installed policy intact. After expiry, all hook calls
  are denied until a valid replacement arrives. There is no grace period.
- Lower serials are refused. An equal serial requires the same installed
  signature. Restore older contents by signing them with a new, higher serial.
- Policy changes affect subsequent hook invocations. Changed command options or
  installed briefing handlers require another `apply` run.

`spec.sync.pullEvery` supplies the pull interval when `--every` is omitted.
`spec.sync.shipEvery` does the same for `ship --policy FILE`. Explicit `--every` takes
precedence; `--every 0s` forces one run. These fields do not start processes. See
[policy sync settings](cli.md#policy-sync-settings).

## Record local decisions

Preview an installation with local logging:

```sh
cyberboar apply --agent claude-code --scope local --policy .cyberboar/policy.yaml --audit .cyberboar/audit.jsonl
```

Add `--write` after inspecting it. `apply` makes the audit path absolute. An unwritable
configured log denies the call. `spec.audit.sink` alone does not enable logging.

| Event field | Use |
|---|---|
| `time`, `agent`, `version` | Identify source and time. |
| `session`, `toolUseId` | Correlate calls when supplied. |
| `decision`, `rule`, `reason` | Inspect the decision and responsible rule. |
| `tool` | The agent's own name for the tool. Codex calls its shell tool `Bash`, PowerShell on Windows included. |
| `policyName`, `policySha256` | Identify the policy used. |
| `actions` | Inspect inferred file, shell or MCP actions. Empty when the call is refused before it is understood (an `error.*` or `adapter.*` rule). |
| `actionsOmitted` | Detect a size-bounded, incomplete action list. |
| `durationMs` | Observe decision latency. |

Events record decisions, not execution results. Newer fields may appear; see the [event
schema](../pkg/audit/schema/event.v1.json). Recognized credentials are redacted, but
logs still need restricted access and appropriate retention.

## Use a compatible console

A service must implement the [protocol](protocol/README.md), including mutual TLS and
request/response signatures. Enrollment establishes identity and policy assignment; it
does not install hooks.

```sh
cyberboar enroll --server https://console.example.test --token-file ./enrollment-token --state ./state
cyberboar pull --state ./state --out ./policy.yaml --pubkey ./policy-signing.pub --every 0s
cyberboar ship --state ./state --audit ./audit.jsonl --every 0s
```

Use a token file, stdin (`--token-file -`) or `CYBERBOAR_ENROLL_TOKEN`; there is no
token-value flag. Protect the state directory for the account running these commands.
Endpoint identity and policy-signing keys are separate.

`ship` retains its cursor and retries unacknowledged batches. Delivery is at least once.
Services stay silent on empty rounds; a one-shot run prints its summary. Coordinate
rotation with the shipping service and perform a
successful final upload first; see [audit rotation](deploy-mdm.md#rotate-the-audit-log).

For ownership, service definitions, key storage, upgrades and recovery, follow [MDM
deployment](deploy-mdm.md).
