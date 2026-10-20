# Troubleshooting

Start with the returned decision and rule ID. Reproduce problems with dummy data, and
retain the policy and agent version involved.

## Check the installation

1. Run `cyberboar version` using the executable path in the agent's settings.
2. Run `cyberboar check POLICY`.
3. Confirm the hook's policy, public-key, audit and state paths are accessible
   to the agent's account. Managed pull/ship state may belong to a different
   account from hook tripwire state.
4. Reload the agent configuration. In Codex, trust user/project hooks in `/hooks`.
5. Test allowed and denied calls in a session. If logging is enabled, confirm
   the matching event.

`explain` evaluates independently and does not prove a hook is installed. Previewing
`apply` does not write settings; installation requires `--write`.

## Common symptoms

| Symptom | Check and recovery |
|---|---|
| Every call is denied | Check the error reason, policy path/schema, signature, expiry and `minimumVersion`. Development builds meet no version floor. |
| A denied operation runs | Verify scope, hook loading, Codex trust and audit event. Review agent hook failure and visibility limits. |
| An ask rule blocks without prompting | Codex, Cursor and opencode receive deny for ask; Copilot also denies in headless mode. |
| Cursor shell commands with relative paths are denied | Cursor's shell keeps its directory between calls and reports it only when the call sets a working directory. Start the command with `cd /absolute/project/path &&`. |
| Copilot in VS Code doesn't run the hook | Trust the workspace, keep `chat.useHooks` on and start a new chat. Run `apply` again if CyberBoar 1.0.0-rc.1 wrote the hook: VS Code's Local agent skips its `exec` form. **Chat: Configure Hooks** lists the files VS Code loaded; the **GitHub Copilot Chat Hooks** output channel shows each run. |
| Copilot terminal commands in VS Code ask for confirmation | The agent terminal keeps its directory between commands and VS Code doesn't report it, so relative paths may be anywhere. Start the command with `cd /absolute/project/path &&`. |
| Native Windows calls are blocked | Use Claude Code with Git Bash or another agent with the Linux binary in WSL/a Linux container. |
| A read gets `builtin.guarded` | Shell access to guarded settings is a potential write. Use a native read tool for inspection; a user must change settings. |
| A recursive search/archive is blocked | The directory may contain a protected file or built-in protected path. Review `files.containing` and narrow the operation. |
| `secrets.<id>` blocks test data | Review the finding. Use placeholders; add a justified `secrets.ignore` exception only after review. |
| Session remains blocked | The tripwire is locked. Inspect with `unlock` and investigate before unlocking. |
| No audit file exists | Confirm `--audit` in the installed hook. `spec.audit.sink` does not create a log. |
| Audit errors block calls | Check ownership, append permissions, free space and the absolute path. |
| Tools break after a binary update/removal | Restore a valid binary at the configured path or update settings with `apply`. |

From the affected project directory:

```sh
cyberboar explain --policy .cyberboar/policy.yaml --command 'cat .env' --verbose
```

For a tripwire, use the hook's same absolute state directory:

```sh
cyberboar unlock --state /absolute/path/to/hook-state
cyberboar unlock --state /absolute/path/to/hook-state --agent claude-code --session SESSION_ID
```

## Signed policy and transport failures

| Failure | Action |
|---|---|
| Invalid/expired signature | Run `verify --pubkey KEY POLICY`. Publish a valid newly signed policy with a higher serial. |
| Update rejected as rollback | Re-sign older contents with a higher serial; do not delete rollback state to bypass the check. |
| Pull reports a lock error | Retry after the competing process finishes. The persistent `.lock` filename is normal; the process lock releases on exit. |
| Redirect or TLS error | Serve directly over TLS 1.3. Use `--ca` for a trusted private CA. |
| Enrollment refuses another host/name | Follow managed reassignment or migration; enrollment pins console and assignment. |
| Certificate expired | Re-enroll with a valid token, retaining key and ID. Expired certificates cannot renew. |
| `401 stale` | Correct endpoint/console clock synchronization. |
| `ship` cannot deliver | Check enrollment, URL, permissions and signatures. Unacknowledged events remain local for retry. |

Enrollment and shipping require a compatible console service. Skip enrollment for local
use or static distribution. See [Operations](operations.md), [CLI reference](cli.md) and
[MDM recovery](deploy-mdm.md#lapsed-reassigned-moved-and-removed-machines).

## Report a problem

For ordinary issues, include OS/architecture, CyberBoar/agent versions, scope, minimal
policy, exact tool call and observed rule ID. Remove credentials and unrelated personal
data. See [Contributing](../CONTRIBUTING.md) for intake rules.

Report vulnerabilities privately by [email](mailto:security@cyberboar.io) or
[GitHub](https://github.com/CyberBoarIO/CyberBoar/security/advisories/new), as described in
[SECURITY.md](../SECURITY.md). Do not publish bypass details in an issue.
