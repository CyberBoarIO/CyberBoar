# Security model

CyberBoar makes policy decisions for tool calls delivered by an agent's hook or plugin.
It is not an operating-system sandbox. Coverage depends on hook visibility, the
information supplied with each call, and permissions protecting the installed
configuration.

## Enforcement boundary

| Layer | Responsibility |
|---|---|
| Agent hook/plugin | Deliver the proposed call and honor the decision. |
| CyberBoar adapter | Translate known tools into file, shell or MCP actions; deny unclassified tools. |
| Policy engine | Evaluate deterministically and deny decision errors. |
| OS and administrator | Protect deployment files and constrain launched processes. |

`allow` does not grant permissions; the agent's own approval system still applies. `ask`
becomes deny where the interface cannot safely request confirmation. A call outside hook
visibility has no CyberBoar decision or hook audit event.

## Failure handling

Invalid input, unreadable/invalid policies, signature failure, expired signed policies,
decision timeout and internal evaluation failure produce denial. If logging is
configured, inability to append an event also denies. CyberBoar has no fail-open option.

An agent may fail open when its hook cannot launch or the hook protocol fails. Review
[agent failure behavior](agents.md#failure-behavior) and the [capability
matrix](capability-matrix.md) separately from engine behavior.

## File and shell coverage

Native file tools expose paths directly. Shell analysis parses Bash syntax and models
named paths, redirections, pipelines, nested shell code and selected program options
without executing anything.

- Launched programs can open files absent from their command line. Scripts,
  build tools, test runners, task targets and container entrypoints are opaque.
  Govern their invocation with command rules where appropriate.
- A path rule sees an explicit SSH key argument, but cannot stop `git push`
  from reading SSH's default key internally.
- Symlinks and path aliases are checked. Hard links, bind mounts and races
  between checking and execution are outside the path-rule boundary.
- Unsupported zsh syntax is denied. Syntax interpreted differently by Bash
  and the actual shell can remain a bypass.
- Shell configuration such as `dotglob`, `nullglob` and `CDPATH` is not visible
  unless supplied in the analyzed command. Missing shell or working-directory
  information can make adapter decisions more restrictive.

Native Windows support covers Claude Code (Git Bash and its PowerShell tool) and Codex
CLI (PowerShell). Unknown mounts and ambiguous Windows paths are denied. PowerShell is
analyzed as a [checked subset](powershell.md): constructs outside it are treated as
able to do anything, and the user's PowerShell profiles, which Codex runs, are trusted
as the user's configuration. See [system requirements](system-requirements.md).

Shell startup files (`~/.bashrc`, `~/.zshrc` and the others the agents' shells read)
are guarded, since what they hold runs outside the hook's checks. A program the agent
starts can still write them, as it can any file.

## Secrets, MCP and network access

Secret checks cover command text, credentials added by writes/edits, and MCP argument
content available to the adapter, including object keys and string values. Patch moves
check the complete rewritten file, including credentials already in the source.
Edits scan the complete resulting file so a credential assembled from existing and new
text is checked. Cursor does not document its write tools' inputs, so a Cursor write is
checked on the text it carries alone. Scan inputs over 4 MiB are blocked when secret checks are enabled.
The checks recognize some quoting, escape, variable and
encoding forms, but cannot discover every secret or reconstruct values obtained only at
runtime or assembled across calls. Tools that send text without touching local files
are not scanned: web fetch and search (`WebFetch`, `WebSearch`, `web_fetch`, `webfetch`,
`websearch`) and messages to other sessions or the user (`SendMessage`,
`PushNotification`, `ArtifactComments`), so a credential in a URL or a message is not
found. Detection is not general data-loss prevention.

MCP rules match server/tool names. They do not validate argument semantics or constrain
the server after a permitted call. Network egress and git history are not inspected.
Denying `curl` does not create a network boundary for other programs.

## Configuration integrity

Built-in guards deny direct agent changes to hook settings, policy, key, audit log,
binary and state. Indirect changes remain possible: launched programs can modify files
they have permission to write, and branch switches can replace project configuration.
Git branch operations are not modeled as arbitrary repository writes.

A developer controlling an advisory installation can remove it. Managed deployment
requires administrator-owned files, protected signing keys and agent settings users
cannot disable. Use OS sandboxing for a boundary around processes the agent launches.

## Signed distribution and audit records

Policy signatures authenticate bytes, serial and expiry. `pull` rejects lower serials,
invalid signatures and expired bundles. A failed update leaves the installed policy in
force until expiry; then the hook denies all calls. An administrator able to replace the
policy, signature and pinned key can change that trust boundary.

Audit events describe decisions, not proof that tools ran or completed. Recognized
credentials are redacted, but paths, commands and metadata can still be sensitive.
Restrict access and retention. Authenticated console delivery is at least once;
consumers must tolerate duplicates.

The recorded decision is the verdict at audit-write time. A signature that expires
during that write can still make the final hook response deny, and a failed audit
write also denies even when no event could be recorded. An allowed event alone
therefore does not establish that the agent received an allow response.

See [Operations](operations.md) and the [protocol](protocol/README.md) for exact
contracts. Report vulnerabilities privately under [SECURITY.md](../SECURITY.md).
