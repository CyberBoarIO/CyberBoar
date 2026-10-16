# Security policy

Report policy bypasses and security defects privately through either channel:

- Email: **security@cyberboar.io**
- GitHub: [Report a vulnerability](https://github.com/CyberBoarIO/CyberBoar/security/advisories/new)

Do not open a public issue for a vulnerability.

## Reporting

Include the CyberBoar version, operating system, expected result and observed result.
Where applicable, include a minimal policy, exact tool call or command line, and agent
version. Use dummy secrets; do not send credentials, private keys or unrelated personal
information. A reproducible `explain` result that permits a forbidden action is sufficient.

We aim to acknowledge reports within **3 working days** and fix confirmed bypasses
before coordinated disclosure. Credit is given unless you request otherwise.

## Scope

- Bypasses of file, command or MCP rules for constructs CyberBoar claims to
  handle, including allow-list escapes. The [rule corpus](testdata/corpus/)
  supplies executable coverage cases.
- Decision failures that do not produce denial, including malformed input,
  crashes or deadline handling.
- Invalidly signed or rollback policy installs, or audit delivery to a destination
  other than the enrolled console.
- Authentication defects in the CyberBoar endpoint client, including request signing,
  verification of console responses, and unauthorized reading or replacement of enrolled
  identity keys. See the
  [protocol authentication contract](docs/protocol/README.md#endpoint-authentication).
- Tampering with release artifacts, checksum manifests, signatures or SBOMs.

## Documented limitations

The [security model](docs/security-model.md) and [capability
matrix](docs/capability-matrix.md) describe the enforcement boundary. Documented limits
include user removal of advisory hooks, opaque launched programs, network egress, git
history, hard links, bind mounts and races between decision and action.

Reports showing a limit is broader than documented, or demonstrating a practical attack
that exposes an inaccurate security claim, are welcome.

## Supported versions

Only the latest minor release line receives security fixes, delivered as new patch
releases. Older minor and major release lines do not receive backports.

For release candidates, only the latest candidate is supported. Security fixes are
also applied to `main`.

If possible, confirm the issue on the latest supported release or `main` before
submitting your report.
