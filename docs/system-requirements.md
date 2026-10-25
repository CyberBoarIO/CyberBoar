# System requirements

CyberBoar runs on the developer's machine. Download the binary for its operating system
and CPU; there is no universal macOS or Windows executable. Prebuilt binaries do not
need Go. Source builds require **Go 1.27.3 or later**.

## Operating systems and architectures

Release tooling builds all six targets with `CGO_ENABLED=0`.

| Platform | Target | Minimum / validation target | Native verification |
|---|---|---|---|
| macOS Intel | `darwin/amd64` | macOS 13 Ventura or later | Manual binary and component smoke tests passed |
| macOS Apple Silicon | `darwin/arm64` | macOS 13 Ventura or later | Continuous native CI |
| Windows Intel/AMD | `windows/amd64` | Windows 10 / Server 2016 or later; use a maintained release | Continuous native CI |
| Windows ARM | `windows/arm64` | Windows 11 on ARM | Manual binary and component smoke tests passed |
| Linux Intel/AMD | `linux/amd64` | 64-bit Linux supported by Go 1.27 | Continuous native CI |
| Linux ARM | `linux/arm64` | 64-bit Linux supported by Go 1.27 | Native PR and weekly tests configured; first hosted run pending |

The OS minimums follow [Go 1.27](https://go.dev/doc/go1.27) and [Go's
requirements](https://go.dev/wiki/MinimumRequirements). CyberBoar has not independently
tested every distribution or older OS edition. Native CI targets Ubuntu 26.04,
macOS 26, Windows Server 2025 on x64 and Windows 11 on ARM64.
A built binary or component smoke test does not
establish every agent/OS/CPU combination. In particular, real Claude Code integration on
Windows ARM64 remains unverified.

## Agent and shell requirements

| Environment | Requirements |
|---|---|
| macOS / Linux | A supported agent and its hook/plugin interface. Shell analysis uses Bash semantics. |
| Native Windows | Claude Code with Git for Windows / Git Bash. Unknown mounts and ambiguous paths are denied. |
| WSL / Linux dev container | Install the Linux binary and agent inside that environment. |

Codex, Copilot CLI, Cursor and opencode are denied on native Windows because PowerShell
analysis is not connected to the engine. Cursor CLI passed the real-agent harness;
Cursor editor sessions remain unverified. Review [Agent setup](agents.md) and the [capability
matrix](capability-matrix.md) for versions, confirmation behavior and hook failure
limits.

CyberBoar is a policy hook, not an OS sandbox.

Linux hook execution requires a mounted procfs with `/proc/self/exe` available.
The hook uses its executable path to protect its own binary; if that path cannot
be resolved, the hook denies the call. Minimal containers must provide procfs.

## Endpoint key storage

TPM hardware is optional. Enrollment's `auto` setting tries available stores in the
following order:

| OS | Key stores |
|---|---|
| Windows x64 / ARM64 | CNG hardware TPM, CNG software provider, protected key file |
| Linux | TPM 2.0 through `/dev/tpmrm0`, protected key file |
| macOS Intel / Apple Silicon | Protected key file; Keychain/Secure Enclave are not implemented |

Hardware-backed keys reduce extraction risk. A protected file key can still be copied by
an account that can read it. State directories require private permissions. See [MDM
deployment](deploy-mdm.md) for ownership and storage choices.

## Download and operating-system trust

Releases provide archives, SHA-256 checksums, SBOMs and Sigstore signatures for the
checksum manifest. These signatures are separate from Apple Developer ID
signing/notarization and Microsoft Authenticode signing, neither of which is
implemented. Downloaded binaries may trigger Gatekeeper or SmartScreen.

A checksum verifies an archive against the manifest, not the manifest's publisher.
Follow [Getting started](getting-started.md) for installation and verification.

## Platform validation

The [platform compatibility tests](../.github/workflows/platform-compatibility-tests.yml)
build and test all six release targets natively on every PR and weekly. Linux x64
and ARM64 run the Go test suite with a software TPM; the macOS and Windows jobs run
selected native component tests. The [quality checks](../.github/workflows/quality-checks.yml)
run repository-wide validation and post-merge fuzzing separately.

Review the native build, version output, policy validation and tests under
**Actions → Platform compatibility tests**.

Jobs have 15-minute timeouts, except Windows x64 with 20 minutes.
Windows checks include Git Bash mount handling, NTFS
paths, ACLs and CNG storage. These checks supplement real-agent testing; they do not
replace it.
