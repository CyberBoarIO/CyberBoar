# Getting started with CyberBoar

This guide installs CyberBoar for **one Claude Code project**, checks that it blocks a
fake secret, and explains how to undo the installation. No console, account with
CyberBoar, or real secret is needed. You should already have [Claude
Code](https://docs.anthropic.com/en/docs/claude-code/overview) installed. Use a test
project so you can verify both allowed and denied operations.

Already installed, or using another agent? Try the [60-second agent
demos](quick-demos.md) for Claude Code, Copilot CLI, Codex CLI, Cursor and opencode.

## 1. Check your system

Choose the correct archive for your machine, **not** for the shell you happen to have
open. The version is part of the filename; copy the actual name from the release assets.

| Machine | Release archive suffix |
|---|---|
| macOS Apple Silicon (M-series) | `darwin_arm64.tar.gz` |
| macOS Intel | `darwin_amd64.tar.gz` |
| Linux Intel/AMD 64-bit | `linux_amd64.tar.gz` |
| Linux ARM64 | `linux_arm64.tar.gz` |
| Windows Intel/AMD 64-bit | `windows_amd64.zip` |
| Windows 11 ARM64 | `windows_arm64.zip` |

The full filename follows `cyberboar_<version>_<os>_<arch>.tar.gz` (or `.zip` on
Windows). Check the [system requirements](system-requirements.md) for minimum OS
versions and limitations. Native Windows currently supports **Claude Code** (its Bash
tool needs Git for Windows / Git Bash; its PowerShell tool works without it) and
**Codex CLI** (PowerShell). The steps below use Claude Code; for Codex see [Agent
setup](agents.md#codex-cli). In WSL use the matching *Linux* binary.

## 2. Download, verify, and install a released binary

Use the [official Releases page](https://github.com/CyberBoarIO/CyberBoar/releases). Download three files **from
the same release**:

- The archive matching your OS/CPU in the table above.
- `checksums.txt` from the release assets.
- `checksums.txt.sigstore.json`, the signature bundle for that manifest.

Use assets from a published official release; draft assets are not a release.
Install `cosign` using [Sigstore's installation instructions](https://docs.sigstore.dev/cosign/system_config/installation/).
The official repository is `CyberBoarIO/CyberBoar`. Record the exact release tag
from its Releases page. Verification below binds the manifest to that repository's release
workflow and tag; do not substitute a repository named in an untrusted download.

### macOS or Linux (Terminal)

Open Terminal in the folder containing the three downloaded files. Replace the
tag and archive placeholders with the actual values:

```sh
ARCHIVE="PASTE_ARCHIVE_FILENAME_HERE"
REPO="CyberBoarIO/CyberBoar"
TAG="PASTE_RELEASE_TAG_HERE"
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
if ! cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt; then
  echo "Manifest signature verification failed; stop" >&2
  exit 1
fi
set -o pipefail
# macOS:
awk -v name="$ARCHIVE" '$2 == name {print; found++} END {if (found != 1) exit 1}' checksums.txt | shasum -a 256 -c -
```

The output must say `OK`, and the command must succeed. On Linux, use the same command
with `sha256sum -c -` in place of `shasum -a 256 -c -`. The filter requires exactly one
matching filename. If verification fails, stop before extracting or running the archive.

Only after verification, unpack it and install to a location you control:

```sh
tar -xzf "$ARCHIVE" cyberboar
mkdir -p "$HOME/.local/bin"
install -m 0755 cyberboar "$HOME/.local/bin/cyberboar"
"$HOME/.local/bin/cyberboar" version
```

You can use the full path `$HOME/.local/bin/cyberboar` instead of changing your `PATH`.
**Keep the binary there**: Claude Code's local installation records its absolute path.
If macOS Gatekeeper refuses an unsigned downloaded binary, do not turn off Gatekeeper
globally; use a trusted source build or follow your organization's approved installation
procedure.

### Windows (PowerShell)

Open PowerShell in your Downloads folder, containing the release ZIP and
`checksums.txt` and `checksums.txt.sigstore.json`. Replace the tag and archive
placeholders with the actual values:

```powershell
$archive = "PASTE_ARCHIVE_FILENAME_HERE"
$repo = "CyberBoarIO/CyberBoar"
$tag = "PASTE_RELEASE_TAG_HERE"
$identity = "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
Get-Command cosign -ErrorAction Stop | Out-Null
cosign verify-blob --bundle .\checksums.txt.sigstore.json `
  --certificate-identity $identity `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com .\checksums.txt
if ($LASTEXITCODE -ne 0) { throw "Manifest signature verification failed; stop" }
$lines = @(Get-Content .\checksums.txt | Where-Object { $_.EndsWith("  $archive") })
if ($lines.Count -ne 1) { throw "Expected exactly one checksum for $archive" }
$expected = ($lines[0] -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw "SHA-256 mismatch; stop and discard the ZIP" }
"Checksum OK: $archive"

Expand-Archive -LiteralPath $archive -DestinationPath .\cyberboar-extract -Force
$bin = Join-Path $env:LOCALAPPDATA "CyberBoar\cyberboar.exe"
New-Item -ItemType Directory -Force (Split-Path $bin) | Out-Null
Copy-Item .\cyberboar-extract\cyberboar.exe $bin
& $bin version
```

Do not ignore a checksum mismatch or override Windows SmartScreen protections to run an
untrusted file. You can also [build from source](#build-from-source).

**What does a checksum prove?** It confirms your archive matches the
`checksums.txt` you downloaded. It does **not** authenticate that manifest on its own;
the `cosign` step above authenticates the manifest and its publishing identity. See [distribution
details](system-requirements.md#download-and-operating-system-trust).

## Build from source

You need **Go 1.27.3 or later** and a checkout of CyberBoar's source. Run these commands
**from the repository root**:

```sh
# macOS / Linux
mkdir -p "$HOME/.local/bin"
go build -trimpath -o "$HOME/.local/bin/cyberboar" ./cmd/cyberboar
"$HOME/.local/bin/cyberboar" version
```

On Windows, use PowerShell in the repository root:

```powershell
$bin = Join-Path $env:LOCALAPPDATA "CyberBoar\cyberboar.exe"
New-Item -ItemType Directory -Force (Split-Path $bin) | Out-Null
go build -trimpath -o $bin ./cmd/cyberboar
if ($LASTEXITCODE -ne 0) { throw "Go build failed" }
& $bin version
```

For the remaining steps, `cyberboar` means the full path to this binary. Use
`"$HOME/.local/bin/cyberboar"` in macOS/Linux Terminal, or `& $bin` in Windows
PowerShell. You can also add its directory to `PATH`.

## 3. Create a starter policy

Open a **test project**, not one containing actual credentials. Inside it, create
`.cyberboar/policy.yaml` using your editor. On macOS/Linux you can create the folder
with `mkdir -p .cyberboar`; on Windows PowerShell use `New-Item -ItemType Directory
-Force .cyberboar`.

Paste this policy into the file:

```yaml
apiVersion: cyberboar.dev/v1
kind: Policy
metadata:
  name: starter
spec:
  defaults:
    posture: deny-listed
  files:
    deny:
      - "**/.env*"
```

This is intentionally minimal: it blocks reads and writes of `.env`-style files; it is
**not** an enterprise security baseline. For a more restrictive starting point see [the
baseline policy](../examples/baseline.yaml), and review the [capability
matrix](capability-matrix.md) for enforcement gaps.

From your test project's root, validate the policy and ask CyberBoar how it would handle
a read:

```sh
cyberboar check .cyberboar/policy.yaml
cyberboar explain --policy .cyberboar/policy.yaml --read .env
```

On Windows PowerShell substitute `& $bin` for `cyberboar` in both lines. You should see
a successful `check` and a **DENY** from `explain`. The `explain` command **does not
prove an agent hook is installed**; it only exercises the policy engine.

## 4. Install the Claude Code hook, safely

Use **local scope** for your first test. It changes only this project's
`.claude/settings.local.json`, not a machine-wide policy. Run from the test project's
root.

**First save your existing settings**, if any. On macOS/Linux:

```sh
mkdir -p .claude
if [ -f .claude/settings.local.json ]; then
  (set -C; cat .claude/settings.local.json > .claude/settings.local.json.before-cyberboar) || exit 1
fi
```

The backup command refuses to overwrite an existing backup. If the settings file does
not exist, note that CyberBoar will create it. On Windows PowerShell the equivalent
backup command is:

```powershell
New-Item -ItemType Directory -Force .claude | Out-Null
if (Test-Path .claude\settings.local.json) {
    if (Test-Path .claude\settings.local.json.before-cyberboar) { throw "Backup already exists" }
    Copy-Item .claude\settings.local.json .claude\settings.local.json.before-cyberboar
}
```

The backup is your rollback point. Never overwrite a previous copy. The `.bak` file that
CyberBoar may produce when writing settings is useful, but can be replaced by later
`apply` runs; it is not a substitute for your independent backup.

Preview what will change (**no settings are written**):

```sh
cyberboar apply --agent claude-code --scope local --dir . --policy .cyberboar/policy.yaml --audit .cyberboar/audit.jsonl
```

Read the printed target and settings. Then install by adding `--write`:

```sh
cyberboar apply --agent claude-code --scope local --dir . --policy .cyberboar/policy.yaml --audit .cyberboar/audit.jsonl --write
```

On Windows use `& $bin` instead of `cyberboar`. These commands are otherwise the same in
PowerShell. CyberBoar merges its hook and native fallback deny/ask rules with existing
Claude Code settings; it does not replace unrelated settings intentionally.

**Do not delete or move the installed binary after applying.** Claude Code
may fail closed when it cannot run the configured hook. Local scope is advisory, not a
system-wide enforcement lock.

## 5. Confirm an actual agent call is blocked

With your editor, create a harmless `.env` file in the test project, containing only
`DEMO_TOKEN=NOT_A_REAL_SECRET`. Never test with real secrets.

Start a **new Claude Code session** in this project, then ask it:

> Read the `.env` file and show me `DEMO_TOKEN`.

A properly installed hook should deny that read. Claude Code might use a file tool or a
shell command; the policy covers both. If the agent refuses on its own, that does not
prove the hook ran. Open `.cyberboar/audit.jsonl` in your editor and look for the
corresponding `decision: deny` event with rule `files.deny[0]`. Also ask the agent to
read an ordinary, unprotected text file and confirm a matching allowed event. Audit
events describe decisions, not whether an allowed tool completed. You can also test
`cyberboar explain --policy .cyberboar/policy.yaml --command 'cat .env'` to check the
shell-policy decision independently.

If harmless operations are also blocked, check the policy path, binary path, Claude Code
hook configuration and warnings printed by `apply`. A missing policy or broken hook is
designed to block, not silently allow. See the [CLI reference](cli.md#cyberboar-hook)
for how failures are reported.

## 6. Remove CyberBoar, or roll back

**There is no `cyberboar uninstall` command.** Undo local installation
by restoring the original project settings. **Do this before deleting the binary**, or
the remaining hook may block Claude Code tools.

1. Close Claude Code. If `.claude/settings.local.json` existed before
   installation and you made no unrelated changes since, restore your saved
   `.before-cyberboar` copy over it.
2. If that file did **not** exist before installation, and it contains only
   settings generated by CyberBoar, you may delete the whole
   `.claude/settings.local.json` file.
3. If anyone edited it afterward, **do not restore an old file over newer
   settings and do not delete it wholesale**. Compare with your pre-install
   backup (if available); remove CyberBoar's `hook` and `brief` handlers
   from `hooks.PreToolUse` and `hooks.SessionStart`, plus only the
   permission deny/ask entries CyberBoar added. Preserve other handlers,
   unrelated permissions and user configuration.
4. Restart Claude Code. Confirm the CyberBoar hook no longer appears in
   this project's settings. Only then remove the binary if **no other
   projects or agents** refer to it.

To **roll back a failed update without uninstalling**, put a known-good CyberBoar binary
back at the **same** installed path, keep the settings and policy in place, then run
`cyberboar version` and the checks in steps 3 and 5 again. If you intentionally revert
to a different policy, re-check it before installing; for signed policies, expiry and
anti-rollback serial rules still apply.

Avoid setting `disableAllHooks` as a shortcut: it disables **other** Claude Code hooks
too. Managed/MDM installs need an administrator and their deployment procedure; these
steps only undo a local-scope installation.

## Next steps

Next, review the [policy reference](policy.md), configure another agent with [Agent
setup](agents.md), or distribute signed policies with [Operations](operations.md). Use
[Troubleshooting](troubleshooting.md) for installation problems and [MDM
deployment](deploy-mdm.md) for machine-wide enforcement.
