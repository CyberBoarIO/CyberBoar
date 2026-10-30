# MDM deployment

Install administrator-owned CyberBoar files, signed policies, managed hooks and
background refresh/audit jobs. The examples target Claude Code; review [Agent
setup](agents.md) before applying them to another integration.

Prerequisites: administrator access, a verified binary, an Ed25519 policy-signing public
key, signed policies refreshed on a schedule, and an MDM or configuration manager
capable of deploying files and jobs.

**Console prerequisite:** enrollment and audit delivery require a compatible
service implementing the protocol. The endpoint release does not include one. For
deployment without a console, skip enrollment, pull signed policies from a static bundle
host with `--server` and `--name`, and forward audit logs with your existing log agent.
`enroll` establishes machine identity and policy assignment; it is not required for
standalone hooks or static-site pulls. See [Operations](operations.md) for the
static-host commands.

See [System requirements](system-requirements.md) for supported architectures, minimum
OS versions, key-store limitations and distribution-signing status.

## Ownership and trust

Coding agents run as the developer. Anything the developer's account can write, a
program the agent starts can write too, so everything that decides what is enforced
belongs to root or SYSTEM and is installed by the MDM:

| What | Why the developer's account must not write it |
|---|---|
| `cyberboar` binary | it is the hook |
| policy signing public key | decides which policies are genuine; installed by the MDM, never fetched from the console |
| console public key (optional) | the key the console's answers must be signed with, pinned before the first contact |
| installed policy and its `.sig` | written only by `cyberboar pull`, which checks the signature; the `.sig` also holds the serial below which `pull` installs nothing |
| managed agent settings | install the hook and lock it (`allowManagedHooksOnly`) |
| endpoint state: key, certificate, enrollment, endpoint ID | identify and authenticate the endpoint and its console assignment |

The developer's account needs append access to the audit log. Validate the permissions
with the actual hook account before rollout.

Keep endpoint enrollment state private to the root/SYSTEM service account. Hook tripwire
state must instead be writable by the account running the agent. Do not point the hook
at private enrollment state. An unpinned hook state path can be influenced by the user's
environment; see [CLI environment](cli.md#environment).

Endpoint identity files must be private to the account running `enroll`, `ship` and
`pull` (also SYSTEM and Administrators on Windows), and the state directory must not
be writable by other accounts. This prevents a root or SYSTEM job from trusting a
key or console address supplied by a developer. After enrollment, requests are
signed with the endpoint key over mutual TLS, and every successful answer they act on must be
signed with the console key the machine pinned at enrollment; the console only serves a
machine the policy it assigned it ([Endpoint
authentication](protocol/README.md#endpoint-authentication)).

## Paths

The rest of this guide uses these paths; any root- or SYSTEM-owned location works.

| | macOS | Linux | Windows |
|---|---|---|---|
| binary | `/usr/local/lib/cyberboar/VERSION/cyberboar`, linked from `/usr/local/bin/cyberboar` | the same as macOS | `C:\Program Files\CyberBoar\VERSION\cyberboar.exe` |
| config (`policy.pub`, `console.pub`, `policy.yaml`) | `/Library/Application Support/CyberBoar` | `/etc/cyberboar` | `C:\ProgramData\CyberBoar` |
| endpoint state | `/Library/Application Support/CyberBoar/state` | `/var/lib/cyberboar` | `C:\ProgramData\CyberBoar\state` |
| audit log | `/Library/Logs/CyberBoar/audit.jsonl` | `/var/log/cyberboar/audit.jsonl` | `C:\ProgramData\CyberBoar\audit.jsonl` |

`cyberboar enroll` creates the state directory private to the account running it: mode
0700 on macOS and Linux, and on Windows a protected DACL for SYSTEM and that account
(SYSTEM, under an MDM) that inherits nothing.

## 1. Create an enrollment token

On the console, create an enrollment token for the policy these machines get, with a
bound on how many machines it enrolls and until when. The console shows it once. It is a
credential: create one per rollout wave, pass it only through your MDM's secret
handling, and revoke it when you no longer need it.

Re-enrollment with an existing key/ID does not spend another token use, but still
requires a known, unexpired and unrevoked token. Token policy and authorization are
defined by the compatible console's protocol implementation.

If the console shows its public key (the one its answers are signed with), save it as
`console.pub`. Pinning it is optional when the console's TLS certificate is verified,
and required with `--insecure-skip-verify`. The pin authenticates the enrollment
response. It does not protect the token from an impersonated TLS server when server
certificate verification is disabled; use `--ca` for a private CA or self-signed setup.

## 2. Install the files

Deliver the binary, `policy.pub` and, if you pin it, `console.pub` as a package (Intune:
a Win32 app or a macOS PKG; Fleet: a custom package). Each version of the binary goes in
a directory of its own named after it (`VERSION` above, such as `1.0.0-rc.1`), never
over another, so that an upgrade can switch to it in one step ("Upgrade the binary"
below). Verify the package's release signature and expected version before running its
binary. Then run this as root. It creates the audit log so developers can append to it
but not read other developers' lines, truncate or replace it:

```sh
# Linux (macOS: use the macOS paths above, and `chflags uappnd` instead of `chattr +a`)
install -d -m 0755 -o root /usr/local/lib/cyberboar
mkdir -m 0755 /usr/local/lib/cyberboar/1.0.0-rc.1   # stop if this version already exists
install -m 0755 -o root cyberboar /usr/local/lib/cyberboar/1.0.0-rc.1/cyberboar
ln -s /usr/local/lib/cyberboar/1.0.0-rc.1/cyberboar /usr/local/bin/cyberboar
install -d -m 0755 -o root /etc/cyberboar /var/log/cyberboar
install -m 0644 -o root policy.pub console.pub /etc/cyberboar/
touch /var/log/cyberboar/audit.jsonl
chown root /var/log/cyberboar/audit.jsonl
chmod 0622 /var/log/cyberboar/audit.jsonl
chattr +a /var/log/cyberboar/audit.jsonl   # append only, even for programs the agent starts
```

On Windows, as SYSTEM:

```powershell
$dir = "C:\ProgramData\CyberBoar"
New-Item -ItemType Directory -Force $dir | Out-Null
icacls $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
if (-not (Test-Path "$dir\audit.jsonl")) {
    New-Item -ItemType File "$dir\audit.jsonl" | Out-Null
}
# Users (S-1-5-32-545) may append, not write, read or delete.
icacls "$dir\audit.jsonl" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:(AD,S,RA)"
```

The Windows append-only audit configuration is not validated in a real managed agent
deployment. Confirm append succeeds and read/truncate/delete fail under the developer
account before wider rollout.

## 3. Enroll, install the policy, install the hook

As root (macOS and Linux):

```sh
#!/bin/sh
set -eu
server=https://console.example.com
exe=/usr/local/lib/cyberboar/1.0.0-rc.1/cyberboar
state=/var/lib/cyberboar           # macOS: "/Library/Application Support/CyberBoar/state"
conf=/etc/cyberboar                # macOS: "/Library/Application Support/CyberBoar"
# Fleet replaces $FLEET_SECRET_… before the script runs; with Intune, the token is in the script.
printf '%s' "$FLEET_SECRET_CYBERBOAR_ENROLL_TOKEN" |
  "$exe" enroll --server "$server" --state "$state" --console-key "$conf/console.pub" --token-file -
"$exe" pull --state "$state" --out "$conf/policy.yaml" --pubkey "$conf/policy.pub" --every 0s
"$exe" apply --agent claude-code --scope managed --lock --write \
  --policy "$conf/policy.yaml" --pubkey "$conf/policy.pub" --audit /var/log/cyberboar/audit.jsonl
```

As SYSTEM (Windows):

```powershell
$exe = "C:\Program Files\CyberBoar\1.0.0-rc.1\cyberboar.exe"
$conf = "C:\ProgramData\CyberBoar"
# Fleet replaces $FLEET_SECRET_… before the script runs; with Intune, put the token here.
"$FLEET_SECRET_CYBERBOAR_ENROLL_TOKEN" | & $exe enroll --server https://console.example.com --state "$conf\state" --console-key "$conf\console.pub" --token-file -
if ($LASTEXITCODE -ne 0) { exit 1 }
& $exe pull --state "$conf\state" --out "$conf\policy.yaml" --pubkey "$conf\policy.pub" --every 0s
if ($LASTEXITCODE -ne 0) { exit 1 }
& $exe apply --agent claude-code --scope managed --lock --write --policy "$conf\policy.yaml" --pubkey "$conf\policy.pub" --audit "$conf\audit.jsonl"
```

Leave out `--console-key` if you don't pin the console key. The token is read from a
file or stdin (`--token-file -`) or from `CYBERBOAR_ENROLL_TOKEN`, never from a flag,
which every user on the machine could see in the process list.

In managed, user and local scopes, `apply` writes the path of the binary that runs it
into the hook settings. Invoke the versioned path directly. Project scope uses
`cyberboar` on `PATH` unless `--command` is given; replacing the link then changes what
those hooks run too.

`enroll` is safe to run on every check-in: an enrolled machine with a valid certificate
sends nothing and needs no token, and one whose certificate is due renews it. The policy
is installed before the hook, because a hook without its policy denies every tool call.
For Codex, install its managed hook separately with the same policy/key options; on
Windows it goes to `%ProgramData%\OpenAI\Codex\requirements.toml`. Windows managed
scope and locking remain unverified in a real managed deployment.

`enroll` makes the endpoint key in the TPM where it can (Linux's `/dev/tpmrm0`, the
Platform Crypto Provider on Windows), else on Windows in the Software Key Storage
Provider, else in a file in the state directory; it says on stderr when it passed one
over. TPM and CNG provider keys are created non-exportable. A file-backed key can be
copied by an account able to read it. TPM keys cannot be moved to another machine by
copying state. On fleets that have TPMs, add `--key-storage tpm`: a machine whose TPM
can't be reached then fails to enroll instead of getting a file key. macOS uses a
protected file key; Secure Enclave storage is not implemented. An existing endpoint
keeps its key store. Changing stores requires resetting identity state and enrolling as
a new endpoint; revoke the old identity on the console as part of that migration.

With a company CA in front of the console, add `--ca FILE` to `enroll`, `pull` and
`ship`. They speak TLS 1.3 only. `--insecure-skip-verify` exists for setups that can't
verify the server, warns on every run, and needs the pinned console key at enrollment.

## 4. Keep the policy current and ship events

Install two supervised jobs as root or SYSTEM; `--every` keeps each running. Both renew
the machine's client certificate once half its lifetime has passed, so both need write
access to the state directory.

You can keep both intervals in the signed policy instead of repeating them in the
service files:

```yaml
spec:
  audit:
    sink: https://console.example.test/api/v1/events
  sync:
    shipEvery: 5s
    pullEvery: 4h
```

With these settings, omit `--every` from the examples below and add `--policy` pointing
to the installed policy for `ship`. `pull` reads its signed `--out` file, including the
first policy it downloads. Both commands pick up new intervals on their next round.
Explicit `--every` always overrides the policy; use `--every 0s` in rollout or
log-rotation jobs that must finish after one run. A `0s` or omitted policy interval
makes that command exit after its current round, so keep a positive interval for
background services. Setting the sink and intervals does not create an OS service; the
MDM still installs and starts the jobs.

Linux: create `/etc/systemd/system/cyberboar-pull.service`. Create a separate
`cyberboar-ship.service` with `ExecStart=/usr/local/bin/cyberboar ship --audit
/var/log/cyberboar/audit.jsonl --state /var/lib/cyberboar --every 1m` and
`ReadWritePaths=/var/lib/cyberboar`:

```ini
[Unit]
Description=CyberBoar policy updates
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/cyberboar pull --state /var/lib/cyberboar --out /etc/cyberboar/policy.yaml --pubkey /etc/cyberboar/policy.pub --every 5m
Restart=always
RestartSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/cyberboar /var/lib/cyberboar
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Then `systemctl enable --now cyberboar-pull cyberboar-ship`.

macOS: create `/Library/LaunchDaemons/dev.cyberboar.pull.plist` (root:wheel, 0644) and a
corresponding ship daemon, loaded with `launchctl bootstrap system
/Library/LaunchDaemons/dev.cyberboar.pull.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.cyberboar.pull</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/cyberboar</string><string>pull</string>
    <string>--state</string><string>/Library/Application Support/CyberBoar/state</string>
    <string>--out</string><string>/Library/Application Support/CyberBoar/policy.yaml</string>
    <string>--pubkey</string><string>/Library/Application Support/CyberBoar/policy.pub</string>
    <string>--every</string><string>5m</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
</dict>
</plist>
```

Windows: register a scheduled task as SYSTEM in the step 3 script, and a corresponding
ship task with `ship --audit "$conf\audit.jsonl" --state "$conf\state" --every 1m`:

```powershell
$action = New-ScheduledTaskAction -Execute $exe -Argument "pull --state `"$conf\state`" --out `"$conf\policy.yaml`" --pubkey `"$conf\policy.pub`" --every 5m"
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName "CyberBoar pull" -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
  -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest) -Settings $settings -Force
Start-ScheduledTask -TaskName "CyberBoar pull"
```

### Upgrade the binary

Never replace the binary in place. Codex, Copilot CLI and Claude Code before 2.1.295 run
the tool call when the hook can't start, so any moment where the hook's path is missing
or half written lets calls through with only the native deny rules `apply` added. (From
2.1.295 on, Claude Code blocks the call instead: `apply` installs the hook with
`onFailure: block`.) Windows can't overwrite a running `.exe`: replacing one takes two
renames, with such a moment between them. A package step that deletes the old file and
then copies the new one has the same gap on macOS and Linux.

Instead, install the new version next to the old one, check it, and let its own `apply`
switch the hook over: `apply` replaces the settings file with one rename, so the agent
reads either the old hook command or the new one. As root (Windows: as SYSTEM, alike,
with `$exe` the new path and the scheduled tasks registered again with it). Verify the
release signature and expected version before this step; `check` validates the policy,
not the binary's provenance, and only warns when the binary is below the policy's
version floor:

```sh
#!/bin/sh
set -eu
new=1.0.0-rc.2
dir=/usr/local/lib/cyberboar
conf=/etc/cyberboar
install -d -m 0755 -o root "$dir"
mkdir -m 0755 "$dir/$new"           # never overwrite an installed version
install -m 0755 -o root cyberboar "$dir/$new/cyberboar"
exe="$dir/$new/cyberboar"
"$exe" version
"$exe" check "$conf/policy.yaml"     # it runs here and accepts the installed policy
"$exe" apply --agent claude-code --scope managed --lock --write \
  --policy "$conf/policy.yaml" --pubkey "$conf/policy.pub" --audit /var/log/cyberboar/audit.jsonl
# The link the jobs and people use, replaced with one rename.
link=/usr/local/bin/cyberboar
ln -s "$dir/$new/cyberboar" "$link.next"
mv -f "$link.next" "$link"         # both names are in the same directory/filesystem
systemctl restart cyberboar-pull cyberboar-ship   # macOS: launchctl kickstart -k system/dev.cyberboar.pull, and ship
```

Run `apply` with the same flags as when the hook was installed, for every agent it was
installed for. If `check` fails or warns that the minimum version is not met, stop
there: the old version keeps enforcing. A failed upgrade must not remove or overwrite
any installed version. Agent sessions can retain old hook commands. Keep every version
they may still reference, even across several upgrades; remove it only after those
sessions have ended or restarted and the managed settings and scheduled jobs no longer
reference it. Restart or reload the agents as their hook configuration requires, and
verify a policy-denied call stays blocked before raising the fleet's version floor.

To make sure no machine keeps enforcing with an older release, upgrade the fleet first
and then set `minimumVersion` in the policy: from then on a hook older than that denies
every tool call and says why, to the agent and to the user.

### Rotate the audit log

`ship` remembers how far it has sent the audit log and recognizes the log by how it
starts. When it finds the log rotated, it first sends the rest of the old log, which it
looks for next to the new one: a file whose name starts with the log's
(`audit.jsonl.1`, `audit.jsonl-20261030`) and that starts as the log did. Then it sends
the new log from its start. If the old log is gone (deleted, already compressed, or the
log was truncated in place without a copy), the lines it got after the last run can't
be sent: `ship` warns on stderr and adds one to `stats.logsLost`, a total every batch
carries, so the console sees it ([protocol](protocol/README.md#audit-events)).

So rotate by renaming the log, keep the newest rotated file uncompressed until `ship`
has run (logrotate's `delaycompress`), and avoid `copytruncate`: lines written between
its copy and its truncation are lost. With logrotate (`/etc/logrotate.d/cyberboar`),
running `ship` in `prerotate` also sends everything before the rename; if that run fails
(the console can't be reached, or the `ship` service is in the middle of a round),
logrotate leaves the log in place and tries again on its next run. On Linux the
append-only attribute has to come off for the rotation and go back on the new log:

```
/var/log/cyberboar/audit.jsonl {
    weekly
    rotate 12
    compress
    delaycompress
    create 0622 root root
    prerotate
        /usr/local/bin/cyberboar ship --audit /var/log/cyberboar/audit.jsonl --state /var/lib/cyberboar --every 0s && chattr -a /var/log/cyberboar/audit.jsonl
    endscript
    postrotate
        chattr +a /var/log/cyberboar/audit.jsonl
    endscript
}
```

On macOS and Windows, use the same coordinated final-upload procedure. Resume agent
sessions only after the new log exists with the required append permissions.

### Sign policies on a schedule

Every signature carries a serial and expiry ([protocol
rules](protocol/README.md#rollback-and-expiry)): machines never install a policy with a
lower serial than the one they have, and from the expiry on the hook denies every tool
call until a newer signed policy arrives. So sign in a scheduled CI job, not only when a
policy changes, with a rising serial and an expiry well beyond the longest time a
machine may go without reaching the console:

```sh
cyberboar sign --key "$POLICY_SIGNING_KEY" --serial "$(date +%s)" --expires 720h policies/*.yaml
```

Serialize signing jobs so timestamp serials cannot collide. Refresh well before the
30-day (`720h`) expiry, allowing for offline periods and failed pulls. After expiry,
calls remain denied until a valid update arrives; there is no grace period. Restore
older contents by signing them with a higher serial. `--expires 0` disables expiry,
allowing a server to freeze endpoints on a policy indefinitely.

## Intune

- Windows: package the binary, `policy.pub`, `console.pub` and an install script from steps
  2 and 4 as a Win32 app (install behaviour: System). Put the enrollment of step 3 in a separate
  platform script (Devices › Scripts and remediations; not as the signed-in user; 64-bit
  PowerShell), so the token doesn't live in the app package.
- macOS: deliver the binary and the keys as a PKG, and steps 2 to 4 as a shell script that
  doesn't run as the signed-in user (it then runs as root).
- Linux: Intune doesn't run scripts on Linux; use Fleet or your configuration management.
- The token: embedding it in the enrollment script exposes it to Intune administrators
  and on the machine while the script runs. Keep its uses to the rollout wave and
  its validity short.
- Checking: a remediation whose detection script checks that
  `C:\ProgramData\CyberBoar\state\enrollment.json` exists and both tasks run, and whose
  remediation script is step 3, also brings back a machine whose certificate lapsed (below)
  while its token is valid.

## Fleet

- Install: add the binary as a custom package; its install script is steps 2 to 4. fleetd
  runs it as root or SYSTEM. Scripts must be enabled for fleetd.
- The token: store it as a Fleet secret (`FLEET_SECRET_CYBERBOAR_ENROLL_TOKEN`, set through
  GitOps). Fleet substitutes `$FLEET_SECRET_…` in scripts, so it isn't shown in the UI.
- Checking: policies (osquery) that pass on a healthy machine; attach the enrollment script
  as the policy's "run script" automation to repair a machine that fails:

```sql
-- Enrolled, with the enrollment and key private to root.
SELECT 1 FROM file WHERE path = '/var/lib/cyberboar/enrollment.json' AND uid = 0 AND mode = '0600';
SELECT 1 FROM file WHERE path = '/var/lib/cyberboar/endpoint.key' AND uid = 0 AND mode = '0600';
-- The certificate is being renewed (30-day certificates renew every 15 days).
SELECT 1 FROM file WHERE path = '/var/lib/cyberboar/endpoint.crt' AND mtime > strftime('%s', 'now') - 20 * 86400;
-- The audit log is append-only for developers (Linux: 0622, root-owned).
SELECT 1 FROM file WHERE path = '/var/log/cyberboar/audit.jsonl' AND uid = 0 AND mode = '0622';
-- Both jobs are running (Windows: name = 'cyberboar.exe').
SELECT 1 FROM processes WHERE name = 'cyberboar' AND cmdline LIKE '% pull %';
SELECT 1 FROM processes WHERE name = 'cyberboar' AND cmdline LIKE '% ship %';
-- The hook is installed in managed settings (macOS: /Library/Application Support/ClaudeCode/…).
SELECT 1 FROM file WHERE path = '/etc/claude-code/managed-settings.d/50-cyberboar.json' AND uid = 0;
```

## Lapsed, reassigned, moved and removed machines

- A machine that was off for longer than its certificate's lifetime
  (30 days is the recommended lifetime) can't renew: `ship` and `pull` fail and say so, events
  stay in the audit log and the installed policy stays. Running step 3 with a valid token enrolls
  it again with the same key and ID; no use of the token is spent.
- A machine keeps the policy it was enrolled with. After the console assigns
  it another, `pull` fails with `forbidden` and the installed policy stays, until the machine
  enrolls again: remove `endpoint.crt` from the state directory and run step 3. The machine keeps
  its key, ID and pinned console key, and the console answers with the new policy.
- Revoking a machine on the console refuses its requests from then on (`revoked`), and its
  endpoint ID can't enroll again.
- Reimaging wipes the state, so the machine enrolls as a new endpoint; revoke the old one.
- Moving to another console means starting over: remove `endpoint-id`, `endpoint.key`,
  `endpoint.crt` and `enrollment.json` from the state directory, then enroll with a token from the
  new console. `enroll` refuses to switch consoles by itself.
