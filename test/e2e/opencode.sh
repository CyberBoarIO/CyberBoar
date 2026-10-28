#!/usr/bin/env bash
# End-to-end check against a real opencode.
#
# Builds cyberboar, installs its plugin with `apply --agent opencode --scope
# user` into a throwaway HOME and XDG directories, and runs `opencode run`
# headless against test/e2e/scripted-model.py, a local OpenAI-compatible
# endpoint that asks for a fixed list of tool calls, configured as a custom
# provider. No account and no real model are involved, so the runs are
# deterministic and free. It checks that:
#   - the fake secret never reaches the model;
#   - the plugin blocks the secret (read and bash), an SSH key, a .env write,
#     writing and editing the plugin file itself, an MCP server off the allow
#     list, apply_patch onto the secret, and a subagent's read of the secret;
#   - harmless calls go through, and the briefing reaches the system prompt;
#   - with the hook binary gone, every call is blocked.
# Needs: go, python3, curl, tar, network access to registry.npmjs.org (or
# OPENCODE=/path/to/opencode). Linux x64 or arm64.
# Usage: test/e2e/opencode.sh [--version 1.19.0] [--capture FILE]
#   --capture appends every plugin input the hook receives to FILE, with the
#   project directory replaced by {{root}} and the rest of the throwaway
#   directory by /tmp/e2e (for captured-<version>.jsonl).

set -euo pipefail

version=1.19.0
capture=
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift ;;
    --capture) capture="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
model_pid=
trap 'kill $model_pid 2>/dev/null || true; rm -rf "$work"' EXIT
secret="fake-e2e-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"

opencode=${OPENCODE:-}
if [ -z "$opencode" ]; then
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "unsupported machine $(uname -m)" >&2; exit 2 ;;
  esac
  mkdir -p "$work/opencode"
  curl -fsSL "https://registry.npmjs.org/opencode-linux-$arch/-/opencode-linux-$arch-$version.tgz" |
    tar -xz -C "$work/opencode" --strip-components=1
  opencode="$work/opencode/bin/opencode"
fi

home="$work/home" proj="$work/proj" xdg="$work/xdg"
mkdir -p "$home/.ssh" "$proj/src" "$proj/.cyberboar" "$xdg/config/opencode" "$xdg/data" "$xdg/cache" "$xdg/state"
printf 'not a real key %s\n' "$secret" > "$home/.ssh/id_rsa"
printf 'API_KEY=%s\n' "$secret" > "$proj/.env"
printf '# Demo\n' > "$proj/README.md"
printf 'package main\n' > "$proj/src/main.go"
{
  cat "$repo/examples/baseline.yaml"
  printf '  session:\n    briefing:\n      message: "E2E briefing marker."\n'
} > "$proj/.cyberboar/policy.yaml"
git -C "$proj" init -q

(cd "$repo" && go build -ldflags "-X main.version=e2e" -o "$work/bin/cyberboar" ./cmd/cyberboar)
hookcmd="$work/bin/cyberboar"
if [ -n "$capture" ]; then
  # Records each input on its own line, then hands it to the real hook.
  cat > "$work/bin/capture-hook" <<EOF
#!/bin/sh
input=\$(cat)
[ -n "\$input" ] && printf '%s\n' "\$input" >> "$work/capture.jsonl"
printf '%s' "\$input" | exec "$work/bin/cyberboar" "\$@"
EOF
  chmod +x "$work/bin/capture-hook"
  hookcmd="$work/bin/capture-hook"
fi
HOME="$home" XDG_CONFIG_HOME="$xdg/config" "$work/bin/cyberboar" apply --agent opencode --scope user --command "$hookcmd" \
  --policy "$proj/.cyberboar/policy.yaml" --audit "$work/audit.jsonl" --write >/dev/null
plugin="$xdg/config/opencode/plugin/cyberboar.js"
plugin_sum=$(sha256sum "$plugin")

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
# The provider: OpenAI-compatible, served by the scripted model. A model ID
# with "gpt-" gets apply_patch instead of edit and write.
python3 - "$port" "$repo/test/e2e/mcp-server.py" > "$xdg/config/opencode/opencode.json" <<'PY'
import json, sys
port, mcp = sys.argv[1:3]
print(json.dumps({
    "$schema": "https://opencode.ai/config.json",
    "provider": {"scripted": {"npm": "@ai-sdk/openai-compatible", "name": "Scripted",
                              "options": {"baseURL": "http://127.0.0.1:%s/v1" % port, "apiKey": "unused"},
                              "models": {"scripted": {"name": "scripted", "tool_call": True},
                                         "gpt-5-scripted": {"name": "gpt-5-scripted", "tool_call": True}}}},
    "permission": "allow",
    "autoupdate": False,
    "share": "disabled",
    "mcp": {"e2e-srv": {"type": "local", "command": ["python3", mcp]}},
}, indent=2))
PY

# run NAME MODEL: one `opencode run` with the script in $work/NAME.json.
run() {
  python3 "$repo/test/e2e/scripted-model.py" "$port" "$work/$1.json" "$work/$1-model.jsonl" &
  model_pid=$!
  for _ in $(seq 50); do curl -fs "http://127.0.0.1:$port/v1/models" >/dev/null && break; sleep 0.1; done
  (cd "$proj" && env -i PATH="$PATH" HOME="$home" SHELL=/bin/bash TERM=dumb XDG_CONFIG_HOME="$xdg/config" \
    XDG_DATA_HOME="$xdg/data" XDG_CACHE_HOME="$xdg/cache" XDG_STATE_HOME="$xdg/state" \
    OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 \
    timeout 300 "$opencode" run -m "scripted/$2" "Run the e2e script." > "$work/$1-stdout.txt" 2> "$work/$1-stderr.txt") || true
  kill $model_pid 2>/dev/null || true
  wait $model_pid 2>/dev/null || true
  model_pid=
}

python3 - "$proj" "$home" "$plugin" > "$work/tools.json" <<'PY'
import json, sys
proj, home, plugin = sys.argv[1:4]
print(json.dumps([
    ["bash", {"command": "ls src", "description": "harmless"}],
    ["bash", {"command": "cat .env", "description": "secret"}],
    ["read", {"filePath": proj + "/README.md"}],
    ["read", {"filePath": "src"}],
    ["read", {"filePath": ".env"}],
    ["read", {"filePath": home + "/.ssh/id_rsa"}],
    ["write", {"filePath": "src/ok.txt", "content": "ok\n"}],
    ["edit", {"filePath": "src/ok.txt", "oldString": "ok", "newString": "fine"}],
    ["write", {"filePath": proj + "/.env.prod", "content": "X=1\n"}],
    ["write", {"filePath": plugin, "content": "export {}\n"}],
    ["edit", {"filePath": plugin, "oldString": "throw", "newString": "return"}],
    ["bash", {"command": "rm -f " + plugin, "description": "remove the plugin"}],
    ["bash", {"command": "git push origin main", "description": "push"}],
    ["glob", {"pattern": "**/*.md"}],
    ["grep", {"pattern": "Demo", "path": "."}],
    ["grep", {"pattern": "package", "path": "src"}],
    ["todowrite", {"todos": [{"content": "x", "status": "pending", "priority": "high"}]}],
    ["e2e-srv_do_thing", {"a": "x"}],
    ["read_mcp_resource", {"server": "e2e-srv", "uri": "e2e://x"}],
    ["list_mcp_resources", {}],
    ["list", {"path": "."}],
    ["task", {"description": "explore", "prompt": "look", "subagent_type": "general"}],
    ["read", {"filePath": ".env"}],
]))
PY
python3 - "$proj" > "$work/patch.json" <<'PY'
import json, sys
proj = sys.argv[1]
patch = lambda body: {"patchText": "*** Begin Patch\n" + body + "*** End Patch\n"}
print(json.dumps([
    ["apply_patch", patch("*** Add File: src/patched.txt\n+hello\n")],
    ["apply_patch", patch("*** Update File: .env\n@@\n-API_KEY\n+API_KEY=x\n")],
    ["apply_patch", patch("*** Add File: .opencode/plugin/allow.js\n+export {}\n")],
]))
PY
printf '[["bash", {"command": "ls src", "description": "harmless"}], ["write", {"filePath": "src/unhooked.txt", "content": "x"}]]\n' > "$work/nohook.json"

run tools scripted
run patch gpt-5-scripted
# The hook binary is gone: the plugin must block every call.
mv "$hookcmd" "$hookcmd.away"
run nohook scripted
mv "$hookcmd.away" "$hookcmd"

fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
# count DECISION TOOL|- RULE-PREFIX|-: audit lines matching all given filters.
count() {
  python3 - "$work/audit.jsonl" "$@" <<'PY'
import json, sys
path, decision, tool, rule = sys.argv[1:5]
n = 0
try:
    lines = open(path).read().splitlines()
except FileNotFoundError:
    lines = []
for line in lines:
    e = json.loads(line)
    if decision != "-" and e["decision"] != decision: continue
    if tool != "-" and e.get("tool") != tool: continue
    if rule != "-" and not e["rule"].startswith(rule): continue
    n += 1
print(n)
PY
}
# result FILE TEXT: the tool results the model got in a run contain TEXT.
result() {
  python3 - "$work/$1-model.jsonl" "$2" <<'PY'
import json, sys
path, text = sys.argv[1:3]
for line in open(path):
    for m in json.loads(line).get("messages", []):
        if m.get("role") == "tool" and text in json.dumps(m.get("content")):
            sys.exit(0)
sys.exit(1)
PY
}
check "the fake secret never reaches the model" "! grep -q '$secret' '$work'/*-model.jsonl"
check "the briefing reaches the system prompt" "grep -q 'E2E briefing marker' '$work/tools-model.jsonl'"
check "bash cat .env is denied" "[ \$(count deny bash files.deny) -ge 1 ]"
check "read .env, ~/.ssh/id_rsa and the subagent's .env are denied" "[ \$(count deny read files.deny) -ge 3 ]"
check "writing .env.prod is denied" "[ \$(count deny write files.deny) -ge 1 ]"
check "writing, editing and removing the plugin are denied" "[ \$(count deny write builtin.guarded) -ge 1 ] && [ \$(count deny edit builtin.guarded) -ge 1 ] && [ \$(count deny bash builtin.guarded) -ge 1 ]"
check "git push needs confirmation, so it is denied" "[ \$(count ask bash commands.ask) -ge 1 ]"
check "grep over the project holding .env is denied" "[ \$(count deny grep files.deny) -ge 1 ]"
check "an MCP server off the allow list is denied" "[ \$(count deny e2e-srv_do_thing posture.allow-listed) -ge 1 ] && [ \$(count deny read_mcp_resource posture.allow-listed) -ge 1 ]"
check "apply_patch: harmless allowed, .env and the plugin directory denied" "[ \$(count allow apply_patch -) -ge 1 ] && [ \$(count deny apply_patch files.deny) -ge 1 ] && [ \$(count deny apply_patch builtin.guarded) -ge 1 ]"
check "harmless calls are allowed" "[ \$(count allow bash -) -ge 1 ] && [ \$(count allow read -) -ge 2 ] && [ \$(count allow write -) -ge 1 ] && [ \$(count allow edit -) -ge 1 ] && [ \$(count allow glob -) -ge 1 ] && [ \$(count allow grep -) -ge 1 ] && [ \$(count allow todowrite -) -ge 1 ]"
check "listing every server's resources is denied" "[ \$(count deny list_mcp_resources posture.allow-listed) -ge 1 ]"
check "a call to a tool that doesn't exist reaches the plugin as invalid" "[ \$(count allow invalid -) -ge 1 ]"
check "the subagent call is seen" "[ \$(count allow task -) -ge 1 ]"
check "no hook setup or internal errors" "[ \$(count - - error.) -eq 0 ]"
check "the model is told why" "result tools 'blocked by policy rule files.deny' && result tools 'can change how the agent' && result tools \"can't ask for confirmation\""
check "src/ok.txt and src/patched.txt were written, .env.prod was not" "[ -f '$proj/src/ok.txt' ] && [ -f '$proj/src/patched.txt' ] && [ ! -e '$proj/.env.prod' ]"
check "the plugin is unchanged" "[ \"\$(sha256sum '$plugin')\" = '$plugin_sum' ] && [ ! -e '$proj/.opencode' ]"
check "without the hook binary every call is blocked" "result nohook 'could not run' && [ ! -e '$proj/src/unhooked.txt' ]"
echo "decisions:"
python3 -c '
import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l); a = (e.get("actions") or [{}])[0]
    print("  %-5s %-26s %-18s %s" % (e["decision"], e["rule"], e.get("tool", ""), (a.get("command") or a.get("path") or a.get("server") or "")[-50:]))
' "$work/audit.jsonl" 2>/dev/null || true
if [ -n "$capture" ] && [ -f "$work/capture.jsonl" ]; then
  sed -e "s#$proj#{{root}}#g" -e "s#$work#/tmp/e2e#g" "$work/capture.jsonl" >> "$capture"
fi
if [ $fail -ne 0 ]; then
  for r in tools patch nohook; do echo "opencode stderr ($r):"; tail -20 "$work/$r-stderr.txt"; done
fi
exit $fail
