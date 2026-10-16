#!/usr/bin/env bash
# End-to-end check against a real GitHub Copilot CLI.
#
# Builds cyberboar, installs it with `apply --agent copilot-cli --scope user`
# into a throwaway HOME, and runs Copilot CLI (headless) against
# test/e2e/scripted-model.py, a local OpenAI-compatible endpoint that asks
# for a fixed list of tool calls. No GitHub account and no real model are
# involved (Copilot's bring-your-own-model mode), so the run is deterministic
# and free. It checks:
#   - the fake secret never reaches the model;
#   - the hook denies the secret, an SSH key, a .env write, a hook-file write
#     and SQL file access, through Copilot's own tools and a subagent;
#   - a deny rule covers an MCP tool whose server name Copilot rewrites
#     (e2e.srv is offered as e2e-srv-…);
#   - apply accepts the config.json with comments that Copilot writes;
#   - harmless calls go through, and the session briefing reaches the model.
# Needs: go, python3, curl, tar, network access to registry.npmjs.org (or
# COPILOT=/path/to/copilot). Linux x64 or arm64.
# Usage: test/e2e/copilot-cli.sh [--version 1.0.97]

set -euo pipefail

version=1.0.97
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'kill $model_pid 2>/dev/null || true; rm -rf "$work"' EXIT
model_pid=
secret="fake-e2e-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"

copilot=${COPILOT:-}
if [ -z "$copilot" ]; then
  case "$(uname -m)" in
    x86_64) arch=x64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "unsupported machine $(uname -m)" >&2; exit 2 ;;
  esac
  mkdir -p "$work/copilot"
  curl -fsSL "https://registry.npmjs.org/@github/copilot-linux-$arch/-/copilot-linux-$arch-$version.tgz" |
    tar -xz -C "$work/copilot" --strip-components=1
  copilot="$work/copilot/copilot"
fi

home="$work/home" proj="$work/proj"
mkdir -p "$home/.ssh" "$proj/src" "$proj/.cyberboar"
printf 'not a real key %s\n' "$secret" > "$home/.ssh/id_rsa"
printf 'API_KEY=%s\n' "$secret" > "$proj/.env"
printf '# Demo\n' > "$proj/README.md"
printf 'package main\n' > "$proj/src/main.go"
{
  cat "$repo/examples/baseline.yaml"
  printf '  session:\n    briefing:\n      message: "E2E briefing marker."\n'
} > "$proj/.cyberboar/policy.yaml"
git -C "$proj" init -q
# A deny rule for an MCP server whose name has a dot, ahead of the allow list
sed -i 's|^  mcp:$|  mcp:\n    deny:\n      - "e2e.srv/do_thing"|' "$proj/.cyberboar/policy.yaml"
mkdir -p "$home/.copilot"
first_launch_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '// User settings belong in settings.json.\n// This file is managed automatically.\n{\n  "firstLaunchAt": "%s"\n}\n' "$first_launch_at" > "$home/.copilot/config.json"
python3 -c 'import json, sys; json.dump({"mcpServers": {"e2e.srv": {"type": "local", "command": "python3", "args": [sys.argv[1]], "tools": ["*"]}}}, open(sys.argv[2], "w"))' \
  "$repo/test/e2e/mcp-server.py" "$home/.copilot/mcp-config.json"

(cd "$repo" && go build -ldflags "-X main.version=e2e" -o "$work/bin/cyberboar" ./cmd/cyberboar)
HOME="$home" COPILOT_HOME= "$work/bin/cyberboar" apply --agent copilot-cli --scope user \
  --policy "$proj/.cyberboar/policy.yaml" --audit "$work/audit.jsonl" --write >/dev/null

python3 - "$proj" "$home" > "$work/script.json" <<'PY'
import json, sys
proj, home = sys.argv[1:3]
print(json.dumps([
    ["bash", {"command": "ls src", "description": "harmless"}],
    ["bash", {"command": "cat .env", "description": "secret"}],
    ["view", {"path": proj + "/README.md"}],
    ["view", {"path": proj}],
    ["view", {"path": home + "/.ssh/id_rsa"}],
    ["create", {"path": proj + "/src/ok.txt", "file_text": "ok\n"}],
    ["create", {"path": proj + "/.env.prod", "file_text": "X=1\n"}],
    ["create", {"path": proj + "/.github/hooks/allow.json", "file_text": "{}"}],
    ["bash", {"command": "git push origin main", "description": "push"}],
    ["sql", {"description": "q", "query": "select 1"}],
    ["sql", {"description": "q", "query": "ATTACH '" + proj + "/.env' AS x"}],
    ["task", {"name": "sub", "prompt": "look", "agent_type": "explore", "description": "explore"}],
    ["view", {"path": proj + "/.env"}],
    ["e2e-srv-do_thing", {"a": "x"}],
]))
PY
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 "$repo/test/e2e/scripted-model.py" "$port" "$work/script.json" "$work/model.jsonl" &
model_pid=$!
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$port/v1/models" >/dev/null && break; sleep 0.1; done

(cd "$proj" && HOME="$home" COPILOT_HOME= XDG_CONFIG_HOME= XDG_STATE_HOME= \
  COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:$port/v1" COPILOT_PROVIDER_MODEL_ID=claude-sonnet-4.5 \
  COPILOT_PROVIDER_WIRE_MODEL=scripted timeout 300 "$copilot" -p "Run the e2e script." --allow-all-tools \
  > "$work/stdout.txt" 2> "$work/stderr.txt") || true

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
check "the fake secret never reaches the model" "! grep -q '$secret' '$work/model.jsonl'"
check "the session briefing reaches the model" "grep -q 'E2E briefing marker' '$work/model.jsonl'"
check "bash cat .env is denied" "[ \$(count deny bash files.deny) -ge 1 ]"
check "view .env and ~/.ssh/id_rsa are denied" "[ \$(count deny view files.deny) -ge 2 ]"
check "creating .env.prod is denied" "[ \$(count deny create files.deny) -ge 1 ]"
check "writing a Copilot hooks file is denied" "[ \$(count deny create builtin.guarded) -ge 1 ]"
check "SQL file access is denied" "[ \$(count deny sql adapter.sqlFileAccess) -ge 1 ]"
check "git push asks (denied by Copilot in -p)" "[ \$(count ask bash commands.ask) -ge 1 ]"
check "harmless calls are allowed" "[ \$(count allow bash -) -ge 1 ] && [ \$(count allow view -) -ge 2 ] && [ \$(count allow create -) -ge 1 ]"
check "the subagent call is seen" "[ \$(count allow task -) -ge 1 ]"
check "the deny rule covers the rewritten MCP name" "[ \$(count deny e2e-srv-do_thing mcp.deny) -ge 1 ]"
check "no hook setup or internal errors" "[ \$(count - - error.) -eq 0 ]"
check "src/ok.txt was written, .env.prod was not" "[ -f '$proj/src/ok.txt' ] && [ ! -e '$proj/.env.prod' ]"
echo "decisions:"
python3 -c '
import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l); a = (e.get("actions") or [{}])[0]
    print("  %-5s %-26s %-6s %s" % (e["decision"], e["rule"], e.get("tool", ""), (a.get("command") or a.get("path") or "")[-50:]))
' "$work/audit.jsonl" 2>/dev/null || true
if [ $fail -ne 0 ]; then
  echo "copilot stderr:"; tail -20 "$work/stderr.txt"
fi
exit $fail
