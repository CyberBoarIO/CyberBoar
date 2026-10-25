#!/usr/bin/env bash
# End-to-end check against a real Codex CLI.
#
# Builds cyberboar, installs it with `apply --agent codex --scope user` into a
# throwaway CODEX_HOME, and runs `codex exec` against test/e2e/scripted-model.py
# (its Responses API), which asks for a fixed list of tool calls. No OpenAI
# account and no real model are involved, so the run is deterministic and free.
# Codex's sandbox and its hook trust prompt are bypassed for the run, since a
# container may not allow the sandbox and nobody is there to trust the hook.
# It checks:
#   - the fake secret never reaches the model, and the briefing does;
#   - the hook denies the secret, through a relative workdir that only the
#     session transcript shows, an image view and a write to the hook settings;
#   - a command started with a terminal (tty) is denied, since write_stdin,
#     which types into it, never reaches the hook;
#   - a deny rule covers an MCP tool whose name Codex rewrites (e2e.srv is
#     offered as mcp__e2e_srv);
#   - harmless calls go through.
# Needs: go, python3, curl, tar, network access to registry.npmjs.org (or
# CODEX=/path/to/codex). Linux x64 or arm64.
# Usage: test/e2e/codex.sh [--version 0.155.0]

set -euo pipefail

version=0.155.0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
# Codex clones its plugin marketplace into CODEX_HOME in the background, and
# the clone can outlive codex exec and still be writing when the run ends.
# Stop it and retry the removal, since a cleanup failure isn't a failed check
cleanup() {
  kill $model_pid 2>/dev/null || true
  pkill -f -- "$work" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    rm -rf "$work" 2>/dev/null && return
    sleep 1
  done
  echo "warning: could not remove $work" >&2
}
trap cleanup EXIT
model_pid=
secret="fake-e2e-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"

codex=${CODEX:-}
if [ -z "$codex" ]; then
  case "$(uname -m)" in
    x86_64) arch=x64 triple=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) arch=arm64 triple=aarch64-unknown-linux-musl ;;
    *) echo "unsupported machine $(uname -m)" >&2; exit 2 ;;
  esac
  mkdir -p "$work/codex"
  curl -fsSL "https://registry.npmjs.org/@openai/codex/-/codex-$version-linux-$arch.tgz" |
    tar -xz -C "$work/codex" --strip-components=1
  codex="$work/codex/vendor/$triple/bin/codex"
fi

home="$work/home" proj="$work/proj" codex_home="$work/home/.codex"
mkdir -p "$home/.ssh" "$codex_home" "$proj/src" "$proj/.cyberboar"
printf 'not a real key %s\n' "$secret" > "$home/.ssh/id_rsa"
printf 'API_KEY=%s\n' "$secret" > "$proj/.env"
printf '# Demo\n' > "$proj/README.md"
printf 'package main\n' > "$proj/src/main.go"
{
  cat "$repo/examples/baseline.yaml"
  printf '  session:\n    briefing:\n      message: "E2E briefing marker."\n'
} > "$proj/.cyberboar/policy.yaml"
# A deny rule for an MCP server whose name has a dot, ahead of the allow list
sed -i 's|^  mcp:$|  mcp:\n    deny:\n      - "e2e.srv/do_thing"|' "$proj/.cyberboar/policy.yaml"
git -C "$proj" init -q

(cd "$repo" && go build -ldflags "-X main.version=e2e" -o "$work/bin/cyberboar" ./cmd/cyberboar)
HOME="$home" CODEX_HOME="$codex_home" "$work/bin/cyberboar" apply --agent codex --scope user \
  --policy "$proj/.cyberboar/policy.yaml" --audit "$work/audit.jsonl" --write >/dev/null

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
cat >> "$codex_home/config.toml" <<EOF
model = "scripted"
model_provider = "scripted"
[model_providers.scripted]
name = "scripted"
base_url = "http://127.0.0.1:$port/v1"
wire_api = "responses"
[mcp_servers."e2e.srv"]
command = "python3"
args = ["$repo/test/e2e/mcp-server.py"]
EOF

python3 - "$proj" > "$work/script.json" <<'PY'
import json, sys
proj = sys.argv[1]
print(json.dumps([
    ["exec_command", {"cmd": "ls"}],
    ["exec_command", {"cmd": "cat .env"}],
    ["exec_command", {"cmd": "cat ../.env", "workdir": "src"}],
    ["exec_command", {"cmd": "cat main.go", "workdir": "src"}],
    ["exec_command", {"cmd": "more README.md", "tty": True}],
    ["exec_command", {"cmd": "echo '{}' > .codex/hooks.json"}],
    ["exec_command", {"cmd": "git push origin main"}],
    ["view_image", {"path": proj + "/.env"}],
    ["ns:mcp__e2e_srv:do_thing", {"a": "x"}],
    ["get_goal", {}],
]))
PY
python3 "$repo/test/e2e/scripted-model.py" "$port" "$work/script.json" "$work/model.jsonl" &
model_pid=$!
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$port/v1/models" >/dev/null && break; sleep 0.1; done

(cd "$proj" && HOME="$home" CODEX_HOME="$codex_home" timeout 300 "$codex" exec --skip-git-repo-check \
  --dangerously-bypass-approvals-and-sandbox --dangerously-bypass-hook-trust "Run the e2e script." \
  < /dev/null > "$work/stdout.txt" 2> "$work/stderr.txt") || true

fail=0
check() { if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi; }
# count DECISION TOOL|- RULE-PREFIX|-: audit lines matching all given filters
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
check "cat .env is denied, also through a relative workdir" "[ \$(count deny Bash files.deny) -ge 2 ]"
check "a command with a terminal is denied" "[ \$(count deny Bash adapter.interactiveSession) -ge 1 ]"
check "writing the hook settings is denied" "[ \$(count deny Bash builtin.guarded) -ge 1 ]"
check "git push asks, which Codex gets as a deny" "[ \$(count ask Bash commands.ask) -ge 1 ]"
check "viewing .env as an image is denied" "[ \$(count deny view_image files.deny) -ge 1 ]"
check "the deny rule covers the rewritten MCP name" "[ \$(count deny mcp__e2e_srv__do_thing mcp.deny) -ge 1 ]"
check "harmless calls are allowed" "[ \$(count allow Bash -) -ge 2 ] && [ \$(count allow get_goal -) -ge 1 ]"
check "no hook setup or internal errors" "[ \$(count - - error.) -eq 0 ] && [ \$(count - - adapter.callNotFound) -eq 0 ]"
echo "decisions:"
python3 -c '
import json, sys
for l in open(sys.argv[1]):
    e = json.loads(l); a = (e.get("actions") or [{}])[0]
    print("  %-5s %-28s %-24s %s" % (e["decision"], e["rule"], e.get("tool", ""), (a.get("command") or a.get("path") or "")[-40:]))
' "$work/audit.jsonl" 2>/dev/null || true
if [ $fail -ne 0 ]; then
  echo "codex stderr:"; tail -20 "$work/stderr.txt"
fi
exit $fail
