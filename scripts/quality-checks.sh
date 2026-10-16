#!/usr/bin/env bash
# Repository-wide quality checks on Linux, used by quality and release Actions
# Native platform compatibility and real-agent integration run separately
# --full also runs extended-tests.sh (fuzzing and the Bash differential)
set -euo pipefail
cd "$(dirname "$0")/.."
full=false
case "$#:${1:-}" in
  0:) ;;
  1:--full) full=true ;;
  *) echo "usage: $0 [--full]" >&2; exit 2 ;;
esac
if [[ $(go env GOOS) != linux ]]; then
  echo "quality checks require Linux; use the platform-compatibility scripts for native platform tests" >&2
  exit 2
fi

step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

step "gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then echo "$unformatted"; exit 1; fi

step "go vet"
go vet ./...
GOOS=windows go vet ./...   # native runtime tests run in the platform workflow
GOOS=darwin go vet ./...    # native runtime tests run in the platform workflow

step "go test"
go test -count=1 ./...

step "release-note gates"
python3 -m unittest discover -s test/release -p 'test_*.py' -v

step "workflow helper tests"
python3 -m unittest discover -s test/workflows -p 'test_*.py' -v

step "fuzz targets"
# Every fuzz target is listed, so --full and OSS-Fuzz (test/fuzz/oss-fuzz) run
# it: none left out.
diff <(grep -rhoE '^func Fuzz[A-Za-z0-9]+' --include='*_test.go' . | sed 's/^func //' | sort) \
  <(awk 'NF && $1 !~ /^#/ { print $2 }' test/fuzz/targets.txt | sort)

step "secret rules"
# rules_gen.go is generated from gitleaks.toml: regenerating it must give the committed file
# A mismatch is put back and fails the check
rules=internal/secrets/rules_gen.go
saved=$(mktemp)
cp "$rules" "$saved"
python3 -I scripts/gen-secret-rules.py >/dev/null
gofmt -w "$rules"
if ! cmp -s "$rules" "$saved"; then
  cp "$saved" "$rules"
  rm -f "$saved"
  echo "$rules is not what scripts/gen-secret-rules.py generates from gitleaks.toml" >&2
  exit 1
fi
rm -f "$saved"

step "go mod verify"
go mod verify

step "golangci-lint"
# staticcheck, gosec, errcheck and a few more; the set and every exception are in .golangci.yml
tools=$(mktemp -d)
trap 'rm -rf "$tools"' EXIT
GOBIN="$tools" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
"$tools/golangci-lint" run ./...
GOOS=windows "$tools/golangci-lint" run ./...
GOOS=darwin "$tools/golangci-lint" run ./...

step "gitleaks"
# Every commit, not only the tree: a secret removed later is still in the
# history. .gitleaks.toml allows the protocol's published test keys. Offline,
# unlike scanners that try each secret they find against its service.
GOBIN="$tools" go install github.com/zricethezav/gitleaks/v8@v8.30.1
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = false ] && \
    git rev-parse --verify HEAD >/dev/null 2>&1; then
  "$tools/gitleaks" git --no-banner --redact .
else
  warn "no complete committed history: gitleaks scans the files only"
  "$tools/gitleaks" dir --no-banner --redact .
fi

step "govulncheck"
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

step "latency budget"
# Alone, so other packages' tests don't skew the timing (docs/latency.md).
go test -count=1 -run '^TestLatencyBudget$' ./cmd/cyberboar/ -args -latency

step "PowerShell parser differential"
# PowerShell's own parser against ours (docs/powershell.md); GitHub's
# runners carry pwsh. Without it, TestParseGolden still replays the
# recorded trees in "go test".
if command -v pwsh >/dev/null; then scripts/pwsh-differential.sh; else warn "pwsh not installed: differential skipped"; fi

step "race detector"
if command -v gcc >/dev/null || command -v cc >/dev/null; then
  CGO_ENABLED=1 go test -race -count=1 ./...
else
  warn "no C compiler: -race skipped"
fi

if $full; then
  bash scripts/extended-tests.sh
fi

step "all checks passed"
