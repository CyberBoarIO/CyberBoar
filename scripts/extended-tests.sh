#!/usr/bin/env bash
# Fuzzing and the Bash parser differential after quality checks pass
# Actions run this after a merge to main; local runs can use quality-checks.sh --full

set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> real-bash parser differential"
bash scripts/bash-differential.sh

echo "==> fuzzing (60s per target)"
while read -r pkg fn; do
  go test -run '^$' -fuzz "^$fn\$" -fuzztime 60s "./$pkg/"
done < <(awk 'NF && $1 !~ /^#/ { print $1, $2 }' test/fuzz/targets.txt)
