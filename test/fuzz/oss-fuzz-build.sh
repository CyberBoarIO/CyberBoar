#!/usr/bin/env bash
# Builds every Go fuzz target in test/fuzz/targets.txt as a libFuzzer
# binary inside OSS-Fuzz's base-builder-go image (test/fuzz/oss-fuzz).

set -euo pipefail
cd "$(dirname "$0")/../.."
module=$(go list -m)

awk 'NF && $1 !~ /^#/ { print $1, $2 }' test/fuzz/targets.txt | while read -r pkg fn; do
  compile_native_go_fuzzer_v2 "$module/$pkg" "$fn" "$fn"
done
