#!/usr/bin/env bash
# Compare CyberBoar's PowerShell parser with PowerShell using parser fixtures
# and generated variations, and its wildcard matching with PowerShell's.
# PowerShell only parses the commands.
#
# CYBERBOAR_PWSH_DIFF_VARIATIONS sets the number of generated variations
# CYBERBOAR_PWSH_DIFF_SEED sets the seed used to generate them
# Run with -update to refresh the recorded parser results

set -euo pipefail

cd "$(dirname "$0")/.."
if [ "${1:-}" = "-update" ]; then
  set -- -args -update
else
  set --
fi
CYBERBOAR_PWSH_DIFF=1 go test -count=1 -run '^TestPowerShellDifferential' -v ./internal/engine/shell/pwsh/ "$@" |
  grep -E "compared|different tree|rejected, PowerShell accepts|error of type|out of date|^(ok|FAIL|---)|^\s+(go|pwsh):"
CYBERBOAR_PWSH_DIFF=1 go test -count=1 -run '^TestPSWildcardDifferential$' ./internal/engine/shell/
