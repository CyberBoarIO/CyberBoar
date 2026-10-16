#!/usr/bin/env bash
# Compare CyberBoar's shell parser with Bash using corpus commands,
# parser fixtures and generated variations. Bash only parses the commands
#
# CYBERBOAR_BASH_DIFF_VARIATIONS sets the number of generated variations
# CYBERBOAR_BASH_DIFF_SEED sets the seed used to generate them

set -euo pipefail

cd "$(dirname "$0")/.."
CYBERBOAR_BASH_DIFF=1 go test -count=1 -run TestBashDifferential -v ./internal/engine/shell/ | grep -E "compared|parser differential|missed|^(ok|FAIL|---)"
