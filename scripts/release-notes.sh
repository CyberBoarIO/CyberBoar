#!/usr/bin/env bash
# Prints a dated release section for TAG
# No tag should publish a placeholder

set -euo pipefail
cd "$(dirname "$0")/.."
tag=${1:?usage: scripts/release-notes.sh TAG}

heading=$(awk -v tag="$tag" '
  /^## / && index($0, "## [" tag "] - ") == 1 { print }
' CHANGELOG.md)
date=${heading#* - }
if [[ -z "$heading" || ! "$date" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})$ ]]; then
  echo "release-notes: CHANGELOG.md needs exactly one dated section for $tag (## [$tag] - YYYY-MM-DD)" >&2
  exit 1
fi
year=$((10#${BASH_REMATCH[1]}))
month=$((10#${BASH_REMATCH[2]}))
day=$((10#${BASH_REMATCH[3]}))
days=31
case $month in
  4|6|9|11) days=30 ;;
  2)
    days=28
    if (( year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) )); then days=29; fi
    ;;
esac
if (( year < 1 || month < 1 || month > 12 || day < 1 || day > days )); then
  echo "release-notes: $date is not a valid calendar date for $tag" >&2
  exit 1
fi

notes=$(awk -v tag="$tag" '
  /^## / { if (found) exit; found = (index($0, "## [" tag "] - ") == 1); next }
  found
' CHANGELOG.md)
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "release-notes: CHANGELOG.md has no notes for $tag" >&2
  exit 1
fi
printf '%s\n' "$notes"
