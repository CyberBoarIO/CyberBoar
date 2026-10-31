#!/usr/bin/env bash
# Starts the docs site's build after a push to main or a published release.
# This run's log is public

set -euo pipefail

: "${DOCS_TRIGGER:?}"

fail() { echo "docs trigger: $1" >&2; exit 1; }
mask() { [[ ${GITHUB_ACTIONS:-} != true ]] || echo "::add-mask::$1"; }

line_re='^(url|form-string) = "([^"\\]*)"$'
url_re='^https://([A-Za-z0-9.-]+(:[0-9]+)?)(/[^[:space:]]*)$'
config="" urls="" forms=""
while IFS= read -r line || [[ -n $line ]]; do
  line=${line%$'\r'}
  [[ -n ${line//[[:space:]]/} ]] || continue
  [[ $line =~ $line_re ]] || fail "DOCS_TRIGGER holds a line other than url = \"…\" or form-string = \"…\""
  key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
  if [[ $key == url ]]; then
    [[ $value =~ $url_re ]] || fail "DOCS_TRIGGER's url is not an https URL"
    # Secrets are masked whole
    mask "${BASH_REMATCH[1]}"
    [[ ${BASH_REMATCH[3]} == / ]] || mask "${BASH_REMATCH[3]}"
    urls+=.
  else
    [[ $value == ?*=* ]] || fail "DOCS_TRIGGER holds a form-string without a name"
    mask "$value"
    field=${value#*=}
    [[ ${#field} -lt 8 ]] || mask "$field"
    forms+=.
  fi
  config+="$key = \"$value\""$'\n'
done <<<"$DOCS_TRIGGER"
[[ $urls == . && -n $forms ]] || fail "DOCS_TRIGGER needs one url and at least one form-string"

code=$(printf %s "$config" | curl --config - --proto '=https' --tlsv1.2 --silent --output /dev/null \
  --write-out '%{http_code}' --max-time 30 --retry 3 2>/dev/null) || code=none
[[ $code =~ ^2[0-9][0-9]$ ]] || fail "the docs build wasn't started (HTTP status $code)"
echo "docs build started"
