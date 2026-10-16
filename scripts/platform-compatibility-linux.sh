#!/usr/bin/env bash
# Native Linux x64 and ARM64 checks for the platform compatibility workflow
# Repository-wide quality checks are in quality-checks.sh

set -euo pipefail
cd "$(dirname "$0")/.."

expected_arch=${1:-$(go env GOARCH)}
if [[ $# -gt 1 || ! $expected_arch =~ ^(amd64|arm64)$ ]]; then
  echo "usage: $0 [amd64|arm64]" >&2
  exit 2
fi
if [[ $(go env GOOS)/$(go env GOARCH) != linux/"$expected_arch" ]]; then
  echo "expected linux/$expected_arch" >&2
  exit 1
fi

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$build_dir/cyberboar" ./cmd/cyberboar
"$build_dir/cyberboar" version
"$build_dir/cyberboar" check examples/baseline.yaml
go test -count=1 ./...
