#!/usr/bin/env bash
# Native Intel and Apple Silicon tests for the platform compatibility workflow
# scripts/quality-checks.sh handles repository-wide lint, security and documentation checks

set -euo pipefail
cd "$(dirname "$0")/.."

expected_arch=${1:-$(go env GOARCH)}
if [[ $# -gt 1 || ! $expected_arch =~ ^(amd64|arm64)$ ]]; then
  echo "usage: $0 [amd64|arm64]" >&2
  exit 2
fi
if [[ $(go env GOOS)/$(go env GOARCH) != darwin/"$expected_arch" ]]; then
  echo "expected darwin/$expected_arch" >&2
  exit 1
fi

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$build_dir/cyberboar" ./cmd/cyberboar
"$build_dir/cyberboar" version
"$build_dir/cyberboar" check examples/baseline.yaml
go test -count=1 ./internal/engine/osfs ./internal/engine/shell \
  ./internal/endpoint/keystore ./internal/endpoint/enroll \
  ./internal/endpoint/pull ./internal/endpoint/ship \
  ./internal/hook/tripwire ./cmd/cyberboar
