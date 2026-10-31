#!/usr/bin/env bash
# Native Windows x64 checks: the Windows corpus files on NTFS,
# junctions and 8.3 short names, and the Windows reading of paths
# Run by the platform compatibility workflow; scripts/quality-checks.sh uses POSIX paths

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $(go env GOOS)/$(go env GOARCH) != windows/amd64 ]]; then
  echo "expected windows/amd64" >&2
  exit 1
fi

go vet ./...
go build ./...
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$build_dir/cyberboar.exe" ./cmd/cyberboar
"$build_dir/cyberboar.exe" version
"$build_dir/cyberboar.exe" check examples/baseline.yaml
# Installer paths use the host separator and must reject other volumes
go test -count=1 -v -run '^(TestProjectPolicyComponents|TestAbsoluteApplyPaths|TestSignSerialExpiry|TestSignReplacesSymlinkWithoutChangingTarget|TestSettingsBackupDoesNotFollowSymlink|TestShortPathName)$' ./cmd/cyberboar/
# Native Python's PATH can select Windows' WSL bash shim
CYBERBOAR_TEST_BASH="$(cygpath -w "$BASH")" python -m unittest discover -s test/release -p 'test_*.py' -v
go test -count=1 -v ./internal/winpath/ ./internal/engine/osfs/ ./internal/adapters/claudecode/gitbash/
go test -count=1 -v -run 'Windows' ./internal/engine/
go test -count=1 -run 'Win' ./internal/engine/shell/ ./internal/adapters/claudecode/
go test -count=1 -run 'TestCorpus/^windows' ./internal/engine/
# The endpoint key and enrolment must be private: protected DACLs for SYSTEM and the current user only
go test -count=1 -v ./internal/endpoint/enroll/
# The endpoint key in CNG: the software provider, and the TPM when the runner has one
go test -count=1 -v ./internal/endpoint/keystore/
# ship's lock is the Windows one (LockFileEx), and it follows a rotated log by its NTFS file ID
go test -count=1 -v -run 'Lock|TestInvalidAcknowledgmentKeepsEvents|Rotated|Replaced|Truncated|Compressed|FileID|Lost' ./internal/endpoint/ship/
go test -count=1 -v ./internal/endpoint/strictjson/
# Policy installation uses the same kernel locking guarantees
go test -count=1 -v ./internal/endpoint/pull/ ./internal/boundedfile/ ./pkg/sign/
# Hook trust, expiry and audit enforcement must also hold on native Windows
go test -count=1 -v -run '^(TestRequiredKeyErrorsDenyEveryAgent|TestOversizedPolicyDenied|TestPolicyExpiresDuringEvaluation|TestPolicyExpiresDuringAudit|TestAuditModePreservesSecretEnforcement|TestPolicyLockIsGuarded|TestMinimumVersion|TestSignedMinimumVersion|TestBriefMinimumVersion)$' ./internal/hook/
# The tripwire's state lock is the Windows one (LockFileEx), and its state files refuse symlinks
go test -count=1 -v ./internal/hook/tripwire/
# FuzzEvaluatePath remains in the fuzz target list and runs on main
