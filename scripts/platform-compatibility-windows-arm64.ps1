# Native Windows ARM64 checks for the platform compatibility workflow

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Invoke-Go {
    & go @args
    if ($LASTEXITCODE -ne 0) {
        throw "go $args failed with exit code $LASTEXITCODE"
    }
}

$targetOS = (Invoke-Go env GOOS).Trim()
$targetArch = (Invoke-Go env GOARCH).Trim()
if ($targetOS -ne 'windows' -or $targetArch -ne 'arm64') {
    throw "Expected windows/arm64, got $targetOS/$targetArch"
}

$buildDir = Join-Path ([System.IO.Path]::GetTempPath()) ('cyberboar-platform-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
    $binary = Join-Path $buildDir 'cyberboar.exe'
    Invoke-Go build -trimpath -o $binary ./cmd/cyberboar
    & $binary version
    if ($LASTEXITCODE -ne 0) { throw "version failed with exit code $LASTEXITCODE" }
    & $binary check examples/baseline.yaml
    if ($LASTEXITCODE -ne 0) { throw "policy check failed with exit code $LASTEXITCODE" }

    # The mount-table test skips if Git is absent; fail explicitly.
    $git = Get-Command git.exe -ErrorAction Stop
    & $git.Source --version
    if ($LASTEXITCODE -ne 0) { throw "git failed with exit code $LASTEXITCODE" }

    Invoke-Go test -count=1 ./internal/winpath ./internal/engine/osfs ./internal/adapters/claudecode/gitbash ./internal/endpoint/enroll ./internal/endpoint/keystore ./internal/endpoint/pull ./internal/boundedfile ./pkg/sign
    Invoke-Go test -count=1 -run 'Win' ./internal/engine/shell ./internal/adapters/claudecode
    Invoke-Go test -count=1 -run 'Windows' ./internal/engine
    Invoke-Go test -count=1 -run 'Lock|Rotated|Replaced|Truncated|Compressed|FileID|Lost' ./internal/endpoint/ship
    Invoke-Go test -count=1 -run '^(TestProjectPolicyComponents|TestAbsoluteApplyPaths|TestShortPathName)$' ./cmd/cyberboar
} finally {
    if (Test-Path $buildDir) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }
}
