# Contributing

Bug reports, compatibility details and proposals are welcome. Report vulnerabilities
privately under [SECURITY.md](SECURITY.md), including policy bypasses; do not publish
them in issues.

## Contribution intake and licensing

CyberBoar is licensed under [AGPL-3.0-only](LICENSE). Code, documentation and test
patches are welcome. Before a patch is merged, each contributor must sign the
[Individual Contributor License Agreement](docs/cla/individual.md). If an employer
owns the work, an authorized representative must also sign the
[Corporate CLA](docs/cla/entity.md) and authorize the contributing employees.

CLA assistant comments on your first pull request with a link to sign the Individual
CLA with your GitHub account. The Corporate CLA is signed by email. See
[signing](docs/cla/README.md#signing). A maintainer checks CLA coverage before
merging. Do not post signed forms or personal information in public PRs or issue
comments. A commit sign-off, PR checkbox or ordinary issue is not a CLA signature.

Contributors retain copyright. The agreements grant licenses that allow contributions
to be distributed in the open-source project and in separately licensed commercial
products. Disclose third-party material and co-authors. You are responsible for the
rights and correctness of submitted patches, including AI-assisted work.

### CLA signer privacy

When you sign the Individual CLA, the Project Owner named in it (dev@cyberboar.io)
receives your GitHub account, legal name, email, country, your answer about employer
rights, and the date and revision you signed. This data is used only to record the
licenses you grant and to contact you about them; the legal basis is the agreement
itself. Signing records are never published.

Signing happens on [CLA assistant](https://cla-assistant.io), operated by SAP, which
stores the data on Microsoft Azure in Europe. Corporate CLAs are signed by email and
kept privately by the Project Owner.

Records are kept for as long as your contributions are distributed, because the
licenses are perpetual. Email dev@cyberboar.io to get a copy of your data or to
correct it. You can also complain to a data protection authority.

## Report an ordinary issue

Include the operating system and architecture, CyberBoar and agent versions, policy
scope, a minimal policy, the exact tool call, expected behavior and observed
decision/rule ID. Use dummy data and remove credentials and unrelated personal
information from logs. Security reports use the private channel above.

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/cyberboar/` | CLI, one file per subcommand |
| `pkg/` | Public Go packages: audit, branding, bundles, endpoint authentication and signing |
| `internal/engine/` | Decision engine and shell analysis; development PowerShell parser |
| `internal/policy/` | Policy loading, schema validation and command patterns |
| `internal/adapters/` | Agent protocols and edit interpretation |
| `internal/hook/` | Hook execution, briefing and tripwire |
| `internal/endpoint/` | Enrollment, pull, ship and key storage |
| `internal/secrets/` | Credential detection |
| `internal/…` | Shared helpers: atomic files, case folding, Windows paths and test helpers |
| `testdata/` | Shared rule corpus and protocol fixtures |
| `test/` | Agent integration and fuzz harnesses; release and workflow tests |
| `examples/` | Example policies distributed in release archives |
| `docs/` | User guides and technical references |
| `scripts/` | CI, differentials and generation commands |

Packages belong in `pkg/` only when another module needs to import them. The public
API's compatibility guarantees begin at `v1.0.0`. Keep other code in `internal/`;
helpers serving one subsystem belong beneath it.

## Build and validation

Use Go 1.27.3 or later, Python 3.9 or later, and Bash. The release and workflow tests
use only Python's standard library; no Python packages are needed:

```sh
go build ./...
go test ./...
scripts/quality-checks.sh
```

The quality script runs on Linux and must pass before a commit or merge. It runs
formatting, vetting and linting for native/Windows/macOS targets, tests, module
verification, latency, secret scanning, dependency checks and race detection. Some
checks need additional tools; skipped checks produce warnings.
`scripts/quality-checks.sh --full` adds fuzzing and the real-Bash parsing differential.

Each script backs one part of the Actions workflows:

| Script | Purpose |
|---|---|
| `scripts/quality-checks.sh` | Repository-wide quality checks, also used before packaging a release |
| `scripts/extended-tests.sh` | Fuzzing and the Bash parser differential after a merge to `main` |
| `scripts/platform-compatibility-linux.sh` | Native Linux x64 or ARM64 build and tests |
| `scripts/platform-compatibility-macos.sh` | Native Intel or Apple Silicon macOS build and tests |
| `scripts/platform-compatibility-windows-x64.sh` | Native Windows x64 checks from Git Bash |
| `scripts/platform-compatibility-windows-arm64.ps1` | Native Windows ARM64 checks from PowerShell |
| `scripts/sync-experimental-branches.sh` | Open or reuse PRs from `main` to experimental branches |

The Linux and macOS helpers accept `amd64` or `arm64` to verify the expected
target, and default to the current Go architecture when run locally. Each native
helper checks the CLI version and baseline policy, and removes its temporary binary
when it finishes. Real-agent integration uses the harnesses in `test/e2e/`.

The [platform compatibility tests](.github/workflows/platform-compatibility-tests.yml)
build and test all six release targets on native runners on every PR and weekly:
Linux x64/ARM64, macOS Intel/Apple Silicon, and Windows x64/ARM64. Windows x64 uses
`scripts/platform-compatibility-windows-x64.sh` from Git Bash. It passes that
interpreter explicitly to native Python so release tests do not accidentally launch
Windows' WSL shim. For standalone release tests on Windows, set `CYBERBOAR_TEST_BASH`
to Git for Windows `bash.exe` path. The
[quality checks workflow](.github/workflows/quality-checks.yml) runs
`scripts/quality-checks.sh` on every PR and push to `main`, and
`scripts/extended-tests.sh` after a merge to `main`. See
[System requirements](docs/system-requirements.md) and
[Hook performance](docs/latency.md) for scope.

The [agent integration tests](.github/workflows/agent-integration-tests.yml) run
with real Codex CLI, Copilot CLI and opencode binaries. PRs use the checked versions; weekly
runs test both checked and latest versions. A scripted local model exercises
CyberBoar's hooks without accounts or paid model calls.

## Matching and test conventions

- For changes to command matching, add a regression case in `testdata/corpus/`
  that fails without the change. Bypass cases belong in `adversarial.yaml`.
- Test each decision error path for denial. There is no fail-open option.
- Use injected clocks for expiry tests. Keep fixed dates only in protocol fixtures,
  captured inputs and calendar boundary tests; derive other test times from the Unix epoch.
- Keep tests in `_test.go` beside the implementation, using an external
  `foo_test` package when only the exported API is needed.
- Put package fixtures in that package's `testdata/`. Only shared rule/protocol
  contracts belong in top-level `testdata/`.
- Shared test helpers belong in packages named `…test`, imported only by tests.
  Dependency guards and `TestBinaryLinksNoTestCode` enforce this separation.
- Do not add production hooks, mutable globals or exported options solely for
  tests. Inject the clock, environment, filesystem or device where control is
  needed, with production defaults.
- Prefer the standard library. Justify a new dependency in the commit message.
- When dependencies change, review their licenses and update the versions and
  upstream license texts in `THIRD_PARTY_NOTICES.txt`. Keep the notices in release
  archives; the dependency SBOM does not replace the license texts.

## Documentation changes

Write current behavior and task instructions, with prerequisites and expected results.
Keep research, implementation history and proposed features out of user guides. Preserve
documented enforcement gaps.

Update command/flag tables in [CLI reference](docs/cli.md) with CLI changes;
`TestCLIReference` checks them. Edit capability prose in
`internal/adapters/matrix_data_test.go`, then regenerate:

```sh
go test ./internal/adapters -update
```

Website publication is managed separately from this repository.

## Pull requests and commits

Discuss design changes in an issue first. Use short-lived branches targeting `main`.
Describe the problem, resulting behavior and validation in the PR.

Commit summaries follow `pkg/path: lowercase imperative summary`.

Disclose AI assistance in the PR description, not a commit trailer. Review and test all
submitted work; the contributor is responsible for it.

Experimental features target their `experimental/*` branch. Long-lived experimental
branches are not rebased. Each push to `main` opens or reuses a pull request from
`main` into each experimental branch missing those commits. Review the PR, resolve
any conflicts, and merge it with a merge commit after CI passes. The workflow never
merges PRs automatically. It can also be rerun manually from GitHub Actions.
Integrate completed experimental work into `main` by merging the whole branch,
preserving ancestry; do not squash or cherry-pick it.
