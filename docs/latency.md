# Hook performance

CyberBoar starts a hook process for each intercepted tool call. The performance target
is a **median of at most 50 ms** for representative operations, measured from process
start to exit with policy loading, signature verification, evaluation and local audit
append included.

## Benchmark scope

The latency test covers file reads, simple commands, pipelines with globs, recursive
searches over a project of a few hundred files, writes and edits. It starts the real
binary 15 times per case with a signed baseline policy.

Run it separately so concurrent tests do not distort timing:

```sh
go test -count=1 -run '^TestLatencyBudget$' ./cmd/cyberboar/ -args -latency
```

The quality checks workflow runs this check on Linux. The target is a
repository regression budget, not a guarantee for every machine or input. Disk, CPU,
antivirus and audit storage can affect observed latency. `BenchmarkEvaluate` in
`internal/engine` measures evaluation without process startup.

## Resource bounds

| Operation | Bound / failure behavior |
|---|---|
| Hook decision | `--deadline`, default `5s`; includes policy, signature and key reads. Timeout denies. |
| Directory scan | At most 50,000 entries; different lexical aliases count again. An incomplete check can deny. |
| Single directory enumeration | Capped before sorting/matching; oversized directories deny even under `files.containing: ask`. |
| Audit append and reason redaction | Share the audit time limit; failure denies. |
| Signed policy expiry | Checked again after evaluation/auditing, before answering. |

Policy/key inputs must be regular files and are size-bounded before parsing. Large
recursive operations fall outside the representative 50 ms budget and are bounded by
scan limits and the decision deadline.

For timeout diagnosis, see [Troubleshooting](troubleshooting.md). Agent hook timeouts
and failure behavior are listed in the [capability matrix](capability-matrix.md).
