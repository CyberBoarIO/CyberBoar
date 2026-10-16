# OSS-Fuzz

Build CyberBoar's Go fuzz tests as libFuzzer executables with
[OSS-Fuzz](https://google.github.io/oss-fuzz/).

## Build and run

Requires Docker and a checkout of [google/oss-fuzz](https://github.com/google/oss-fuzz).
The Go builder image must provide the Go version required by [go.mod](../../../go.mod).

Copy this directory's `Dockerfile`, `build.sh` and `project.yaml` into
`projects/cyberboar/` in the OSS-Fuzz checkout. From that checkout's root, run:

```sh
python3 infra/helper.py build_image cyberboar
python3 infra/helper.py build_fuzzers cyberboar
python3 infra/helper.py check_build cyberboar
```

The Dockerfile fetches CyberBoar from `CyberBoarIO/CyberBoar`.
Executables are placed in `build/out/cyberboar/`. Each executable is named after
the fuzz function it runs, for example `FuzzParseLine`.
To run one target:

```sh
python3 infra/helper.py run_fuzzer cyberboar FuzzParseLine
```

## Add a target

Add the Go `Fuzz` function and list its package and name in [targets.txt](../targets.txt).
The build script reads this list, and the quality checks reject missing targets.

This build does not export Go's `f.Add` seeds or `testdata/fuzz` files.
Supply an OSS-Fuzz seed corpus separately; see the
[seed corpus instructions](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#seed-corpus).

For hosted continuous fuzzing, submit the configuration through
[OSS-Fuzz's project setup process](https://google.github.io/oss-fuzz/getting-started/new-project-guide/).
