# Policy regression tests

CyberBoar can check intended decisions before policy deployment without installing an agent hook. Keep regression cases in version control beside your policies.

```sh
cyberboar check examples/baseline.yaml
cyberboar test --policy examples/baseline.yaml --cases testdata/policy-cases/baseline.tests.yaml
```

The test cases live in a **separate** YAML file, not under `spec` in the enforcement policy.

```yaml
tests:
  - name: Block env file
    action:
      read: .env
      cwd: /work/repo
      home: /home/dev
      workspace: /work/repo
    expect: deny
  - name: Require push approval
    action:
      command: git push origin main
      cwd: /work/repo
      home: /home/dev
      workspace: /work/repo
    expect: ask
  - name: Block other MCP servers
    action:
      mcp: slack/post
    expect: deny
```

Each case selects **exactly one** of `read`, `write`, `list`, `command` or `mcp`. Expected decisions are `allow`, `ask` and `deny`. Optional `cwd`, `home` and `workspace` must be absolute, and default to the running process's working directory, user's home and working directory respectively. File checks depend on the real filesystem: build hermetic fixtures in a throwaway directory when testing directory traversal, symlinks or existing files. The example uses virtual, POSIX-style paths; it is intended for macOS/Linux. Native Windows users should set appropriate absolute Windows paths in their cases.

`test` prints one PASS or FAIL line per case and a summary; it returns 1 for test mismatches or invalid fixtures, 2 for incorrect flags, and 0 when all pass. Inputs are bounded to 1 MiB and 1000 cases. It evaluates intent through the core engine, not the real agent harness, so it **does not prove hook enforcement** or coverage.

`check` prints advisory warnings for exactly duplicated patterns and exact cross-list conflicts (deny wins over ask/allow). It deliberately does not claim semantic overlap detection between different globs.

For integration verification, install a hook, ask the agent to attempt a harmless policy-denied operation, and confirm its actual denial and optional audit record. See [Agent setup](agents.md).
