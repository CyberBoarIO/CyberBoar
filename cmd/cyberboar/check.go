package main

import (
	"flag"
	"fmt"
	"io"
	"slices"

	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/secrets"
	"cyberboar.dev/cyberboar/internal/semver"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// runCheck loads each policy and reports whether it compiles. Unknown secret
// rule IDs in secrets.ignore, and a minimumVersion this binary doesn't meet,
// are reported without failing the check
func runCheck(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintf(stderr, "usage: %s check POLICY...\n", brand.Name) }
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	failed := false
	for _, path := range fs.Args() {
		p, _, err := loadPolicy(path)
		if err != nil {
			failed = true
			fmt.Fprintf(stdout, "invalid %s: %v\n", path, err)
			continue
		}
		fmt.Fprintf(stdout, "ok      %s (%s)\n", path, p.Metadata.Name)
		for _, warning := range policy.Lint(p) {
			fmt.Fprintf(stdout, "        warning %s: %s\n", warning.Path, warning.Message)
		}
		if m := p.Spec.MinimumVersion; m != "" && !semver.AtLeast(version, m) {
			fmt.Fprintf(stdout, "        minimumVersion: %s; the hook of this version (%s) would block every tool call\n", m, version)
		}
		// An unknown rule ID is not an error, because rule sets change
		// between versions and a policy may be written for a newer one
		for _, id := range p.Spec.Secrets.Ignore {
			if !slices.Contains(secrets.Rules(), id) {
				fmt.Fprintf(stdout, "        secrets.ignore: no rule %q in this version\n", id)
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}
