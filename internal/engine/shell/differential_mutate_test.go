package shell_test

import (
	"math/rand/v2"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestBashDifferentialMutated runs the bash differential over variations of the
// corpus command lines: quotes, escapes, operators and brackets inserted,
// runs deleted or repeated, two lines spliced. The variations are what nobody
// writes by hand, which is where parsers disagree. The seed is fixed, so a
// run is reproducible; CYBERBOAR_BASH_DIFF_VARIATIONS sets how many (default
// 3000) and CYBERBOAR_BASH_DIFF_SEED another seed.
//
// Variations are less predictable than the corpus, so on top of the containment
// in TestBashDifferential bash runs in fresh user and network namespaces
// (unshare -rn): no network, and no privileges outside them. Without unshare
// the test skips rather than run unconfined.
func TestBashDifferentialMutated(t *testing.T) {
	if os.Getenv("CYBERBOAR_BASH_DIFF") != "1" {
		t.Skip("set CYBERBOAR_BASH_DIFF=1 (scripts/bash-differential.sh)")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not installed")
	}
	sandbox := []string{"unshare", "-rn", "--"}
	if err := exec.Command(sandbox[0], append(sandbox[1:], "true")...).Run(); err != nil {
		t.Skipf("no sandbox for variations (unshare -rn): %v", err)
	}
	n := 3000
	if v := os.Getenv("CYBERBOAR_BASH_DIFF_VARIATIONS"); v != "" {
		if n, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}

	seed := uint64(1)
	if v := os.Getenv("CYBERBOAR_BASH_DIFF_SEED"); v != "" {
		if seed, err = strconv.ParseUint(v, 10, 64); err != nil {
			t.Fatal(err)
		}
	}

	seeds := slices.Sorted(mapKeys(differentialInputs(t)))
	rng := rand.New(rand.NewPCG(seed, 2))
	work := t.TempDir()
	seen := map[string]bool{}
	var compared, skipped, rejected int
	var diffs []string
	for range n {
		in := mutate(rng, seeds)
		if seen[in] {
			continue
		}
		seen[in] = true
		switch outcome, detail := compareWithBash(t, bash, sandbox, work, in); outcome {
		case skippedInput:
			skipped++
		case rejectedByBash:
			rejected++
		case differs:
			diffs = append(diffs, detail)
		default:
			compared++
		}
	}
	t.Logf("variations: compared %d with bash; %d rejected by bash, %d not parsed or skipped", compared, rejected, skipped)
	for _, d := range diffs {
		t.Errorf("parser differential: %s", d)
	}
}

// fragments are what mutations insert: the characters and short sequences
// the two parsers treat specially.
var fragments = []string{
	`\`, `'`, `"`, "`", `$`, "\n", "\t", " ", `;`, `&`, `|`, `(`, `)`, `{`, `}`, `#`, `!`, `=`, `<`, `>`,
	`\` + "\n", `$(`, `$((`, `<(`, `>(`, `${`, `$'`, `$"`, `[[ `, ` ]]`, `{a,b}`, `*`, `?`, `[`, `]`,
	`;;`, `&&`, `||`, `|&`, `2>&1`, `<<E` + "\nE\n", `<<<`, `coproc `, `function `, `time `, `! `,
	`case x in x) `, `;; esac`, `for i in 1; do `, `; done`, `if true; then `, `; fi`, `x=1 `, `a[1]=`,
	`declare -a `, `eval `, `\n`, `@(x)`, `~`, `%`, `^`, `,`, `-`, `--`,
}

// mutate returns a variation of a random seed: one to three edits.
func mutate(rng *rand.Rand, seeds []string) string {
	s := seeds[rng.IntN(len(seeds))]
	for range 1 + rng.IntN(3) {
		i := rng.IntN(len(s) + 1)
		switch rng.IntN(5) {
		case 0, 1: // insert a fragment
			s = s[:i] + fragments[rng.IntN(len(fragments))] + s[i:]
		case 2: // delete a run
			j := min(len(s), i+1+rng.IntN(4))
			if i < j {
				s = s[:i] + s[j:]
			}
		case 3: // repeat a run
			j := min(len(s), i+1+rng.IntN(8))
			s = s[:j] + s[i:j] + s[j:]
		case 4: // splice another seed in
			o := seeds[rng.IntN(len(seeds))]
			k := rng.IntN(len(o) + 1)
			s = s[:i] + o[k:]
		}
	}
	return strings.ToValidUTF8(s, "")
}
