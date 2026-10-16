package pwsh

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

var update = flag.Bool("update", false, "rewrite "+goldenPath+" from PowerShell (with CYBERBOAR_PWSH_DIFF=1)")

var (
	inputsDir  = filepath.Join("testdata", "differential")
	goldenPath = filepath.Join(inputsDir, "trees.jsonl")
)

// TestParseGolden replays the differential offline: trees.jsonl holds what
// PowerShell's parser made of every input in testdata/differential
// (its tree, or that it failed), recorded by TestPowerShellDifferential, and
// Parse must agree with it as the differential requires
// It needs no PowerShell
func TestParseGolden(t *testing.T) {
	version, golden := readGolden(t)
	inputs := pwshInputs(t)
	results := make([]pwshResult, len(inputs))
	for i, in := range inputs {
		r, ok := golden[in]
		if !ok {
			t.Fatalf("%q is not in %s: run scripts/pwsh-differential.sh -update", in, goldenPath)
		}
		results[i] = r
	}
	if len(golden) != len(inputs) {
		t.Fatalf("%s has %d entries for %d inputs: run scripts/pwsh-differential.sh -update", goldenPath, len(golden), len(inputs))
	}
	compareResults(t, inputs, results, "PowerShell "+version+" (recorded): ")
}

// TestPowerShellDifferential compares the parser with PowerShell's own
// (docs/powershell.md): scripts/pwsh-ast.ps1 has Parser.ParseInput read every
// input in testdata/differential and writes its syntax tree, and
// the tree Parse builds must be the same, node for node and offset for
// offset. PowerShell only parses; nothing runs
//
// What PowerShell accepts and Parse refuses (docs/powershell.md) is counted,
// not an error: the engine denies it. Everything else that differs is an
// error, both ways: a different tree is a command line read differently, and
// valid PowerShell Parse rejects without refusing it is a parser bug, even
// though it fails closed. What PowerShell rejects and Parse accepts is logged:
// PowerShell would run nothing, and the post-parse checks that need types
// resolved are not ported (check.go). It needs pwsh (or Windows PowerShell)
// and CYBERBOAR_PWSH_DIFF=1 (scripts/pwsh-differential.sh); -update rewrites
// trees.jsonl, which TestParseGolden replays without PowerShell
func TestPowerShellDifferential(t *testing.T) {
	pwsh := needPwsh(t)
	inputs := pwshInputs(t)
	version, results := pwshParse(t, pwsh, inputs)
	compareResults(t, inputs, results, "PowerShell "+version+": ")
	if *update {
		writeGolden(t, version, inputs, results)
		return
	}
	gv, golden := readGolden(t)
	if gv != version {
		t.Logf("PowerShell %s differs from recorded %s; comparing parser results", version, gv)
	}
	for i, in := range inputs {
		g, ok := golden[in]
		if !ok {
			t.Errorf("%s has no recorded result for %q: run scripts/pwsh-differential.sh -update", goldenPath, in)
			continue
		}
		if g != results[i] {
			t.Errorf("%s: PowerShell %s parses %q differently from recorded %s:\n  current:  %+v\n  recorded: %+v",
				goldenPath, version, in, gv, results[i], g)
		}
	}
	if len(golden) != len(inputs) {
		t.Errorf("%s has %d recorded inputs, expected %d: run scripts/pwsh-differential.sh -update",
			goldenPath, len(golden), len(inputs))
	}
}

// TestPowerShellDifferentialMutated runs the differential over variations of
// the inputs: quotes, escapes, operators and brackets inserted, runs deleted
// or repeated, two inputs spliced. The variations are what nobody writes by
// hand, which is where parsers disagree. The seed is fixed, so a run is
// reproducible; CYBERBOAR_PWSH_DIFF_VARIATIONS sets how many (default 5000) and
// CYBERBOAR_PWSH_DIFF_SEED another seed
func TestPowerShellDifferentialMutated(t *testing.T) {
	pwsh := needPwsh(t)
	n, seed := 5000, uint64(1)
	if v := os.Getenv("CYBERBOAR_PWSH_DIFF_VARIATIONS"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	if v := os.Getenv("CYBERBOAR_PWSH_DIFF_SEED"); v != "" {
		var err error
		if seed, err = strconv.ParseUint(v, 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	seeds := pwshInputs(t)
	rng := rand.New(rand.NewPCG(seed, 3))
	seen := map[string]bool{}
	var variations []string
	for range n {
		if in := mutatePwsh(rng, seeds); !seen[in] {
			seen[in] = true
			variations = append(variations, in)
		}
	}
	version, results := pwshParse(t, pwsh, variations)
	compareResults(t, variations, results, "variations, PowerShell "+version+": ")
}

// TestPowerShellDifferentialFuzzCorpus runs the differential over a
// FuzzParsePowerShell corpus, the directory in CYBERBOAR_PWSH_DIFF_FUZZ
// (under go env GOCACHE, fuzz/cyberboar.dev/cyberboar/internal/engine/shell/pwsh/
// FuzzParsePowerShell): what the fuzzer found interesting in our parser,
// read by PowerShell's
func TestPowerShellDifferentialFuzzCorpus(t *testing.T) {
	dir := os.Getenv("CYBERBOAR_PWSH_DIFF_FUZZ")
	if dir == "" {
		t.Skip("set CYBERBOAR_PWSH_DIFF_FUZZ to a FuzzParsePowerShell corpus directory")
	}
	pwsh := needPwsh(t)
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	var inputs []string
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- test only, a corpus the developer names
		if err != nil {
			t.Fatal(err)
		}
		// A corpus file is "go test fuzz v1" and a line string("…")
		_, lit, ok := strings.Cut(string(data), "\nstring(")
		if !ok {
			continue
		}
		in, err := strconv.Unquote(strings.TrimSuffix(strings.TrimSpace(lit), ")"))
		// PowerShell never sees invalid UTF-8 or NUL from an agent (the
		// hook reads JSON); Parse rejects both
		if err == nil && utf8.ValidString(in) && !strings.ContainsRune(in, 0) {
			inputs = append(inputs, in)
		}
	}
	version, results := pwshParse(t, pwsh, inputs)
	compareResults(t, inputs, results, "fuzz corpus, PowerShell "+version+": ")
}

func needPwsh(t *testing.T) string {
	t.Helper()
	if os.Getenv("CYBERBOAR_PWSH_DIFF") != "1" {
		t.Skip("set CYBERBOAR_PWSH_DIFF=1 (scripts/pwsh-differential.sh)")
	}
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("PowerShell not installed")
	return ""
}

// pwshInputs reads testdata/differential/*.txt: inputs separated
// by lines holding only "---"; a block starting with # is a comment
// They come back sorted, without duplicates
func pwshInputs(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(inputsDir, "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no differential inputs: %v", err)
	}
	var inputs []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range strings.Split(string(data), "\n---\n") {
			if block = strings.Trim(block, "\n"); block != "" && !strings.HasPrefix(block, "#") {
				inputs = append(inputs, block)
			}
		}
	}
	slices.Sort(inputs)
	return slices.Compact(inputs)
}

// pwshResult is PowerShell's reading of one input: its tree, or OK false
// when it reports a parse error
type pwshResult struct {
	OK  bool   `json:"ok"`
	AST string `json:"ast,omitempty"`
}

// pwshParse has PowerShell parse every input, in one process.
func pwshParse(t *testing.T, pwsh string, inputs []string) (string, []pwshResult) {
	t.Helper()
	in := filepath.Join(t.TempDir(), "inputs.json")
	enc := make([]string, len(inputs))
	for i, s := range inputs {
		enc[i] = base64.StdEncoding.EncodeToString([]byte(s))
	}
	data, err := json.Marshal(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "pwsh-ast.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- test only: PowerShell found on PATH runs our script
	cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, in)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("pwsh-ast.ps1: %v", err)
	}
	var res struct {
		Version string       `json:"version"`
		Results []pwshResult `json:"results"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("pwsh-ast.ps1 output: %v", err)
	}
	if len(res.Results) != len(inputs) {
		t.Fatalf("pwsh-ast.ps1 returned %d results for %d inputs", len(res.Results), len(inputs))
	}
	return res.Version, res.Results
}

type goldenEntry struct {
	In string `json:"in"`
	pwshResult
}

// readGolden reads trees.jsonl: a first line {"version": …}, then an entry
// per input, sorted
func readGolden(t *testing.T) (string, map[string]pwshResult) {
	t.Helper()
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("%v (run scripts/pwsh-differential.sh -update)", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	var head struct {
		Version string `json:"version"`
	}
	if !sc.Scan() || json.Unmarshal(sc.Bytes(), &head) != nil || head.Version == "" {
		t.Fatalf("%s: no version line", goldenPath)
	}
	golden := map[string]pwshResult{}
	for sc.Scan() {
		var e goldenEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("%s: %v", goldenPath, err)
		}
		golden[e.In] = e.pwshResult
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return head.Version, golden
}

func writeGolden(t *testing.T, version string, inputs []string, results []pwshResult) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]string{"version": version}); err != nil {
		t.Fatal(err)
	}
	for i, in := range inputs {
		if err := enc.Encode(goldenEntry{In: in, pwshResult: results[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(goldenPath, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// compareResults checks Parse against PowerShell's results, as
// TestPowerShellDifferential describes
func compareResults(t *testing.T, inputs []string, results []pwshResult, label string) {
	t.Helper()
	var same, refused, limits, bothRejected, overAccepted int
	for i, in := range inputs {
		sb, err := Parse(in)
		var pe *Error
		switch {
		case err != nil && !errors.As(err, &pe):
			t.Errorf("%q: error of type %T: %v", in, err, err)
		case !results[i].OK && err != nil:
			bothRejected++
		case !results[i].OK:
			overAccepted++
			t.Logf("accepted, PowerShell rejects (safe): %q", in)
		case err != nil && pe.Refused:
			refused++
			if testing.Verbose() {
				t.Logf("refused: %q: %v", in, err)
			}
		case errors.Is(err, shell.ErrTooComplex) || errors.Is(err, shell.ErrTooLarge):
			limits++
		case err != nil:
			t.Errorf("%q: rejected, PowerShell accepts: %v\n  pwsh: %s", in, err, results[i].AST)
		default:
			if got := dump(sb); got != results[i].AST {
				t.Errorf("%q: different tree\n  go:   %s\n  pwsh: %s", in, got, results[i].AST)
			} else {
				same++
			}
		}
	}
	t.Logf("%scompared %d inputs: %d same, %d refused, %d over limits, %d rejected by both, %d rejected only by PowerShell",
		label, len(inputs), same, refused, limits, bothRejected, overAccepted)
}

// pwshFragments are what mutations insert: the characters and short
// sequences PowerShell's tokenizer treats specially
var pwshFragments = []string{
	"`", `'`, `"`, `$`, "\n", "\r", "\r\n", "\t", " ", `;`, `&`, `|`, `(`, `)`, `{`, `}`, `#`, `!`, `=`,
	`<`, `>`, "`\n", `$(`, `@(`, `@{`, `${`, `[`, `]`, `::`, `.`, `..`, `,`, `-`, `--`, `--%`, `&&`,
	`||`, `2>&1`, `*>`, `>>`, `<#`, `#>`, "@'\n", "\n'@", "@\"\n", "\n\"@", `""`, `''`, `-f `,
	`-eq `, `-not `, `-join `, `[int]`, `$x`, `$env:`, `@x`, `{}`, `()`, `0x`, `1e`, `kb`, `?`, `??`,
	`?.`, `%`, `+`, `++`, `+=`, `/`, `*`, `if (1) {`, `} else {`, `switch (1) {`,
	`foreach ($x in 1) {`, `function f {`, `param(`, `begin {`, `try {`, `} catch {`, `trap {`,
	`return `, `break `, `exit `, `throw `, `‘`, `’`, `“`, `”`, `–`, " ", " ", "\u0085",
}

// mutatePwsh returns a variation of a random seed: one to three edits
func mutatePwsh(rng *rand.Rand, seeds []string) string {
	s := seeds[rng.IntN(len(seeds))]
	for range 1 + rng.IntN(3) {
		i := rng.IntN(len(s) + 1)
		switch rng.IntN(5) {
		case 0, 1:
			s = s[:i] + pwshFragments[rng.IntN(len(pwshFragments))] + s[i:]
		case 2:
			j := min(len(s), i+1+rng.IntN(4))
			if i < j {
				s = s[:i] + s[j:]
			}
		case 3:
			j := min(len(s), i+1+rng.IntN(8))
			s = s[:j] + s[i:j] + s[j:]
		case 4:
			o := seeds[rng.IntN(len(seeds))]
			k := rng.IntN(len(o) + 1)
			s = s[:i] + o[k:]
		}
	}
	return strings.ToValidUTF8(s, "")
}
