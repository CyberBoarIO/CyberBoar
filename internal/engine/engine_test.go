package engine

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

func emptyPolicy(posture policy.Posture) *policy.Policy {
	return &policy.Policy{
		APIVersion: brand.APIVersion,
		Kind:       "Policy",
		Metadata:   policy.Metadata{Name: "test"},
		Spec:       policy.Spec{Defaults: policy.Defaults{Posture: posture}},
	}
}

func mustCompile(t *testing.T, p *policy.Policy) *Compiled {
	t.Helper()
	c, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var readme = Action{Tool: ToolRead, Path: "README.md", Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}

// expiresAfterFirstCheck is a context that is live the first time Evaluate
// asks and has expired every time after: the deadline passes while the policy is being evaluated
type expiresAfterFirstCheck struct {
	context.Context
	checks int
}

func (c *expiresAfterFirstCheck) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.DeadlineExceeded
	}
	return nil
}

func expiresDuringEvaluation() context.Context {
	return &expiresAfterFirstCheck{Context: context.Background()}
}

// Every case here would allow if the fail-closed path were missing
func TestFailClosed(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))

	t.Run("context already expired", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertDeny(t, Evaluate(ctx, c, readme), RuleDeadline)
	})

	t.Run("context expires during evaluation", func(t *testing.T) {
		assertDeny(t, Evaluate(expiresDuringEvaluation(), c, readme), RuleDeadline)
	})

	t.Run("panic during evaluation", func(t *testing.T) {
		// A Compiled without a policy panics on its first rule lookup
		assertDeny(t, Evaluate(context.Background(), &Compiled{}, readme), RuleInternal)
	})

	t.Run("nil context", func(t *testing.T) {
		//nolint:staticcheck // SA1012: deliberately passing nil to prove it fails closed
		assertDeny(t, Evaluate(nil, c, readme), RuleInternal)
	})

	t.Run("unknown posture", func(t *testing.T) {
		c := mustCompile(t, emptyPolicy("permissive"))
		assertDeny(t, Evaluate(context.Background(), c, readme), RulePostureAllowListed)
	})

	shellAction := readme
	shellAction.Tool, shellAction.Path, shellAction.Command = ToolShell, "", "ls"
	t.Run("command line over the size limit", func(t *testing.T) {
		big := shellAction
		big.Command = "echo " + strings.Repeat("x", 64<<10)
		assertDeny(t, Evaluate(context.Background(), c, big), RuleCommandTooLarge)
	})
	t.Run("bare assignments over the command limit", func(t *testing.T) {
		big := shellAction
		big.Command = strings.Repeat("LD_PRELOAD=x;", shell.MaxCommands+1)
		assertDeny(t, Evaluate(context.Background(), c, big), RuleTooComplex)
	})
}

func assertDeny(t *testing.T, v Verdict, rule string) {
	t.Helper()
	if v.Decision != Deny || v.Rule != rule {
		t.Errorf("want deny by %s, got %s by %s (%s)", rule, v.Decision, v.Rule, v.Reason)
	}
	if v.Reason == "" {
		t.Error("deny without a reason")
	}
}

func TestCompileRejectsNilPolicy(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Error("Compile(nil) succeeded")
	}
}

func TestStrictest(t *testing.T) {
	allow := Verdict{Decision: Allow, Rule: "a"}
	ask := Verdict{Decision: Ask, Rule: "q"}
	deny1 := Verdict{Decision: Deny, Rule: "d1"}
	deny2 := Verdict{Decision: Deny, Rule: "d2"}
	bogus := Verdict{Decision: "maybe", Rule: "x"}

	for _, tc := range []struct {
		name string
		in   []Verdict
		want string
	}{
		{"single allow", []Verdict{allow}, "a"},
		{"ask beats allow", []Verdict{allow, ask}, "q"},
		{"deny beats ask", []Verdict{ask, deny1, allow}, "d1"},
		{"first deny wins a tie", []Verdict{deny1, deny2}, "d1"},
		{"a rule beats the posture on a tie", []Verdict{{Decision: Deny, Rule: RulePostureAllowListed}, deny2}, "d2"},
		{"the posture beats a secret on a tie", []Verdict{{Decision: Deny, Rule: RuleSecretsPrefix + "x"}, {Decision: Deny, Rule: RulePostureAllowListed}}, RulePostureAllowListed},
		{"unknown decision counts as deny", []Verdict{allow, bogus}, "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Strictest(tc.in)
			if !ok || got.Rule != tc.want {
				t.Errorf("got %+v (ok=%v), want rule %s", got, ok, tc.want)
			}
		})
	}
	if _, ok := Strictest(nil); ok {
		t.Error("Strictest(nil) reported a verdict")
	}
}

// A directory too large to scan is denied in every containing mode
func TestContainingScanLimit(t *testing.T) {
	root := t.TempDir()
	for i := range 10 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{"**/.env*"}
	a := Action{Tool: ToolRead, Path: root, Cwd: root, Home: "/home/dev", Workspaces: []string{root}}

	for _, mode := range []policy.Containing{"", policy.ContainingDeny} { // "": a Policy not built by Load
		p.Spec.Files.Containing = mode
		b := mustCompile(t, p).bind(fileEnv{fs: a.fs(), protected: a.Protected})
		f := b.scanDir(root, false, 5)
		v, hit := b.containingResult(root, f)
		if !hit {
			t.Fatalf("limit finding did not decide: %+v", f)
		}
		assertDeny(t, v.verdict, RuleContainingLimit)
	}
	p.Spec.Files.Containing = policy.ContainingAsk
	b := mustCompile(t, p).bind(fileEnv{fs: a.fs()})
	result, hit := b.containingResult(root, b.scanDir(root, false, 5))
	if !hit || result.verdict.Decision != Deny || result.verdict.Rule != RuleContainingLimit {
		t.Errorf("containing ask over the limit: got %+v (hit=%v)", result, hit)
	}
	// With "ignore" the walk looks only for what the built-in rules deny,
	// which it can't rule out past the limit either
	p.Spec.Files.Containing = policy.ContainingIgnore
	if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != Allow {
		t.Errorf("containing ignore: got %s by %s", v.Decision, v.Rule)
	}
	b = mustCompile(t, p).bind(fileEnv{fs: a.fs(), protected: a.Protected})
	f := b.scanDir(root, false, 5)
	v, hit := b.containingResult(root, f)
	if !hit {
		t.Fatalf("limit finding did not decide: %+v", f)
	}
	assertDeny(t, v.verdict, RuleContainingLimit)
}

// Alias descendants count again because their lexical names need their own policy checks
// The shared entry limit bounds that extra work
func TestContainingAliasScanLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("engine paths differ from OS paths on Windows")
	}
	root := t.TempDir()
	real := filepath.Join(root, "a-real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(real, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a-real", filepath.Join(root, "z-link")); err != nil {
		t.Skipf("can't create a symlink: %v", err)
	}
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{"**/absent"}
	a := Action{Tool: ToolRead, Path: root, Cwd: root, Home: "/home/dev", Workspaces: []string{root}}
	b := mustCompile(t, p).bind(fileEnv{fs: a.fs()})
	if f := b.scanDir(root, false, 4); f.kind != foundUncheckable || f.rule != RuleContainingLimit {
		t.Errorf("alias exceeds shared budget: %+v", f)
	}
	if f := b.scanDir(root, false, 6); f.kind != foundNothing {
		t.Errorf("six entries fit the budget: %+v", f)
	}
}

// Entries found walking / are named /bin, not //bin, so absolute rules match
// them. Reading / is denied by the built-in rules before any walk, so the
// walk is called directly, with a rule for an entry it reaches before /dev
func TestContainingScanAtRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/ is not a directory on Windows")
	}
	entries, err := os.ReadDir("/")
	if err != nil || len(entries) == 0 || entries[0].Name() >= "dev" {
		t.Skip("no entry in / before /dev")
	}
	first := "/" + entries[0].Name()
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{first}
	p.Spec.Files.Containing = policy.ContainingDeny
	b := mustCompile(t, p).bind(fileEnv{fs: Action{}.fs()})
	if f := b.scanDir("/", false, maxScanEntries); f.rule != "files.deny[0]" || f.kind != foundDeny || f.entry != first {
		t.Errorf("scanDir(/) = %+v; want a deny finding by files.deny[0] at %s", f, first)
	}
}

// The walk keys each directory by its resolved path, so one it can't
// resolve can't be walked and is a deny finding
// Reading such a directory fails earlier, so the walk is called directly, on a link loop
func TestContainingScanUnresolvable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("engine paths differ from OS paths on Windows")
	}
	root := t.TempDir()
	for _, l := range [][2]string{{"b", "a"}, {"a", "b"}} {
		if err := os.Symlink(l[0], filepath.Join(root, l[1])); err != nil {
			t.Skipf("can't create a symlink: %v", err)
		}
	}
	b := mustCompile(t, emptyPolicy(policy.DenyListed)).bind(fileEnv{fs: Action{}.fs()})
	if f := b.scanDir(filepath.Join(root, "a"), false, maxScanEntries); f.kind != foundUncheckable || f.rule != RuleContainingLimit {
		t.Errorf("scanDir of a link loop = %+v; want a deny finding by %s", f, RuleContainingLimit)
	}
}

// A policy without deny or ask rules still has the built-in rules to
// enforce, so a directory too large to walk is denied as it is under any
// other policy: past the limit there may be a link to /proc/self/environ
func TestContainingScanLimitWithoutRules(t *testing.T) {
	root := t.TempDir()
	for i := range 10 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The link's name sorts after the files, so a walk of 5 entries stops before it
	if err := os.Symlink("/proc/self/environ", filepath.Join(root, "zenv")); err != nil {
		t.Skipf("can't create a symlink: %v", err)
	}
	p := emptyPolicy(policy.DenyListed)
	for _, mode := range []policy.Containing{policy.ContainingDeny, policy.ContainingAsk, policy.ContainingIgnore} {
		p.Spec.Files.Containing = mode
		for _, protected := range [][]string{nil, {"/var/lib/state"}} {
			a := Action{Tool: ToolRead, Path: root, Cwd: root, Home: "/home/dev", Workspaces: []string{root}, Protected: protected}
			b := mustCompile(t, p).bind(fileEnv{fs: a.fs(), protected: a.Protected})
			f := b.scanDir(root, false, 5)
			v, hit := b.containingResult(root, f)
			if !hit {
				t.Fatalf("limit finding did not decide: %+v", f)
			}
			assertDeny(t, v.verdict, RuleContainingLimit)
			assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RuleProcfs)
		}
	}
}

// A directory the walk can't read could hold a link to /proc/self/environ,
// so reading what holds it is denied in every containing mode
func TestContainingUnreadable(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("a directory without permissions is still readable here (root, or Windows)")
	}
	a := Action{Tool: ToolRead, Path: root, Cwd: root, Home: "/home/dev", Workspaces: []string{root}}
	p := emptyPolicy(policy.DenyListed)
	assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RuleContainingLimit)
	p.Spec.Files.Deny = []string{"**/.env*"}
	for _, mode := range []policy.Containing{policy.ContainingDeny, policy.ContainingIgnore} {
		p.Spec.Files.Containing = mode
		assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RuleContainingLimit)
	}
	p.Spec.Files.Containing = policy.ContainingAsk
	assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RuleContainingLimit)
}

// ~user expands to that user's home, like bash: the agent's own user name is another way to write ~
func TestTildeUserResolves(t *testing.T) {
	u, err := user.Current()
	if err != nil || u.HomeDir == "" || strings.ContainsAny(u.Username, `\ `) {
		t.Skipf("no current user ~ can name: %v", err)
	}
	home, repo := u.HomeDir, t.TempDir()

	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{"~/.ssh/**"}
	c := mustCompile(t, p)
	for cmd, want := range map[string]Decision{
		"cat ~" + u.Username + "/.ssh/id_rsa":    Deny,
		"cat ~" + u.Username + "/notes.txt":      Allow,
		"cat ~nobody42/.ssh/x":                   Ask,
		"cd ~" + u.Username + "/.ssh && cat key": Deny,
	} {
		v := Evaluate(context.Background(), c, Action{Tool: ToolShell, Command: cmd, Cwd: repo, Home: home, Workspaces: []string{repo}})
		if v.Decision != want {
			t.Errorf("%s: %s by %s (%s), want %s", cmd, v.Decision, v.Rule, v.Reason, want)
		}
	}
}

// A name with a character Win32 forbids can't exist for Windows programs,
// so it is never looked up, even where the file system underneath could hold it
func TestWindowsForbiddenNameNotLookedUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS can't hold the fixture's name")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "c", "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "c", "secrets"), filepath.Join(root, "c", "k|y")); err != nil {
		t.Fatal(err)
	}
	fsys := osfs.FS{Windows: true, Drives: map[string]string{"c": filepath.Join(root, "c")}}
	got, err := resolvePath(fsys, "/c/k|y/token")
	if err != nil || got != "/c/k|y/token" {
		t.Fatalf("resolvePath = %q, %v; want the name kept as written", got, err)
	}
}

// An MCP call involves no path, so on Windows, as on POSIX, it needs no home directory or working directory
func TestWindowsMCPNeedsNoPaths(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))
	a := Action{Tool: ToolMCP, MCP: MCPCall{Server: "github", Tool: "search"}, Platform: PlatformWindows}
	if v := Evaluate(context.Background(), c, a); v.Decision != Allow {
		t.Errorf("got %s by %s (%s)", v.Decision, v.Rule, v.Reason)
	}
}

// Drive letters are case-insensitive: one given twice is refused rather than one of the two picked at random
func TestDuplicateDriveRefused(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))
	a := Action{Tool: ToolRead, Path: `C:\w\README.md`, Cwd: `C:\w`, Home: `C:\Users\dev`, Workspaces: []string{`C:\w`},
		Platform: PlatformWindows, Drives: map[string]string{"C": "/tmp/a", "c": "/tmp/b"}}
	assertDeny(t, Evaluate(context.Background(), c, a), RuleInvalidAction)
}

// A workspace root that holds the home directory is refused, and the reason
// shows it as the user knows it on Windows, not in the engine's /c/... form
func TestWindowsHomeWorkspaceReason(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))
	a := Action{Tool: ToolRead, Path: `C:\Users\dev\README.md`, Cwd: `C:\Users\dev`, Home: `C:\Users\dev`, Workspaces: []string{`C:\Users\dev`},
		Platform: PlatformWindows, Drives: map[string]string{"C": t.TempDir()}}
	v := Evaluate(context.Background(), c, a)
	assertDeny(t, v, RuleInvalidAction)
	if !strings.Contains(v.Reason, `workspace root C:\Users\dev is`) || !strings.Contains(v.Reason, "start the agent in a project folder") {
		t.Errorf("reason = %q", v.Reason)
	}
}

// An unresolved link or directory cycle cannot be approved without checking
// the files it might expose, even if an earlier protected file would ask
func TestContainingAskDeniesIncompleteWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("engine paths differ from OS paths on Windows")
	}
	for _, target := range []string{"loop", "."} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ".env"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "loop")); err != nil {
				t.Skipf("can't create a symlink: %v", err)
			}
			p := emptyPolicy(policy.DenyListed)
			p.Spec.Files.Deny = []string{"**/.env"}
			p.Spec.Files.Containing = policy.ContainingAsk
			a := Action{Tool: ToolRead, Path: root, Cwd: root, Home: "/home/dev", Workspaces: []string{root}}
			assertDeny(t, Evaluate(context.Background(), mustCompile(t, p), a), RuleContainingLimit)
			if err := os.Remove(filepath.Join(root, "loop")); err != nil {
				t.Fatal(err)
			}
			if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != Ask || v.Rule != "files.deny[0]" {
				t.Errorf("complete check of a protected file: got %s by %s", v.Decision, v.Rule)
			}
		})
	}
}

// A word longer than a file name can be, such as a long sed script, is no
// file, so it is checked as a missing path, not denied as unresolvable
func TestLongWordIsNoFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("engine paths differ from OS paths on Windows")
	}
	root := t.TempDir()
	long := strings.Repeat("x", 300)
	got, err := resolvePath(Action{}.fs(), root+"/"+long+"/y")
	if err != nil || got != root+"/"+long+"/y" {
		t.Fatalf("resolvePath = %q, %v; want the path itself", got, err)
	}
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{"**/.env*"}
	repo := filepath.Join(root, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	a := Action{Tool: ToolShell, Command: "sed -n 's/" + long + "/y/p' README.md", Cwd: repo, Home: root, Workspaces: []string{repo}}
	if v := Evaluate(context.Background(), mustCompile(t, p), a); v.Decision != Allow {
		t.Errorf("got %s by %s: %s", v.Decision, v.Rule, v.Reason)
	}
	if nameTooLong(strings.Repeat("/d", shortPathMax/2), syscall.ENAMETOOLONG) {
		t.Error("a path over PATH_MAX counts as a name too long")
	}
}
