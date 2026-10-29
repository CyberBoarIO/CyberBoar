package tripwire

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/engine"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newStore(t *testing.T) (Store, *clock) {
	c := &clock{time.Now().UTC().Truncate(time.Second)}
	return Store{Dir: t.TempDir(), Now: c.now}, c
}

func TestLocksAtLimit(t *testing.T) {
	s, _ := newStore(t)
	for i := 1; i <= 3; i++ {
		st, err := s.Record("claude-code", "s1", "files.deny[0]", 3, 0)
		if err != nil {
			t.Fatal(err)
		}
		if st.Locked != (i == 3) {
			t.Fatalf("after %d denials locked = %v", i, st.Locked)
		}
	}
	st, err := s.Check("claude-code", "s1")
	if err != nil || !st.Locked || len(st.Denials) != 3 {
		t.Fatalf("Check = %+v, %v; want locked with 3 denials", st, err)
	}
	// Other sessions and agents are separate.
	for _, k := range [][2]string{{"claude-code", "s2"}, {"codex", "s1"}} {
		if st, err := s.Check(k[0], k[1]); err != nil || st.Locked || len(st.Denials) != 0 {
			t.Errorf("Check(%v) = %+v, %v; want a clean session", k, st, err)
		}
	}
}

func TestWindow(t *testing.T) {
	s, c := newStore(t)
	for i := range 5 {
		st, err := s.Record("codex", "s", "commands.deny[0]", 3, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if st.Locked {
			t.Fatalf("denial %d locked, but only two fall within any 10 minutes", i+1)
		}
		c.advance(6 * time.Minute)
	}
	c.advance(-6 * time.Minute)
	s.Record("codex", "s", "x", 3, 10*time.Minute)
	st, _ := s.Record("codex", "s", "x", 3, 10*time.Minute)
	if !st.Locked {
		t.Fatal("three denials within the window must lock")
	}
}

func TestWholeSessionByDefault(t *testing.T) {
	s, c := newStore(t)
	var st State
	for range 3 {
		st, _ = s.Record("a", "s", "files.deny[0]", 3, 0)
		c.advance(24 * time.Hour)
	}
	if !st.Locked {
		t.Fatal("with no window, denials count for the whole session")
	}
}

func TestStaysLockedAndUnlock(t *testing.T) {
	s, c := newStore(t)
	s.Record("a", "s", "r", 1, time.Minute)
	c.advance(time.Hour)
	st, _ := s.Check("a", "s")
	if !st.Locked {
		t.Fatal("a lock must not expire with the window")
	}
	if had, err := s.Unlock("a", "s"); !had || err != nil {
		t.Fatalf("Unlock = %v, %v", had, err)
	}
	if st, _ := s.Check("a", "s"); st.Locked {
		t.Fatal("still locked after Unlock")
	}
	if had, err := s.Unlock("a", "s"); had || err != nil {
		t.Fatalf("second Unlock = %v, %v; want false, nil", had, err)
	}
}

func TestConcurrentDenialsAllCount(t *testing.T) {
	s, _ := newStore(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := s.Record("a", "s", "r", 100, 0); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if st, _ := s.Check("a", "s"); len(st.Denials) != 20 {
		t.Fatalf("recorded %d of 20 concurrent denials", len(st.Denials))
	}
}

// Every unreadable state is an error, which the hook turns into a deny.
func TestBrokenStateIsAnError(t *testing.T) {
	s, c := newStore(t)
	if _, err := s.Record("a", "s", "r", 3, 0); err != nil {
		t.Fatal(err)
	}
	path := s.file("a", "s")
	for name, data := range map[string]string{
		"corrupt":       "{not json",
		"wrong session": `{"agent":"a","session":"other"}`,
		"mismatch":      `{"agent":"a","session":"s","denials":["` + c.now().Format(time.RFC3339) + `"]}`,
		// A write stopped before its truncate: the new state, then the old one's tail
		"interrupted write": `{"agent":"a","session":"s"}"denials":[]}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Check("a", "s"); err == nil {
			t.Errorf("%s: Check succeeded", name)
		}
		if _, err := s.Record("a", "s", "r", 3, 0); err == nil {
			t.Errorf("%s: Record succeeded", name)
		}
	}
	if _, err := s.Record("a", "s2", "r", 0, 0); err == nil {
		t.Error("a limit below 1 must be refused")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := s.Check("a", "s"); err == nil {
		t.Error("a symlinked state file must be refused")
	}
	if _, err := s.Record("a", "s", "r", 3, 0); err == nil {
		t.Error("recording through a symlink must be refused")
	}
}

// Recording a shorter state leaves no trace of the longer one before it.
func TestWriteReplacesLongerState(t *testing.T) {
	s, c := newStore(t)
	for range 3 {
		if _, err := s.Record("a", "s", "files.deny[0]", 5, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	c.advance(time.Hour)
	if _, err := s.Record("a", "s", "r", 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	st, err := s.Check("a", "s")
	if err != nil || len(st.Denials) != 1 || st.Rules[0] != "r" {
		t.Fatalf("Check = %+v, %v; want only the last denial", st, err)
	}
}

// A state file larger than maxState is refused even when it holds valid
// JSON, and recording a denial leaves it as it is, so the session stays
// refused. A file of exactly maxState bytes is read.
func TestStateSizeLimit(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Record("a", "s", "r", 3, 0); err != nil {
		t.Fatal(err)
	}
	path := s.file("a", "s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	padded := func(n int) []byte { return []byte(string(data) + strings.Repeat(" ", n-len(data))) }

	if err := os.WriteFile(path, padded(maxState), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := s.Check("a", "s"); err != nil || len(st.Denials) != 1 {
		t.Fatalf("file of maxState bytes: state %+v, err %v", st, err)
	}

	if err := os.WriteFile(path, padded(maxState+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check("a", "s"); err == nil {
		t.Error("Check read a file over maxState")
	}
	if _, err := s.Record("a", "s", "r", 3, 0); err == nil {
		t.Error("Record read a file over maxState")
	}
	if _, err := s.Check("a", "s"); err == nil {
		t.Error("the refused Record replaced the file over maxState")
	}
}

func TestList(t *testing.T) {
	s, _ := newStore(t)
	s.Record("codex", "b", "r", 5, 0)
	s.Record("claude-code", "z", "r", 1, 0)
	s.Record("claude-code", "a", "r", 5, 0)
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, st := range got {
		keys = append(keys, st.Agent+"/"+st.Session)
	}
	want := []string{"claude-code/z", "claude-code/a", "codex/b"}
	if len(keys) != 3 || keys[0] != want[0] || keys[1] != want[1] || keys[2] != want[2] {
		t.Fatalf("List = %v, want %v (locked first)", keys, want)
	}
}

func TestCountsRules(t *testing.T) {
	for rule, want := range map[string]bool{
		"files.deny[0]": true, "commands.denyInterpreters": true, "mcp.deny[1]": true,
		"posture.allow-listed": true, "builtin.procfs": true, "builtin.powershell": true, "files.containing": true,
		"secrets.github-pat": true, "secrets.unchecked": true,
		"error.deadline": false, "error.policySignature": false, "adapter.unclassifiedTool": false,
		"adapter.callNotFound": false, RuleLocked: false, "": false,
		engine.RuleUnparseable: true, engine.RuleTooComplex: true, engine.RuleCommandTooLarge: true,
		engine.RuleUnresolvablePath: false, engine.RuleInternal: false, engine.RuleNoPolicy: false,
	} {
		if Counts(rule) != want {
			t.Errorf("Counts(%q) = %v, want %v", rule, !want, want)
		}
	}
}
