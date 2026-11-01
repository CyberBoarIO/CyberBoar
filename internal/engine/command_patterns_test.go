package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/policy/cmdpattern"
)

// Rules use shell quoting too, so equivalent argument spellings must match
// after the policy is loaded, for deny, ask and allow rules.
func TestQuotedCommandPatternEscapes(t *testing.T) {
	for _, tc := range []struct {
		pattern, command string
	}{
		{`printf "\$TOKEN"`, `printf '$TOKEN'`},
		{`printf "a\"b"`, `printf 'a"b'`},
		{`printf "a\\b"`, `printf 'a\b'`},
		{`printf "\q"`, `printf '\q'`},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			for _, kind := range []string{"deny", "ask", "allow"} {
				t.Run(kind, func(t *testing.T) {
					p := emptyPolicy(policy.DenyListed)
					want, other := Deny, Allow
					switch kind {
					case "deny":
						p.Spec.Commands.Deny = []string{tc.pattern}
					case "ask":
						p.Spec.Commands.Ask = []string{tc.pattern}
						want = Ask
					case "allow":
						p.Spec.Commands.Allow = []string{tc.pattern}
						want, other = Allow, Deny
					}
					data, err := json.Marshal(p)
					if err != nil {
						t.Fatal(err)
					}
					loaded, err := policy.Load(data)
					if err != nil {
						t.Fatal(err)
					}
					c := mustCompile(t, loaded)
					a := Action{Tool: ToolShell, Command: tc.command, Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}
					if v := Evaluate(context.Background(), c, a); v.Decision != want || v.Rule != "commands."+kind+"[0]" {
						t.Errorf("matching argument: %s by %s, want %s", v.Decision, v.Rule, want)
					}
					a.Command = "printf different"
					if v := Evaluate(context.Background(), c, a); v.Decision != other {
						t.Errorf("different argument: %s by %s, want %s", v.Decision, v.Rule, other)
					}
				})
			}
		})
	}
}

// Matching short options split over many words takes bounded work: a long
// run without the rule's letters is passed over, and one too long to search
// matches at best possibly, which still denies.
func TestFlagRunMatchingIsBounded(t *testing.T) {
	p, err := cmdpattern.Parse("rm -rf /")
	if err != nil {
		t.Fatal(err)
	}
	argv := func(n int, tail ...string) []shell.Elem {
		out := []shell.Elem{{Kind: shell.Lit, Text: "rm"}}
		for range n {
			out = append(out, shell.Elem{Kind: shell.Lit, Text: "-r"})
		}
		for _, w := range tail {
			out = append(out, shell.Elem{Kind: shell.Lit, Text: w})
		}
		return out
	}
	for _, tc := range []struct {
		name string
		argv []shell.Elem
		min  level
		max  level
	}{
		{"no f", argv(20000, "/"), noMatch, noMatch},
		{"f at the end", argv(20000, "-f", "/"), possible, certain},
		{"f, then no root", argv(20000, "-f", "x"), noMatch, possible},
		{"short", argv(3, "-f", "/"), certain, certain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			l := matchArgv(p.Stages[0], tc.argv, true, true)
			if l < tc.min || l > tc.max {
				t.Errorf("level %d, want %d to %d", l, tc.min, tc.max)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
}
