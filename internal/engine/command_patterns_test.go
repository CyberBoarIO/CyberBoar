package engine

import (
	"context"
	"encoding/json"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
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
