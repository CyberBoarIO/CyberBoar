package engine

import (
	"context"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
)

// A path only known at run time is denied by the built-in rules when its
// literal parts pin it under /proc or /dev, as a literal or a glob there is
// A policy with no rules must not let it through
func TestBuiltinRulesCoverRunTimePaths(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))
	run := func(cmd string) Verdict {
		return Evaluate(context.Background(), c, Action{Tool: ToolShell, Command: cmd, Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}})
	}
	for cmd, rule := range map[string]string{
		"cat /proc/$PPID/environ":               RuleProcfs,
		`cat "/proc/$PPID/environ"`:             RuleProcfs,
		"cat /proc/${PPID}/environ":             RuleProcfs,
		`cat "/proc/$(pgrep -f agent)/environ"`: RuleProcfs,
		"cat /proc/`pgrep agent`/environ":       RuleProcfs,
		"xargs -0 < /proc/$PPID/environ":        RuleProcfs,
		`cat '/proc/'"$p"'/environ'`:            RuleProcfs,
		"cat /PROC/$PPID/environ":               RuleProcfs,
		"cat /tmp/../proc/$PPID/environ":        RuleProcfs,
		"cat /proc$X":                           RuleProcfs,
		"cat $D/proc/self/environ":              RuleProcfs,
		`cat "${D}proc/1/environ"`:              RuleProcfs,
		"cat $R/x/../../proc/self/environ":      RuleProcfs,
		"cat /dev/fd/$n":                        RuleDevFD,
		"cat /dev/std$x":                        RuleDevFD,
		"cat /dev/$x":                           RuleDevFD,
		`cat "$ROOT"/dev/fd/3`:                  RuleDevFD,
	} {
		assertDeny(t, run(cmd), rule)
	}
	// Literal parts that pin nothing protected leave the verdict to the policy
	for _, cmd := range []string{
		`cat "$f"`, "cat $f", `cat "$REPO/proc/handlers/main.go"`, `cat "$X/proc/notes"`,
		"cat /procedures/$X", "cat /dev/null$X", "cat <(echo hi)", "exec 3<>/dev/tcp/$host/80",
		"echo /proc/$PPID/environ", "ls ~-/x",
	} {
		if v := run(cmd); v.Decision == Deny {
			t.Errorf("%s: denied by %s (%s)", cmd, v.Rule, v.Reason)
		}
	}
}

func TestSplitShape(t *testing.T) {
	for shape, want := range map[string]string{
		"/proc/*/environ": "/proc/…/environ",
		`/a\*b/*`:         "/a*b/…",
		"*":               "…",
		`x\\*`:            `x\…`,
	} {
		if got := shapeDisplay(shape); got != want {
			t.Errorf("shapeDisplay(%q) = %q, want %q", shape, got, want)
		}
	}
}
