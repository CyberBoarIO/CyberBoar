package engine

import (
	"fmt"
	"strings"
)

// Decision is the engine's answer. The zero value is not a valid decision.
type Decision string

const (
	// Allow lets the action run.
	Allow Decision = "allow"
	// Ask stops the action until the user confirms it.
	Ask Decision = "ask"
	// Deny blocks the action.
	Deny Decision = "deny"
)

func (d Decision) severity() int {
	switch d {
	case Allow:
		return 1
	case Ask:
		return 2
	default: // Deny, and anything unexpected
		return 3
	}
}

// Built-in rule IDs for verdicts no policy rule produced.
// Audit events and `cyberboar explain` show them, so the strings are stable.
const (
	RulePostureDenyListed  = "posture.deny-listed"
	RulePostureAllowListed = "posture.allow-listed"
	RuleNoPolicy           = "error.noPolicy"
	RuleInvalidAction      = "error.invalidAction"
	RuleDeadline           = "error.deadline"
	RuleInternal           = "error.internal"
	RuleUnresolvablePath   = "error.unresolvablePath"
	RuleProcfs             = "builtin.procfs"
	RuleDevFD              = "builtin.devfd"
	RuleSelf               = "builtin.self"
	// RuleGuarded denies changing what installs and configures CyberBoar
	// (Action.Guarded): an agent could otherwise switch its own hook off.
	RuleGuarded = "builtin.guarded"
	// RuleWindowsPath denies Windows paths the engine refuses to read: UNC
	// paths, device namespaces, drive-relative paths, alternate data streams and device names.
	RuleWindowsPath = "builtin.windowsPath"
	// RuleContainingLimit is used when a directory was too large, or partly
	// unreadable, to rule out protected files inside it (files.containing).
	RuleContainingLimit = "files.containing"
)

// noRetry ends deny reasons. Without it, agents tend to retry a blocked
// action through a different tool or encoding.
const noRetry = "do not retry it in another form"

// Verdict is a decision plus why. Reason is shown to both the user and the
// agent, so deny reasons are phrased to discourage retrying another way.
type Verdict struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	// Rule identifies what decided, either a policy rule such as
	// "files.deny[0]" or a built-in ID such as "error.noPolicy".
	Rule string `json:"rule"`
	// Notice, when set, is also told to the user directly, where the agent
	// can show the user a message of its own (Claude Code's systemMessage).
	// It is set when the call was blocked for a reason only the user can do
	// something about, such as PowerShell outside native Windows.
	// The engine never sets it.
	Notice string `json:"notice,omitempty"`
}

func deny(rule, reason string) Verdict {
	return Verdict{Decision: Deny, Reason: reason, Rule: rule}
}

func invalidAction(err error) Verdict {
	return deny(RuleInvalidAction, fmt.Sprintf("the action could not be understood (%v), so it is blocked; %s", err, noRetry))
}

// Strictest returns the most severe verdict (deny > ask > allow).
// On ties a policy rule's verdict wins over the posture's, and the posture's
// over a secret's, since each says more about what to do instead; then the
// earliest wins, so results are deterministic
// ok is false for an empty list.
func Strictest(vs []Verdict) (v Verdict, ok bool) {
	for i, c := range vs {
		sc, sv := c.Decision.severity(), v.Decision.severity()
		if i == 0 || sc > sv || sc == sv && tieRank(c.Rule) > tieRank(v.Rule) {
			v = c
		}
	}
	return v, len(vs) > 0
}

// tieRank orders verdicts of one severity: a secret's, the posture's, then a policy rule's.
func tieRank(rule string) int {
	switch {
	case strings.HasPrefix(rule, RuleSecretsPrefix):
		return 0
	case rule == RulePostureDenyListed || rule == RulePostureAllowListed:
		return 1
	}
	return 2
}
