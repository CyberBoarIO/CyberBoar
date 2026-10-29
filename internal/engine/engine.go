// Package engine decides whether an agent action is allowed under a policy.
//
// Evaluate never returns an error: every failure becomes a deny verdict (fail-closed).
package engine

import (
	"context"
	"errors"
	"fmt"

	"cyberboar.dev/cyberboar/internal/policy"
)

// Compiled is a policy prepared for evaluation.
type Compiled struct {
	policy   *policy.Policy
	files    fileRules
	commands cmdRules
	mcp      mcpRules
}

// Compile prepares a loaded policy for evaluation.
func Compile(p *policy.Policy) (*Compiled, error) {
	if p == nil {
		return nil, errors.New("engine: nil policy")
	}
	cmds, err := compileCmdRules(p.Spec.Commands.Rules)
	if err != nil {
		return nil, fmt.Errorf("engine: %v", err)
	}
	return &Compiled{
		policy:   p,
		files:    compileFileRules(p.Spec.Files.Rules),
		commands: cmds,
		mcp:      compileMCPRules(p.Spec.MCP),
	}, nil
}

// Policy returns the policy c was compiled from.
func (c *Compiled) Policy() *policy.Policy { return c.policy }

// allowListed reports whether a kind of action (files, commands or MCP)
// needs an allow rule. It does under allow-listed posture, and whenever the
// kind has an allow list, since allow rules under deny-listed posture would
// otherwise do nothing. A posture this code doesn't know counts as allow-listed.
func (c *Compiled) allowListed(r policy.Rules) bool {
	return c.policy.Spec.Defaults.Posture != policy.DenyListed || len(r.Allow) > 0
}

// Evaluate decides action a under policy c. A nil c (no valid policy) denies.
func Evaluate(ctx context.Context, c *Compiled, a Action) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			v = deny(RuleInternal, "internal error while evaluating the policy, so the action is blocked; do not retry it in another form")
		}
	}()

	if c == nil {
		return deny(RuleNoPolicy, "no valid policy is loaded, so every action is blocked until the user fixes the policy; do not retry")
	}
	if ctx.Err() != nil {
		return deadlineVerdict()
	}
	a, pv := a.fromPlatform()
	if pv != nil {
		return *pv
	}
	if err := a.validate(); err != nil {
		return invalidAction(err)
	}
	switch a.Tool {
	case ToolShell:
		v = c.evalShell(a)
	case ToolRead, ToolWrite, ToolList:
		v = c.evalFile(a)
	default: // ToolMCP
		v = c.evalMCP(a)
	}
	// A deny stands whatever else is found. Otherwise a secret's verdict
	// wins when it is stricter, and the policy's on a tie, so that the audit log names the policy's rule
	if v.Decision != Deny && (a.Tool == ToolShell || a.Tool == ToolWrite || a.Tool == ToolMCP) {
		if sv := c.evalSecrets(ctx, a); sv != nil {
			v, _ = Strictest([]Verdict{v, *sv})
		}
	}
	if ctx.Err() != nil {
		return deadlineVerdict()
	}
	return v
}

// deadlineVerdict is the verdict for an evaluation whose context has ended.
func deadlineVerdict() Verdict {
	return deny(RuleDeadline, "the policy decision timed out, so the action is blocked")
}

// allowNoRule is the verdict when no rule matched and no allow list applies.
func allowNoRule() Verdict {
	return Verdict{Decision: Allow, Reason: "no rule matched", Rule: RulePostureDenyListed}
}
