// Package briefing writes what an agent is told when a session starts
// (spec.session.briefing). The briefing says which rules apply, and that a
// denied call means the agent should stop and ask, never try another way.
// The text is advisory, and the hook enforces the policy either way.
package briefing

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// maxListed bounds each list of patterns in the text.
const maxListed = 15

// Text is the briefing for a policy, or "" when the policy turns it off.
// It is deterministic: the same policy gives the same text.
func Text(p *policy.Policy) string {
	if !p.Spec.Session.Briefing.On() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s enforces the policy %q on every tool call in this session, including subagents.\n", brand.DisplayName, p.Metadata.Name)

	s := p.Spec
	var denied, asked []string
	add := func(list *[]string, what string, pats []string) {
		if len(pats) > 0 {
			*list = append(*list, what+": "+listed(pats))
		}
	}
	add(&denied, "files", s.Files.Deny)
	add(&denied, "commands", s.Commands.Deny)
	add(&denied, "MCP servers and tools", s.MCP.Deny)
	if s.Commands.InterpretersDenied() {
		denied = append(denied, "inline code: sh -c, bash -c, eval, python -c, node -e and other interpreters given code on the command line or stdin")
	}
	add(&asked, "files", s.Files.Ask)
	add(&asked, "commands", s.Commands.Ask)
	add(&asked, "MCP servers and tools", s.MCP.Ask)
	if len(denied) > 0 {
		b.WriteString("\nDenied:\n")
		for _, d := range denied {
			b.WriteString("- " + d + "\n")
		}
		if s.Files.Containing != policy.ContainingIgnore && len(s.Files.Deny) > 0 {
			b.WriteString("- directories that contain a denied file, for commands that read or change what's inside (grep -r, tar, cp -r)\n")
		}
	}
	if len(asked) > 0 {
		b.WriteString("\nNeed the user's confirmation:\n")
		for _, a := range asked {
			b.WriteString("- " + a + "\n")
		}
	}
	var only []string
	add(&only, "files", s.Files.Allow)
	add(&only, "commands", s.Commands.Allow)
	add(&only, "MCP servers and tools", s.MCP.Allow)
	if s.Defaults.Posture == policy.AllowListed || len(only) > 0 {
		b.WriteString("\nAllowed only when on the allow list")
		if s.Defaults.Posture != policy.AllowListed {
			b.WriteString(" (for these kinds)")
		}
		b.WriteString(":\n")
		for _, o := range only {
			b.WriteString("- " + o + "\n")
		}
		if len(only) == 0 {
			b.WriteString("- nothing is listed, so every file access, command and MCP call is denied\n")
		}
	}

	b.WriteString("\nIf a tool call is denied, do not try another way to do the same thing: no other tool, command, " +
		"spelling, encoding, path, script or subagent. Stop, tell the user what you needed and why, and let them decide; " +
		"only they can change the policy.\n")
	if tw := s.Session.Tripwire; tw.On() {
		within := "in this session"
		if d := tw.WindowDuration(); d > 0 {
			within = "within " + short(d)
		}
		fmt.Fprintf(&b, "After %d denied calls %s, %s locks the session and blocks every tool call until the user starts a new one or unlocks it.\n",
			tw.Limit(), within, brand.DisplayName)
	}
	if m := strings.TrimSpace(s.Session.Briefing.Message); m != "" {
		b.WriteString("\nFrom the policy's authors:\n" + m + "\n")
	}
	return b.String()
}

// Windows returns what the briefing adds to Text on native Windows, where
// Claude Code has a PowerShell tool next to Bash. PowerShell code isn't
// analyzed, so every PowerShell command is denied, and an agent that isn't
// told so keeps reaching for it.
func Windows(p *policy.Policy) string {
	if !p.Spec.Session.Briefing.On() {
		return ""
	}
	return fmt.Sprintf("\nOn this Windows machine, run commands with the Bash tool (Git Bash), where they are checked. "+
		"%s can't check PowerShell yet, so every command for the PowerShell tool is blocked, whatever the policy allows. "+
		"If a task can only be done in PowerShell, tell the user instead of trying.\n", brand.DisplayName)
}

// NoPolicy is the briefing when the hook will deny everything.
func NoPolicy(why string) string {
	return fmt.Sprintf("%s has no valid policy for this session (%s), so every tool call will be denied. "+
		"Tell the user before doing anything else; do not try to work around it.\n", brand.DisplayName, why)
}

// short renders a window without zero units, as in 30m, 2h or 1h30m.
func short(d time.Duration) string {
	h, m, sec := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if sec > 0 || b.Len() == 0 {
		fmt.Fprintf(&b, "%ds", sec)
	}
	return b.String()
}

// Unavailable is the briefing when the briefing hook itself is
// misconfigured. The PreToolUse hook still enforces the policy.
func Unavailable(why string) string {
	return fmt.Sprintf("%s's briefing is unavailable (%s), but its policy is enforced on every tool call. "+
		"If a tool call is denied, do not try another way to do the same thing: stop and tell the user.\n", brand.DisplayName, why)
}

// listed joins up to maxListed patterns and says how many are left out.
func listed(pats []string) string {
	if len(pats) <= maxListed {
		return strings.Join(pats, ", ")
	}
	return strings.Join(pats[:maxListed], ", ") + fmt.Sprintf(" and %d more", len(pats)-maxListed)
}

// SessionStartOutput is the SessionStart hook answer both Claude Code and
// Codex read. Their schemas agree on hookSpecificOutput.additionalContext.
// Empty text gives no output.
func SessionStartOutput(text string) []byte {
	if text == "" {
		return nil
	}
	out, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "SessionStart", "additionalContext": text,
	}})
	return append(out, '\n')
}
