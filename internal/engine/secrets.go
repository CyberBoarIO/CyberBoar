package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/secrets"
)

// RuleSecretsPrefix starts the rule ID of a verdict on a secret
// The rest of the ID is the rule that found it: an ID from secrets.Rules, or secrets.TooLong
const RuleSecretsPrefix = "secrets."

// evalSecrets looks for credentials in what a shell action runs, a write adds or an MCP call sends
// It returns nil when there are none, or the policy turned the check off
// A scan the deadline cut short is a deny, since a secret may sit in the part not read
func (c *Compiled) evalSecrets(ctx context.Context, a Action) *Verdict {
	cfg := c.policy.Spec.Secrets
	if cfg.Action == policy.SecretsOff {
		return nil
	}
	var f *secrets.Finding
	var err error
	what := "the command"
	switch a.Tool {
	case ToolWrite:
		what = "what is written to " + a.displayPath()
		f, err = writeSecret(ctx, a, cfg.Ignore)
	case ToolMCP:
		what = "what is sent to the MCP tool " + a.MCP.Server + "/" + a.MCP.Tool
		var found []secrets.Finding
		found, err = findSecrets(ctx, a.Content, cfg.Ignore)
		f = first(found)
	default:
		f, err = commandSecret(ctx, a.Command, cfg.Ignore)
	}
	if err != nil {
		if errors.Is(err, shell.ErrTooLarge) || errors.Is(err, shell.ErrTooComplex) {
			v := deny(RuleTooComplex, "the command expands into too much text to check for secrets, so it is blocked; split it into simpler commands")
			return &v
		}
		v := deadlineVerdict()
		return &v
	}
	if f == nil {
		return nil
	}
	v := Verdict{Decision: Deny, Rule: RuleSecretsPrefix + f.Rule}
	if cfg.Action == policy.SecretsAsk {
		v.Decision = Ask
	}
	switch f.Rule {
	case secrets.TooLong:
		v.Reason = fmt.Sprintf("%s is too long to check for secrets (over %d MiB), so it is blocked; write or run it in smaller parts", what, secrets.MaxText>>20)
	case Unchecked:
		v.Reason = fmt.Sprintf("%s can't be checked for secrets (%s), so it is blocked; read the file again and retry with old text that matches it exactly", what, f.Description)
	default:
		// The reason names the rule, never the secret, because the reason is shown to the agent and the user, and logged
		v.Reason = fmt.Sprintf("%s holds what looks like a secret (%s), so it is blocked; "+
			"pass credentials through environment variables or files the user set up, never in commands or files the agent writes. "+
			"If it is not a secret, the policy's secrets.ignore can list %s; %s", what, f.Rule, f.Rule, noRetry)
	}
	return &v
}

// Unchecked is the secrets finding for a write whose result can't be
// worked out, because the file can't be read or the edit doesn't apply to it
const Unchecked = "unchecked"

// MaxFile is the largest file, in bytes, that the secrets check reads before an edit to it
// An edit to a larger file is a finding of secrets.TooLong
const MaxFile = 8 << 20

// commandSecret returns the first secret in a command line, read both as
// written and as bash reads it, which turns gh""p_x into ghp_x
func commandSecret(ctx context.Context, command string, ignore []string) (*secrets.Finding, error) {
	found, err := findSecrets(ctx, command, ignore)
	if err != nil || len(found) > 0 {
		return first(found), err
	}
	texts, err := shellTexts(command)
	if err != nil {
		return nil, err
	}
	for _, text := range texts {
		if found, err = findSecrets(ctx, text, ignore); err != nil || len(found) > 0 {
			return first(found), err
		}
	}
	return nil, nil
}

// shellTexts returns what bash may make of a command line's words
// The first text has each word on a line of its own
// The second runs the commands' arguments together, as printf %s%s gh p_x or echo -n in turn would print them
func shellTexts(command string) ([]string, error) {
	words, args, err := shell.Literals(command)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, nil
	}
	return []string{strings.Join(words, "\n"), args}, nil
}

// writeSecret returns the first secret a write adds to its file. It reads
// the file, since a secret the file already holds doesn't count: an agent
// may edit next to a credential it didn't write, or remove one. For an
// edit, it checks the file as it would be after the edit, so that a secret
// put together from parts (edits next to each other, or an edit next to
// text written earlier) is found too
// A move checks the complete result, without the source's existing-secret allowance
func writeSecret(ctx context.Context, a Action, ignore []string) (*secrets.Finding, error) {
	if a.Content == "" && a.Rewrite == nil {
		return nil, nil
	}
	var old string
	var exists bool
	abs, rerr := absPath(a.Path, a.Cwd, a.Home)
	if rerr == nil {
		old, exists, rerr = a.fs().ReadFile(abs, MaxFile)
	}
	if rerr != nil && a.Rewrite != nil {
		if errors.Is(rerr, osfs.ErrTooLarge) {
			return &secrets.Finding{Rule: secrets.TooLong}, nil
		}
		return &secrets.Finding{Rule: Unchecked, Description: "the file can't be read"}, nil
	}
	if rerr != nil {
		old = "" // a whole new content, checked without the allowance
	}
	isNew := func(f secrets.Finding, text string) bool {
		return a.RewriteMoves || f.Rule == secrets.TooLong || !strings.Contains(old, text[f.Start:f.End])
	}
	var found []secrets.Finding
	if a.Content != "" {
		hits, err := findSecrets(ctx, a.Content, ignore)
		if err != nil {
			return nil, err
		}
		for _, f := range hits {
			if isNew(f, a.Content) {
				found = append(found, f)
				break
			}
		}
	}
	if a.Rewrite != nil && len(found) == 0 {
		results, err := a.Rewrite(old, exists)
		switch {
		case errors.Is(err, ErrRewriteTooLarge):
			return &secrets.Finding{Rule: secrets.TooLong}, nil
		case err != nil && !exists:
			// The tool fails too, and changes no file that isn't there
			results = nil
		case err != nil:
			// The tool may still apply the edit, matching more loosely than
			// package edits can follow, and so write a secret nobody checked
			return &secrets.Finding{Rule: Unchecked, Description: "the edit doesn't apply to the file as it is: " + err.Error()}, nil
		}
		for _, res := range results {
			hits, err := findSecrets(ctx, res, ignore)
			if err != nil {
				return nil, err
			}
			for _, f := range hits {
				if isNew(f, res) {
					found = append(found, f)
					break
				}
			}
			if len(found) > 0 {
				break
			}
		}
	}
	return first(found), nil
}

// first returns a pointer to the first finding, or nil when there are none
func first(found []secrets.Finding) *secrets.Finding {
	if len(found) == 0 {
		return nil
	}
	return &found[0]
}

// findSecrets returns the secrets in text, plain or encoded, in the order of their offsets
func findSecrets(ctx context.Context, text string, ignore []string) ([]secrets.Finding, error) {
	found, err := secrets.Scan(ctx, text, ignore)
	if err != nil {
		return nil, err
	}
	decoded, err := secrets.ScanDecoded(ctx, text, ignore)
	if err != nil {
		return nil, err
	}
	found = append(found, decoded...)
	slices.SortStableFunc(found, func(a, b secrets.Finding) int { return a.Start - b.Start })
	return found, nil
}

// displayPath is the action's path as the agent wrote it
func (a Action) displayPath() string {
	if a.display != "" {
		return a.display
	}
	return a.Path
}

// Redact replaces the secrets in s, plain or encoded, with their rule's
// name, for logs, whatever a policy says and ignoring no rule
// With command set, s is a shell command line, and a secret only the shell would
// see (split by quotes) replaces the whole line
// Text whose scan can't finish is replaced whole too
func Redact(ctx context.Context, s string, command bool) string {
	if s == "" {
		return s
	}
	found, err := findSecrets(ctx, s, nil)
	if err != nil {
		return "[REDACTED:unchecked]"
	}
	red := secrets.Redact(s, found)
	if command {
		texts, err := shellTexts(red)
		if err != nil {
			return "[REDACTED:unchecked]"
		}
		for _, text := range texts {
			more, err := findSecrets(ctx, text, nil)
			switch {
			case err != nil:
				return "[REDACTED:unchecked]"
			case len(more) > 0:
				return "[REDACTED:" + more[0].Rule + "]"
			}
		}
	}
	return red
}
