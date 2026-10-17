package engine

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/fold"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/policy/cmdpattern"
)

// Rule IDs of the verdicts the command check gives itself rather than from a policy rule
const (
	// RuleDenyInterpreters denies inline code when the policy sets denyInterpreters
	RuleDenyInterpreters = "commands.denyInterpreters"
	// RuleNoCommand allows a command line that runs no commands
	RuleNoCommand = "builtin.noCommand"
	// RuleUnparseable denies a command line that isn't valid shell syntax
	RuleUnparseable = "error.unparseable"
	// RuleCommandTooLarge denies a command line longer than shell.MaxBytes
	RuleCommandTooLarge = "error.commandTooLarge"
	// RuleTooComplex denies commands that exceed nesting, command or expansion limits
	RuleTooComplex = "error.tooComplex"
)

// level is how sure a match is
type level int

const (
	noMatch level = iota
	possible
	certain
)

// cmdRule is a compiled command rule
// Its id is the rule ID verdicts report
type cmdRule struct {
	id  string
	pat *cmdpattern.Pattern
}

// cmdRules holds the compiled command rules by kind
type cmdRules struct {
	deny, ask, allow []cmdRule
}

// compileCmdRules parses the command patterns of a policy
// An error names the rule that does not parse
func compileCmdRules(r policy.Rules) (cmdRules, error) {
	build := func(list string, pats []string) ([]cmdRule, error) {
		out := make([]cmdRule, 0, len(pats))
		for i, p := range pats {
			cp, err := cmdpattern.Parse(p)
			if err != nil {
				return nil, fmt.Errorf("commands.%s[%d]: %v", list, i, err)
			}
			out = append(out, cmdRule{id: fmt.Sprintf("commands.%s[%d]", list, i), pat: cp})
		}
		return out, nil
	}
	var rs cmdRules
	var err error
	if rs.deny, err = build("deny", r.Deny); err != nil {
		return rs, err
	}
	if rs.ask, err = build("ask", r.Ask); err != nil {
		return rs, err
	}
	rs.allow, err = build("allow", r.Allow)
	return rs, err
}

// matchArgv matches pattern tokens against a prefix of argv. A Many element
// stands for zero or more words, so the search branches
// Any path through a run-time word is at best a possible match
//
// With skipOptions, as for deny and ask rules, options may stand before
// every token but the first, each perhaps with its value in the next word,
// since global options come before a subcommand (`kubectl -n prod delete`).
// Which options take a value differs between programs, so both readings are
// tried. A rare false match, such as `aws --profile iam s3 ls` for `aws iam`,
// only denies or asks. Allow rules, and ask rules exempting a command from
// allow-listed posture, keep exact prefixes, so skipping never allows more
func matchArgv(toks []cmdpattern.Token, argv []shell.Elem, folded, skipOptions bool) level {
	memo := map[[2]int]level{}
	var rec func(ti, ai int) level
	rec = func(ti, ai int) level {
		if ti == len(toks) {
			return certain
		}
		if ai == len(argv) {
			return noMatch
		}
		key := [2]int{ti, ai}
		if l, ok := memo[key]; ok {
			return l
		}
		var l level
		switch e := argv[ai]; e.Kind {
		case shell.Lit:
			if toks[ti].Match(e.Text, folded) {
				l = rec(ti+1, ai+1)
			}
			if skipOptions && ti > 0 && isOption(e.Text) {
				l = max(l, rec(ti, ai+1))
				if !strings.Contains(e.Text, "=") && ai+2 <= len(argv) {
					l = max(l, rec(ti, ai+2))
				}
			}
		case shell.One:
			if toks[ti].MayMatch(e.Text, folded) {
				l = min(possible, rec(ti+1, ai+1))
			}
		case shell.Many:
			l = rec(ti, ai+1) // expands to no words
			if toks[ti].MayMatch(e.Text, folded) {
				l = max(l, rec(ti+1, ai)) // one of its words matches, and more may follow
			}
			l = min(possible, l)
		}
		memo[key] = l
		return l
	}
	return rec(0, 0)
}

// isOption reports whether an argv word is an option ("-n", "--namespace=x")
func isOption(w string) bool { return len(w) > 1 && w[0] == '-' }

// matchCommand is the best match of a deny or ask rule's single-stage pattern over a command's layers
func matchCommand(toks []cmdpattern.Token, c shell.Command) (level, []shell.Elem) {
	best, which := noMatch, c.Layers[0]
	for _, layer := range c.Layers {
		if l := matchArgv(toks, layer, true, true); l > best {
			best, which = l, layer
		}
	}
	if isUnknown(which) {
		which = c.Layers[0] // it says nothing, so show what was written
	}
	return best, which
}

// matchRule finds the best match of a deny/ask pattern anywhere in the analysis
// For a pipeline pattern, each stage must match a command fed by the previous one
func matchRule(r cmdRule, an *shell.Analysis) (level, []shell.Elem) {
	stages := r.pat.Stages
	best, shown := noMatch, []shell.Elem(nil)
	// first is the first stage's layer on the chain being followed, so the
	// command shown is the one whose chain set best
	var chain func(stage, from int, sofar level, first []shell.Elem)
	chain = func(stage, from int, sofar level, first []shell.Elem) {
		if stage == len(stages) {
			if sofar > best {
				best, shown = sofar, first
			}
			return
		}
		for i, c := range an.Commands {
			if stage > 0 && !an.Feeds(from, i) {
				continue
			}
			l, layer := matchCommand(stages[stage], c)
			if l == noMatch || min(sofar, l) <= best {
				continue
			}
			if stage == 0 {
				first = layer
			}
			chain(stage+1, i, min(sofar, l), first)
		}
	}
	chain(0, -1, certain, nil)
	return best, shown
}

// render joins argv into the command line shown in a verdict's reason
func render(argv []shell.Elem) string {
	parts := make([]string, len(argv))
	for i, e := range argv {
		parts[i] = e.Shown()
	}
	return strings.Join(parts, " ")
}

// evalShell decides a shell command line
func (c *Compiled) evalShell(a Action) Verdict {
	env, err := prepareFileEnv(a)
	if err != nil {
		return invalidAction(err)
	}
	an, err := shell.AnalyzeWith(a.Command, a.Home, shell.Options{Cwd: a.Cwd, CwdUnknown: a.CwdUnknown, CDPath: a.CDPath, Persistent: a.ShellPersists, FS: env.fs, Mounts: a.Mounts})
	switch {
	case errors.Is(err, shell.ErrTooLarge):
		return deny(RuleCommandTooLarge, fmt.Sprintf("the command is longer than %d bytes and cannot be checked, so it is blocked; %s", shell.MaxBytes, noRetry))
	case errors.Is(err, shell.ErrUnparseable):
		return deny(RuleUnparseable, fmt.Sprintf("the command could not be parsed (%v), so it is blocked; %s", err, noRetry))
	case errors.Is(err, shell.ErrTooComplex):
		return deny(RuleTooComplex, "the command is too deeply nested or runs too many commands to be checked, so it is blocked; split it into simpler commands")
	case err != nil:
		return deny(RuleInternal, "internal error while analyzing the command, so it is blocked; "+noRetry)
	}
	if len(an.Commands) == 0 && len(an.Files) == 0 {
		return Verdict{Decision: Allow, Rule: RuleNoCommand, Reason: "the command line runs no commands"}
	}

	// The order of precedence is a certain deny from a command rule, then one
	// from a file rule, then inline code under denyInterpreters, then a
	// command or path not on the allow list, then an ask, and last an allow
	var asks []Verdict
	for _, r := range c.commands.deny {
		switch l, argv := matchRule(r, an); l {
		case certain:
			return deny(r.id, fmt.Sprintf("the command `%s` is blocked by policy rule %s; do not attempt alternative ways to run it", render(argv), r.id))
		case possible:
			asks = append(asks, Verdict{Decision: Ask, Rule: r.id, Reason: fmt.Sprintf("the command `%s` might run something policy rule %s blocks (parts of it are only known at run time), so it needs confirmation", render(argv), r.id)})
		}
	}
	b := c.bind(env)
	var notAllowed *Verdict
	for _, ref := range an.Files {
		if ref.Mount != "" {
			// This is a Git Bash path outside the drives. Its emulated /proc
			// and /dev/fd fall under the built-in rules, and its device files are not files
			if v, hit := builtinRule(ref.Mount); hit {
				return v
			}
			if shell.MSYSDevice(ref.Mount) {
				continue
			}
		}
		if ref.Refused != "" {
			return deny(RuleWindowsPath, fmt.Sprintf("the command uses the path %s: %s, so it is blocked; %s", ref.Display, ref.Refused, noRetry))
		}
		if !ref.Certain {
			if v, hit := builtinShape(ref.Shape); hit {
				return v
			}
			if v, ok := b.anywhereDeny(ref); ok {
				return v
			}
			if v, ok := possibleFile(b, ref); ok {
				asks = append(asks, v)
			}
			if b.allowListed && ref.Accessed && notAllowed == nil {
				v := deny(RulePostureAllowListed, fmt.Sprintf("the command may access `%s`, a path only known at run time, which the allow list can't cover; do not attempt alternative ways to perform it", ref.Display))
				notAllowed = &v
			}
			continue
		}
		how := changeNone
		switch {
		case ref.Modifies:
			how = changeModify
		case ref.Accessed:
			how = changeWrite
		}
		for _, p := range append([]string{ref.Path}, ref.Alts...) {
			if p == "" {
				continue
			}
			if ref.Repo {
				p = repoRoot(b.env.fs, p)
			}
			switch r := b.checkPath(ref.Display, p, ref.Contents, ref.Accessed, how); r.outcome {
			case outDenied:
				return r.verdict
			case outAsk:
				asks = append(asks, r.verdict)
			case outNotAllowed:
				if notAllowed == nil {
					notAllowed = &r.verdict
				}
			}
		}
	}
	if c.policy.Spec.Commands.InterpretersDenied() && len(an.Code) > 0 {
		what := an.Code[0].What
		return deny(RuleDenyInterpreters, fmt.Sprintf("the command runs inline code (%s), which this policy blocks (denyInterpreters); do not attempt to run the code another way", what))
	}
	cmdsListed := c.allowListed(c.policy.Spec.Commands.Rules)
	if cmdsListed {
		if layer, ok := c.unlisted(an); ok {
			return deny(RulePostureAllowListed, fmt.Sprintf("the command `%s` is not on the allow list; do not attempt alternative ways to run it", render(layer)))
		}
	}
	if b.allowListed && notAllowed != nil {
		return *notAllowed
	}
	for _, r := range c.commands.ask {
		if l, argv := matchRule(r, an); l != noMatch {
			asks = append(asks, Verdict{Decision: Ask, Rule: r.id, Reason: fmt.Sprintf("the command `%s` needs confirmation (policy rule %s)", render(argv), r.id)})
		}
	}
	if len(asks) > 0 {
		return asks[0]
	}
	switch {
	case len(an.Commands) == 0:
		return Verdict{Decision: Allow, Rule: RuleNoCommand, Reason: "the command line runs no commands"}
	case cmdsListed:
		id := c.allowRule(an.Commands[0].Layers[0])
		return Verdict{Decision: Allow, Rule: id, Reason: "every command is allowed by the policy's allow list"}
	default:
		return allowNoRule()
	}
}

// anywhereDeny checks a relative path in an unknown directory against the
// deny rules anchored anywhere (**/...)
// Whatever the directory is, the path's tail decides whether they match
func (b *boundRules) anywhereDeny(ref shell.FileRef) (Verdict, bool) {
	if ref.Rel == "" {
		return Verdict{}, false
	}
	// Only the components after the last ".." are certain
	segs := strings.Split(path.Clean(ref.Rel), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] == ".." {
			segs = segs[i+1:]
			break
		}
	}
	tail := strings.Join(segs, "/")
	if tail == "" || tail == "." {
		return Verdict{}, false
	}
	folded := fold.String(tail)
	for _, r := range b.deny {
		for i, pat := range r.pats {
			if !strings.HasPrefix(pat, "**/") {
				continue
			}
			// As in boundRule.match, the written forms count as well as the
			// folded ones, since folding can narrow a bracket expression
			// An error is no match here because the caller then asks
			ok, _ := doublestar.Match(pat, tail)
			if !ok {
				ok, _ = doublestar.Match(r.lower[i], folded)
			}
			if ok {
				return deny(r.id, fmt.Sprintf("access to %s is blocked by policy rule %s; do not attempt alternative ways to read or modify it", ref.Display, r.id)), true
			}
		}
	}
	return Verdict{}, false
}

// possibleFile is the verdict for a path only known at run time
// It could be any file, so any deny or ask rule might match. The verdict
// names the first rule that could, but the reason doesn't blame it alone
func possibleFile(b *boundRules, ref shell.FileRef) (Verdict, bool) {
	var rule string
	switch {
	case len(b.deny) > 0:
		rule = b.deny[0].id
	case len(b.ask) > 0:
		rule = b.ask[0].id
	case len(b.env.protected) > 0:
		rule = RuleSelf
	case len(b.env.guarded) > 0:
		rule = RuleGuarded
	default:
		return Verdict{}, false
	}
	switch {
	case ref.Rel != "" && strings.HasPrefix(ref.Display, "*/"):
		// A tail under a directory only known at run time, such as ~ when HOME may have changed
		return Verdict{Decision: Ask, Rule: rule, Reason: fmt.Sprintf("the command might access `…/%s`, a path in a directory only known at run time "+
			"that could be any file, including files the policy protects (rule %s among them), so it needs confirmation", ref.Rel, rule)}, true
	case ref.Rel != "":
		return Verdict{Decision: Ask, Rule: rule, Reason: fmt.Sprintf("the command might access `%s` relative to a working directory the hook isn't told, "+
			"so it could be any file, including files the policy protects (rule %s among them), so it needs confirmation; "+
			"starting the command with `cd /absolute/directory &&` lets its paths be checked", ref.Display, rule)}, true
	}
	shown := ref.Display
	if ref.Shape != "" && shown == "…" {
		shown = shapeDisplay(ref.Shape)
	}
	hint := ""
	if strings.Contains(shown, "$") {
		// The analysis doesn't follow variables, not even one set earlier on the same line
		hint = "; the hook doesn't follow shell variables, so writing the path itself lets it be checked"
	}
	return Verdict{Decision: Ask, Rule: rule, Reason: fmt.Sprintf("the command might access `%s`, a path only known at run time that could be any file, "+
		"including files the policy protects (rule %s among them), so it needs confirmation%s", shown, rule, hint)}, true
}

// unlisted returns the first command layer that no allow rule certainly matches
// A certain match of a single-command ask rule counts as allowed,
// since ask rules name commands that may run after confirmation
func (c *Compiled) unlisted(an *shell.Analysis) ([]shell.Elem, bool) {
	for _, cmd := range an.Commands {
		for _, layer := range cmd.Layers {
			if c.allowRule(layer) != "" {
				continue
			}
			asked := false
			for _, r := range c.commands.ask {
				if len(r.pat.Stages) == 1 && matchArgv(r.pat.Stages[0], layer, true, false) == certain {
					asked = true
					break
				}
			}
			if !asked {
				if isUnknown(layer) {
					return cmd.Layers[0], true // show what was written, not a placeholder
				}
				return layer, true
			}
		}
	}
	return nil, false
}

// allowRule returns the first allow rule that certainly matches argv, or ""
func (c *Compiled) allowRule(argv []shell.Elem) string {
	for _, r := range c.commands.allow {
		if matchArgv(r.pat.Stages[0], argv, false, false) == certain {
			return r.id
		}
	}
	return ""
}

// isUnknown reports whether layer is the shell analyzer's layer for a
// command that could be anything, a single element that stands for any words
func isUnknown(layer []shell.Elem) bool {
	return len(layer) == 1 && layer[0].Kind == shell.Many && !layer[0].Glob && layer[0].Text == "*"
}
