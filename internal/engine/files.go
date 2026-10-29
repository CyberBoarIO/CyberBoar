package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/fold"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/winpath"
	"cyberboar.dev/cyberboar/pkg/brand"
)

type anchor int

const (
	anchorAbsolute  anchor = iota // "/etc/shadow"
	anchorHome                    // "~/.ssh/**" or "~"
	anchorAnywhere                // "**/.env*"
	anchorWorkspace               // "secrets/**"
)

type fileRule struct {
	id     string // "files.deny[0]"
	anchor anchor
	rest   string // pattern without its anchor prefix, or "" for a bare "~"
}

type fileRules struct {
	deny, ask, allow []fileRule
}

func compileFileRules(r policy.Rules) fileRules {
	build := func(list string, pats []string) []fileRule {
		out := make([]fileRule, 0, len(pats))
		for i, p := range pats {
			fr := fileRule{id: fmt.Sprintf("files.%s[%d]", list, i)}
			switch {
			case p == "~":
				fr.anchor = anchorHome
			case strings.HasPrefix(p, "~/"):
				fr.anchor, fr.rest = anchorHome, p[2:]
			case strings.HasPrefix(p, "/"):
				fr.anchor, fr.rest = anchorAbsolute, p[1:]
			case strings.HasPrefix(p, "**/"):
				fr.anchor, fr.rest = anchorAnywhere, p
			default:
				fr.anchor, fr.rest = anchorWorkspace, p
			}
			out = append(out, fr)
		}
		return out
	}
	return fileRules{deny: build("deny", r.Deny), ask: build("ask", r.Ask), allow: build("allow", r.Allow)}
}

// fileEnv holds the anchors of one action. It keeps both the given and the
// resolved form of the home directory and of every workspace root.
type fileEnv struct {
	fs           osfs.FS
	homes, roots []string
	protected    []string // CyberBoar's own directories, given and resolved
	guarded      []string // Action.Guarded, given and resolved
}

// prepareFileEnv resolves the home directory, workspace roots, protected and
// guarded paths of a. An error makes the whole action invalid rather than
// checked against some of the anchors: a workspace root that is a drive's
// root, or that contains the home directory, would widen what the workspace rules cover.
func prepareFileEnv(a Action) (fileEnv, error) {
	env := fileEnv{fs: a.fs()}
	// show gives a path back in the form the user knows: C:\x on Windows, not /c/x
	show := func(p string) string {
		if env.fs.Windows {
			return winpath.FromGitBash(p)
		}
		return p
	}
	home := cleanPath(a.Home, env.fs.Windows)
	homeRes, err := resolvePath(env.fs, a.Home)
	if err != nil {
		return env, fmt.Errorf("home directory: %v", err)
	}
	env.homes = appendUnique(nil, home, homeRes)

	for _, ws := range a.Workspaces {
		wsRes, err := resolvePath(env.fs, ws)
		if err != nil {
			return env, fmt.Errorf("workspace root %s: %v", show(ws), err)
		}
		forms := appendUnique(nil, cleanPath(ws, env.fs.Windows), wsRes)
		for _, r := range forms {
			if env.fs.Windows && isDriveRoot(r) {
				return env, fmt.Errorf("workspace root %s is a drive's root: start the agent in a project folder", show(ws))
			}
			for _, h := range env.homes {
				if isSameOrAncestor(r, h) {
					return env, fmt.Errorf("workspace root %s is /, the home directory, or contains it: start the agent in a project folder", show(ws))
				}
			}
		}
		env.roots = appendUnique(env.roots, forms...)
	}
	for _, p := range a.Protected {
		res, err := resolvePath(env.fs, p)
		if err != nil {
			return env, fmt.Errorf("protected directory %s: %v", show(p), err)
		}
		env.protected = appendUnique(env.protected, cleanPath(p, env.fs.Windows), res)
	}
	for _, p := range a.Guarded {
		res, err := resolvePath(env.fs, p)
		if err != nil {
			return env, fmt.Errorf("guarded path %s: %v", show(p), err)
		}
		env.guarded = appendUnique(env.guarded, cleanPath(p, env.fs.Windows), res)
	}
	return env, nil
}

// change is how an action may change the path it names (builtin.guarded).
type change int

const (
	changeNone   change = iota // reads only (the agent's Read tool)
	changeWrite                // may write the path (file tools that write, and any shell access)
	changeModify               // may also delete, move or replace it and what a directory holds
)

// guardRule denies a change to a guarded path (builtin.guarded).
// That is writing the path or anything inside a guarded directory, and with
// changeModify also deleting, moving or replacing a directory that holds one
// The shell can't tell reading from writing, so every shell access counts as a write.
// Reading stays possible with the agent's file tools.
func (e fileEnv) guardRule(display string, candidates []string, how change) (Verdict, bool) {
	if how == changeNone {
		return Verdict{}, false
	}
	for _, g := range e.guarded {
		for _, c := range candidates {
			what := display
			switch {
			case isSameOrAncestor(g, c):
			case how == changeModify && isSameOrAncestor(c, g):
				what = "the directory " + display + " holds a file that"
			default:
				continue
			}
			return deny(RuleGuarded, fmt.Sprintf("%s can change how the agent or %s runs (the agent's settings and hooks, shell startup files, the policy or the hook itself), "+
				"which agents may not change, so this is blocked. To look at a file, use the agent's file tool; ask the user to make any change; %s",
				what, brand.Name, noRetry)), true
		}
	}
	return Verdict{}, false
}

// selfRule denies a path inside one of CyberBoar's own directories, or, when
// the action touches contents, a directory that holds one (builtin.self).
// Paths are compared folded, like deny rules.
func (e fileEnv) selfRule(display string, candidates []string, contents bool) (Verdict, bool) {
	for _, p := range e.protected {
		for _, c := range candidates {
			if isSameOrAncestor(p, c) || (contents && isSameOrAncestor(c, p)) {
				return deny(RuleSelf, fmt.Sprintf("%s is or holds %s's own state, which agents may not touch, so access is blocked; %s", display, brand.Name, noRetry)), true
			}
		}
	}
	return Verdict{}, false
}

// expand returns the rule's pattern(s) as absolute globs without the leading "/".
func (r fileRule) expand(env fileEnv) []string {
	join := func(bases []string) []string {
		out := make([]string, 0, len(bases))
		for _, b := range bases {
			p := globEscape(strings.TrimPrefix(b, "/"))
			// A home directory of / leaves no base. Joining with "/" would
			// give "/.ssh/**", which no candidate matches once its own leading "/" is gone
			switch {
			case p == "":
				p = r.rest
			case r.rest != "":
				p += "/" + r.rest
			}
			out = append(out, p)
		}
		return out
	}
	switch r.anchor {
	case anchorHome:
		return join(env.homes)
	case anchorWorkspace:
		return join(env.roots)
	default:
		return []string{r.rest}
	}
}

// boundRule is a rule expanded for one action's home and workspace roots.
type boundRule struct {
	id    string
	pats  []string // case-sensitive
	lower []string // folded (fold.String), for deny and ask
}

// match reports whether any candidate path matches. Every rule matches the
// pattern as written against the path as written. With folded (deny and ask
// rules), the folded pattern against the folded path also counts, which
// ignores case, Unicode normalization and ignorable characters, as macOS and
// other case-insensitive filesystems do.
func (r boundRule) match(candidates []string, folded bool) bool {
	for _, c := range candidates {
		name := strings.TrimPrefix(c, "/")
		ok, err := matchAnyPattern(r.pats, name)
		if err == nil && !ok && folded {
			// Folding a bracket expression can change what it holds ([A-z]
			// becomes [a-z], [!e] then also excludes E), so the folded form
			// only adds matches to the written one
			ok, err = matchAnyPattern(r.lower, fold.String(name))
		}
		if err != nil {
			// Patterns are validated at load, so an error here is a bug
			// Deny and ask rules count it as a match, allow rules as no match
			return folded
		}
		if ok {
			return true
		}
	}
	return false
}

// matchAnyPattern reports whether one of pats matches name.
// It stops at the first error.
func matchAnyPattern(pats []string, name string) (bool, error) {
	for _, pat := range pats {
		if ok, err := doublestar.Match(pat, name); ok || err != nil {
			return ok, err
		}
	}
	return false, nil
}

// boundRules are a policy's file rules bound to one action.
type boundRules struct {
	env              fileEnv
	deny, ask, allow []boundRule
	containing       policy.Containing
	allowListed      bool
}

// bind expands the policy's file rules for the anchors in env.
func (c *Compiled) bind(env fileEnv) *boundRules {
	bindRules := func(rs []fileRule) []boundRule {
		out := make([]boundRule, len(rs))
		for i, r := range rs {
			out[i] = boundRule{id: r.id, pats: r.expand(env)}
			for _, p := range out[i].pats {
				out[i].lower = append(out[i].lower, fold.String(p))
			}
		}
		return out
	}
	return &boundRules{
		env:  env,
		deny: bindRules(c.files.deny), ask: bindRules(c.files.ask), allow: bindRules(c.files.allow),
		containing:  c.policy.Spec.Files.Containing,
		allowListed: c.allowListed(c.policy.Spec.Files.Rules),
	}
}

func (b *boundRules) firstMatch(rules []boundRule, candidates []string, folded bool) (string, bool) {
	for _, r := range rules {
		if r.match(candidates, folded) {
			return r.id, true
		}
	}
	return "", false
}

type outcome int

const (
	outDenied     outcome = iota // verdict is a deny
	outAsk                       // verdict is an ask
	outNotAllowed                // no allow rule matched under allow-listed posture
	outAllowed                   // allowed, and rule names the allow rule or posture
)

// pathResult is the decision for one path. Its outcome says which kind of
// decision it is, verdict is the verdict to report for it, and rule names
// the allow rule or posture that let it through.
type pathResult struct {
	outcome outcome
	verdict Verdict
	rule    string
}

// maxScanEntries bounds the walk of a directory argument (files.containing).
// A larger directory counts as containing a protected file.
const maxScanEntries = osfs.MaxDirEntries

// checkPath decides one path. With contents, the action may read or change
// what a directory contains. With accessed, the path is opened, so under
// allow-listed posture it needs an allow rule.
func (b *boundRules) checkPath(display, abs string, contents, accessed bool, how change) pathResult {
	denied := func(v Verdict) pathResult { return pathResult{outcome: outDenied, verdict: v} }
	lexical := cleanPath(abs, b.env.fs.Windows)
	// The built-in rules run on the lexical path before resolution, since
	// resolving /proc/<pid>/cwd may itself fail and the verdict must not
	// depend on that
	if v, hit := builtinRule(lexical); hit {
		return denied(v)
	}
	resolved, hops, err := resolveLinks(b.env.fs, abs)
	if err != nil {
		return denied(unresolvable(display, err))
	}
	for _, p := range append(hops, resolved) {
		if v, hit := builtinRule(p); hit {
			return denied(v)
		}
	}
	candidates := appendUnique(nil, lexical, resolved)
	if b.env.fs.Windows || strings.Contains(abs, "/..") {
		// Win32 applies ".." before following links, and so do programs
		// that clean a path before opening it, where the kernel and
		// programs under Git Bash apply it after, as resolvePath does
		// Both readings count
		lexRes, err := resolvePath(b.env.fs, lexical)
		if err != nil {
			return denied(unresolvable(display, err))
		}
		if v, hit := builtinRule(lexRes); hit {
			return denied(v)
		}
		candidates = appendUnique(candidates, lexRes)
	}
	if contents {
		// What a directory holds is read too, and grep -R, cp -rL or a native
		// read of / or /proc reach the files the built-in rules deny
		for _, c := range candidates {
			if v, hit := builtinHolder(display, c); hit {
				return denied(v)
			}
		}
	}
	if v, hit := b.env.selfRule(display, candidates, contents); hit {
		return denied(v)
	}
	if v, hit := b.env.guardRule(display, candidates, how); hit {
		return denied(v)
	}

	if id, ok := b.firstMatch(b.deny, candidates, true); ok {
		return denied(deny(id, fmt.Sprintf("access to %s is blocked by policy rule %s; do not attempt alternative ways to read or modify it", display, id)))
	}
	askInside := ""
	var found finding
	if contents {
		// A path with ".." after a link names one directory for the kernel
		// and another for Win32 or a program that cleans the path first
		// Each candidate that is a directory is walked, and the strictest
		// finding counts
		for _, c := range candidates {
			if info, err := b.env.fs.Stat(c); err != nil || !info.IsDir() {
				continue
			}
			if f := b.scanDir(c, b.allowListed && accessed, maxScanEntries); f.kind > found.kind {
				found = f
			}
		}
	}
	if result, hit := b.containingResult(display, found); hit {
		return result
	}
	if found.kind == foundAsk {
		askInside = found.rule
	}
	if id, ok := b.firstMatch(b.ask, candidates, true); ok {
		return pathResult{outcome: outAsk, verdict: Verdict{Decision: Ask, Rule: id, Reason: fmt.Sprintf("access to %s needs confirmation (policy rule %s)", display, id)}}
	}
	if askInside != "" {
		reason := fmt.Sprintf("the directory %s contains files policy rule %s protects, so this needs confirmation", display, askInside)
		return pathResult{outcome: outAsk, verdict: Verdict{Decision: Ask, Rule: askInside, Reason: reason}}
	}
	if !b.allowListed || !accessed {
		return pathResult{outcome: outAllowed, rule: RulePostureDenyListed}
	}
	allowedBy, ok := b.allowedBy(candidates)
	if !ok {
		return pathResult{outcome: outNotAllowed, verdict: deny(RulePostureAllowListed,
			fmt.Sprintf("access to %s is not on the allow list for this workspace; do not attempt alternative ways to perform it", display))}
	}
	return pathResult{outcome: outAllowed, rule: allowedBy}
}

// containingResult converts a blocking directory finding to the policy's decision.
// Built-in denials and incomplete checks cannot become confirmations.
func (b *boundRules) containingResult(display string, found finding) (pathResult, bool) {
	inside := b.env.fs.Show(found.entry)
	switch found.kind {
	case foundUncheckable:
		reason := fmt.Sprintf("the directory %s can't be fully checked (%s), so access is blocked; "+
			"name specific files or subdirectories instead", display, inside)
		return pathResult{outcome: outDenied, verdict: deny(RuleContainingLimit, reason)}, true
	case foundBuiltin:
		if found.rule == RuleSelf {
			reason := fmt.Sprintf("the directory %s holds %s, which leads to %s's own state that agents may not touch, "+
				"so access is blocked; %s", display, inside, brand.Name, noRetry)
			return pathResult{outcome: outDenied, verdict: deny(RuleSelf, reason)}, true
		}
		what := "process information under /proc"
		if found.rule == RuleDevFD {
			what = "the agent's open files under /dev"
		}
		return pathResult{outcome: outDenied, verdict: deny(found.rule, fmt.Sprintf("the directory %s holds %s, which leads to %s, so access is blocked; %s", display, inside, what, noRetry))}, true
	case foundDeny, foundNotAllowed:
		what := fmt.Sprintf("the directory %s contains %s, which policy rule %s protects", display, inside, found.rule)
		out := outDenied
		switch found.rule {
		case RulePostureAllowListed:
			what = fmt.Sprintf("the directory %s holds %s, which is not on the allow list for this workspace or links to a path that is not", display, inside)
			out = outNotAllowed
		}
		if b.containing == policy.ContainingAsk {
			return pathResult{outcome: outAsk, verdict: Verdict{Decision: Ask, Rule: found.rule, Reason: what + ", so this needs confirmation"}}, true
		}
		// ContainingDeny, and any value this code doesn't know
		return pathResult{outcome: out, verdict: deny(found.rule, what+"; name specific files or subdirectories instead, and do not attempt alternative ways to read it")}, true
	}
	return pathResult{}, false
}

// allowedBy reports whether every candidate matches an allow rule, so that a
// symlink inside an allowed area can't lead outside it
// The rule returned is the one the last candidate matched, which is the resolved path's.
func (b *boundRules) allowedBy(candidates []string) (string, bool) {
	var id string
	for _, c := range candidates {
		var ok bool
		if id, ok = b.firstMatch(b.allow, []string{c}, false); !ok {
			return "", false
		}
	}
	return id, true
}

// A finding is what a walk of a directory found. It holds the rule that
// matched and the entry it matched, or RuleContainingLimit and why the walk stopped.
type finding struct {
	kind  findingKind
	rule  string
	entry string
}

// findingKind orders findings from the least strict to the strictest.
type findingKind int

const (
	foundNothing     findingKind = iota
	foundAsk                     // an ask rule matched an entry
	foundNotAllowed              // an entry or its link target is off the allow list
	foundDeny                    // a deny rule matched an entry
	foundBuiltin                 // a built-in rule matched, which every files.containing mode denies
	foundUncheckable             // the walk could not check every entry; partial checks cannot ask
)

// scanDir walks dir breadth-first, in name order, for entries a deny or ask
// rule matches and, with allowList, for entries that are not on the allow
// list or link to a path that is not. It returns the strictest finding, the
// first of its kind.
//
// Links are resolved, and a link to a directory is followed, as grep -R and
// cp -rL follow it. An entry is checked by the name the walk reached it by,
// which may go through links, by its resolved path, and by its link target.
// Each alias is walked: a rule for alias/private may not match the target's
// own name. A link back to an ancestor cannot be checked under every name
// it generates, so it counts as an unreadable directory. Every entry,
// including one reached through another alias, counts toward the one limit.
// A selfOnly walk can reuse a resolved directory, since the built-in rules
// depend on the target rather than the alias's spelling.
//
// The built-in rules are checked on every entry, link targets included,
// whatever files.containing says: programs that follow links (grep -R,
// cp -rL) read through a link to /proc/self/environ. For the same reason
// whatever the walk can't check is a RuleContainingLimit deny finding in
// every walk: more entries than the limit, a directory it can't read, or a
// link it can't resolve. Any of them could hide such a link.
//
// A built-in finding or an incomplete check ends the walk. A deny finding
// ends it too, except under files.containing "ask", where a deny finding
// only asks and a built-in rule further on must still deny.
//
// With files.containing "ignore", or with no rule to look for, the walk is
// selfOnly: it looks only for what the built-in rules deny.
func (b *boundRules) scanDir(dir string, allowList bool, budget int) finding {
	selfOnly := b.containing == policy.ContainingIgnore || len(b.deny)+len(b.ask) == 0 && !allowList
	denyDecides := b.containing != policy.ContainingAsk
	// An entry is checked when its directory is read, before anything under
	// it. At each step, every entry seen so far has passed the built-in
	// rules, and found is the strictest policy finding among them.
	var found finding
	// keep records f if it is stricter than what was found so far, and
	// reports whether the walk can stop
	keep := func(f finding) bool {
		if f.kind > found.kind {
			found = f
		}
		return f.kind == foundUncheckable || f.kind == foundDeny && denyDecides
	}
	unreadable := func(what string) finding {
		return finding{kind: foundUncheckable, rule: RuleContainingLimit, entry: what}
	}
	// A walkDir keeps the name the walk reached it by and its ancestors, so
	// distinct aliases are checked while links back up the tree terminate.
	type walkDir struct {
		name, resolved string
		parent         *walkDir
	}
	res, err := resolvePath(b.env.fs, dir)
	if err != nil {
		return unreadable(dir + " (unresolvable)")
	}
	queue := []*walkDir{{name: dir, resolved: res}}
	visited := map[string]bool{res: true}
	seen := 0
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		entries, err := b.env.fs.ReadDir(d.resolved)
		if errors.Is(err, osfs.ErrTooLarge) {
			// No sorted prefix is available. Asking could hide a built-in deny
			// among entries that an unbounded enumeration would have checked
			return finding{kind: foundUncheckable, rule: RuleContainingLimit, entry: fmt.Sprintf("%s has more than %d entries, too many to enumerate", d.name, osfs.MaxDirEntries)}
		}
		if err != nil {
			if keep(unreadable(d.name + " (unreadable)")) {
				return found
			}
			continue
		}
		for _, e := range entries {
			if seen++; seen > budget {
				keep(unreadable(fmt.Sprintf("more than %d entries, too many to check", budget)))
				return found
			}
			p := path.Join(d.name, e.Name()) // not d.name + "/", which may be "/"
			res := path.Join(d.resolved, e.Name())
			candidates := appendUnique(nil, p, res)
			var hops []string
			isDir := e.IsDir()
			linked := e.Type()&fs.ModeSymlink != 0 || b.env.fs.Windows && e.Type()&fs.ModeIrregular != 0
			if linked {
				target, via, err := resolveLinks(b.env.fs, res)
				var info fs.FileInfo
				if err == nil {
					// A dangling link leads nowhere, so there is nothing to walk
					if info, err = b.env.fs.Stat(target); errors.Is(err, fs.ErrNotExist) {
						err = nil
					}
				}
				if err != nil {
					if keep(unreadable(p + " (unresolvable link)")) {
						return found
					}
					continue
				}
				candidates, hops, res = append(candidates, target), via, target
				isDir = info != nil && info.IsDir()
			}
			for _, c := range append(hops, candidates...) {
				if v, hit := builtinHolder(p, c); hit {
					return finding{kind: foundBuiltin, rule: v.Rule, entry: p}
				}
			}
			// What a directory entry holds is read too, so an entry or a link
			// target that holds the state is denied, as builtinHolder denies
			// one that holds /proc
			if _, hit := b.env.selfRule(p, candidates, true); hit {
				return finding{kind: foundBuiltin, rule: RuleSelf, entry: p}
			}
			if !selfOnly && keep(b.checkEntry(p, candidates, allowList)) {
				return found
			}
			if !isDir || selfOnly && visited[res] {
				continue
			}
			cycle := false
			for ancestor := d; linked && ancestor != nil; ancestor = ancestor.parent {
				if ancestor.resolved == res {
					cycle = true
					break
				}
			}
			if cycle {
				if keep(unreadable(p + " (directory link cycle)")) {
					return found
				}
				continue
			}
			visited[res] = true
			queue = append(queue, &walkDir{name: p, resolved: res, parent: d})
		}
	}
	return found
}

// checkEntry applies the policy's rules to one entry of a walk, in the order
// checkPath applies them to a path: a deny rule, then an ask rule, which also
// exempts the entry from the allow list, then with allowList the allow rules.
func (b *boundRules) checkEntry(p string, candidates []string, allowList bool) finding {
	if id, ok := b.firstMatch(b.deny, candidates, true); ok {
		return finding{kind: foundDeny, rule: id, entry: p}
	}
	if id, ok := b.firstMatch(b.ask, candidates, true); ok {
		return finding{kind: foundAsk, rule: id, entry: p}
	}
	if allowList {
		if _, ok := b.allowedBy(candidates); !ok {
			return finding{kind: foundNotAllowed, rule: RulePostureAllowListed, entry: p}
		}
	}
	return finding{}
}

// unresolvable is the deny verdict for a path that resolvePath failed on.
func unresolvable(display string, err error) Verdict {
	return deny(RuleUnresolvablePath, fmt.Sprintf("the path %s could not be resolved (%v), so access is blocked; %s", display, err, noRetry))
}

// builtinRule checks the always-on rules that no policy can switch off.
// The path is folded, since on a case-insensitive root volume (macOS) /DEV/fd is /dev/fd.
func builtinRule(p string) (Verdict, bool) {
	p = fold.String(p)
	if p == "/dev/fd" || strings.HasPrefix(p, "/dev/fd/") ||
		p == "/dev/stdin" || p == "/dev/stdout" || p == "/dev/stderr" {
		return deny(RuleDevFD, "paths under /dev/fd and /dev/std* name the agent's open files, which the policy cannot check, so access is blocked; "+noRetry), true
	}
	if rest, ok := strings.CutPrefix(p, "/proc/"); ok {
		first, _, nested := strings.Cut(rest, "/")
		if nested || first == "self" || first == "thread-self" || isDigits(first) {
			return deny(RuleProcfs, "process information under /proc can expose secrets and reach arbitrary files, so access is blocked; "+noRetry), true
		}
	}
	return Verdict{}, false
}

// builtinShape is builtinRule for a path only known at run time, given its
// shape (shell.FileRef.Shape). It denies when the shape's literal parts pin
// the path to what the built-in rules protect: its literal start is /proc or
// a path in it, or can still become /dev/fd or /dev/std*, as in
// /proc/$PPID/environ or /dev/fd/$n. Literal text after a run-time part
// counts when it names such a path on its own, as in ${D}/proc/self/environ,
// where D may be empty. A shape that pins nothing, such as that of "$f", is
// left to the policy's rules.
func builtinShape(shape string) (Verdict, bool) {
	if shape == "" {
		return Verdict{}, false
	}
	pieces := splitShape(shape)
	display := "`" + shapeDisplay(shape) + "`"
	procfs := deny(RuleProcfs, fmt.Sprintf("the command might access %s, a path under /proc only known at run time; process "+
		"information under /proc can expose secrets and reach arbitrary files, so it is blocked; %s", display, noRetry))
	devfd := deny(RuleDevFD, fmt.Sprintf("the command might access %s, a path under /dev only known at run time that can name "+
		"the agent's open files, which the policy cannot check, so it is blocked; %s", display, noRetry))
	if start := pieces[0]; strings.HasPrefix(start, "/") {
		p := fold.String(path.Clean(start))
		if p == "/proc" || strings.HasPrefix(p, "/proc/") {
			return procfs, true
		}
		if p == "/dev" || strings.HasPrefix(p, "/dev/") {
			for _, target := range []string{"/dev/fd/", "/dev/stdin", "/dev/stdout", "/dev/stderr"} {
				if strings.HasPrefix(target, p) || strings.HasPrefix(p, target) {
					return devfd, true
				}
			}
		}
	}
	for _, piece := range pieces[1:] {
		v, hit := builtinRule(path.Clean("/" + strings.TrimLeft(piece, "/")))
		if !hit {
			continue
		}
		// /proc/<name>/<more> is denied for any name, but a literal tail such
		// as $REPO/proc/handlers/main.go names a project directory. Only the
		// process directories themselves pin a tail under /proc
		if v.Rule == RuleProcfs {
			rest := strings.TrimPrefix(fold.String(path.Clean("/"+strings.TrimLeft(piece, "/"))), "/proc/")
			if first, _, _ := strings.Cut(rest, "/"); first != "self" && first != "thread-self" && !isDigits(first) {
				continue
			}
			return procfs, true
		}
		return devfd, true
	}
	return Verdict{}, false
}

// shapeDisplay shows a shape in a reason, with "…" for each run-time part.
func shapeDisplay(shape string) string { return strings.Join(splitShape(shape), "…") }

// splitShape returns the literal pieces of a shape, unescaped, between its
// unescaped "*"s. The first piece is what the path starts with.
func splitShape(shape string) []string {
	var pieces []string
	var b strings.Builder
	esc := false
	for _, r := range shape {
		switch {
		case esc:
			esc = false
			b.WriteRune(r)
		case r == '\\':
			esc = true
		case r == '*':
			pieces = append(pieces, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(pieces, b.String())
}

// builtinHolder is builtinRule for an action that reads what a directory
// holds. It also denies /, /proc and /dev, whose contents are what the
// built-in rules protect. display names p in the reason.
func builtinHolder(display, p string) (Verdict, bool) {
	if v, hit := builtinRule(p); hit {
		return v, true
	}
	switch fold.String(p) {
	case "/", "/proc":
		return deny(RuleProcfs, fmt.Sprintf("reading what %s holds reaches process information under /proc, "+
			"which can expose secrets and reach arbitrary files, so it is blocked; %s", display, noRetry)), true
	case "/dev":
		return deny(RuleDevFD, fmt.Sprintf("reading what %s holds reaches /dev/fd and /dev/std*, which name the agent's open files, so it is blocked; %s", display, noRetry)), true
	}
	return Verdict{}, false
}

// isDigits reports whether s is a non-empty string of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// evalFile decides a read or write of a.Path by the agent's own file tools.
func (c *Compiled) evalFile(a Action) Verdict {
	env, err := prepareFileEnv(a)
	if err != nil {
		return invalidAction(err)
	}
	abs, err := absPath(a.Path, a.Cwd, a.Home)
	if err != nil {
		return invalidAction(err)
	}
	display := a.Path
	if a.display != "" {
		// Show the path as the agent wrote it, with one separator
		// Windows reads / and \ alike, and a mix such as C:\x/y reads as two styles
		display = strings.ReplaceAll(a.display, "/", `\`)
	}
	how := changeNone
	if a.Tool == ToolWrite {
		how = changeWrite
	}
	r := c.bind(env).checkPath(display, abs, a.Tool != ToolList, true, how)
	switch r.outcome {
	case outAllowed:
		if r.rule == RulePostureDenyListed {
			return allowNoRule()
		}
		return Verdict{Decision: Allow, Rule: r.rule, Reason: "allowed by policy rule " + r.rule}
	default:
		return r.verdict
	}
}
