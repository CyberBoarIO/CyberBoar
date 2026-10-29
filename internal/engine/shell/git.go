package shell

import (
	"regexp"
	"strings"
)

// Git runs programs, and changes the work trees it is pointed at, through its
// command line and its config. Global options such as -C choose where a
// command works, subcommands such as clone, rebase and difftool take options
// that name a program, and git config can set keys that git later runs as programs

// wrapGit strips git's global options so "git -C dir push" is "git push".
// Options that can run arbitrary programs make the command unknown.
func wrapGit(_ *analyzer, _ string, args []Elem) unwrapped {
	withValue := set("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
		"--super-prefix", "--list-cmds")
	unknown := false
	var dir *Elem // -C DIR, each relative to the one before
	i := 0
	for ; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			return unwrapped{unknown: true}
		}
		t := e.Text
		if !strings.HasPrefix(t, "-") {
			break
		}
		if t == "-C" && i+1 < len(args) {
			dir = gitDir(dir, args[i+1])
		}
		name, _, hasVal := strings.Cut(t, "=")
		switch name {
		case "-c", "--config-env":
			unknown = true // config such as core.sshCommand or alias.x=!cmd runs programs
		case "--exec-path":
			unknown = unknown || hasVal // with a value: runs subcommands from any directory
		}
		if strings.HasPrefix(t, "-c") && len(t) > 2 {
			unknown = true // attached form: -ckey=value
			continue
		}
		if withValue[name] && !hasVal {
			i++
		}
	}
	switch {
	case i >= len(args):
		return unwrapped{unknown: unknown} // no subcommand
	case i > 0:
		// Strip the global options; the next round sees the plain subcommand
		return unwrapped{next: append([]Elem{{Kind: Lit, Text: "git"}}, args[i:]...), replace: true, dir: dir, unknown: unknown}
	case args[0].Kind != Lit:
		return unwrapped{unknown: true}
	}
	u := gitSubcommand(args[0].Text, args[1:])
	u.unknown = u.unknown || unknown
	return u
}

// gitDir is where git -C next moves from prev (nil: the current directory).
// An empty path leaves it unchanged; a second one isn't followed.
func gitDir(prev *Elem, next Elem) *Elem {
	switch {
	case next.Kind == Lit && next.Text == "":
		return prev
	case prev == nil:
		return &next
	}
	return &Elem{Kind: Many, Text: "*"}
}

// gitSubcommand finds the program-running options of git subcommands, and
// config writes that make git run programs later.
func gitSubcommand(sub string, args []Elem) unwrapped {
	var u unwrapped
	valueOf := func(i int, opt string) (Elem, int, bool) {
		t := args[i].Text
		if !strings.HasPrefix(opt, "--") {
			if t == opt && i+1 < len(args) {
				return args[i+1], i + 1, true
			}
			return Elem{}, i, false
		}
		switch val, hasVal, ok := longOpt(t, opt); {
		case ok && hasVal:
			return Elem{Kind: Lit, Text: val}, i, true
		case ok && i+1 < len(args):
			return args[i+1], i + 1, true
		}
		return Elem{}, i, false
	}
	scan := func(opts ...string) {
		for i := 0; i < len(args); i++ {
			if args[i].Kind != Lit {
				continue
			}
			for _, opt := range opts {
				if v, next, ok := valueOf(i, opt); ok {
					u.cmdLines = append(u.cmdLines, cmdLine("git "+sub+" "+opt, v))
					i = next
					break
				}
			}
		}
	}
	switch sub {
	case "clone":
		scan("--upload-pack", "-u")
	case "fetch", "pull", "ls-remote", "remote":
		scan("--upload-pack")
	case "push":
		scan("--receive-pack", "--exec")
	case "archive":
		scan("--exec")
	case "rebase":
		scan("--exec", "-x")
	case "grep":
		scan("--open-files-in-pager", "-O")
		for _, e := range args {
			if e.Kind == Lit && strings.HasPrefix(e.Text, "-O") && len(e.Text) > 2 {
				u.cmdLines = append(u.cmdLines, cmdLine("git grep -O", Elem{Kind: Lit, Text: e.Text[2:]}))
			}
		}
	case "difftool", "mergetool":
		scan("--extcmd", "-x", "--tool-cmd")
	case "filter-branch":
		scan("--env-filter", "--tree-filter", "--index-filter", "--parent-filter", "--msg-filter",
			"--commit-filter", "--tag-name-filter")
	case "submodule":
		for i, e := range args {
			if e.Kind == Lit && e.Text == "foreach" {
				rest := args[i+1:]
				for len(rest) > 0 && rest[0].Kind == Lit && strings.HasPrefix(rest[0].Text, "-") {
					rest = rest[1:]
				}
				if len(rest) > 0 {
					text, dyn := join(rest)
					u.cmdLines = append(u.cmdLines, codeRun{what: "git submodule foreach", text: text, dynamic: dyn})
				}
				break
			}
		}
	case "bisect":
		if len(args) > 1 && args[0].Kind == Lit && args[0].Text == "run" {
			u.extra = append(u.extra, args[1:])
		}
	case "config":
		if key, ok := gitConfigWrite(args); ok && gitExecKey.MatchString(key) {
			u.code = append(u.code, codeRun{what: "git config " + key + " (makes git run a program later)", foreign: true})
		} else if !ok {
			u.unknown = true
		}
	}
	return u
}

// gitExecKey matches config keys whose values git runs as programs, or that
// point git at hooks or other config.
var gitExecKey = regexp.MustCompile(`^(alias\..+|core\.(sshcommand|editor|pager|fsmonitor|hookspath|askpass|gitproxy)|` +
	`sequence\.editor|diff\.external|diff\..+\.(command|textconv)|.+\.textconv|filter\..+|merge\..+\.driver|` +
	`credential(\..+)?\.helper|gpg(\..+)?\.program|uploadpack\.packobjectshook|include(if\..+)?\.path|` +
	`pager\..+|browser\..+\.cmd|man\..+\.cmd|difftool\..+\.cmd|mergetool\..+\.cmd)$`)

// gitConfigWrite returns the key a `git config` invocation sets
// ok is false when it can't tell (run-time words).
func gitConfigWrite(args []Elem) (key string, ok bool) {
	var ops []string
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			return "", false
		}
		switch t := e.Text; {
		case t == "-f":
			i++
		case strings.HasPrefix(t, "--"):
			if _, hasVal, ok := longOpt(t, "file", "blob", "type", "default", "comment", "value"); ok && !hasVal {
				i++
			}
		case strings.HasPrefix(t, "-"):
		default:
			ops = append(ops, t)
		}
	}
	switch {
	case len(ops) >= 3 && ops[0] == "set":
		return strings.ToLower(ops[1]), true
	case len(ops) >= 1 && (ops[0] == "get" || ops[0] == "list" || ops[0] == "unset" || ops[0] == "edit" ||
		ops[0] == "rename-section" || ops[0] == "remove-section"):
		return "", true
	case len(ops) >= 2:
		return strings.ToLower(ops[0]), true
	}
	return "", true
}

// gitTrees are the work trees a git command names with -C, --work-tree or
// --git-dir, whose whole tree it may change.
func (a *analyzer) gitTrees(raw []Elem, d dir) []FileRef {
	var out []FileRef
	for i, e := range raw {
		if e.Kind != Lit {
			continue
		}
		name, val, hasVal := strings.Cut(e.Text, "=")
		switch name {
		case "-C", "--work-tree", "--git-dir":
		default:
			continue
		}
		if !hasVal {
			if i+1 >= len(raw) || raw[i+1].Kind != Lit {
				continue // a run-time word is already a path only known at run time
			}
			val = raw[i+1].Text
		}
		r := a.pathRef(val, d)
		r.Modifies, r.Repo = true, true
		out = append(out, r)
	}
	return out
}
