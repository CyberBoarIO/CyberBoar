package shell

import (
	"maps"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// codeRun is code a command runs: `sh -c CODE`, `python -c CODE`, an
// ssh ProxyCommand, … what names the construct for deny reasons.
type codeRun struct {
	what    string
	text    string
	dynamic bool   // only known at run time
	foreign bool   // not shell code, so it can't be analyzed
	start   *dir   // where it starts, if not where the command runs (ssh: the remote home)
	alias   string // the alias whose body this is
}

// stdinRun is code a command reads from stdin (`bash`, `python -`, `at`).
type stdinRun struct {
	what    string
	foreign bool
	start   *dir // as for codeRun
}

// unwrapped is what a wrapper, shell or interpreter reveals about what it runs.
type unwrapped struct {
	next     []Elem    // argv of the wrapped command; nil if it runs none
	dir      *Elem     // the directory next runs in (env -C DIR), if not the wrapper's
	replace  bool      // next is a normalized form of the same command (git), not a new layer
	extra    [][]Elem  // further commands it runs as argv (find -exec)
	code     []codeRun // inline code it runs
	cmdLines []codeRun // command lines it runs through a shell (ssh -o ProxyCommand=…)
	stdin    *stdinRun // it runs code read from stdin
	assigns  []Elem    // NAME=VALUE settings it puts in the environment (env, sudo)
	files    []Elem    // files its script opens (sed r/w, awk getline/redirections)
	unknown  bool      // it may run something the analysis can't see
}

type wrapperFunc func(a *analyzer, name string, args []Elem) unwrapped

// wrappers maps a command name to what it runs. Anything not listed is opaque:
// only its own argv is matched, and what it runs is not seen.
var wrappers = map[string]wrapperFunc{}

// init fills wrappers. The order matters only for registerTools, which
// combines a tool with a wrapper already registered under its name (bun).
func init() {
	registerExecOpts()
	registerInterpreters()
	registerRemote()
	registerRunners()
	registerTools()
	registerUnwrap()
}

func registerUnwrap() {
	maps.Copy(wrappers, map[string]wrapperFunc{
		"sudo": wrapSudo, "doas": wrapDoas, "env": wrapEnv,
		"command": wrapCommand, "builtin": wrapPlain, "nohup": wrapPlain, "busybox": wrapPlain,
		"exec":    optsThenCommand(optSpec{short: "a"}),
		"nice":    optsThenCommand(optSpec{short: "n", long: set("adjustment"), abbrev: true}),
		"time":    optsThenCommand(optSpec{short: "fo", long: set("format", "output"), abbrev: true}),
		"stdbuf":  optsThenCommand(optSpec{short: "ioe", long: set("input", "output", "error"), abbrev: true}),
		"setsid":  optsThenCommand(optSpec{}),
		"timeout": wrapTimeout, "ionice": wrapIonice, "flock": wrapFlock, "watch": wrapWatch,
		"su": wrapSu, "runuser": wrapSu, "script": wrapScript, "chroot": wrapChroot,
		"xargs": wrapXargs, "find": wrapFind, "git": wrapGit,
		"eval": wrapEval, "trap": wrapTrap, "alias": wrapAlias,
		"fish": wrapFish,
	})
	for _, sh := range []string{"sh", "bash", "rbash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh"} {
		wrappers[sh] = wrapShell
	}
}

// optSpec describes a command's options, for finding where its operands start.
type optSpec struct {
	short    string          // short options that take an argument
	optional string          // short options whose argument, if any, is the rest of the word (sed -i.bak)
	long     map[string]bool // long options that take an argument
	flags    map[string]bool // long options without one that begin another's name (grep --binary)
	plus     bool            // +o style options too (shells)
	permute  bool            // options may follow operands (GNU getopt), until "--"
	abbrev   bool            // long options may be cut short (getopt_long: --sig for --signal)
}

type parsedOpts struct {
	spec      optSpec
	all       []namedOpt // every option in order, value an empty Lit for plain flags
	rest      []Elem     // operands
	ambiguous bool       // a run-time word sat where an option could be
}

type namedOpt struct {
	name  string // "x" for -x, "--name" for a long option as written
	value Elem
}

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func parseOpts(args []Elem, spec optSpec) parsedOpts {
	p := parsedOpts{spec: spec}
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			// Could be an option, an operand or (Many) several of either.
			p.ambiguous = true
			if spec.permute {
				p.rest = append(p.rest, e)
				continue
			}
			p.rest = append(p.rest, args[i:]...)
			return p
		}
		t := e.Text
		value := func() Elem {
			if i+1 >= len(args) {
				return Elem{}
			}
			i++
			if args[i].Kind == Many {
				p.ambiguous = true // may be several words, shifting everything after it
			}
			return args[i]
		}
		switch {
		case t == "--":
			p.rest = append(p.rest, args[i+1:]...)
			return p
		case strings.HasPrefix(t, "--") && len(t) > 2:
			name, val, hasVal := strings.Cut(t[2:], "=")
			v := Elem{Kind: Lit, Text: val}
			if !hasVal && spec.takesValue(name) {
				v = value()
			}
			p.all = append(p.all, namedOpt{"--" + name, v})
		case len(t) > 1 && (t[0] == '-' || (spec.plus && t[0] == '+')):
			for j := 1; j < len(t); j++ {
				c := string(t[j])
				if strings.Contains(spec.optional, c) {
					p.all = append(p.all, namedOpt{c, Elem{Kind: Lit, Text: t[j+1:]}})
					break
				}
				if strings.Contains(spec.short, c) {
					v := Elem{Kind: Lit, Text: t[j+1:]}
					if j+1 == len(t) {
						v = value()
					}
					p.all = append(p.all, namedOpt{c, v})
					break
				}
				p.all = append(p.all, namedOpt{c, Elem{Kind: Lit}})
			}
		default:
			if !spec.permute {
				p.rest = append(p.rest, args[i:]...)
				return p
			}
			p.rest = append(p.rest, e)
		}
	}
	return p
}

// longOpt reads t as one of the long options names ("--exec"), written in
// full or cut short as getopt_long allows, and returns its "=value" if any.
// Taking an ambiguous abbreviation as any of them is safe: getopt_long
// refuses it, so nothing runs.
func longOpt(t string, names ...string) (value string, hasValue, ok bool) {
	written, ok := strings.CutPrefix(t, "--")
	if !ok {
		return "", false, false
	}
	written, value, hasValue = strings.Cut(written, "=")
	if written == "" {
		return "", false, false
	}
	for _, n := range names {
		if strings.HasPrefix(strings.TrimPrefix(n, "--"), written) {
			return value, hasValue, true
		}
	}
	return "", false, false
}

// takesValue reports whether the long option name takes a value. getopt_long
// takes any unambiguous prefix of a long option and refuses an ambiguous one,
// so with abbrev a prefix of an option that takes a value is that option.
func (s optSpec) takesValue(name string) bool {
	if s.long[name] {
		return true
	}
	if !s.abbrev || s.flags[name] {
		return false
	}
	for l := range s.long {
		if strings.HasPrefix(l, name) {
			return true
		}
	}
	return false
}

// matches reports whether the option given ("x" for -x, "--name" for a long
// option as written) is the option name ("x" or "name"). Where the program
// takes abbreviations, a long option is any one it is a prefix of; exact
// reads it as written only.
func (s optSpec) matches(given, name string, exact bool) bool {
	if len(name) == 1 {
		return given == name
	}
	written, ok := strings.CutPrefix(given, "--")
	if !ok {
		return false
	}
	if exact || !s.abbrev || s.flags[written] {
		return written == name
	}
	return strings.HasPrefix(name, written)
}

// has reports whether any of the named options was given. Where finding an
// option lets the analysis conclude less runs, use hasExact.
func (p parsedOpts) has(names ...string) bool {
	_, ok := p.find(names, false)
	return ok
}

// hasExact is has without abbreviations.
func (p parsedOpts) hasExact(names ...string) bool {
	_, ok := p.find(names, true)
	return ok
}

// values returns every value given for the named options, in order.
func (p parsedOpts) values(names ...string) []Elem {
	var out []Elem
	for _, o := range p.all {
		for _, n := range names {
			if p.spec.matches(o.name, n, false) {
				out = append(out, o.value)
				break
			}
		}
	}
	return out
}

// value returns the value of the last of the named options given.
func (p parsedOpts) value(names ...string) (Elem, bool) {
	return p.find(names, false)
}

func (p parsedOpts) find(names []string, exact bool) (Elem, bool) {
	for _, v := range slices.Backward(p.all) {
		for _, n := range names {
			if p.spec.matches(v.name, n, exact) {
				return v.value, true
			}
		}
	}
	return Elem{}, false
}

// shellCode is a word run as shell code by the construct what.
func shellCode(what string, e Elem) codeRun {
	return codeRun{what: what, text: e.Text, dynamic: e.Kind != Lit}
}

// joinedCode is words joined with spaces and run as shell code (eval, watch).
func joinedCode(what string, words []Elem) codeRun {
	text, dyn := join(words)
	return codeRun{what: what, text: text, dynamic: dyn}
}

func optsThenCommand(spec optSpec) wrapperFunc {
	return func(_ *analyzer, _ string, args []Elem) unwrapped {
		p := parseOpts(args, spec)
		return unwrapped{next: p.rest, unknown: p.ambiguous}
	}
}

func wrapPlain(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) > 0 && args[0].Kind == Lit && args[0].Text == "--" {
		args = args[1:]
	}
	return unwrapped{next: args}
}

// splitAssignments separates leading NAME=VALUE words (sudo, env).
func splitAssignments(args []Elem) (assigns, rest []Elem) {
	i := 0
	for i < len(args) && args[i].Kind == Lit && isAssignment(args[i].Text) {
		i++
	}
	return args[:i], args[i:]
}

func isAssignment(s string) bool {
	name, _, ok := strings.Cut(s, "=")
	return ok && name != "" && !strings.HasPrefix(name, "-")
}

func wrapSudo(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "ugpChDrtTUR", long: set("user", "group", "host", "prompt",
		"close-from", "chdir", "role", "type", "command-timeout", "other-user", "chroot"), abbrev: true})
	if p.hasExact("e", "edit") {
		return unwrapped{unknown: p.ambiguous} // sudoedit: edits files, runs no command
	}
	assigns, rest := splitAssignments(p.rest)
	var u unwrapped
	switch {
	case !p.has("s", "shell", "i", "login"):
		u = unwrapped{next: rest}
	case len(rest) == 0:
		u = unwrapped{stdin: &stdinRun{what: "sudo -s/-i reading commands from stdin"}}
	default:
		u = unwrapped{code: []codeRun{joinedCode("sudo -s", rest)}}
	}
	u.assigns, u.unknown = assigns, p.ambiguous
	if d, ok := p.value("D", "chdir"); ok {
		u.dir = &d
	} else if p.has("i", "login") {
		u.dir = &Elem{Kind: Many, Text: "*"} // the login shell starts in the user's home
	}
	return u
}

func wrapDoas(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "uC"})
	if p.has("s") && len(p.rest) == 0 {
		return unwrapped{stdin: &stdinRun{what: "doas -s reading commands from stdin"}, unknown: p.ambiguous}
	}
	return unwrapped{next: p.rest, unknown: p.ambiguous}
}

func wrapEnv(a *analyzer, _ string, args []Elem) unwrapped {
	// "env -" is "env -i".
	var norm []Elem
	for i, e := range args {
		if e.Kind == Lit && e.Text == "-" {
			continue
		}
		if e.Kind == Lit && e.Text == "--" {
			norm = append(norm, args[i:]...)
			break
		}
		norm = append(norm, e)
	}
	p := parseOpts(norm, optSpec{short: "uCSa", long: set("unset", "chdir", "split-string", "argv0"), abbrev: true})
	assigns, next := splitAssignments(p.rest)
	if s, ok := p.value("S", "split-string"); ok {
		if s.Kind != Lit {
			return unwrapped{unknown: true}
		}
		split, ok := a.splitWords(s.Text)
		if !ok {
			return unwrapped{unknown: true}
		}
		next = append(split, next...)
	}
	u := unwrapped{next: next, assigns: assigns, unknown: p.ambiguous}
	if d, ok := p.value("C", "chdir"); ok {
		u.dir = &d
	}
	return u
}

// splitWords splits a string into words with shell quoting rules (env -S).
func (a *analyzer) splitWords(s string) ([]Elem, bool) {
	f, err := syntax.NewParser().Parse(strings.NewReader(s), "")
	if err != nil || len(f.Stmts) != 1 {
		return nil, false
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(f.Stmts[0].Redirs) > 0 {
		return nil, false
	}
	return a.words(call.Args), true
}

func wrapCommand(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{})
	if p.has("v", "V") {
		return unwrapped{unknown: p.ambiguous} // only describes the command
	}
	return unwrapped{next: p.rest, unknown: p.ambiguous}
}

func wrapTimeout(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "sk", long: set("signal", "kill-after"), abbrev: true})
	if len(p.rest) == 0 {
		return unwrapped{unknown: p.ambiguous}
	}
	return unwrapped{next: p.rest[1:], unknown: p.ambiguous || p.rest[0].Kind == Many}
}

func wrapIonice(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "cnpPu", long: set("class", "classdata", "pid", "pgid", "uid"), abbrev: true})
	if p.hasExact("p", "P", "u", "pid", "pgid", "uid") {
		return unwrapped{unknown: p.ambiguous} // changes existing processes
	}
	return unwrapped{next: p.rest, unknown: p.ambiguous}
}

// wrapFlock is the wrapper for flock: flock [opts] FILE CMD… or flock [opts] FILE -c CODE
// (util-linux only recognizes -c right after FILE).
func wrapFlock(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "wE", long: set("wait", "timeout", "conflict-exit-code"), abbrev: true})
	if len(p.rest) < 2 {
		return unwrapped{unknown: p.ambiguous}
	}
	after := p.rest[1:]
	if after[0].Kind == Lit && (after[0].Text == "-c" || after[0].Text == "--command") {
		if len(after) < 2 {
			return unwrapped{unknown: p.ambiguous}
		}
		return unwrapped{code: []codeRun{shellCode("flock -c", after[1])}, unknown: p.ambiguous}
	}
	return unwrapped{next: after, unknown: p.ambiguous || p.rest[0].Kind == Many}
}

// wrapWatch is the wrapper for watch: watch joins its operands and runs them with sh -c, unless -x.
func wrapWatch(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "nq", long: set("interval", "equexit", "shotsdir"), abbrev: true})
	if p.has("x", "exec") {
		return unwrapped{next: p.rest, unknown: p.ambiguous}
	}
	if len(p.rest) == 0 {
		return unwrapped{unknown: p.ambiguous}
	}
	return unwrapped{code: []codeRun{joinedCode("watch (runs its arguments with sh -c; use watch -x)", p.rest)}, unknown: p.ambiguous}
}

// wrapSu covers su and runuser: -c CODE, runuser -u USER CMD…, or an
// interactive shell that reads its commands from stdin.
func wrapSu(_ *analyzer, name string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "cgGswu", permute: true, long: set("command",
		"session-command", "group", "supp-group", "shell", "whitelist-environment", "user"), abbrev: true})
	var u unwrapped
	if v, ok := p.value("c", "command", "session-command"); ok {
		u = unwrapped{code: []codeRun{shellCode(name+" -c", v)}}
	} else if p.has("u", "user") {
		u = unwrapped{next: p.rest}
	} else {
		u = unwrapped{stdin: &stdinRun{what: name + " reading commands from stdin"}}
	}
	u.unknown = p.ambiguous
	if p.has("l", "login") || slices.ContainsFunc(p.rest, func(e Elem) bool { return e.Kind == Lit && e.Text == "-" }) {
		u.dir = &Elem{Kind: Many, Text: "*"} // a login shell starts in the user's home
	}
	return u
}

func wrapScript(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "cEIOBTm", permute: true, long: set("command", "echo",
		"log-in", "log-out", "log-io", "log-timing", "logging-format", "output-limit"), abbrev: true})
	if v, ok := p.value("c", "command"); ok {
		return unwrapped{code: []codeRun{shellCode("script -c", v)}, unknown: p.ambiguous}
	}
	return unwrapped{stdin: &stdinRun{what: "script reading commands from stdin"}, unknown: p.ambiguous} // runs an interactive shell
}

func wrapChroot(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{long: set("userspec", "groups"), abbrev: true})
	if len(p.rest) <= 1 {
		return unwrapped{stdin: &stdinRun{what: "chroot shell reading commands from stdin"}, unknown: p.ambiguous} // runs $SHELL -i
	}
	return unwrapped{next: p.rest[1:], unknown: p.ambiguous || p.rest[0].Kind == Many}
}

// wrapXargs is the wrapper for xargs: the command gets extra arguments read from stdin.
func wrapXargs(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "adEILnPs", optional: "eil", long: set("arg-file", "delimiter",
		"max-args", "max-procs", "max-chars", "process-slot-var"), abbrev: true})
	next := p.rest
	if len(next) == 0 {
		next = []Elem{{Kind: Lit, Text: "echo"}}
	}
	return unwrapped{next: append(append([]Elem(nil), next...), Elem{Kind: Many, Text: "*"}), unknown: p.ambiguous}
}

// wrapFind extracts the commands run by -exec, -execdir, -ok and -okdir.
func wrapFind(_ *analyzer, _ string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		switch e.Text {
		case "-exec", "-execdir", "-ok", "-okdir":
		default:
			continue
		}
		var cmd []Elem
		for i++; i < len(args); i++ {
			w := args[i]
			if w.Kind == Lit && (w.Text == ";" || w.Text == "+") {
				break
			}
			if w.Kind == Lit && strings.Contains(w.Text, "{}") {
				w = Elem{Kind: One, Text: strings.ReplaceAll(w.Text, "{}", "*")} // a found path
			}
			cmd = append(cmd, w)
		}
		if len(cmd) > 0 {
			u.extra = append(u.extra, cmd)
		}
	}
	return u
}

func wrapEval(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) > 0 && args[0].Kind == Lit && args[0].Text == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return unwrapped{}
	}
	return unwrapped{code: []codeRun{joinedCode("eval", args)}}
}

// wrapTrap is the wrapper for trap: `trap CODE SIGNAL…` runs CODE later, when the signal arrives.
func wrapTrap(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{})
	if len(p.rest) < 2 || (p.rest[0].Kind == Lit && p.rest[0].Text == "-") {
		return unwrapped{unknown: p.ambiguous}
	}
	return unwrapped{code: []codeRun{shellCode("trap", p.rest[0])}, unknown: p.ambiguous}
}

// wrapAlias is the wrapper for alias: an alias body is code that runs wherever the alias is used.
// In a persistent shell a later command may use it, and bash puts the words
// after the name right after the body, so the body is checked followed by
// words only known at run time.
func wrapAlias(a *analyzer, _ string, args []Elem) unwrapped {
	var u unwrapped
	for _, e := range args {
		if e.Kind != Lit {
			u.unknown = true
			continue
		}
		if _, body, ok := strings.Cut(e.Text, "="); ok {
			if a.persistent {
				body += ` "$@"`
			}
			u.code = append(u.code, codeRun{what: "alias", text: body})
		}
	}
	return u
}

// wrapShell handles POSIX-style shells: -c CODE, a script file, or stdin.
func wrapShell(a *analyzer, name string, args []Elem) unwrapped {
	if informational(args) {
		return unwrapped{} // prints and exits before it reads any code
	}
	p := parseOpts(args, optSpec{short: "oO", plus: true, long: set("rcfile", "init-file")})
	for _, o := range p.values("O") {
		a.shoptOption(o) // bash -O dotglob
	}
	switch {
	case p.has("c"):
		if len(p.rest) == 0 {
			return unwrapped{unknown: p.ambiguous}
		}
		return unwrapped{code: []codeRun{shellCode(name+" -c", p.rest[0])}, unknown: p.ambiguous}
	case p.has("s") || len(p.rest) == 0:
		return unwrapped{stdin: &stdinRun{what: name + " reading commands from stdin"}, unknown: p.ambiguous}
	default:
		// A script file: its contents are not analyzed.
		return unwrapped{unknown: p.ambiguous}
	}
}

// informational reports whether a shell's arguments are --version or --help
// before any option that gives it code, a script or stdin to run. The shell
// prints and exits at those, so no code runs.
func informational(args []Elem) bool {
	for _, e := range args {
		switch {
		case e.Kind != Lit:
			return false
		case e.Text == "--version" || e.Text == "--help":
			return true
		case e.Text == "-" || e.Text == "--" || !strings.HasPrefix(e.Text, "-") || strings.HasPrefix(e.Text, "--") || strings.Contains(e.Text, "c"):
			return false
		}
	}
	return false
}

// wrapFish is the wrapper for fish and other non-POSIX shells: fish syntax isn't POSIX, so its code
// is foreign.
func wrapFish(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "cCi", long: set("command", "init-command")})
	if v, ok := p.value("c", "command", "C", "init-command"); ok {
		return unwrapped{code: []codeRun{{what: "fish -c", text: v.Text, foreign: true}}, unknown: p.ambiguous}
	}
	if len(p.rest) == 0 {
		return unwrapped{stdin: &stdinRun{what: "fish reading commands from stdin", foreign: true}, unknown: p.ambiguous}
	}
	return unwrapped{unknown: p.ambiguous}
}
