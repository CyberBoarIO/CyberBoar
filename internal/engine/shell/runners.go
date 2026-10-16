package shell

import (
	"regexp"
	"strings"
)

// Programs that run another program, a shell command or foreign code
// (GTFOBins and friends). Their options are only partly modelled, so besides
// the command they seem to run, most also add an unknown layer: a deny rule
// can still match with certainty through the parsed layer, and anything the
// parsing got wrong is still a possible match (ask)

func registerRunners() {
	for name, fn := range map[string]wrapperFunc{
		// Run their operands as a command after options.
		"strace":      runner(0, optSpec{short: "abeEIoOpPsSuUX"}),
		"ltrace":      runner(0, optSpec{short: "aAeDFlLnopsSuwx"}),
		"valgrind":    runner(0, optSpec{}),
		"unshare":     runner(0, optSpec{short: "SGRwl"}),
		"nsenter":     runner(0, optSpec{short: "tSG"}),
		"systemd-run": runner(0, optSpec{short: "pEMHu", long: set("unit", "property", "uid", "gid", "setenv", "working-directory", "description", "slice", "machine", "host", "on-calendar", "timer-property", "path-property", "socket-property", "service-type", "nice"), abbrev: true}),
		"pkexec":      runner(0, optSpec{long: set("user")}),
		"numactl":     runner(0, optSpec{short: "CNmpiP"}),
		"prlimit":     runner(0, optSpec{short: "p"}),
		"setpriv":     runner(0, optSpec{long: set("reuid", "regid", "ruid", "rgid", "euid", "egid", "groups", "inh-caps", "ambient-caps", "bounding-set", "securebits", "pdeathsig", "selinux-label", "apparmor-profile", "landlock-access", "landlock-rule"), abbrev: true}),
		"torsocks":    runner(0, optSpec{short: "upaPi"}),
		"proxychains": runner(0, optSpec{short: "f"}), "proxychains4": runner(0, optSpec{short: "f"}),
		"firejail":    runner(0, optSpec{}),
		"bwrap":       runner(0, optSpec{}),
		"xvfb-run":    runner(0, optSpec{short: "nsfepw", long: set("server-num", "server-args", "auth-file", "error-file", "xauth-protocol", "wait"), abbrev: true}),
		"dbus-launch": runner(0, optSpec{}),
		"catchsegv":   runner(0, optSpec{}),
		"cgexec":      runner(0, optSpec{short: "g"}),
		"taskset":     runner(1, optSpec{}, "p", "pid"),
		"chrt":        runner(1, optSpec{short: "T P D"}, "p", "pid"),
		"faketime":    runner(1, optSpec{short: "p"}),
		"perf":        wrapPerf,
		"entr":        wrapEntr,
		"sg":          wrapSg,
		// Run whatever they are told, in ways not worth modelling: anything
		"tmux": wrapTmux, "screen": wrapScreen,
		"hyperfine": unknownRunner, "run-parts": unknownRunner, "parallel": unknownRunner,
		// Run shell commands or foreign code given in their arguments
		"socat": wrapSocat,
		"nc":    wrapNetcat, "ncat": wrapNetcat, "netcat": wrapNetcat,
		"sqlite3": wrapSqlite, "psql": wrapSQLShell, "mysql": wrapSQLShell, "mariadb": wrapSQLShell,
		"less": wrapPager, "more": wrapPager, "most": wrapPager,
		"make": wrapMake, "gmake": wrapMake,
		"openssl": wrapOpenSSL,
		"csh":     wrapFish, "tcsh": wrapFish, // not bash syntax: foreign
		"jrunscript": interpreter(interpSpec{short: "efl", code: []string{"e"}, file: []string{"f"}}),
		"jjs":        interpreter(interpSpec{}),
		"jshell":     interpreter(interpSpec{}),
		"irb":        interpreter(interpSpec{short: "I", none: []string{"v", "version"}}),
		"pry":        interpreter(interpSpec{short: "e", code: []string{"e"}}),
	} {
		wrappers[name] = fn
	}
}

// runner runs its operands, after skip positional words, as a command
// With any of pidFlags it acts on an existing process and runs nothing
func runner(skip int, spec optSpec, pidFlags ...string) wrapperFunc {
	spec.short = strings.ReplaceAll(spec.short, " ", "")
	return func(_ *analyzer, _ string, args []Elem) unwrapped {
		p := parseOpts(args, spec)
		if len(pidFlags) > 0 && p.hasExact(pidFlags...) {
			return unwrapped{unknown: p.ambiguous}
		}
		if len(p.rest) <= skip {
			return unwrapped{unknown: true}
		}
		return unwrapped{next: p.rest[skip:], unknown: true}
	}
}

func unknownRunner(*analyzer, string, []Elem) unwrapped { return unwrapped{unknown: true} }

// wrapPerf is the wrapper for perf: `perf stat|record|trace … CMD` runs CMD
func wrapPerf(a *analyzer, name string, args []Elem) unwrapped {
	if len(args) == 0 || args[0].Kind != Lit {
		return unwrapped{unknown: len(args) > 0}
	}
	switch args[0].Text {
	case "stat", "record", "trace", "top", "kvm", "sched", "lock", "mem", "c2c", "kmem":
		return runner(0, optSpec{short: "eoprCGIMcFjGmT"})(a, name, args[1:])
	}
	return unwrapped{}
}

// wrapEntr runs its operands when files change; with -s they are shell code
func wrapEntr(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{})
	if p.has("s") {
		return unwrapped{code: []codeRun{joinedCode("entr -s", p.rest)}, unknown: p.ambiguous}
	}
	return unwrapped{next: p.rest, unknown: p.ambiguous}
}

// wrapSg is the wrapper for sg: `sg [-] GROUP [-c] COMMAND…` runs COMMAND through /bin/sh -c.
func wrapSg(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) > 0 && args[0].Kind == Lit && args[0].Text == "-" {
		args = args[1:]
	}
	if len(args) < 2 {
		return unwrapped{unknown: len(args) > 0 && args[0].Kind != Lit}
	}
	rest := args[1:]
	if rest[0].Kind == Lit && rest[0].Text == "-c" {
		rest = rest[1:]
	}
	return unwrapped{code: []codeRun{joinedCode("sg -c", rest)}}
}

// tmuxQuiet are tmux commands that neither run nor type commands
var tmuxQuiet = set("ls", "list-sessions", "list-windows", "list-panes", "list-clients", "list-keys",
	"list-buffers", "kill-session", "kill-server", "kill-window", "kill-pane", "has-session", "has",
	"attach", "attach-session", "a", "detach", "detach-client", "display-message", "display", "-V")

func wrapTmux(_ *analyzer, _ string, args []Elem) unwrapped {
	for _, e := range args {
		if e.Kind != Lit {
			return unwrapped{unknown: true}
		}
		if !strings.HasPrefix(e.Text, "-") || e.Text == "-V" {
			return unwrapped{unknown: !tmuxQuiet[e.Text]}
		}
	}
	return unwrapped{unknown: true} // no command: a new session running a shell
}

func wrapScreen(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) == 1 && args[0].Kind == Lit && (args[0].Text == "-ls" || args[0].Text == "-list") {
		return unwrapped{}
	}
	return unwrapped{unknown: true}
}

// wrapSocat finds EXEC: (a command) and SYSTEM: (shell code) addresses, and
// the files that file and socket addresses open
func wrapSocat(_ *analyzer, _ string, args []Elem) unwrapped {
	var u unwrapped
	for _, e := range args {
		if e.Kind != Lit {
			u.unknown = true
			continue
		}
		kind, rest, ok := strings.Cut(e.Text, ":")
		if !ok {
			continue
		}
		value, _, _ := strings.Cut(rest, ",") // address options follow a comma
		switch k := strings.ToUpper(kind); {
		case k == "EXEC":
			u.cmdLines = append(u.cmdLines, cmdLine("socat EXEC:", Elem{Kind: Lit, Text: value}))
		case k == "SYSTEM":
			u.code = append(u.code, codeRun{what: "socat SYSTEM:", text: value})
		case socatFileAddrs[k] && value != "":
			u.files = append(u.files, Elem{Kind: Lit, Text: value})
		}
	}
	return u
}

// socatFileAddrs are the socat address types whose value is a file path
var socatFileAddrs = set("FILE", "OPEN", "CREATE", "CREAT", "GOPEN", "PIPE", "NAMEDPIPE",
	"UNIX", "UNIX-CONNECT", "UNIX-LISTEN", "UNIX-L", "UNIX-SENDTO", "UNIX-RECV", "UNIX-RECVFROM", "UNIX-CLIENT")

// wrapNetcat is the wrapper for netcat: -e PROG runs a program, -c / --sh-exec shell code, --lua-exec Lua
func wrapNetcat(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			u.unknown = true
			continue
		}
		opt, val, hasVal := strings.Cut(e.Text, "=")
		_, _, exec := longOpt(e.Text, "exec")
		_, _, shExec := longOpt(e.Text, "sh-exec")
		_, _, luaExec := longOpt(e.Text, "lua-exec")
		value := func() Elem {
			if hasVal {
				return Elem{Kind: Lit, Text: val}
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return Elem{Kind: Many, Text: "*"}
		}
		switch {
		case opt == "-e" || exec:
			u.cmdLines = append(u.cmdLines, cmdLine(name+" -e", value()))
		case opt == "-c" || shExec:
			u.code = append(u.code, shellCode(name+" -c", value()))
		case luaExec:
			value()
			u.code = append(u.code, codeRun{what: name + " --lua-exec", foreign: true})
		case strings.HasPrefix(opt, "-e") && len(opt) > 2 && !strings.HasPrefix(opt, "--"):
			u.cmdLines = append(u.cmdLines, cmdLine(name+" -e", Elem{Kind: Lit, Text: opt[2:]}))
		case strings.HasPrefix(opt, "-c") && len(opt) > 2 && !strings.HasPrefix(opt, "--"):
			u.code = append(u.code, shellCode(name+" -c", Elem{Kind: Lit, Text: opt[2:]}))
		}
	}
	return u
}

var sqliteShell = regexp.MustCompile(`(?m)^\s*\.(shell|system)\b\s*(.*)$`)

// wrapSqlite finds .shell and .system dot-commands in its arguments
func wrapSqlite(_ *analyzer, _ string, args []Elem) unwrapped {
	var u unwrapped
	for _, e := range args {
		if e.Kind != Lit {
			u.unknown = true
			continue
		}
		for _, m := range sqliteShell.FindAllStringSubmatch(e.Text, -1) {
			u.code = append(u.code, codeRun{what: "sqlite3 ." + m[1], text: m[2]})
		}
	}
	return u
}

var sqlShellEscape = regexp.MustCompile(`\\!\s*(.*)|(?im)^\s*system\s+(.*)$`)

// wrapSQLShell finds shell escapes (\! cmd, system cmd) in psql -c and mysql -e statements
func wrapSQLShell(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for _, e := range args {
		if e.Kind != Lit {
			u.unknown = true
			continue
		}
		for _, m := range sqlShellEscape.FindAllStringSubmatch(e.Text, -1) {
			u.code = append(u.code, codeRun{what: name + " shell escape", text: m[1] + m[2]})
		}
	}
	return u
}

// wrapPager is the wrapper for less and more: `less +'!cmd'` runs a shell command at startup
func wrapPager(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for _, e := range args {
		if e.Kind != Lit {
			if e.Text == "*" || strings.HasPrefix(e.Text, "+") {
				u.unknown = true
			}
			continue
		}
		if strings.HasPrefix(e.Text, "+") && strings.ContainsAny(e.Text, "!|") {
			u.code = append(u.code, codeRun{what: name + " +!", text: strings.TrimLeft(e.Text, "+!|")})
		}
	}
	return u
}

// wrapMake is the wrapper for make: --eval adds makefile code; -f - reads a makefile from stdin
func wrapMake(_ *analyzer, name string, args []Elem) unwrapped {
	// -j, -l and -O take a value only in the same word; -L takes none.
	p := parseOpts(args, optSpec{short: "CEfIoW", optional: "jlO", long: set("directory", "eval", "file", "makefile",
		"include-dir", "old-file", "what-if", "assume-old", "assume-new", "new-file"), abbrev: true})
	if _, ok := p.value("E", "eval"); ok {
		return foreignCode(name + " --eval")
	}
	for _, v := range p.values("f", "file", "makefile") {
		if v.Kind != Lit || v.Text == "-" || v.Text == "/dev/stdin" {
			return foreignStdin(name + " -f -")
		}
	}
	return unwrapped{unknown: p.ambiguous}
}

// wrapOpenSSL is the wrapper for openssl: -engine and -provider load a shared library into the process
func wrapOpenSSL(_ *analyzer, _ string, args []Elem) unwrapped {
	for _, e := range args {
		if e.Kind == Lit && (e.Text == "-engine" || e.Text == "-provider" || e.Text == "-provider-path") {
			return foreignCode("openssl " + e.Text)
		}
	}
	return unwrapped{}
}
