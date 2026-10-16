package shell

import (
	"regexp"
	"strings"
	"sync"

	"cyberboar.dev/cyberboar/internal/fold"
)

// Interpreters, shells and programs that run code or commands given on their
// command line or on stdin

// versioned maps "python3.12", "perl5.36", "lua5.4" to their family
var versioned = regexp.MustCompile(`^(python|pypy|node|nodejs|ruby|perl|php|lua|luajit|tclsh|wish)[0-9.]*$`)

// lookupWrapper finds what a command name runs, including versioned
// interpreters. The name is folded: on macOS, PATH lookup finds /bin/sh for
// "SH" (case-insensitive filesystems) and for "s\u200Dh" (HFS+). Folding a
// shell builtin (eval, command) only adds analysis, so it is stricter too
func lookupWrapper(name string) wrapperFunc {
	name = fold.String(name)
	ws := foldedWrappers()
	if fn := ws[name]; fn != nil {
		return fn
	}
	if m := versioned.FindStringSubmatch(name); m != nil {
		return ws[m[1]]
	}
	if loader.MatchString(name) {
		return wrapLoader
	}
	return nil
}

// foldedWrappers is wrappers keyed by folded name ("Rscript" → "rscript"),
// built after every init function has filled wrappers
var foldedWrappers = sync.OnceValue(func() map[string]wrapperFunc {
	m := make(map[string]wrapperFunc, len(wrappers))
	for name, fn := range wrappers {
		m[fold.String(name)] = fn
	}
	return m
})

func registerInterpreters() {
	python := interpreter(interpSpec{short: "cmWXQ", code: []string{"c"}, none: []string{"m", "V", "version", "h", "help"}})
	node := interpreter(interpSpec{short: "eprC", long: set("eval", "print", "require", "import", "loader",
		"experimental-loader", "input-type", "conditions", "title"),
		code: []string{"e", "p", "eval", "print"}, none: []string{"v", "version", "h", "help", "c", "check"}})
	perl := interpreter(interpSpec{short: "eEM", code: []string{"e", "E"}, none: []string{"v", "V", "version", "c"}})
	lua := interpreter(interpSpec{short: "el", code: []string{"e"}, none: []string{"v"}})
	tcl := interpreter(interpSpec{})
	for name, fn := range map[string]wrapperFunc{
		"python": python, "pypy": python,
		"node": node, "nodejs": node,
		"bun":  interpreter(interpSpec{short: "e", long: set("eval", "print"), code: []string{"e", "eval", "print"}, noStdin: true}),
		"ruby": interpreter(interpSpec{short: "eIrCE", code: []string{"e"}, none: []string{"v", "version", "h", "help"}}),
		"perl": perl,
		"php":  interpreter(interpSpec{short: "rBREcdfzStF", code: []string{"r", "B", "R", "E"}, none: []string{"S", "v", "version", "h", "help", "i", "m", "l"}, file: []string{"f"}}),
		"lua":  lua, "luajit": lua,
		"Rscript":   interpreter(interpSpec{short: "e", code: []string{"e"}, none: []string{"version", "help"}, noStdin: true}),
		"R":         interpreter(interpSpec{short: "ef", long: set("file"), code: []string{"e"}, none: []string{"version", "help"}, file: []string{"f", "file"}}),
		"osascript": interpreter(interpSpec{short: "el", code: []string{"e"}}),
		"expect":    interpreter(interpSpec{short: "cfbD", code: []string{"c"}, file: []string{"f", "b"}}),
		"tclsh":     tcl, "wish": tcl,
		"deno": wrapDeno, "gdb": wrapGdb, "emacs": wrapEmacs, "emacsclient": wrapEmacs,
		"pwsh": wrapPowerShell, "pwsh.exe": wrapPowerShell, "powershell": wrapPowerShell, "powershell.exe": wrapPowerShell,
		"awk": wrapAwk, "gawk": wrapAwk, "mawk": wrapAwk, "nawk": wrapAwk,
		"sed": wrapSed, "gsed": wrapSed,
		"at": wrapAt, "batch": wrapAt, "crontab": wrapCrontab,
		"julia":      interpreter(interpSpec{short: "eEtpLCJ", long: set("eval", "print", "threads", "project", "procs", "load", "sysimage", "cpu-target", "home", "startup-file", "history-file", "optimize", "check-bounds", "depwarn", "compile", "machine-file", "banner", "color", "code-coverage", "track-allocation", "math-mode", "heap-size-hint", "gcthreads"), code: []string{"e", "E", "eval", "print"}, none: []string{"v", "version", "h", "help"}, abbrev: true}),
		"octave":     interpreter(interpSpec{long: set("eval", "path", "exec-path", "image-path", "info-file", "info-program", "doc-cache-file", "texi-macros-file"), code: []string{"eval"}, none: []string{"v", "version", "h", "help"}, abbrev: true}),
		"octave-cli": interpreter(interpSpec{long: set("eval", "path", "exec-path"), code: []string{"eval"}, none: []string{"v", "version", "h", "help"}, abbrev: true}),
		"gnuplot":    interpreter(interpSpec{short: "ec", code: []string{"e"}, file: []string{"c"}, none: []string{"V", "version", "h", "help"}}),
		"ghc":        interpreter(interpSpec{short: "eo", code: []string{"e"}, noStdin: true}),
		"ghci":       interpreter(interpSpec{short: "e", code: []string{"e"}}),
		"elixir":     interpreter(interpSpec{short: "er", long: set("eval", "require", "sname", "name", "cookie", "erl", "pa", "pz"), code: []string{"e", "eval"}, noStdin: true}),
		"iex":        interpreter(interpSpec{long: set("eval", "sname", "name", "cookie", "erl", "dot-iex", "remsh"), code: []string{"eval"}}),
		"scala":      interpreter(interpSpec{short: "ecj", long: set("execute", "classpath", "cp"), code: []string{"e", "execute"}}),
		"scala-cli":  interpreter(interpSpec{short: "e", long: set("execute-scala", "execute-java", "execute-script"), code: []string{"e", "execute-scala", "execute-java", "execute-script"}, noStdin: true}),
		"kotlinc":    interpreter(interpSpec{short: "ed", long: set("expression", "script"), code: []string{"e", "expression"}}),
		"kotlin":     interpreter(interpSpec{short: "ec", long: set("expression", "classpath", "cp", "howtorun"), code: []string{"e", "expression"}}),
		"groovy":     interpreter(interpSpec{short: "ec", long: set("classpath", "encoding"), code: []string{"e"}, noStdin: true}),
		"groovysh":   interpreter(interpSpec{short: "e", long: set("evaluate", "classpath"), code: []string{"e", "evaluate"}}),
		"clojure":    interpreter(interpSpec{short: "eiSA", long: set("eval", "init"), code: []string{"e", "eval"}}),
		"clj":        interpreter(interpSpec{short: "eiSA", long: set("eval", "init"), code: []string{"e", "eval"}}),
		"guile":      interpreter(interpSpec{short: "celsLx", code: []string{"c", "e"}, file: []string{"s", "l"}}),
		"racket":     interpreter(interpSpec{short: "eftrlpk", long: set("eval", "load", "require", "lib", "main", "require-script"), code: []string{"e", "eval"}, file: []string{"f", "t", "r", "load", "require", "require-script"}}),
		"sbcl":       interpreter(interpSpec{long: set("eval", "load", "script", "core", "dynamic-space-size", "control-stack-size", "userinit", "sysinit"), code: []string{"eval"}, file: []string{"load", "script"}}),
		"raku":       interpreter(interpSpec{short: "eIM", code: []string{"e"}, none: []string{"v", "version", "h", "help", "c"}}),
		"perl6":      interpreter(interpSpec{short: "eIM", code: []string{"e"}, none: []string{"v", "version", "h", "help", "c"}}),
		"rakudo":     interpreter(interpSpec{short: "eIM", code: []string{"e"}, none: []string{"v", "version", "h", "help", "c"}}),
		"qjs":        interpreter(interpSpec{short: "eI", long: set("eval", "include", "memory-limit", "stack-size"), code: []string{"e", "eval"}}),
		"csi":        interpreter(interpSpec{short: "epPsR", long: set("eval", "print", "pretty-print", "script"), code: []string{"e", "p", "P", "eval", "print", "pretty-print"}, file: []string{"s", "script"}}),
		"swipl":      interpreter(interpSpec{short: "gtlsfFx", code: []string{"g", "t"}, file: []string{"l", "s", "f", "x"}}),
		"swift":      interpreter(interpSpec{short: "e", code: []string{"e"}}),
		"crystal":    wrapCrystal,
		"erl":        wrapErl,
		"cmd":        wrapCmdExe, "cmd.exe": wrapCmdExe,
		"rc": wrapFish, "elvish": wrapFish, "nu": wrapFish, "xonsh": wrapFish, "ion": wrapFish,
		"osh": wrapFish, "ysh": wrapFish, "oil": wrapFish, "murex": wrapFish,
		"toybox": wrapPlain,
		"ed":     wrapEd,
		"nano":   wrapNano, "pico": wrapNano, "rnano": wrapNano,
		"ansible":    wrapAnsible,
		"salt-call":  wrapSalt,
		"salt":       wrapSalt,
		"puppet":     wrapPuppet,
		"chef-apply": interpreter(interpSpec{short: "el", long: set("execute", "log_level"), code: []string{"e", "execute"}, noStdin: true, abbrev: true}),
		"ssh-keygen": wrapSSHKeygen,
	} {
		wrappers[name] = fn
	}
	for _, ed := range []string{"vim", "nvim", "vi", "ex", "view", "vimdiff", "gvim", "rvim",
		"rview", "evim", "eview", "rgvim", "rgview", "gview", "vimx"} {
		wrappers[ed] = wrapVim
	}
}

type interpSpec struct {
	short   string          // short options that take a value, code options included
	long    map[string]bool // long options that take a value
	code    []string        // options whose value is code
	none    []string        // options after which it runs no code from stdin (version, module, server)
	file    []string        // options naming a code file (not analyzed)
	noStdin bool            // with no operand it doesn't read code from stdin
	abbrev  bool            // long options may be cut short (getopt_long)
}

func optName(o string) string {
	if len(o) == 1 {
		return "-" + o
	}
	return "--" + o
}

func interpreter(spec interpSpec) wrapperFunc {
	return func(_ *analyzer, name string, args []Elem) unwrapped {
		p := parseOpts(args, optSpec{short: spec.short, long: spec.long, abbrev: spec.abbrev})
		for _, c := range spec.code {
			if v, ok := p.value(c); ok {
				return unwrapped{code: []codeRun{{what: name + " " + optName(c), text: v.Text, foreign: true}}, unknown: p.ambiguous}
			}
		}
		if p.hasExact(spec.none...) || p.hasExact(spec.file...) {
			return unwrapped{unknown: p.ambiguous}
		}
		if (len(p.rest) == 0 && !spec.noStdin) || (len(p.rest) > 0 && p.rest[0].Kind == Lit && p.rest[0].Text == "-") {
			return unwrapped{stdin: &stdinRun{what: name + " reading code from stdin", foreign: true}, unknown: p.ambiguous}
		}
		return unwrapped{unknown: p.ambiguous} // a script file: not analyzed
	}
}

func foreignCode(what string) unwrapped {
	return unwrapped{code: []codeRun{{what: what, foreign: true}}}
}

func foreignStdin(what string) unwrapped {
	return unwrapped{stdin: &stdinRun{what: what, foreign: true}}
}

func wrapDeno(_ *analyzer, _ string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{})
	if len(p.rest) == 0 {
		return foreignStdin("deno repl reading code from stdin")
	}
	switch sub := p.rest[0]; {
	case sub.Kind != Lit:
		return foreignCode("deno with a run-time subcommand")
	case sub.Text == "eval":
		return foreignCode("deno eval")
	case sub.Text == "repl":
		return foreignStdin("deno repl reading code from stdin")
	}
	for _, e := range p.rest[1:] {
		if e.Kind == Lit && e.Text == "-" {
			return foreignStdin("deno reading code from stdin")
		}
	}
	return unwrapped{unknown: p.ambiguous}
}

// wrapGdb is the wrapper for gdb: -ex runs debugger commands (which include `shell`)
// Without -batch, gdb reads commands from stdin.
func wrapGdb(_ *analyzer, _ string, args []Elem) unwrapped {
	batch := false
	for _, e := range args {
		if e.Kind != Lit {
			continue
		}
		// getopt_long_only: one dash or two, and cut short (-eval for -eval-command)
		opt, _, _ := strings.Cut(strings.TrimLeft(e.Text, "-"), "=")
		switch {
		case !strings.HasPrefix(e.Text, "-"):
		case opt == "ex" || opt == "iex" ||
			len(opt) > 1 && (strings.HasPrefix("eval-command", opt) || strings.HasPrefix("init-eval-command", opt)):
			return foreignCode("gdb -ex")
		case opt == "batch":
			batch = true
		}
	}
	if batch {
		return unwrapped{}
	}
	return foreignStdin("gdb reading commands from stdin")
}

// wrapVim is the wrapper for vim and its variants: editor commands (-c, +cmd, keystrokes from
// stdin) can run programs
func wrapVim(_ *analyzer, name string, _ []Elem) unwrapped {
	return foreignCode(name + " (editor commands can run programs)")
}

func wrapEmacs(_ *analyzer, name string, args []Elem) unwrapped {
	batch := false
	for _, e := range args {
		if e.Kind != Lit {
			continue
		}
		opt, _, _ := strings.Cut(strings.TrimLeft(e.Text, "-"), "=")
		_, _, code := longOpt(e.Text, "eval", "execute") // startup.el completes "--" options
		switch {
		case !strings.HasPrefix(e.Text, "-"):
		case code || opt == "eval" || opt == "execute":
			return foreignCode(name + " --eval")
		case opt == "batch" || opt == "script":
			batch = true
		}
	}
	if batch {
		return unwrapped{}
	}
	return foreignStdin(name + " (interactive)")
}

// wrapPowerShell is the wrapper for PowerShell: parameters are case-insensitive and may be
// abbreviated. Windows PowerShell treats the first positional argument as -Command, pwsh as -File
func wrapPowerShell(_ *analyzer, name string, args []Elem) unwrapped {
	legacy := strings.HasPrefix(fold.String(name), "powershell")
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			return foreignCode(name + " with run-time arguments")
		}
		t := strings.ToLower(strings.TrimSpace(e.Text))
		if t == "" {
			return foreignCode(name + " with an empty argument")
		}
		// PowerShell accepts slash switches and three Unicode dash forms,
		// and trims whitespace around a parameter before reading it
		opt := strings.TrimLeft(t, "-/\u2013\u2014\u2015")
		if opt == t {
			if legacy {
				return foreignCode(name + " (positional command)")
			}
			return unwrapped{} // a script file
		}
		match := func(full, minimum string) bool {
			return len(opt) >= len(minimum) && strings.HasPrefix(full, opt)
		}
		switch {
		case opt == "":
			return foreignStdin(name + " reading commands from stdin")
		case match("command", "c") || match("encodedcommand", "e") || opt == "ec" ||
			opt == "commandwithargs" || opt == "cwa":
			return foreignCode(name + " -Command")
		case match("file", "f"):
			if i+1 < len(args) && args[i+1].Kind == Lit && args[i+1].Text == "-" {
				return foreignStdin(name + " reading commands from stdin")
			}
			return unwrapped{}
		case !legacy && match("version", "v"), match("help", "h"), opt == "?":
			return unwrapped{}
		}
		// These parameters consume the next word. It is a value, not the
		// positional script file that ends PowerShell's option parsing
		value := legacy && match("version", "v")
		for _, o := range [][2]string{
			{"executionpolicy", "ex"}, {"ep", "ep"},
			{"outputformat", "o"}, {"of", "of"},
			{"inputformat", "inp"}, {"if", "if"},
			{"workingdirectory", "wo"}, {"wd", "wd"},
			{"configurationname", "config"}, {"configurationfile", "configurationfile"},
			{"custompipename", "cus"}, {"settingsfile", "settings"},
			{"windowstyle", "w"}, {"encodedarguments", "encodeda"}, {"ea", "ea"},
		} {
			value = value || match(o[0], o[1])
		}
		if value {
			i++
			if i >= len(args) || args[i].Kind != Lit {
				return foreignCode(name + " with run-time or missing option values")
			}
			continue
		}
		flag := false
		for _, o := range [][2]string{
			{"noexit", "noe"}, {"noprofile", "nop"}, {"nologo", "nol"},
			{"noninteractive", "noni"}, {"interactive", "i"},
			{"sta", "sta"}, {"mta", "mta"}, {"login", "l"},
			{"noprofileloadtime", "noprofileloadtime"},
		} {
			flag = flag || match(o[0], o[1])
		}
		if !flag {
			if !legacy && strings.HasPrefix(t, "/") {
				return unwrapped{} // an unrecognized slash word is a script path
			}
			return foreignCode(name + " with an unrecognized option")
		}
	}
	return foreignStdin(name + " reading commands from stdin")
}

// awkSystem matches system() and gawk's @load
var awkSystem = regexp.MustCompile(`\bsystem\s*\(|@load`)

// awkRuns reports whether an awk program has a construct that runs programs:
// system(), pipes to and from commands (print | "cmd", "cmd" | getline, |&),
// and gawk's @load. A single | is also regex alternation; that false positive is accepted
func awkRuns(prog string) bool {
	if awkSystem.MatchString(prog) {
		return true
	}
	for i := 0; i < len(prog); i++ {
		if prog[i] != '|' {
			continue
		}
		if i+1 < len(prog) && prog[i+1] == '|' {
			i++ // || is logical or
			continue
		}
		return true
	}
	return false
}

func wrapAwk(_ *analyzer, name string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "FvfeilEZ", optional: "dDLop", long: set("field-separator", "assign", "file",
		"source", "include", "load", "exec"), abbrev: true})
	if p.has("l", "load") {
		return foreignCode(name + " -l (loads a native extension)")
	}
	progs := p.values("e", "source")
	if !p.hasExact("f", "file", "E", "exec") && len(progs) == 0 && len(p.rest) > 0 {
		progs = append(progs, p.rest[0])
	}
	u := unwrapped{unknown: p.ambiguous}
	for _, prog := range progs {
		if prog.Kind != Lit {
			return foreignCode(name + " with a run-time program")
		}
		if awkRuns(prog.Text) {
			return foreignCode(name + " program running commands (system(), pipes)")
		}
		u.files = append(u.files, awkFiles(prog.Text)...)
	}
	return u
}

// streamNames are the special file names sed and awk handle themselves without opening a file
var streamNames = set("/dev/stdout", "/dev/stderr", "/dev/stdin", "-")

var (
	// awkLiteralFile matches getline [VAR] < FILE, and print > FILE / >> FILE,
	// with FILE a string literal; awkDynamicFile, with anything else
	awkLiteralFile = regexp.MustCompile(`(?s)(?:getline(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*<|>>?)\s*"((?:[^"\\]|\\.)*)"`)
	awkDynamicFile = regexp.MustCompile(`(?:getline(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*<|>>?)\s*[A-Za-z_$(]`)
)

// awkFiles returns the files an awk program opens with getline < FILE or a
// > / >> redirection. A target only known at run time is a Many element
// Comparisons (a > "b", a > b) look the same; those false positives are accepted
func awkFiles(prog string) []Elem {
	var out []Elem
	for _, m := range awkLiteralFile.FindAllStringSubmatch(prog, -1) {
		name, known := awkString(m[1])
		if !known {
			out = append(out, Elem{Kind: Many, Text: "*"})
		} else if !streamNames[name] {
			out = append(out, Elem{Kind: Lit, Text: name})
		}
	}
	if awkDynamicFile.MatchString(prog) {
		out = append(out, Elem{Kind: Many, Text: "*"})
	}
	return out
}

// awkString decodes portable AWK string escapes. Other escapes depend on
// the implementation, so a filename containing one is unknown
func awkString(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", false
		}
		switch c := s[i]; c {
		case '\n': // continued source line
		case '\\', '"', '/':
			b.WriteByte(c)
		case 'a', 'b', 'f', 'n', 'r', 't', 'v':
			b.WriteByte(map[byte]byte{'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}[c])
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v := int(c - '0')
			for n := 1; n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7'; n++ {
				i++
				v = v*8 + int(s[i]-'0')
			}
			if v == 0 || v > 0xff {
				return "", false
			}
			b.WriteByte(byte(v)) // #nosec G115 -- v <= 0xff, checked above
		default:
			return "", false
		}
	}
	return b.String(), true
}

func wrapSed(_ *analyzer, name string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "efl", optional: "i", long: set("expression", "file", "line-length"), abbrev: true})
	if p.hasExact("sandbox") {
		return unwrapped{unknown: p.ambiguous} // e, r and w are rejected
	}
	scripts := p.values("e", "expression")
	if !p.hasExact("f", "file") && len(scripts) == 0 && len(p.rest) > 0 {
		scripts = append(scripts, p.rest[0])
	}
	u := unwrapped{unknown: p.ambiguous}
	for _, sc := range scripts {
		if sc.Kind != Lit {
			return foreignCode(name + " with a run-time script")
		}
		runs, files := sedScan(sc.Text)
		if runs {
			return foreignCode(name + " e command or s///e flag")
		}
		for _, f := range files {
			if !streamNames[f] {
				u.files = append(u.files, Elem{Kind: Lit, Text: f})
			}
		}
	}
	return u
}

// sedScan reports whether a sed script uses GNU sed's `e` command or the `e`
// flag of `s`, which run shell commands, and returns the files its r, R, w, W
// commands and s///w flag open. A script it can't parse counts as running commands
func sedScan(s string) (runs bool, files []string) {
	i, n := 0, len(s)
	fileToEOL := func(i int) int {
		start := i
		for i < n && s[i] != '\n' {
			i++
		}
		if f := strings.TrimSpace(s[start:i]); f != "" {
			files = append(files, f)
		}
		return i
	}
	// delimited skips a delimited part starting after its opening delimiter,
	// returning the index after the closing one, or -1
	delimited := func(i int, d byte) int {
		for ; i < n; i++ {
			switch s[i] {
			case '\\':
				i++
			case d:
				return i + 1
			case '\n':
				return -1
			}
		}
		return -1
	}
	toEOL := func(i int) int {
		for i < n && s[i] != '\n' {
			if s[i] == '\\' {
				i++
			}
			i++
		}
		return i
	}
	toSep := func(i int) int {
		for i < n && s[i] != '\n' && s[i] != ';' {
			i++
		}
		return i
	}
	for i < n {
		switch s[i] {
		case ' ', '\t', '\n', ';', '}':
			i++
			continue
		}
		// Addresses: numbers, $, /regex/, \cREGEXc, with , ~ ! + between
	addr:
		for i < n {
			c := s[i]
			switch {
			case c >= '0' && c <= '9', c == '$', c == ',', c == '~', c == '!', c == '+', c == ' ', c == '\t':
				i++
			case c == '/':
				if i = delimited(i+1, '/'); i < 0 {
					return true, files
				}
				for i < n && (s[i] == 'I' || s[i] == 'M') {
					i++
				}
			case c == '\\':
				if i+1 >= n {
					return true, files
				}
				if i = delimited(i+2, s[i+1]); i < 0 {
					return true, files
				}
			default:
				break addr
			}
		}
		if i >= n {
			return true, files // an address without a command: invalid
		}
		c := s[i]
		i++
		switch c {
		case 'e':
			return true, files
		case '{', '=', 'd', 'D', 'g', 'G', 'h', 'H', 'n', 'N', 'p', 'P', 'x', 'z', 'F':
		case 'l', 'L', 'q', 'Q':
			for i < n && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		case 's':
			if i >= n {
				return true, files
			}
			d := s[i]
			if i = delimited(i+1, d); i < 0 {
				return true, files
			}
			if i = delimited(i, d); i < 0 {
				return true, files
			}
			for i < n && strings.IndexByte("gpiImMe0123456789w", s[i]) >= 0 {
				switch s[i] {
				case 'e':
					return true, files
				case 'w':
					i = fileToEOL(i + 1)
					continue
				}
				i++
			}
		case 'y':
			if i >= n {
				return true, files
			}
			d := s[i]
			if i = delimited(i+1, d); i < 0 {
				return true, files
			}
			if i = delimited(i, d); i < 0 {
				return true, files
			}
		case 'r', 'R', 'w', 'W':
			i = fileToEOL(i)
		case 'a', 'i', 'c', '#':
			i = toEOL(i)
		case ':', 'b', 't', 'T', 'v':
			i = toSep(i)
		default:
			return true, files // unknown command
		}
	}
	return false, files
}

// wrapAt is the wrapper for at and batch: at and batch read shell commands to run later from stdin
// or -f FILE
func wrapAt(_ *analyzer, name string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "qft"})
	if p.has("l", "r", "d", "c", "V", "f") {
		return unwrapped{unknown: p.ambiguous}
	}
	return unwrapped{stdin: &stdinRun{what: name + " reading commands from stdin"}, unknown: p.ambiguous}
}

// wrapCrontab is the wrapper for crontab: crontab - (or no file) installs jobs read from stdin
func wrapCrontab(_ *analyzer, name string, args []Elem) unwrapped {
	p := parseOpts(args, optSpec{short: "u"})
	if p.has("l", "r", "e", "i", "T") {
		return unwrapped{unknown: p.ambiguous}
	}
	if len(p.rest) == 0 || (p.rest[0].Kind == Lit && p.rest[0].Text == "-") {
		return unwrapped{stdin: &stdinRun{what: name + " reading jobs from stdin", foreign: true}, unknown: p.ambiguous}
	}
	return unwrapped{unknown: p.ambiguous}
}

// loader matches the dynamic loader, which runs the program it is given
var loader = regexp.MustCompile(`^ld(-linux[a-z0-9_-]*|-musl[a-z0-9_-]*)?\.so(\.[0-9]+)*$`)

var loaderOpts = longOpts{
	long:      set("list", "verify", "inhibit-cache", "list-tunables", "list-diagnostics", "help", "version"),
	longValue: set("library-path", "inhibit-rpath", "audit", "preload", "argv0", "glibc-hwcaps-prepend", "glibc-hwcaps-mask"),
}

func wrapLoader(_ *analyzer, _ string, args []Elem) unwrapped {
	starts, amb := operandStarts(args, 0, loaderOpts)
	var argvs [][]Elem
	for _, i := range starts {
		if i < len(args) {
			argvs = append(argvs, args[i:])
		}
	}
	return runsEach(argvs, amb)
}

func wrapCrystal(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) > 0 && args[0].Kind == Lit && args[0].Text == "eval" {
		return foreignCode("crystal eval")
	}
	return unwrapped{}
}

// wrapErl is the wrapper for erl: -eval runs code; with no arguments erl is a shell reading stdin
func wrapErl(_ *analyzer, _ string, args []Elem) unwrapped {
	for _, e := range args {
		if e.Kind == Lit && e.Text == "-eval" {
			return foreignCode("erl -eval")
		}
	}
	if len(args) == 0 {
		return foreignStdin("erl reading code from stdin")
	}
	return unwrapped{}
}

// wrapCmdExe is the wrapper for cmd.exe: cmd /c and /k run a command line (not bash syntax)
// Git Bash users write //c (a single /c is turned into the path C:/), and cmd reads a
// switch glued to its command (/cdir), so any word starting with slashes and c, k or r counts
func wrapCmdExe(_ *analyzer, name string, args []Elem) unwrapped {
	for _, e := range args {
		if e.Kind != Lit {
			return unwrapped{unknown: true}
		}
		if t := strings.ToLower(strings.TrimLeft(e.Text, "/")); len(t) < len(e.Text) && t != "" && strings.ContainsRune("ckr", rune(t[0])) {
			return foreignCode(name + " " + e.Text)
		}
	}
	return foreignStdin(name + " reading commands from stdin")
}

// wrapEd is the wrapper for ed: ed reads its commands, "!command" among them, from stdin
func wrapEd(*analyzer, string, []Elem) unwrapped {
	return foreignStdin("ed reading commands from stdin")
}

// wrapNano is the wrapper for nano: -s/--speller names a program nano runs
func wrapNano(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		v, hasVal, speller := longOpt(e.Text, "speller")
		switch {
		case hasVal:
			u.cmdLines = append(u.cmdLines, cmdLine(name+" --speller", Elem{Kind: Lit, Text: v}))
		case (e.Text == "-s" || speller) && i+1 < len(args):
			i++
			u.cmdLines = append(u.cmdLines, cmdLine(name+" --speller", args[i]))
		}
	}
	return u
}

// wrapAnsible is the wrapper for ansible: -a ARGS is a command line for the command (the default),
// shell and raw modules; other modules take key=value arguments
func wrapAnsible(_ *analyzer, name string, args []Elem) unwrapped {
	module := "command"
	var argsVal *Elem
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		// argparse takes -aARGS and unambiguous prefixes (--mod, --ar)
		t := e.Text
		val, hasVal, isModule := longOpt(t, "module-name")
		if !isModule {
			var isArgs bool
			val, hasVal, isArgs = longOpt(t, "args")
			switch {
			case isArgs:
			case len(t) >= 2 && t[0] == '-' && (t[1] == 'a' || t[1] == 'm'):
				isModule, val, hasVal = t[1] == 'm', t[2:], len(t) > 2
			default:
				continue
			}
		}
		if !hasVal {
			if i+1 >= len(args) {
				continue
			}
			i++
			if args[i].Kind != Lit {
				if isModule {
					module = "" // unknown: assume it runs the arguments
				} else {
					v := args[i]
					argsVal = &v
				}
				continue
			}
			val = args[i].Text
		}
		if isModule {
			module = strings.TrimPrefix(val, "ansible.builtin.")
		} else {
			v := Elem{Kind: Lit, Text: val}
			argsVal = &v
		}
	}
	switch module {
	case "command", "shell", "raw", "win_shell", "win_command", "":
		if argsVal != nil {
			return unwrapped{cmdLines: []codeRun{cmdLine(name+" -a", *argsVal)}}
		}
	}
	return unwrapped{}
}

// wrapSalt is the wrapper for salt: cmd.run and friends take a command line; cmd.exec_code code
func wrapSalt(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i, e := range args {
		if e.Kind != Lit || i+1 >= len(args) {
			continue
		}
		switch e.Text {
		case "cmd.run", "cmd.shell", "cmd.run_all", "cmd.run_stdout", "cmd.run_stderr", "cmd.run_bg", "cmd.script", "cmd.retcode", "cmd.powershell":
			u.cmdLines = append(u.cmdLines, cmdLine(name+" "+e.Text, args[i+1]))
		case "cmd.exec_code", "cmd.exec_code_all":
			u.code = append(u.code, codeRun{what: name + " " + e.Text, foreign: true})
		}
	}
	return u
}

// wrapPuppet is the wrapper for puppet: puppet apply -e/--execute runs manifest code
func wrapPuppet(_ *analyzer, _ string, args []Elem) unwrapped {
	if len(args) == 0 || args[0].Kind != Lit || args[0].Text != "apply" {
		return unwrapped{}
	}
	for _, e := range args[1:] {
		if _, _, ok := longOpt(e.Text, "execute"); e.Kind == Lit && (e.Text == "-e" || ok) {
			return foreignCode("puppet apply " + e.Text)
		}
	}
	return unwrapped{}
}

// wrapSSHKeygen is the wrapper for ssh-keygen: -D loads a PKCS#11 library (native code),
// like openssl -engine
func wrapSSHKeygen(_ *analyzer, _ string, args []Elem) unwrapped {
	for _, e := range args {
		if e.Kind == Lit && strings.HasPrefix(e.Text, "-") && !strings.HasPrefix(e.Text, "--") && strings.Contains(e.Text, "D") {
			return foreignCode("ssh-keygen -D")
		}
	}
	return unwrapped{}
}
