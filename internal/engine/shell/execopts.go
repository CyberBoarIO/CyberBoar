package shell

import (
	"strings"
)

// Options and environment variables whose value is a command the program runs,
// usually through a shell. Values are analyzed as command lines: a single plain
// command is checked like any command; anything more is inline shell code

func registerExecOpts() {
	for name, fn := range map[string]wrapperFunc{
		"ssh": wrapSSH, "scp": wrapSSH, "sftp": wrapSSH, "slogin": wrapSSH,
		"rsync": wrapRsync, "tar": wrapTar, "gtar": wrapTar, "zip": wrapZip, "man": wrapMan,
	} {
		wrappers[name] = fn
	}
}

func cmdLine(what string, e Elem) codeRun {
	return codeRun{what: what, text: e.Text, dynamic: e.Kind != Lit}
}

func wrapRsync(a *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		t := e.Text
		switch {
		case t == "--":
			return u
		case strings.HasPrefix(t, "--"):
			opt := "--rsh"
			val, hasVal, ok := longOpt(t, opt)
			if !ok {
				opt = "--rsync-path"
				if val, hasVal, ok = longOpt(t, opt); !ok {
					continue
				}
			}
			v := Elem{Kind: Lit, Text: val}
			if !hasVal {
				if i+1 == len(args) {
					continue
				}
				i++
				v = args[i]
			}
			r := cmdLine(name+" "+opt, v)
			if opt == "--rsync-path" {
				r.start = a.homeDir() // run by the remote shell, in the remote home
			}
			u.cmdLines = append(u.cmdLines, r)
		case strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--"):
			if j := strings.IndexByte(t, 'e'); j > 0 {
				v := Elem{Kind: Lit, Text: t[j+1:]}
				if j+1 == len(t) && i+1 < len(args) {
					i++
					v = args[i]
				}
				u.cmdLines = append(u.cmdLines, cmdLine(name+" -e", v))
			}
		}
	}
	return u
}

// wrapTar finds GNU tar's program-running options
func wrapTar(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	long := []string{"to-command", "use-compress-program", "rsh-command", "info-script", "new-volume-script",
		"checkpoint-action"}
	add := func(opt string, v Elem) {
		if opt == "checkpoint-action" {
			if v.Kind == Lit && !strings.HasPrefix(v.Text, "exec=") {
				return // dot, echo, sleep, …
			}
			v.Text = strings.TrimPrefix(v.Text, "exec=")
		}
		u.cmdLines = append(u.cmdLines, cmdLine(name+" --"+opt, v))
	}
	const withValue = "fCTXgKNVbHLIF" // short options taking a value
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		t := e.Text
		switch {
		case t == "--":
			return u
		case strings.HasPrefix(t, "--"):
			var opt, val string
			var hasVal, ok bool
			for _, o := range long {
				if val, hasVal, ok = longOpt(t, o); ok {
					opt = o
					break
				}
			}
			if !ok {
				continue
			}
			v := Elem{Kind: Lit, Text: val}
			if !hasVal && i+1 < len(args) {
				i++
				v = args[i]
			}
			add(opt, v)
		case strings.HasPrefix(t, "-") || i == 0: // "-cIf …", or old-style bundled "cIf …"
			letters := strings.TrimPrefix(t, "-")
			for j := 0; j < len(letters); j++ {
				c := letters[j]
				if strings.IndexByte(withValue, c) < 0 {
					continue
				}
				var v Elem
				if strings.HasPrefix(t, "-") && j+1 < len(letters) {
					v, j = Elem{Kind: Lit, Text: letters[j+1:]}, len(letters) // attached value
				} else if i+1 < len(args) {
					i++
					v = args[i]
				}
				switch c {
				case 'I':
					add("use-compress-program", v)
				case 'F':
					add("info-script", v)
				}
			}
		}
	}
	return u
}

func wrapZip(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		val, hasVal, long := longOpt(e.Text, "--unzip-command")
		switch {
		case long && hasVal:
			u.cmdLines = append(u.cmdLines, cmdLine(name+" -TT", Elem{Kind: Lit, Text: val}))
		case (e.Text == "-TT" || long) && i+1 < len(args):
			i++
			u.cmdLines = append(u.cmdLines, cmdLine(name+" -TT", args[i]))
		}
	}
	return u
}

// wrapMan finds the pager (-P, --pager) and HTML browser (-H, --html)
func wrapMan(_ *analyzer, name string, args []Elem) unwrapped {
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			continue
		}
		t := e.Text
		for _, o := range []struct{ short, long string }{{"-P", "--pager"}, {"-H", "--html"}} {
			val, hasVal, long := longOpt(t, o.long)
			switch {
			case long && hasVal:
				u.cmdLines = append(u.cmdLines, cmdLine(name+" "+o.long, Elem{Kind: Lit, Text: val}))
			case (t == o.short || long) && i+1 < len(args):
				i++
				u.cmdLines = append(u.cmdLines, cmdLine(name+" "+o.long, args[i]))
			case strings.HasPrefix(t, o.short) && len(t) > 2 && !strings.HasPrefix(t, "--"):
				u.cmdLines = append(u.cmdLines, cmdLine(name+" "+o.long, Elem{Kind: Lit, Text: t[2:]}))
			}
		}
	}
	return u
}

// shellEnvVars are the environment variables whose value is run as a command line (analyzed)
var shellEnvVars = set("GIT_SSH_COMMAND", "GIT_SSH", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER",
	"GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "SUDO_ASKPASS", "EDITOR",
	"VISUAL", "PAGER", "MANPAGER", "SYSTEMD_PAGER", "LESSOPEN", "LESSCLOSE", "BROWSER", "FCEDIT",
	"PROMPT_COMMAND")

// foreignEnvVars are the environment variables that make programs load or run code the
// analysis can't see: preloaded libraries, startup files, interpreter options, git config
var foreignEnvVars = set("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH", "BASH_ENV", "ENV", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "PYTHONSTARTUP",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
	"GIT_EXEC_PATH", "GIT_TEMPLATE_DIR")

func isForeignEnvVar(name string) bool {
	return foreignEnvVars[name] || strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_")
}
