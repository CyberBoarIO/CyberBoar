package shell

import (
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/fold"
)

// Project and environment runners: package managers, toolchain managers, dev
// environments and secret injectors that run a command. Their option tables
// are partial: an option not in the table makes the command
// possibly-anything, which is the strict fallback (a deny rule that could match asks)

// toolSub is how one subcommand runs a command
type toolSub struct {
	opts longOpts
	// skip is the number of operands before the command (direnv exec DIR)
	skip int
	// dashOnly: the command follows "--"; the operands before it are not
	// commands (mise exec TOOL@VERSION -- …, chamber exec SERVICE -- …)
	dashOnly bool
	// lineOpts take a shell command line as their value (npx -c, nix-shell --run)
	lineOpts []string
	// restOpts take the rest of the words as the command (nix develop -c)
	restOpts []string
	// shellOpts make the command words a shell command line (pnpm exec -c)
	shellOpts []string
	// lineOperand: the operand after skip is a shell command line (sops exec-env FILE 'cmd')
	lineOperand bool
	// noArgv: operands are not a command (nix-shell's are files)
	noArgv bool
	// stdinShell: without a command it starts a shell that reads commands
	// from stdin, like a bare bash (nix-shell, poetry shell, machinectl shell)
	stdinShell bool
	// alwaysShell: the command words are a shell command line unless an
	// execOpt says otherwise (watchexec, wsl)
	alwaysShell bool
	execOpts    []string
	// entryOpts name the program to run instead of the operand's own
	// (flatpak run --command=X APP ARGS runs X ARGS); without one, the
	// operand runs only its own code and no command is seen
	entryOpts []string
	dirOpts   []string // options naming the directory the command runs in
}

// tool is a program's global options and its subcommands that run commands,
// keyed by their words ("run", "tool run"); "" is the program itself (npx)
type tool struct {
	global  longOpts
	dirOpts []string // global options naming the directory the command runs in (uv --directory)
	subs    map[string]toolSub
}

var (
	uvGlobal = longOpts{
		short: "qvhVn", shortValue: "",
		long: set("quiet", "verbose", "offline", "no-offline", "no-cache", "native-tls", "no-progress", "preview", "no-preview",
			"no-config", "managed-python", "no-managed-python", "no-python-downloads", "help", "version", "system-certs"),
		longValue: set("directory", "project", "cache-dir", "config-file", "color", "python-preference", "allow-insecure-host"),
	}
	uvRun = longOpts{
		short: "qvmsh", shortValue: "wp",
		long: set("no-sync", "frozen", "locked", "isolated", "all-extras", "no-extra", "all-packages", "all-groups", "no-dev",
			"dev", "no-default-groups", "no-project", "module", "script", "gui-script", "active", "no-active", "exact",
			"no-editable", "no-env-file", "only-dev", "quiet", "verbose", "offline", "no-cache", "native-tls", "no-progress",
			"preview", "no-config", "reinstall", "refresh", "upgrade", "compile-bytecode", "no-build", "no-binary",
			"no-build-isolation", "no-sources", "help", "managed-python", "no-managed-python"),
		longValue: set("with", "with-editable", "with-requirements", "env-file", "python", "package", "extra", "group",
			"only-group", "no-group", "index", "default-index", "index-url", "extra-index-url", "find-links", "directory",
			"project", "cache-dir", "config-file", "color", "python-preference", "index-strategy", "keyring-provider",
			"resolution", "prerelease", "exclude-newer", "link-mode", "upgrade-package", "reinstall-package",
			"refresh-package", "no-binary-package", "no-build-package", "config-setting", "python-platform", "max-recursion-depth"),
	}
	uvToolRun = longOpts{
		short: "qvh", shortValue: "wp",
		long: set("isolated", "quiet", "verbose", "offline", "no-cache", "native-tls", "no-progress", "preview", "no-config",
			"reinstall", "refresh", "upgrade", "compile-bytecode", "no-build", "no-binary", "no-build-isolation",
			"no-sources", "help", "managed-python", "no-managed-python", "lfs"),
		longValue: set("from", "with", "with-editable", "with-requirements", "python", "index", "default-index",
			"index-url", "extra-index-url", "find-links", "cache-dir", "config-file", "color", "python-preference",
			"index-strategy", "keyring-provider", "resolution", "prerelease", "exclude-newer", "link-mode",
			"constraints", "overrides", "build-constraints", "env-file"),
	}
	poetryGlobal = longOpts{
		short: "qvnhV", shortValue: "CP",
		long:      set("quiet", "verbose", "no-interaction", "no-ansi", "ansi", "no-plugins", "no-cache", "help", "version"),
		longValue: set("directory", "project"),
	}
	npxOpts = longOpts{
		short: "yq", shortValue: "pcw",
		long:      set("yes", "no", "quiet", "silent", "include-workspace-root", "workspaces", "ignore-scripts", "prefer-online", "prefer-offline", "offline"),
		longValue: set("package", "call", "workspace", "prefix", "registry", "userconfig", "cache", "loglevel", "node-options", "shell"),
	}
	npmGlobal = longOpts{
		short: "gdsq", shortValue: "Cw",
		long:      set("global", "silent", "quiet", "loglevel-silent", "yes", "no", "workspaces", "include-workspace-root", "offline", "prefer-offline", "prefer-online"),
		longValue: set("prefix", "workspace", "registry", "userconfig", "globalconfig", "cache", "loglevel", "node-options", "shell"),
	}
	pnpmGlobal = longOpts{
		short: "rwsh", shortValue: "FC",
		long:      set("recursive", "workspace-root", "silent", "help", "aggregate-output", "stream", "parallel", "no-bail", "bail", "resume-from-last", "include-workspace-root", "fail-if-no-match"),
		longValue: set("filter", "filter-prod", "dir", "reporter", "loglevel", "test-pattern", "changed-files-ignore-pattern", "workspace-concurrency", "resume-from"),
	}
	pnpmExec = longOpts{
		short: "rc", shortValue: "",
		long:      set("recursive", "parallel", "no-reporter-hide-prefix", "reverse", "shell-mode", "report-summary", "resume-from", "silent"),
		longValue: set("workspace-concurrency", "resume-from"),
	}
	envOpts = longOpts{ // conda, mamba, micromamba run
		short: "", shortValue: "np",
		long:      set("no-capture-output", "live-stream", "debug-wrapper-scripts", "attach", "detach", "clean-env"),
		longValue: set("name", "prefix", "cwd", "label", "env", "root-prefix"),
	}
	flagsOnly = longOpts{}
)

var tools = map[string]tool{
	// Ruby runners
	"gem": {
		subs: map[string]toolSub{
			"exec": {
				opts: longOpts{
					short:     "gv",
					long:      set("conservative", "verbose"),
					longValue: set("version", "gem"),
				},
			},
		},
	},

	"bundle": {
		global: longOpts{long: set("no-color", "verbose", "retry")},
		subs: map[string]toolSub{
			"exec": {
				opts: longOpts{
					long:      set("keep-file-descriptors"),
					longValue: set("gemfile"),
				},
			},
		},
	},

	// Python runners
	"uv": {global: uvGlobal, dirOpts: []string{"directory"}, subs: map[string]toolSub{
		"run":      {opts: uvRun, dirOpts: []string{"directory"}},
		"tool run": {opts: uvToolRun},
	}},

	"uvx": {subs: map[string]toolSub{"": {opts: uvToolRun}}},

	"poetry": {global: poetryGlobal, subs: map[string]toolSub{"run": {opts: flagsOnly}, "shell": subShell}},

	"pipenv": {
		global: longOpts{
			long:      set("verbose", "quiet", "clear", "site-packages", "no-site-packages"),
			longValue: set("python"),
		},
		subs: map[string]toolSub{"run": {opts: flagsOnly}, "shell": subShell},
	},

	"pdm": {
		global: longOpts{
			short: "vqIh",
			long:  set("verbose", "quiet", "ignore-python", "pep582", "help"),
		},
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					short:      "gvql",
					shortValue: "p",
					long:       set("global", "verbose", "quiet", "list", "json", "site-packages", "recreate", "skip"),
					longValue:  set("project", "venv"),
				},
			},
		},
	},

	"hatch": {
		global: longOpts{
			short:      "vqh",
			shortValue: "e",
			long:       set("verbose", "quiet", "interactive", "no-interactive", "no-color"),
			longValue:  set("env", "project", "data-dir", "cache-dir", "config"),
		},
		subs: map[string]toolSub{"run": {opts: flagsOnly}, "shell": subShell},
	},

	"conda": {subs: map[string]toolSub{"run": {opts: envOpts}}},

	"mamba": {subs: map[string]toolSub{"run": {opts: envOpts}}},

	"micromamba": {subs: map[string]toolSub{"run": {opts: envOpts}}},

	// JavaScript runners
	"npx": {subs: map[string]toolSub{"": {opts: npxOpts, lineOpts: []string{"c", "call"}}}},

	"npm": {global: npmGlobal, subs: map[string]toolSub{
		"exec": {opts: npxOpts, lineOpts: []string{"c", "call"}},
		"x":    {opts: npxOpts, lineOpts: []string{"c", "call"}},
	}},

	"pnpm": {
		global:  pnpmGlobal,
		dirOpts: []string{"C", "dir"},
		subs: map[string]toolSub{
			"exec": {opts: pnpmExec, shellOpts: []string{"c", "shell-mode"}},
			"dlx": {
				opts: longOpts{
					short:      "c",
					shortValue: "",
					long:       set("shell-mode", "silent"),
					longValue:  set("package", "allow-build"),
				},
				shellOpts: []string{"c", "shell-mode"},
			},
		},
	},

	"yarn": {
		global: longOpts{long: set("silent", "verbose", "offline", "prefer-offline")},
		subs: map[string]toolSub{
			"exec": {opts: flagsOnly},
			"dlx": {
				opts: longOpts{
					short:      "q",
					shortValue: "p",
					long:       set("quiet"),
					longValue:  set("package"),
				},
			},
		},
	},

	"bunx": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					long:       set("bun", "verbose", "silent", "no-install"),
					shortValue: "p",
					longValue:  set("package"),
				},
			},
		},
	},

	"bun": {
		subs: map[string]toolSub{
			"x": {
				opts: longOpts{
					long:       set("bun", "verbose", "silent", "no-install"),
					shortValue: "p",
					longValue:  set("package"),
				},
			},
		},
	},

	// Development environments
	"direnv": {subs: map[string]toolSub{"exec": {opts: flagsOnly, skip: 1}}},

	"mise": {
		global: longOpts{
			short:      "vqy",
			shortValue: "C",
			long:       set("verbose", "quiet", "yes", "raw", "silent"),
			longValue:  set("cd", "env", "jobs"),
		},
		dirOpts: []string{"C", "cd"},
		subs:    map[string]toolSub{"exec": miseExec, "x": miseExec},
	},

	"asdf": {subs: map[string]toolSub{"exec": {opts: flagsOnly}}},

	"devbox": {
		subs: map[string]toolSub{
			"shell": subShell,

			"run": {
				opts: longOpts{
					short:      "qh",
					shortValue: "ce",
					long:       set("quiet", "help", "pure", "list", "omit-nix-env", "recompute"),
					longValue:  set("config", "env", "env-file", "environment"),
				},
			},
		},
	},

	"nix-shell": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "p",
					shortValue: "AIj",
					long:       set("pure", "impure", "packages", "keep-going", "show-trace"),
					longValue:  set("run", "command", "attr", "arg", "argstr", "keep", "include", "expr", "option", "max-jobs", "cores"),
				},
				lineOpts:   []string{"run", "command"},
				noArgv:     true,
				stdinShell: true,
			},
		},
	},

	"nix": {
		global: longOpts{
			long:      set("impure", "offline", "refresh", "show-trace", "verbose", "quiet"),
			longValue: set("extra-experimental-features", "experimental-features", "option"),
		},
		subs: map[string]toolSub{
			"develop": {opts: nixOpts, restOpts: []string{"c", "command"}, noArgv: true, stdinShell: true},
			"shell":   {opts: nixOpts, restOpts: []string{"c", "command"}, noArgv: true, stdinShell: true},
		},
	},

	// Credential and environment injectors
	"op": {
		global: longOpts{
			long:      set("debug", "no-color", "iso-timestamps"),
			longValue: set("account", "config", "session", "cache", "format", "encoding"),
		},
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					long:      set("no-masking", "help"),
					longValue: set("env-file", "environment"),
				},
			},
		},
	},

	"doppler": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					short:      "p",
					shortValue: "c",
					long:       set("preserve-env", "fallback-only", "fallback-readonly", "no-fallback", "forward-signals", "silent", "debug", "no-check-version", "watch", "mount-template", "no-exit-on-write"),
					longValue:  set("project", "config", "command", "token", "fallback", "fallback-passphrase", "mount", "mount-format", "mount-max-reads", "name-transformer", "only-secrets", "api-host", "configuration", "scope", "passphrase"),
				},
				lineOpts: []string{"command"},
			},
		},
	},

	"aws-vault": {
		global: longOpts{
			long:      set("debug"),
			longValue: set("backend", "prompt", "keychain", "pass-dir", "pass-cmd", "pass-prefix", "file-dir"),
		},
		subs: map[string]toolSub{
			"exec": {
				opts: longOpts{
					short:      "ns",
					shortValue: "dt",
					long:       set("no-session", "server", "ec2-server", "ecs-server", "lazy", "json", "stdout"),
					longValue:  set("duration", "mfa-token", "region", "prompt"),
				},
				skip: 1,
			},
		},
	},

	"infisical": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					long:      set("expand", "include-imports", "recursive", "silent", "watch", "silent"),
					longValue: set("env", "projectId", "path", "token", "domain", "command", "tags", "watch-interval"),
				},
				lineOpts: []string{"command"},
			},
		},
	},

	"dotenvx": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					short:      "q",
					shortValue: "fe",
					long:       set("overload", "strict", "quiet", "verbose", "debug", "ignore"),
					longValue:  set("env-file", "env", "env-keys-file", "env-vault-file", "convention", "log-level"),
				},
			},
		},
	},

	"dotenv": {
		global: longOpts{
			short:      "q",
			shortValue: "fe",
			long:       set("quiet", "override", "no-override", "export"),
			longValue:  set("file", "export"),
		},
		subs: map[string]toolSub{"run": {opts: longOpts{long: set("override", "no-override")}}},
	},

	// Process launchers and supervisors
	"unbuffer": {subs: map[string]toolSub{"": {opts: longOpts{short: "p"}}}},

	"caffeinate": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "dimsu",
					shortValue: "tw",
				},
			},
		},
	},

	"tini": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "hsvglwV",
					shortValue: "pe",
				},
			},
		},
	},

	"dumb-init": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "cvVh",
					shortValue: "r",
					long:       set("single-child", "verbose", "version", "help", "setsid", "no-setsid"),
					longValue:  set("rewrite"),
				},
			},
		},
	},

	"gosu": {subs: map[string]toolSub{"": {opts: flagsOnly, skip: 1}}},

	"su-exec": {subs: map[string]toolSub{"": {opts: flagsOnly, skip: 1}}},

	"chpst": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "vP012",
					shortValue: "uUbe/nlLmdofpcrt",
				},
			},
		},
	},

	"sandbox-exec": {subs: map[string]toolSub{"": {opts: longOpts{shortValue: "fpnD"}}}},

	"wsl": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "e",
					long:       set("exec", "system", "help"),
					shortValue: "du",
					longValue:  set("distribution", "user", "cd", "shell-type", "distribution-id"),
				},
				alwaysShell: true,
				execOpts:    []string{"e", "exec"},
			},
		},
	},

	"watchexec": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "rcnopNqvWh",
					shortValue: "wefisdEj",
					long: set("restart", "clear", "postpone", "notify", "no-vcs-ignore", "no-project-ignore", "no-global-ignore",
						"no-default-ignore", "no-discover-ignore", "ignore-nothing", "no-meta", "no-environment", "no-process-group",
						"only-emit-events", "print-events", "quiet", "bell", "timings", "manual", "wrap-process", "help", "version", "verbose"),
					longValue: set("watch", "exts", "filter", "ignore", "signal", "debounce", "shell", "env", "delay-run", "poll",
						"project-origin", "workdir", "stop-signal", "stop-timeout", "on-busy-update", "emit-events-to", "filter-file",
						"ignore-file", "fs-events", "watch-file", "watch-non-recursive", "log-file", "color", "socket", "filter-prog", "timeout"),
				},
				alwaysShell: true,
				execOpts:    []string{"n"},
			},
		},
	},

	"nodemon": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "qvIV",
					shortValue: "xewidC",
					long:       set("quiet", "verbose", "legacy-watch", "no-stdin", "no-update-notifier", "on-change-only", "spawn", "no-colours", "dump", "help", "version"),
					longValue:  set("exec", "ext", "watch", "ignore", "delay", "config", "signal", "cwd"),
				},
				lineOpts: []string{"x", "exec"},
				noArgv:   true,
			},
		},
	},

	// Remote and container sessions
	"mosh": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "an46",
					shortValue: "p",
					long:       set("local", "no-init", "no-ssh-pty", "ssh-pty", "help", "version"),
					longValue:  set("client", "server", "ssh", "predict", "port", "family", "bind-server", "experimental-remote-ip", "predict-overwrite"),
				},
				lineOpts: []string{"ssh", "server"},
				skip:     1,
			},
		},
	},

	"gh": {subs: map[string]toolSub{"codespace ssh": ghSSH, "cs ssh": ghSSH}},

	"vagrant": {
		subs: map[string]toolSub{
			"ssh": {
				opts: longOpts{
					short:      "ptch",
					shortValue: "c",
					long:       set("plain", "tty", "no-tty", "help"),
					longValue:  set("command"),
				},
				lineOpts:   []string{"c", "command"},
				noArgv:     true,
				stdinShell: true,
			},
		},
	},

	"lxc": {subs: map[string]toolSub{"exec": lxcExec}},

	"incus": {subs: map[string]toolSub{"exec": lxcExec}},

	"machinectl": {
		subs: map[string]toolSub{
			"shell": {
				opts: longOpts{
					shortValue: "EM",
					longValue:  set("setenv", "uid", "machine"),
				},
				skip:       1,
				stdinShell: true,
			},
		},
	},

	"toolbox": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					shortValue: "cdr",
					longValue:  set("container", "distro", "release", "preserve-fds"),
				},
			},
			"enter": {
				opts: longOpts{
					shortValue: "cdr",
					longValue:  set("container", "distro", "release"),
				},
				noArgv:     true,
				stdinShell: true,
			},
		},
	},

	"distrobox": {
		subs: map[string]toolSub{
			"enter": {
				opts: longOpts{
					short:      "TVhv",
					shortValue: "ne",
					long:       set("no-tty", "no-workdir", "clean-path", "dry-run", "verbose", "help", "version", "root"),
					longValue:  set("name", "additional-flags"),
				},
				dashOnly: true,
			},
		},
	},

	"gcloud": {
		subs: map[string]toolSub{
			"compute ssh":             gcloudSSH,
			"compute tpus tpu-vm ssh": gcloudSSH,
			"cloud-shell ssh":         gcloudSSH,
			"alpha compute ssh":       gcloudSSH,
			"beta compute ssh":        gcloudSSH,
			"workstations ssh":        gcloudSSH,
		},
	},

	"fly": {subs: map[string]toolSub{"ssh console": flySSH}},

	"flyctl": {subs: map[string]toolSub{"ssh console": flySSH}},

	"heroku": {subs: map[string]toolSub{"run": herokuRun, "run:detached": herokuRun}},

	"railway": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					shortValue: "se",
					longValue:  set("service", "environment"),
					long:       set("no-local", "help"),
				},
			},
		},
	},

	"ssh-agent": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "cDdk",
					shortValue: "aEOPt",
				},
			},
		},
	},

	"dbus-run-session": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					long:      set("help", "version"),
					longValue: set("config-file", "dbus-daemon"),
				},
			},
		},
	},

	"keyctl": {subs: map[string]toolSub{"session": {opts: flagsOnly, skip: 1}}},

	"rr": {
		subs: map[string]toolSub{
			"record": {
				opts: longOpts{
					short:      "nhciuMw",
					shortValue: "bpsteo",
					long:       set("no-syscall-buffer", "chaos", "ignore-nested", "num-cpu-ticks", "wait", "disable-cpuid-features", "asan"),
					longValue:  set("output-trace-dir", "env", "bind-to-cpu", "syscall-buffer-size", "trace-id", "tid"),
				},
			},
		},
	},

	"chronic": {subs: map[string]toolSub{"": {opts: longOpts{short: "ev"}}}},

	"ifne": {subs: map[string]toolSub{"": {opts: longOpts{short: "n"}}}},

	"lckdo": {subs: map[string]toolSub{"": {opts: longOpts{short: "qw"}, skip: 1}}},

	"with-lock-ex": {subs: map[string]toolSub{"": {opts: longOpts{short: "qwf"}, skip: 1}}},

	"nq": {subs: map[string]toolSub{"": {opts: longOpts{short: "ctq"}}}},

	"launchctl": {
		subs: map[string]toolSub{
			"submit": {
				opts: longOpts{
					short:      "p",
					shortValue: "leo",
				},
				dashOnly: true,
			},
		},
	},

	"daemonize": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "v",
					shortValue: "ceEoplu",
				},
			},
		},
	},

	"nsjail": {subs: map[string]toolSub{"": {opts: flagsOnly, dashOnly: true}}},

	"proot": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "0vVhiSR",
					shortValue: "rbmwqk",
					long:       set("root-id", "verbose", "version", "help", "link2symlink", "kill-on-exit"),
					longValue:  set("rootfs", "bind", "mount", "pwd", "cwd", "qemu", "kernel-release"),
				},
			},
		},
	},

	"fakeroot": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "uhv",
					shortValue: "lsi",
					long:       set("unknown-is-real", "help", "version"),
					longValue:  set("lib", "faked"),
				},
			},
		},
	},

	"fakechroot": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "hv",
					shortValue: "elcds",
					long:       set("use-system-libs", "help", "version"),
					longValue:  set("environment", "lib", "config-dir", "bindir"),
				},
			},
		},
	},

	"setarch": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short: "vRFLXBIST3h",
					long:  set("addr-no-randomize", "fdpic-funcptrs", "mmap-page-zero", "addr-compat-layout", "32bit", "read-implies-exec", "short-inode", "whole-seconds", "sticky-timeouts", "3gb", "4gb", "uname-2.6", "verbose", "list", "help", "version"),
				},
				skip: 1,
			},
		},
	},

	"linux32": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short: "vRFLXBIST3h",
					long:  set("addr-no-randomize", "3gb", "4gb", "uname-2.6", "verbose"),
				},
			},
		},
	},

	"linux64": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short: "vRFLXBIST3h",
					long:  set("addr-no-randomize", "3gb", "4gb", "uname-2.6", "verbose"),
				},
			},
		},
	},

	"box64": {subs: map[string]toolSub{"": {opts: flagsOnly}}},

	"box86": {subs: map[string]toolSub{"": {opts: flagsOnly}}},

	"run0": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "h",
					shortValue: "ugD",
					long:       set("no-ask-password", "background", "help", "version", "empower", "pty", "pipe", "via-shell"),
					longValue:  set("user", "group", "nice", "chdir", "setenv", "property", "description", "slice", "slice-inherit", "unit", "machine", "shell-prompt-prefix", "lightweight", "area"),
				},
			},
		},
	},

	"please": {
		subs: map[string]toolSub{
			"": {
				opts: longOpts{
					short:      "elnpwh",
					shortValue: "udgrtc",
					long:       set("help", "version"),
				},
			},
		},
	},

	"flatpak": {
		subs: map[string]toolSub{
			"run": {
				opts: longOpts{
					short: "hvd",
					long: set("user", "system", "devel", "no-session-bus", "session-bus", "no-a11y-bus", "a11y-bus", "sandbox", "log-session-bus",
						"log-system-bus", "log-a11y-bus", "die-with-parent", "no-documents-portal", "file-forwarding", "clear-env", "parent-expose-pids",
						"parent-share-pids", "verbose", "help"),
					longValue: set("command", "branch", "arch", "runtime", "runtime-version", "commit", "runtime-commit", "cwd", "app-path",
						"usr-path", "filesystem", "nofilesystem", "share", "unshare", "socket", "nosocket", "device", "nodevice", "allow", "disallow",
						"env", "unset-env", "env-fd", "own-name", "talk-name", "no-talk-name", "system-own-name", "system-talk-name",
						"system-no-talk-name", "add-policy", "remove-policy", "persist", "instance-id-fd", "installation", "parent-pid"),
				},
				entryOpts: []string{"command"},
			},
		},
	},

	"snap": {subs: map[string]toolSub{"run": {opts: longOpts{long: set("strace", "gdbserver", "experimental-gdbserver", "trace-exec", "debug-log")}}}},

	"just": {subs: map[string]toolSub{"": {opts: flagsOnly, restOpts: []string{"command"}, noArgv: true}}},

	"newgrp": {subs: map[string]toolSub{"": {opts: flagsOnly, noArgv: true, stdinShell: true}}},

	"chamber": {
		subs: map[string]toolSub{
			"exec": {
				opts: longOpts{
					long:      set("strict", "pristine"),
					longValue: set("strict-value", "backend"),
				},
				dashOnly: true,
			},
		},
	},

	"sops": {
		subs: map[string]toolSub{
			"exec-env": {
				opts: longOpts{
					long:      set("background", "pristine", "same-process"),
					longValue: set("user"),
				},
				skip:        1,
				lineOperand: true,
			},
			"exec-file": {
				opts: longOpts{
					long:      set("background", "no-fifo"),
					longValue: set("user", "filename", "output-type", "input-type"),
				},
				skip:        1,
				lineOperand: true,
			},
		},
	},
}

var (
	ghSSH     = toolSub{opts: longOpts{short: "d", shortValue: "cR", long: set("config", "debug", "help"), longValue: set("codespace", "repo", "repo-owner", "profile", "server-port", "debug-file")}, dashOnly: true}
	lxcExec   = toolSub{opts: longOpts{short: "tTh", long: set("force-interactive", "force-noninteractive", "help"), longValue: set("env", "cwd", "user", "group", "mode", "project")}, skip: 1}
	gcloudSSH = toolSub{opts: flagsOnly, lineOpts: []string{"command"}, noArgv: true, stdinShell: true}
	flySSH    = toolSub{opts: flagsOnly, lineOpts: []string{"C", "command"}, noArgv: true, stdinShell: true}
	herokuRun = toolSub{opts: longOpts{short: "x", shortValue: "arse", long: set("exit-code", "no-tty", "no-notify", "help"), longValue: set("app", "remote", "size", "env", "type")}}
	subShell  = toolSub{opts: longOpts{long: set("pure", "quiet", "verbose", "fancy")}, noArgv: true, stdinShell: true}
	miseExec  = toolSub{opts: longOpts{short: "j", shortValue: "c", long: set("fresh-env", "no-prepare", "raw"), longValue: set("command", "jobs")},
		lineOpts: []string{"c", "command"}, dashOnly: true}
	nixOpts = longOpts{long: set("impure", "offline", "refresh", "show-trace", "verbose", "quiet", "ignore-environment", "keep-going", "no-write-lock-file", "recreate-lock-file"),
		shortValue: "ikf", longValue: set("keep", "unset", "file", "expr", "phase", "profile", "override-input", "inputs-from", "reference-lock-file", "output-lock-file", "arg", "argstr", "set-env-var")}
)

func registerTools() {
	wrappers["arch"] = wrapArch
	wrappers["sudo-rs"] = wrapSudo
	wrappers["sem"] = unknownRunner               // GNU parallel: runs through a shell
	wrappers["start-stop-daemon"] = unknownRunner // --exec/--startas and -- ARGS
	for name := range tools {
		if prev := wrappers[name]; prev != nil {
			wrappers[name] = both(prev, wrapTool) // bun: an interpreter too
			continue
		}
		wrappers[name] = wrapTool
	}
}

// both is what either wrapper finds
func both(f, g wrapperFunc) wrapperFunc {
	return func(a *analyzer, name string, args []Elem) unwrapped {
		u, v := f(a, name, args), g(a, name, args)
		var argvs [][]Elem
		for _, w := range []unwrapped{u, v} {
			if w.next != nil {
				argvs = append(argvs, w.next)
			}
			argvs = append(argvs, w.extra...)
		}
		r := runsEach(argvs, u.unknown || v.unknown)
		r.code = append(u.code, v.code...)
		r.cmdLines = append(u.cmdLines, v.cmdLines...)
		r.assigns = append(u.assigns, v.assigns...)
		r.files = append(u.files, v.files...)
		r.stdin = u.stdin
		if r.stdin == nil {
			r.stdin = v.stdin
		}
		return r
	}
}

// wrapTool finds a tool's global options, a subcommand that runs a command, and the command
func wrapTool(a *analyzer, name string, args []Elem) unwrapped {
	t := tools[fold.String(name)]
	var starts []int
	amb := false
	if _, self := t.subs[""]; self {
		starts = []int{0}
	} else {
		starts, amb = operandStarts(args, 0, t.global)
	}
	var out []unwrapped
	for _, i := range starts {
		if sub, ok := t.subs[""]; ok {
			out = append(out, sub.run(name, args[i:]))
			continue
		}
		for words, sub := range t.subs {
			n := subcommand(args[i:], words)
			if n > 0 {
				o := sub.run(name, args[i+n:])
				if o.dir == nil {
					o.dir = lastValue(args[:i], t.dirOpts, t.global)
				}
				out = append(out, o)
			}
		}
	}
	u := unwrapped{unknown: amb}
	var argvs [][]Elem
	for _, o := range out {
		switch {
		case o.dir == nil:
		case u.dir == nil:
			u.dir = o.dir
		case *u.dir != *o.dir:
			u.dir = &Elem{Kind: Many, Text: "*"} // readings disagree
		}
		u.unknown = u.unknown || o.unknown
		u.cmdLines = append(u.cmdLines, o.cmdLines...)
		if o.stdin != nil {
			u.stdin = o.stdin
		}
		if o.next != nil {
			argvs = append(argvs, o.next)
		}
		argvs = append(argvs, o.extra...)
	}
	r := runsEach(argvs, u.unknown)
	r.cmdLines = u.cmdLines
	r.stdin = u.stdin
	r.dir = u.dir
	return r
}

// lastValue returns the value of the last of the options names given in args, or nil
func lastValue(args []Elem, names []string, o longOpts) *Elem {
	var last *Elem
	for i := 0; i < len(args); i++ {
		if args[i].Kind != Lit {
			continue
		}
		if v, next, ok := optValue(args, i, names, o); ok {
			last = &v
			i = next - 1
		}
	}
	return last
}

// subcommand returns how many words of args spell words ("tool run"), or 0
func subcommand(args []Elem, words string) int {
	ws := strings.Fields(words)
	if len(args) < len(ws) {
		return 0
	}
	for k, w := range ws {
		if args[k].Kind != Lit || fold.String(args[k].Text) != w {
			return 0
		}
	}
	return len(ws)
}

// optValue matches args[i] against the options in names and returns the
// option's value (the next word if not joined) and the index after it
func optValue(args []Elem, i int, names []string, o longOpts) (v Elem, next int, ok bool) {
	t := args[i].Text
	for _, n := range names {
		switch {
		case len(n) == 1 && len(t) >= 2 && t[0] == '-' && t[1] != '-':
			// The option ends a short cluster when it takes a value (-yc 'cmd')
			j := strings.IndexByte(t[1:], n[0])
			if j < 0 {
				continue
			}
			j++
			if strings.IndexByte(o.shortValue, n[0]) < 0 {
				return Elem{}, i + 1, true // a flag (pnpm -c)
			}
			if j+1 < len(t) {
				return Elem{Kind: Lit, Text: t[j+1:]}, i + 1, true
			}
			if i+1 < len(args) {
				return args[i+1], i + 2, true
			}
			return Elem{Kind: Lit}, i + 1, true
		case len(n) > 1 && t == "--"+n:
			if !o.longValue[n] {
				return Elem{}, i + 1, true
			}
			if i+1 < len(args) {
				return args[i+1], i + 2, true
			}
			return Elem{Kind: Lit}, i + 1, true
		case len(n) > 1 && strings.HasPrefix(t, "--"+n+"="):
			return Elem{Kind: Lit, Text: t[len(n)+3:]}, i + 1, true
		}
	}
	return Elem{}, i, false
}

// run reads the subcommand's words
func (s toolSub) run(name string, args []Elem) unwrapped {
	var u unwrapped
	shell, exec, ran := false, false, false
	var entry *Elem
	// Options before the operands: command lines, the rest as a command, shell mode
	last := len(args) // tools without an argv (nix) take options anywhere
	if !s.noArgv {
		if end, _ := operandStarts(args, 0, s.opts); len(end) > 0 {
			last = end[len(end)-1]
		}
	}
	for i := 0; i < last && i < len(args); i++ {
		if args[i].Kind != Lit {
			continue
		}
		if args[i].Text == "--" {
			break
		}
		if v, _, ok := optValue(args, i, s.lineOpts, withValues(s.opts, s.lineOpts)); ok {
			u.cmdLines = append(u.cmdLines, cmdLine(name+" "+args[i].Text, v))
			ran = true
		}
		if _, next, ok := optValue(args, i, s.restOpts, s.opts); ok {
			ran = true
			if next < len(args) {
				r := runsEach([][]Elem{args[next:]}, false)
				r.cmdLines = u.cmdLines
				return r
			}
		}
		if _, _, ok := optValue(args, i, s.shellOpts, s.opts); ok {
			shell = true
		}
		if _, _, ok := optValue(args, i, s.execOpts, s.opts); ok {
			exec = true
		}
		if v, _, ok := optValue(args, i, s.entryOpts, withValues(s.opts, s.entryOpts)); ok {
			entry = &v
		}
	}
	shell = shell || s.alwaysShell && !exec
	if s.noArgv {
		if s.stdinShell && !ran {
			u.stdin = &stdinRun{what: name + " (a shell reading stdin)"}
		}
		return u
	}
	starts, amb := operandStarts(args, 0, s.opts)
	u.unknown = amb
	if s.dashOnly {
		dash := slices.IndexFunc(args, func(e Elem) bool { return e.Kind == Lit && e.Text == "--" })
		if dash < 0 {
			// No "--": the operands are what the tool takes (tools, services)
			return u
		}
		starts = []int{dash + 1}
	}
	var argvs [][]Elem
	if s.skip > 0 {
		// Options may follow the skipped operands (lxc exec C1 --env A=1 --
		// CMD, aws-vault exec PROFILE --duration 1h -- CMD)
		var after []int
		for _, i := range starts {
			next, amb2 := operandStarts(args, min(i+s.skip, len(args)), s.opts)
			after = append(after, next...)
			u.unknown = u.unknown || amb2
		}
		starts = after
	}
	for _, i := range starts {
		if i >= len(args) {
			continue
		}
		switch {
		case len(s.entryOpts) > 0:
			if entry != nil {
				argvs = append(argvs, append([]Elem{*entry}, args[min(i+1, len(args)):]...))
			}
		case s.lineOperand:
			u.cmdLines = append(u.cmdLines, cmdLine(name+" (command line)", args[i]))
		case shell:
			words := make([]string, 0, len(args)-i)
			dynamic := false
			for _, e := range args[i:] {
				dynamic = dynamic || e.Kind != Lit
				words = append(words, e.Text)
			}
			u.cmdLines = append(u.cmdLines, codeRun{what: name + " (shell mode)", text: strings.Join(words, " "), dynamic: dynamic})
		default:
			argvs = append(argvs, args[i:])
		}
	}
	if s.stdinShell && !ran && len(argvs) == 0 && len(u.cmdLines) == 0 {
		u.stdin = &stdinRun{what: name + " (a shell reading stdin)"}
	}
	r := runsEach(argvs, u.unknown)
	r.cmdLines, r.stdin = u.cmdLines, u.stdin
	r.dir = lastValue(args[:min(last, len(args))], s.dirOpts, s.opts)
	return r
}

// wrapArch reads macOS arch: architecture flags (-x86_64, -arm64e, …), -e
// NAME=VALUE and -d NAME, then the command
func wrapArch(_ *analyzer, _ string, args []Elem) unwrapped {
	for i := 0; i < len(args); i++ {
		e := args[i]
		switch {
		case e.Kind != Lit:
			return unwrapped{next: args[i:], unknown: true}
		case e.Text == "--":
			return unwrapped{next: args[i+1:]}
		case e.Text == "-e" || e.Text == "-d":
			i++
		case strings.HasPrefix(e.Text, "-"):
		default:
			return unwrapped{next: args[i:]}
		}
	}
	return unwrapped{}
}

// withValues is o with names taking a value
func withValues(o longOpts, names []string) longOpts {
	lv := map[string]bool{}
	for k := range o.longValue {
		lv[k] = true
	}
	sv := o.shortValue
	for _, n := range names {
		if len(n) == 1 {
			sv += n
		} else {
			lv[n] = true
		}
	}
	o.shortValue, o.longValue = sv, lv
	return o
}
