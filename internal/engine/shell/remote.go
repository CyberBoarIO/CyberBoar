package shell

import (
	"maps"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/fold"
)

// Commands that ssh, docker, podman and kubectl run, mostly somewhere else:
// what ssh runs on the remote host, the proxy and local commands it runs on
// this machine, and what docker, podman and kubectl run in a container. They
// are checked like local commands. A remote shell command line starts in the
// home directory, so the local ~ stands in for the remote one; a container
// command is an argv whose words are checked like any argument
// An image's own entrypoint, the remote user's shell and ~/.ssh/config are not seen

func registerRemote() {
	maps.Copy(wrappers, map[string]wrapperFunc{
		"docker": wrapDocker, "podman": wrapDocker,
		"docker-compose": wrapCompose, "podman-compose": wrapCompose,
		"kubectl": wrapKubectl, "oc": wrapKubectl,
	})
}

// login reports whether name is ssh or slogin, compared case-insensitively
// the way lookupWrapper matches names. scp and sftp are not logins.
func login(name string) bool {
	n := fold.String(name)
	return n == "ssh" || n == "slogin"
}

// homeDir is where a remote login starts.
func (a *analyzer) homeDir() *dir {
	if a.homeUnsure || a.home == "" {
		return &dir{} // unknownDir; a copy, so no caller can change the shared value
	}
	return &dir{path: a.home, known: true}
}

// sshPath is one reading of an ssh command line.
type sshPath struct {
	command   int  // index of the first word of the remote command; -1: none
	noCommand bool // -N, -W, -G, -V, -O: no remote command or login shell
	subsystem bool // -s: the command names a subsystem
	noStdin   bool // -n
	dest      bool // a destination was given (GIT_SSH_COMMAND='ssh -i key' has none: git adds it)
}

// maxSSHBranches bounds the readings tried when run-time words sit where an
// option or the destination could be.
const maxSSHBranches = 16

// sshPaths reads an ssh command line the way OpenSSH does: options, the
// destination, more options, then the remote command. A run-time word before
// the command could be an option or the destination, so both readings are
// returned (ambiguous is then set).
func sshPaths(args []Elem) (paths []sshPath, ambiguous bool) {
	const withValue = "BbcDEeFIiJLlmOoPpQRSWw"
	var walk func(i int, seenDest bool, p sshPath)
	walk = func(i int, seenDest bool, p sshPath) {
		if len(paths) >= maxSSHBranches {
			ambiguous = true
			return
		}
		for ; i < len(args); i++ {
			e := args[i]
			if e.Kind != Lit {
				ambiguous = true
				if seenDest {
					walk(i+1, true, p) // an option
					p.command = i      // or the command
					paths = append(paths, p)
					return
				}
				walk(i+1, false, p)           // an option
				seenDest, p.dest = true, true // or the destination
				continue
			}
			t := e.Text
			switch {
			case t == "--":
				i++
				if !seenDest {
					p.dest = i < len(args)
					i++ // the destination
				}
				if i < len(args) {
					p.command = i
				}
				paths = append(paths, p)
				return
			case len(t) > 1 && t[0] == '-':
				for j := 1; j < len(t); j++ {
					c := t[j]
					switch c {
					case 'N', 'G', 'V':
						p.noCommand = true
					case 's':
						p.subsystem = true
					case 'n':
						p.noStdin = true
					case 'W', 'O':
						p.noCommand = true
					}
					if strings.IndexByte(withValue, c) >= 0 {
						if j+1 == len(t) {
							i++ // the value is the next word
						}
						break
					}
				}
			case !seenDest:
				seenDest, p.dest = true, true
			default:
				p.command = i
				paths = append(paths, p)
				return
			}
		}
		paths = append(paths, p)
	}
	walk(0, false, sshPath{command: -1})
	return paths, ambiguous
}

// sshRemote adds what ssh runs on the remote host: the command (its words
// joined with spaces, as ssh sends them to the remote shell) or, with no
// command, a login shell reading stdin.
func sshRemote(a *analyzer, name string, args []Elem, u *unwrapped) {
	paths, ambiguous := sshPaths(args)
	if ambiguous {
		u.unknown = true
	}
	home := a.homeDir()
	seen := map[int]bool{}
	for _, p := range paths {
		switch {
		case p.subsystem:
		case p.command >= 0:
			if seen[p.command] {
				continue
			}
			seen[p.command] = true
			words := make([]string, 0, len(args)-p.command)
			dynamic := false
			for _, e := range args[p.command:] {
				dynamic = dynamic || e.Kind != Lit
				words = append(words, e.Text)
			}
			u.cmdLines = append(u.cmdLines, codeRun{what: name + " (remote command)", text: strings.Join(words, " "), dynamic: dynamic, start: home})
		case p.noCommand || p.noStdin || !p.dest:
		default:
			// A login shell reads commands from stdin, unless a
			// RemoteCommand in the options (checked separately) or the
			// ssh configuration runs something else
			if u.stdin == nil {
				u.stdin = &stdinRun{what: name + " (remote shell reading stdin)", start: home}
			}
		}
	}
}

// wrapSSH finds -o ProxyCommand/LocalCommand/KnownHostsCommand/RemoteCommand,
// scp/sftp -S, and what ssh runs on the remote host.
func wrapSSH(a *analyzer, name string, args []Elem) unwrapped {
	const withValue = "BbcDEeFIiJLlmOoPpQRSWw"
	var u unwrapped
	for i := 0; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit || !strings.HasPrefix(e.Text, "-") || e.Text == "-" {
			continue
		}
		if e.Text == "--" {
			break
		}
		t := e.Text
		for j := 1; j < len(t); j++ {
			c := t[j]
			if strings.IndexByte(withValue, c) < 0 {
				continue
			}
			var v Elem
			if j+1 < len(t) {
				v = Elem{Kind: Lit, Text: t[j+1:]}
			} else if i+1 < len(args) {
				i++
				v = args[i]
			}
			switch {
			case c == 'o':
				if v.Kind != Lit {
					u.unknown = true // could be any option, ProxyCommand included
					break
				}
				key, val := splitSSHOption(v.Text)
				switch key {
				case "proxycommand", "localcommand", "knownhostscommand":
					u.cmdLines = append(u.cmdLines, cmdLine(name+" -o "+key, Elem{Kind: Lit, Text: val}))
				case "pkcs11provider", "securitykeyprovider":
					u.code = append(u.code, codeRun{what: name + " -o " + key + " (a library)", foreign: true})
				case "remotecommand":
					if login(name) {
						r := cmdLine(name+" -o "+key, Elem{Kind: Lit, Text: val})
						r.start = a.homeDir()
						u.cmdLines = append(u.cmdLines, r)
					}
				}
			case c == 'I' && login(name): // a PKCS#11 library: native code, like openssl -engine
				u.code = append(u.code, codeRun{what: name + " -I (a library)", foreign: true})
			case c == 'S' && !login(name): // scp/sftp: the ssh program
				u.cmdLines = append(u.cmdLines, cmdLine(name+" -S", v))
			}
			break
		}
	}
	if login(name) {
		sshRemote(a, name, args, &u)
	}
	return u
}

// splitSSHOption splits "Key=value" or "Key value", lower-casing the key.
func splitSSHOption(s string) (key, val string) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, "= \t")
	if i < 0 {
		return strings.ToLower(s), ""
	}
	key, val = s[:i], strings.TrimLeft(s[i:], "= \t")
	return strings.ToLower(key), val
}

// longOpts is a program's option table: flags, and options taking a value.
type longOpts struct {
	short, shortValue string
	long, longValue   map[string]bool
}

// maxOperandStarts bounds the readings operandStarts returns.
const maxOperandStarts = 8

// operandStarts reads options from args[i:] and returns where the first
// operand may start. "--" ends the options. A run-time word could be an
// option or the operand, so both readings are returned; an option not in
// the table is taken as a flag. Either sets ambiguous.
func operandStarts(args []Elem, i int, o longOpts) (starts []int, ambiguous bool) {
	for ; i < len(args); i++ {
		e := args[i]
		if e.Kind != Lit {
			ambiguous = true
			if len(starts) >= maxOperandStarts {
				return starts, true
			}
			starts = append(starts, i) // the operand, or an option: go on
			continue
		}
		t := e.Text
		switch {
		case t == "--":
			return append(starts, i+1), ambiguous
		case strings.HasPrefix(t, "--"):
			name, _, hasVal := strings.Cut(t[2:], "=")
			switch {
			case o.longValue[name]:
				if !hasVal {
					i++
				}
			case o.long[name], hasVal:
			default:
				ambiguous = true // it may take the next word as its value
			}
		case len(t) > 1 && t[0] == '-':
			for j := 1; j < len(t); j++ {
				c := t[j]
				if strings.IndexByte(o.shortValue, c) >= 0 {
					if j+1 == len(t) {
						i++
					}
					break
				}
				if strings.IndexByte(o.short, c) < 0 {
					ambiguous = true
				}
			}
		default:
			return append(starts, i), ambiguous
		}
	}
	return append(starts, len(args)), ambiguous
}

// hasShortFlag reports whether args[:end] set a short flag c (not as a value).
func hasShortFlag(args []Elem, end int, c byte, o longOpts) bool {
	for _, e := range args[:min(end, len(args))] {
		t := e.Text
		if e.Kind != Lit || len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		for j := 1; j < len(t); j++ {
			if t[j] == c {
				return true
			}
			if strings.IndexByte(o.shortValue, t[j]) >= 0 {
				break
			}
		}
	}
	return false
}

// runsEach runs each argv (next, then extra), skipping empty and repeated ones.
func runsEach(argvs [][]Elem, unknown bool) unwrapped {
	u := unwrapped{unknown: unknown}
	seen := map[string]bool{}
	for _, argv := range argvs {
		if len(argv) == 0 {
			continue
		}
		key := ""
		for _, e := range argv {
			key += e.String() + "\x00"
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if u.next == nil {
			u.next = argv
		} else {
			u.extra = append(u.extra, argv)
		}
	}
	return u
}

var (
	dockerGlobal = longOpts{
		short: "Dv", shortValue: "Hcl",
		long:      set("debug", "tls", "tlsverify", "version", "help", "remote", "syslog"),
		longValue: set("host", "context", "config", "log-level", "tlscacert", "tlscert", "tlskey", "url", "connection", "identity", "root", "runroot", "storage-driver", "storage-opt", "cgroup-manager", "events-backend", "hooks-dir", "network-cmd-path", "runtime", "tmpdir", "volumepath", "module", "log-driver", "imagestore", "db-backend", "cni-config-dir", "conmon", "network-config-dir", "out", "ssh", "transient-store"),
	}
	dockerExec = longOpts{
		short: "ditl", shortValue: "euw",
		long:      set("detach", "interactive", "tty", "privileged", "latest", "help"),
		longValue: set("detach-keys", "env", "env-file", "user", "workdir", "preserve-fds", "preserve-fd", "cidfile"),
	}
	dockerRun = longOpts{
		short: "dithPq", shortValue: "aceElmpuvwh",
		long: set("detach", "interactive", "tty", "init", "no-healthcheck", "oom-kill-disable", "privileged", "publish-all",
			"quiet", "read-only", "rm", "sig-proxy", "disable-content-trust", "help", "replace", "env-host", "unsetenv-all",
			"read-only-tmpfs", "http-proxy", "tls-verify", "rmi", "no-hosts", "no-hostname"),
		longValue: set("add-host", "annotation", "attach", "blkio-weight", "blkio-weight-device", "cap-add", "cap-drop",
			"cgroup-parent", "cgroupns", "cidfile", "cpu-count", "cpu-percent", "cpu-period", "cpu-quota", "cpu-rt-period",
			"cpu-rt-runtime", "cpu-shares", "cpus", "cpuset-cpus", "cpuset-mems", "detach-keys", "device", "device-cgroup-rule",
			"device-read-bps", "device-read-iops", "device-write-bps", "device-write-iops", "dns", "dns-option", "dns-search",
			"domainname", "entrypoint", "env", "env-file", "expose", "gpus", "group-add", "health-cmd", "health-interval",
			"health-retries", "health-start-period", "health-start-interval", "health-timeout", "hostname", "io-maxbandwidth",
			"io-maxiops", "ip", "ip6", "ipc", "isolation", "kernel-memory", "label", "label-file", "link", "link-local-ip",
			"log-driver", "log-opt", "mac-address", "memory", "memory-reservation", "memory-swap", "memory-swappiness", "mount",
			"name", "network", "net", "network-alias", "net-alias", "oom-score-adj", "pid", "pids-limit", "platform", "publish",
			"pull", "restart", "runtime", "security-opt", "shm-size", "stop-signal", "stop-timeout", "storage-opt", "sysctl",
			"tmpfs", "ulimit", "user", "userns", "uts", "volume", "volume-driver", "volumes-from", "workdir",
			"pod", "arch", "os", "variant", "secret", "hooks-dir", "tz", "umask", "uidmap", "gidmap", "subuidname",
			"subgidname", "systemd", "image-volume", "preserve-fds", "personality", "pidfile", "requires", "seccomp-policy",
			"sdnotify", "timeout", "passwd-entry", "group-entry", "chrootdirs", "init-path", "conmon-pidfile",
			"decryption-key", "creds", "authfile", "cert-dir", "env-merge", "unsetenv", "cgroups", "cgroup-conf", "retry",
			"retry-delay", "health-on-failure", "health-log-destination", "health-max-log-count", "health-max-log-size",
			"health-startup-cmd", "health-startup-interval", "health-startup-retries", "health-startup-success",
			"health-startup-timeout", "log-level", "pod-id-file", "rdt-class", "shm-size-systemd", "hostuser"),
	}
	composeGlobal = longOpts{
		shortValue: "fp",
		long:       set("compatibility", "dry-run", "all-resources", "verbose", "help", "version", "podman-build-args", "no-ansi", "no-cleanup", "no-pod"),
		longValue:  set("file", "project-name", "project-directory", "env-file", "profile", "ansi", "progress", "parallel", "podman-args", "podman-run-args", "podman-exec-args", "in-pod", "pod-args"),
	}
	composeExec = longOpts{
		short: "dTit", shortValue: "euw",
		long:      set("detach", "no-TTY", "no-tty", "privileged", "interactive", "tty", "help", "dry-run"),
		longValue: set("env", "index", "user", "workdir"),
	}
	kubectlOpts = longOpts{
		short: "itqh", shortValue: "nscfv",
		long: set("stdin", "tty", "quiet", "help", "insecure-skip-tls-verify", "match-server-version",
			"disable-compression", "warnings-as-errors", "all-namespaces"),
		longValue: set("namespace", "context", "cluster", "user", "server", "kubeconfig", "token", "as", "as-group", "as-uid",
			"request-timeout", "cache-dir", "certificate-authority", "client-certificate", "client-key", "tls-server-name",
			"username", "password", "profile", "profile-output", "v", "vmodule", "log-dir", "log-file", "container", "filename",
			"pod-running-timeout", "log-flush-frequency", "kuberc", "config"),
	}
)

// wrapDocker finds `docker exec`, `docker container exec` and `docker compose exec` (podman alike).
func wrapDocker(_ *analyzer, name string, args []Elem) unwrapped {
	starts, amb := operandStarts(args, 0, dockerGlobal)
	var argvs [][]Elem
	var files []Elem
	for _, i := range starts {
		if i >= len(args) || args[i].Kind != Lit {
			continue
		}
		var u unwrapped
		switch strings.ToLower(args[i].Text) {
		case "exec":
			u = containerExec(name, args[i+1:], dockerExec)
		case "container":
			if i+1 < len(args) && args[i+1].Kind == Lit && strings.ToLower(args[i+1].Text) == "exec" {
				u = containerExec(name, args[i+2:], dockerExec)
			}
		case "compose":
			u = wrapCompose(nil, name, args[i+1:])
		case "run", "create":
			u = containerRun(args[i+1:])
		}
		if len(args) > i+1 && strings.ToLower(args[i].Text) == "container" && args[i+1].Kind == Lit {
			switch strings.ToLower(args[i+1].Text) {
			case "run", "create":
				u = containerRun(args[i+2:])
			}
		}
		files = append(files, u.files...)
		amb = amb || u.unknown
		argvs = append(argvs, u.next)
		argvs = append(argvs, u.extra...)
	}
	u := runsEach(argvs, amb)
	u.files = files
	return u
}

func wrapCompose(_ *analyzer, name string, args []Elem) unwrapped {
	starts, amb := operandStarts(args, 0, composeGlobal)
	var argvs [][]Elem
	for _, i := range starts {
		if i < len(args) && args[i].Kind == Lit && strings.ToLower(args[i].Text) == "exec" {
			u := containerExec(name, args[i+1:], composeExec)
			amb = amb || u.unknown
			argvs = append(argvs, u.next)
			argvs = append(argvs, u.extra...)
		}
	}
	return runsEach(argvs, amb)
}

// containerRun reads `run [OPTIONS] IMAGE [COMMAND...]` (and create): the
// command (after --entrypoint, if given; the image's own entrypoint isn't
// seen) and the host paths it mounts, which the container reads and writes
// like any directory a command is given.
func containerRun(args []Elem) unwrapped {
	var u unwrapped
	var entry []Elem
	starts, amb := operandStarts(args, 0, dockerRun)
	limit := starts[len(starts)-1] // options stop at the image
	for i := 0; i < limit; i++ {
		e := args[i]
		if e.Kind != Lit || !strings.HasPrefix(e.Text, "-") || e.Text == "-" {
			continue
		}
		if e.Text == "--" {
			break
		}
		for _, o := range []string{"v", "volume", "mount", "entrypoint"} {
			v, next, ok := optValue(args, i, []string{o}, dockerRun)
			if !ok {
				continue
			}
			switch o {
			case "entrypoint":
				entry = []Elem{v}
				if v.Kind == Lit && v.Text == "" {
					entry = nil
				}
			case "mount":
				if src, ok := mountSource(v); ok {
					u.files = append(u.files, src)
				}
			default:
				if src, ok := volumeSource(v); ok {
					u.files = append(u.files, src)
				}
			}
			i = next - 1
			break
		}
	}
	var argvs [][]Elem
	for _, i := range starts {
		if i+1 > len(args) {
			continue
		}
		cmd := append(slices.Clone(entry), args[min(i+1, len(args)):]...)
		argvs = append(argvs, cmd)
	}
	r := runsEach(argvs, amb)
	r.files = u.files
	return r
}

// volumeSource returns the host path of -v SRC:DST[:OPTS].
// A source without a slash or a leading dot or tilde is a named volume.
func volumeSource(v Elem) (Elem, bool) {
	if v.Kind != Lit {
		return v, true // only known at run time
	}
	src, _, _ := strings.Cut(v.Text, ":")
	if src == "" || !strings.ContainsAny(src[:1], "/.~") && !strings.Contains(src, "/") {
		return Elem{}, false
	}
	return Elem{Kind: Lit, Text: src}, true
}

// mountSource returns the host path of --mount type=bind,source=SRC,… (the
// keys in any order). A source that looks like a path is taken whatever the type says.
func mountSource(v Elem) (Elem, bool) {
	if v.Kind != Lit {
		return v, true
	}
	bind := false
	var src string
	for kv := range strings.SplitSeq(v.Text, ",") {
		k, val, _ := strings.Cut(kv, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "type":
			bind = strings.EqualFold(val, "bind")
		case "source", "src":
			src = val
		}
	}
	if src == "" {
		return Elem{}, false
	}
	if bind || strings.ContainsAny(src[:1], "/.~") {
		return Elem{Kind: Lit, Text: src}, true
	}
	return Elem{}, false
}

// containerExec reads `exec [OPTIONS] CONTAINER COMMAND...`
// podman's --latest/-l names no container.
func containerExec(name string, args []Elem, o longOpts) unwrapped {
	starts, amb := operandStarts(args, 0, o)
	var argvs [][]Elem
	for _, i := range starts {
		latest := fold.String(name) == "podman" && hasShortFlag(args, i, 'l', o)
		for _, e := range args[:min(i, len(args))] {
			latest = latest || e.Kind == Lit && e.Text == "--latest"
		}
		if !latest {
			i++ // the container
		}
		if i < len(args) {
			argvs = append(argvs, args[i:])
		}
	}
	return runsEach(argvs, amb)
}

// wrapKubectl finds `kubectl exec POD -- COMMAND` and the commands of `run`
// and `debug` (oc alike). Options may come anywhere; the command follows "--"
// or, for exec in the old form, the pod.
func wrapKubectl(_ *analyzer, _ string, args []Elem) unwrapped {
	starts, amb := operandStarts(args, 0, kubectlOpts)
	var argvs [][]Elem
	for _, i := range starts {
		if i >= len(args) || args[i].Kind != Lit {
			continue
		}
		sub := strings.ToLower(args[i].Text)
		if sub != "exec" && sub != "run" && sub != "debug" {
			continue
		}
		rest := args[i+1:]
		dash := slices.IndexFunc(rest, func(e Elem) bool { return e.Kind == Lit && e.Text == "--" })
		if dash >= 0 {
			argvs = append(argvs, rest[dash+1:])
			continue
		}
		if sub != "exec" {
			continue // run and debug take a command only after --
		}
		pods, amb2 := operandStarts(rest, 0, kubectlOpts)
		amb = amb || amb2
		for _, j := range pods {
			if j+1 < len(rest) {
				argvs = append(argvs, rest[j+1:])
			}
		}
	}
	return runsEach(argvs, amb)
}
