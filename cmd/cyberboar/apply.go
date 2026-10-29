package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// runApply installs the hook into an agent's settings. It prints what it
// would write unless --write is given.
func runApply(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	cwd, _ := os.Getwd()
	policyPath := fs.String("policy", h.getenv(envName("policy")), "policy file")
	scope := fs.String("scope", "user", "settings to change: user, project, local or managed")
	dir := fs.String("dir", cwd, "project directory (project and local scopes)")
	managedDir := fs.String("managed-dir", claudecode.ManagedDir(h.goos), "managed settings directory (managed scope; codex: "+
		codex.ManagedDir+", copilot-cli: "+copilot.PolicyDir+", cursor: "+cursorManagedDir(h.goos)+")")
	hookExe := fs.String("command", "", brand.Name+" executable for the hook (default: this binary; project scope: "+brand.Name+" on PATH)")
	auditPath := fs.String("audit", "", "audit log path for the hook")
	stateDir := fs.String("state", "", "the hook's state directory (default: the hook's own, $XDG_STATE_HOME/"+brand.Name+")")
	deadline := fs.Duration("deadline", hook.DefaultDeadline, "hook deadline; must stay below the Claude Code hook timeout")
	lock := fs.Bool("lock", false, "managed scope: set allowManagedHooksOnly so users can't add or disable hooks")
	write := fs.Bool("write", false, "write the settings (default: print them)")
	agent := fs.String("agent", "claude-code", "agent to install into: "+agentList())
	pubkey := fs.String("pubkey", "", "policy signing public key: the hook then refuses unsigned or altered policies (required for --scope managed unless --allow-unsigned)")
	allowUnsigned := fs.Bool("allow-unsigned", false, "managed scope: install without signature checks")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "apply: "+format+"\n", a...)
		return 1
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "apply: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 0 {
		return usage("unexpected argument %q (apply takes no arguments, and flags after one are not read)", fs.Arg(0))
	}
	var apply installer
	managed := ""
	switch *agent {
	case "claude-code":
		apply = applyClaudeCode
	case "codex":
		apply, managed = applyCodex, codex.ManagedDir
		if h.goos == "windows" {
			managed = codex.WindowsManagedDir(h.getenv("ProgramData"))
		}
	case "copilot-cli":
		apply, managed = applyCopilot, copilot.PolicyDir
	case "cursor":
		apply, managed = applyCursor, cursorManagedDir(h.goos)
	case "opencode":
		apply = applyOpencode
	default:
		return usage("unknown --agent %q (%s)", *agent, agentList())
	}
	if *pubkey == "" && *scope == "managed" && !*allowUnsigned {
		return usage("--scope managed needs --pubkey (signed policies) or an explicit --allow-unsigned")
	}
	if *write && !hook.PlatformSupported(h.goos, *agent) {
		// The hook would deny every call here
		return fail("%s", hook.UnsupportedReason(h.goos, *agent))
	}
	a := applyArgs{policy: *policyPath, scope: *scope, dir: *dir, managedDir: *managedDir, command: *hookExe,
		audit: *auditPath, state: *stateDir, pubkey: *pubkey, deadline: *deadline, lock: *lock, write: *write, goos: h.goos}
	var err error
	if a, err = absoluteApplyPaths(a); err != nil {
		return fail("%v", err)
	}
	if a.pubkey != "" {
		if _, err := sign.LoadPublic(a.pubkey); err != nil {
			return fail("%v", err)
		}
	}
	if managed != "" && !flagWasSet(fs, "managed-dir") {
		a.managedDir = managed
	}
	return apply(a, stdout, h.getenv, fail, usage)
}

// installer installs the hook into one agent's settings, or prints what it
// would write. It returns the exit status that fail gives for a failure (1),
// or that usage gives for a flag value or combination the agent doesn't take (2).
type installer func(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int

// applyArgs are apply's flags, as every agent's installer reads them.
type applyArgs struct {
	policy, scope, dir, managedDir, command, audit, state, pubkey string
	deadline                                                      time.Duration
	lock, write                                                   bool
	goos                                                          string // the operating system apply runs on
}

// loadPolicy reads the policy at path and checks that it compiles.
func loadPolicy(path string) (*policy.Policy, *engine.Compiled, error) {
	// #nosec G703 -- the operator's own --policy argument
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := policy.Load(data)
	if err != nil {
		return nil, nil, err
	}
	c, err := engine.Compile(p)
	if err != nil {
		return nil, nil, err
	}
	return p, c, nil
}

// checkDeadline refuses a hook deadline that, with the audit write, reaches
// the agent's hook timeout (in seconds).
func checkDeadline(deadline time.Duration, timeout int, what, after string) error {
	if deadline+hook.AuditLimit < time.Duration(timeout)*time.Second {
		return nil
	}
	return fmt.Errorf("--deadline %s plus %s for the audit write must be below the %s (%ds)%s", deadline, hook.AuditLimit, what, timeout, after)
}

// absoluteApplyPaths resolves paths that the hook must not interpret relative
// to the agent's working directory. Project installers make the policy
// portable after checking that it lies within the project.
func absoluteApplyPaths(a applyArgs) (applyArgs, error) {
	for _, field := range []struct {
		flag string
		path *string
	}{
		{"policy", &a.policy},
		{"dir", &a.dir},
		{"pubkey", &a.pubkey},
		{"audit", &a.audit},
		{"state", &a.state},
	} {
		if *field.path == "" && field.flag != "policy" && field.flag != "dir" {
			continue
		}
		abs, err := filepath.Abs(*field.path)
		if err != nil {
			return a, fmt.Errorf("-%s: can't resolve an absolute path: %w", field.flag, err)
		}
		*field.path = abs
	}
	return a, nil
}

// projectPolicy returns the policy's path relative to the project, with
// slashes, for project-scope hook configuration.
func projectPolicy(dir, policy string) (string, error) {
	rel, err := filepath.Rel(dir, policy)
	if err != nil {
		return "", fmt.Errorf("project scope: can't resolve the policy relative to the project: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("project scope: the policy must be inside the project (%s) so committed hook configuration works on every machine", dir)
	}
	return filepath.ToSlash(rel), nil
}

// userHome returns the user's home directory from HOME, the base of every
// user-scope settings path.
func userHome(getenv func(string) string) (string, error) {
	if home := getenv("HOME"); home != "" {
		return home, nil
	}
	return "", errors.New("HOME is not set")
}

// hookCommand returns the executable the hook runs, which is command or the binary.
func hookCommand(command string) (string, error) {
	if command != "" {
		return command, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("can't find this executable (%v); pass --command", err)
	}
	return exe, nil
}

// emit writes out to target, or for a dry run prints it under a comment
// naming target, then warns about shell configuration the hook can't see.
func emit(stdout io.Writer, a applyArgs, target, comment string, out []byte, getenv func(string) string) error {
	if !a.write {
		fmt.Fprintf(stdout, "%s %s (dry run; add --write to apply)\n%s", comment, target, out)
	} else if err := writeAtomic(target, out); err != nil {
		return err
	} else {
		fmt.Fprintf(stdout, "wrote %s\n", target)
	}
	for _, w := range shellConfigWarnings(getenv("HOME")) {
		fmt.Fprintf(stdout, "WARNING: %s\n", w)
	}
	return nil
}

func printNotes(stdout io.Writer, heading string, notes []string) {
	fmt.Fprintf(stdout, "\n%s\n", heading)
	for _, n := range notes {
		fmt.Fprintf(stdout, "  - %s\n", n)
	}
}

// writeAtomic replaces path via a temporary file, keeping a .bak of a
// previous version.
func writeAtomic(path string, data []byte) error {
	// #nosec G301 -- agents' settings directories are normally 0755.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if old, err := os.ReadFile(path); err == nil {
		if bytes.Equal(old, data) {
			return nil
		}
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
		}
		// Backups must not follow a leaf symlink or expose a partial copy
		if err := atomicfile.Write(path+".bak", old, mode); err != nil {
			return err
		}
	}
	return atomicfile.Write(path, data, mode)
}

// shellConfigWarnings reports settings in the user's shell configuration that
// change how commands resolve paths in ways the hook can't see:
// CDPATH set there (not exported to the hook) and cdable_vars.
func shellConfigWarnings(home string) []string {
	if home == "" {
		return nil
	}
	var out []string
	for _, f := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv", ".zprofile"} {
		data, err := os.ReadFile(filepath.Join(home, f))
		if err != nil {
			continue
		}
		text := string(data)
		for _, s := range []struct{ needle, why string }{
			{"CDPATH", "sets CDPATH: `cd NAME` may land outside the directory the hook assumes"},
			{"cdable_vars", "enables cdable_vars: `cd NAME` may follow a variable"},
		} {
			if strings.Contains(text, s.needle) {
				out = append(out, fmt.Sprintf("~/%s %s; remove it for agent sessions, or export it so the hook sees it", f, s.why))
			}
		}
	}
	return out
}
