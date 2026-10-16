// Command `cyberboar` enforces security policies for coding agents.
//
//	cyberboar hook      | answer one agent hook call from stdin on stdout (exit 2 denies)
//	cyberboar brief     | answer a SessionStart hook with the policy's briefing
//	cyberboar check     | validate policy files
//	cyberboar test      | run YAML policy regression cases
//	cyberboar explain   | show the decision for one action
//	cyberboar apply     | install the hook into an agent's settings
//	cyberboar enroll    | enroll this machine with a console
//	cyberboar ship      | send the audit log to the console
//	cyberboar pull      | fetch the signed policy bundle from the console
//	cyberboar keygen    | create the policy signing key pair
//	cyberboar sign      | sign policy files
//	cyberboar verify    | check policy signatures
//	cyberboar bundle    | write signed policy bundles as a static site
//	cyberboar unlock    | list or clear sessions the tripwire tracks
//	cyberboar version   | print the current version
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// version is set at build time with -ldflags "-X main.version=VERSION"
var version = "dev"

// host is what the commands read from the machine they run on
type host struct {
	getenv func(string) string
	goos   string           // a runtime.GOOS value
	now    func() time.Time // the clock signatures' expiries are checked against
}

func main() {
	h := host{getenv: os.Getenv, goos: runtime.GOOS, now: time.Now}
	os.Exit(h.run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// command runs one command with a new flag set named after it
type command func(h host, fs *flag.FlagSet, args []string, stdin io.Reader, stdout, stderr io.Writer) int

// commands are the commands that take flags, by name
var commands = map[string]command{
	"hook":    runHook,
	"brief":   runBrief,
	"check":   runCheck,
	"test":    runTest,
	"explain": runExplain,
	"apply":   runApply,
	"enroll":  runEnroll,
	"ship":    runShip,
	"pull":    runPull,
	"keygen":  runKeygen,
	"sign":    runSign,
	"verify":  runVerify,
	"bundle":  runBundle,
	"unlock":  runUnlock,
}

func (h host) run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if c, ok := commands[args[0]]; ok {
		return c(h, commandFlagSet(args[0]), args[1:], stdin, stdout, stderr)
	}
	switch args[0] {
	case "version", "--version":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		fs.SetOutput(stderr)
		fs.Usage = func() { fmt.Fprintf(stderr, "usage: %s version\n", brand.Name) }
		if code, ok := parseFlags(fs, args[1:]); !ok {
			return code
		}
		if fs.NArg() > 0 {
			fs.Usage()
			return 2
		}
		fmt.Fprintf(stdout, "%s %s (policy %s)\n", brand.Name, version, brand.APIVersion)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "%s: unknown command %q\n", brand.Name, args[0])
	usage(stderr)
	return 2
}

// defaultStateDir follows the XDG base directory spec, and on Windows uses the local application data dir
func (h host) defaultStateDir() (string, error) {
	if d := h.getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, brand.Name), nil
	}
	if d := h.getenv("LOCALAPPDATA"); h.goos == "windows" && filepath.IsAbs(d) {
		return filepath.Join(d, brand.Name), nil
	}
	home := h.getenv("HOME")
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("no state directory: set --state, XDG_STATE_HOME or HOME")
	}
	return filepath.Join(home, ".local", "state", brand.Name), nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `usage: %[1]s <command> [flags]

  hook     answer one PreToolUse hook call on stdin (--agent claude-code, codex, copilot-cli, cursor or opencode)
  brief    answer a SessionStart hook with the policy's briefing for the agent
  check    validate policy files
  test     run YAML policy regression cases
  explain  show the decision for one action
  apply    install the hook into an agent's settings (dry run unless --write)
  enroll   enroll this machine with a compatible console, or renew its certificate
  ship     send the audit log to the console this machine is enrolled with
  pull     fetch a signed policy bundle from the console or a static site
  keygen   create the key pair that signs policies
  sign     sign policy files with a serial and an expiry (writes POLICY.sig)
  verify   check policy signatures
  bundle   write signed policy bundles as a static site for pull
  unlock   list sessions the tripwire tracks, or unlock one
  version  print the version

Run "%[1]s <command> --help" for a command's flags.
`, brand.Name)
}

// agents are the hook protocols `cyberboar hook --agent` speaks
var agents = map[string]adapters.Adapter{
	claudecode.Adapter{}.Name(): claudecode.Adapter{},
	codex.Adapter{}.Name():      codex.Adapter{},
	copilot.Adapter{}.Name():    copilot.Adapter{},
	cursor.Adapter{}.Name():     cursor.Adapter{},
	opencode.Adapter{}.Name():   opencode.Adapter{},
}

// agentList is the --agent values, sorted, for flag help
func agentList() string {
	names := make([]string, 0, len(agents))
	for n := range agents {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// commandFlagSet keeps the standard flag parser and displays long flags in help
func commandFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of %s:\n", fs.Name())
		printFlagDefaults(fs)
	}
	return fs
}

// printFlagDefaults uses Go's help formatting with double-dash long flag names
func printFlagDefaults(fs *flag.FlagSet) {
	var b bytes.Buffer
	out := fs.Output()
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(out)
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if strings.HasPrefix(line, "  -") && len(strings.Fields(line)[0]) > 2 {
			line = "  --" + strings.TrimPrefix(line, "  -")
		}
		fmt.Fprint(out, line)
	}
}

// parseFlags parses a command's flags. When ok is false, the command stops
// with exit status code: 0 for --help (or -h) and 2 for any other error (docs/cli.md)
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	switch err := fs.Parse(args); {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		return 0, false
	}
	return 2, false
}

// envName is the environment variable for a flag, e.g. CYBERBOAR_POLICY
func envName(flagName string) string {
	return brand.EnvPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}
