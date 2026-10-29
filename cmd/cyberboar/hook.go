package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// runHook must fail closed on everything, flag errors included, because any
// exit code other than 2 lets Claude Code run the tool call. Codex is the
// exception: its deny is the JSON answer with exit 0 (codex.Adapter.Respond).
func runHook(h host, fs *flag.FlagSet, args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	// Read before parsing, which a flag error stops
	forCodex := agentArg(args) == "codex"
	denyNow := func(reason string) int {
		v := engine.Verdict{Decision: engine.Deny, Rule: hook.RuleHookSetup, Reason: reason}
		out := claudecode.Respond(v, brand.Name+": ")
		if forCodex {
			out = codex.Adapter{}.Respond(v, brand.Name+": ")
		}
		// Exit 2 denies whether or not the agent reads the answer.
		_, _ = stdout.Write(out.Stdout)
		_, _ = io.WriteString(stderr, out.Stderr)
		return out.Exit
	}
	defer func() {
		if recover() == nil {
			return
		}
		// The panic may have come from writing to stdout, so the reason goes
		// to stderr alone, and a panic there too still leaves exit 2. Codex
		// needs the answer on stdout, so it gets exit 0 only once that is written
		code = 2
		defer func() { _ = recover() }()
		v := engine.Verdict{Decision: engine.Deny, Rule: hook.RuleHookSetup,
			Reason: "internal error in the hook, so the tool call is blocked"}
		if forCodex {
			if _, err := stdout.Write(codex.Adapter{}.Respond(v, brand.Name+": ").Stdout); err == nil {
				code = 0
			}
			return
		}
		_, _ = io.WriteString(stderr, claudecode.Respond(v, brand.Name+": ").Stderr)
	}()

	fs.SetOutput(io.Discard)
	agent := fs.String("agent", "claude-code", "agent whose hook protocol to speak: "+agentList())
	// The flags have no environment fallbacks, because the agent's environment
	// can come from the project it opened and must not steer the hook
	policyPath := fs.String("policy", "", "policy file")
	auditPath := fs.String("audit", "", "append a JSON audit line per decision")
	pubkey := fs.String("pubkey", "", "require a valid POLICY.sig from this public key")
	deadline := fs.Duration("deadline", hook.DefaultDeadline, "answer deny if the decision takes longer; keep it below the agent's hook timeout")
	stateDir := fs.String("state", "", "state directory: tripwire counts; agents may not touch it (default: $XDG_STATE_HOME/"+brand.Name+")")
	if err := fs.Parse(args); err != nil {
		return denyNow(fmt.Sprintf("the hook is misconfigured (%v), so the tool call is blocked", err))
	}
	if *stateDir == "" {
		// Without a usable default it stays empty, and the hook denies
		// every call if the policy's tripwire is on
		*stateDir, _ = h.defaultStateDir()
	} else if !filepath.IsAbs(*stateDir) {
		return denyNow(fmt.Sprintf("the hook's state directory %q is not an absolute path, so the tool call is blocked", *stateDir))
	}
	if *auditPath != "" && !filepath.IsAbs(*auditPath) {
		// A relative path would follow the agent's working directory, giving
		// one log per project, none of them protected or shipped
		return denyNow(fmt.Sprintf("the hook's audit log %q is not an absolute path, so the tool call is blocked", *auditPath))
	}
	adapter, ok := agents[*agent]
	if !ok {
		return denyNow(fmt.Sprintf("the hook is configured for unsupported agent %q, so the tool call is blocked", *agent))
	}
	if fs.NArg() > 0 {
		return denyNow(fmt.Sprintf("the hook is misconfigured (unexpected argument %q), so the tool call is blocked", fs.Arg(0)))
	}

	// The binary and the key decide what the hook does, so agents may not
	// replace them (builtin.guarded)
	exe, err := os.Executable()
	if err != nil {
		return denyNow(fmt.Sprintf("the hook can't locate its own executable (%v), so the tool call is blocked", err))
	}
	guarded := []string{exe}
	if *pubkey != "" {
		guarded = append(guarded, *pubkey)
	}
	r := hook.Run(context.Background(), stdin, hook.Options{Adapter: adapter, PublicKeyPath: *pubkey, Guarded: guarded,
		PolicyPath: *policyPath, AuditPath: *auditPath, StateDir: *stateDir, Deadline: *deadline, Getenv: h.getenv, GOOS: h.goos, Version: version, Now: h.now})
	if r.Verdict.Rule == hook.RuleHookSetup {
		// Configuration errors deny with exit 2 before reading agent input,
		// including when the agent's ordinary deny uses another exit code
		// (Codex excepted, see runHook)
		return denyNow(r.Verdict.Reason)
	}
	if _, err := stdout.Write(r.Stdout); err != nil {
		// An ask, and Cursor's deny, exit 0 and only work if the agent reads
		// them, so exit 0 without the answer would let the call run
		fmt.Fprintf(stderr, "%s: the hook can't write its answer (%v), so the tool call is blocked\n", brand.Name, err)
		return 2
	}
	_, _ = io.WriteString(stderr, r.Stderr)
	return r.Exit
}

// agentArg returns the --agent value as the flag package will read it, the
// last one given, without parsing the other flags.
func agentArg(args []string) string {
	agent := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !hasValue {
			// Every hook flag takes a value
			if i+1 == len(args) {
				break
			}
			i++
			value = args[i]
		}
		if name == "agent" {
			agent = value
		}
	}
	return agent
}
