package main

import (
	"flag"
	"io"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/hook"
	"cyberboar.dev/cyberboar/internal/hook/briefing"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// runBrief answers a SessionStart hook. It always exits 0, because a
// briefing is advisory (the PreToolUse hook enforces the policy) and must
// never stop a session from starting
func runBrief(h host, fs *flag.FlagSet, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(io.Discard)
	agent := fs.String("agent", "claude-code", "agent: "+agentList()+" (the answer is in the shape the agent reads)")
	policyPath := fs.String("policy", "", "policy file") // no environment fallbacks, as for the hook
	pubkey := fs.String("pubkey", "", "require a valid POLICY.sig from this public key")
	_, _ = io.Copy(io.Discard, io.LimitReader(stdin, 1<<20)) // the SessionStart input isn't needed
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		_, _ = stdout.Write(briefing.SessionStartOutput(briefing.Unavailable("the briefing hook is misconfigured")))
		return 0
	}
	adapter, ok := agents[*agent]
	if !ok {
		_, _ = stdout.Write(briefing.SessionStartOutput(briefing.Unavailable("the briefing hook names an unknown agent")))
		return 0
	}
	o := hook.Options{Adapter: adapter, PolicyPath: *policyPath, GOOS: h.goos, Now: h.now, Version: version}
	if *pubkey != "" {
		k, err := sign.LoadPublic(*pubkey)
		if err != nil {
			out := briefing.SessionStartOutput
			if b, ok := adapter.(adapters.Briefer); ok {
				out = b.SessionStartOutput
			}
			_, _ = stdout.Write(out(briefing.NoPolicy("the policy signing key can't be read")))
			return 0
		}
		o.PublicKey = k
	}
	_, _ = stdout.Write(hook.Brief(o))
	return 0
}
