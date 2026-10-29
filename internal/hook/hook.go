// Package hook runs one agent hook invocation. It reads the tool call, decides
// and answers, and it fails closed on every error
package hook

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/internal/boundedfile"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/hook/briefing"
	"cyberboar.dev/cyberboar/internal/hook/tripwire"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/semver"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// MaxInput bounds the hook input. Write and Edit carry file contents
const MaxInput = 32 << 20

// DefaultDeadline is the internal deadline. It must stay well below the
// agent's hook timeout, because a hook killed by that timeout fails open
const DefaultDeadline = 5 * time.Second

// AuditLimit bounds the audit write after the decision, so the hook answers within Deadline + AuditLimit
// A local append takes microseconds
const AuditLimit = time.Second

// Rule IDs for the hook's own denials, before or around the engine's
const (
	// RuleInputTooLarge denies a hook input over MaxInput
	RuleInputTooLarge = "error.inputTooLarge"
	// RuleAudit denies a call whose audit event can't be written
	RuleAudit = "error.audit"
	// RuleNoAdapter denies when the hook has no agent adapter
	RuleNoAdapter = "error.noAdapter"
	// RuleSignature denies every call while the policy isn't validly signed
	RuleSignature = "error.policySignature"
	// RulePolicyExpired denies every call once the signed policy's expiry has passed
	RulePolicyExpired = "error.policyExpired"
	// RuleTripwireState denies when the tripwire is on and its state can't be read or written
	RuleTripwireState = "error.tripwireState"
	// RuleGuardedPath denies when the hook's own files can't be located
	RuleGuardedPath = "error.guardedPath"
	// RuleVersion denies every call while the hook is older than the
	// policy's minimumVersion, or has no release version to compare
	RuleVersion = "error.versionTooOld"
	// RuleUnsupportedPlatform denies every call on an operating system whose
	// path semantics the engine doesn't implement
	RuleUnsupportedPlatform = "error.unsupportedPlatform"
	// RuleHookSetup denies when the hook command itself can't start, because
	// of bad flags or arguments or files it can't open
	RuleHookSetup = "error.hookSetup"
	// RuleNothingToCheck allows a call that touches nothing the policy governs
	RuleNothingToCheck = "adapter.nothingToCheck"
)

// supported lists the operating systems whose path semantics the engine
// implements, and the agents it can check on each. A nil set means every
// agent. On native Windows, Claude Code runs commands in Git Bash or its
// PowerShell tool, and Codex in PowerShell, which the engine analyzes. Its
// adapters for Copilot CLI, Cursor and opencode don't read their PowerShell
// calls on Windows yet
var supported = map[string]map[string]bool{
	"linux":   nil,
	"darwin":  nil,
	"windows": {"claude-code": true, "codex": true},
}

// PlatformSupported reports whether the engine can check the agent's tool
// calls on operating system goos (a runtime.GOOS value). Elsewhere the hook
// denies every call
func PlatformSupported(goos, agent string) bool {
	agents, ok := supported[goos]
	return ok && (agents == nil || agents[agent])
}

// UnsupportedReason says why an agent can't be checked on operating system
// goos and what to do instead. On Windows it names PowerShell, so a user
// whose agent is blocked there knows the cause and the way out
func UnsupportedReason(goos, agent string) string {
	name := agent
	if n, ok := agentNames[agent]; ok {
		name = n
	}
	if goos == "windows" {
		// opencode uses another shell when its config or $SHELL names one, and is unsupported on Windows either way
		runs := "runs its commands in PowerShell there"
		if agent == "opencode" {
			runs += " by default"
		}
		return fmt.Sprintf("%s does not support %s on native Windows yet: %s %s, which %s can't check, "+
			"so every tool call is blocked. Open the project in WSL or a Linux dev container, where its commands are checked", brand.DisplayName, name, name, runs, brand.DisplayName)
	}
	return fmt.Sprintf("%s does not support %s on %s yet, so every tool call is blocked; run the agent in WSL or on Linux or macOS", brand.DisplayName, name, goos)
}

// agentNames are the names users know the agents by
var agentNames = map[string]string{"claude-code": "Claude Code", "codex": "Codex", "copilot-cli": "Copilot CLI", "cursor": "Cursor", "opencode": "opencode"}

// Options configure one run.
type Options struct {
	// Adapter is the agent's hook protocol. If nil, every call is denied
	Adapter adapters.Adapter
	// PolicyPath is the policy file. A missing or invalid policy denies every call
	PolicyPath string
	// PublicKey, when set, makes a policy count only with a valid signature
	// (PolicyPath + ".sig") that hasn't expired
	// A policy that is unsigned, tampered with or expired denies every call
	PublicKey ed25519.PublicKey
	// PublicKeyPath loads the required signing key within the decision deadline
	// If set, it takes precedence over PublicKey; a read failure denies
	PublicKeyPath string
	// Getenv reads environment variables. If nil, os.Getenv is used
	Getenv func(string) string
	// GOOS is the operating system the hook runs on, as a runtime.GOOS value
	// If empty, it is the one the hook was built for.
	GOOS string
	// AuditPath is the absolute path of the audit log
	// If empty, no audit log is written. Agents may not touch it (builtin.self)
	AuditPath string
	// StateDir is the hook's state directory, which holds the tripwire counts
	// Agents may not touch it (builtin.self)
	// If the policy's tripwire is on and StateDir is empty, every call is denied
	StateDir string
	// Guarded lists further files agents may not change (builtin.guarded),
	// such as the signing key and the hook binary
	// The policy, its signature and the audit log are added from PolicyPath and AuditPath
	Guarded []string
	// Deadline bounds the policy decision
	// If zero, DefaultDeadline is used
	Deadline time.Duration
	// Version is compared with the policy's minimum and recorded in every audit event
	// An unversioned build meets no minimum
	Version string
	// Now returns the current time. If nil, time.Now is used
	Now func() time.Time
}

// Result is the hook's answer plus the verdict behind it
type Result struct {
	adapters.Output
	// Verdict is the decision the Output reports to the agent
	Verdict engine.Verdict
}

// Run handles one PreToolUse invocation. It never panics and always returns
// within the deadline plus AuditLimit
func Run(ctx context.Context, stdin io.Reader, o Options) Result {
	if o.Adapter == nil {
		// With no protocol to answer in, Claude Code's deny shape plus exit 2
		// is the closest thing to a universal "no"
		o.Adapter = claudecode.Adapter{}
		v := deny(RuleNoAdapter, "the hook has no agent adapter configured, so the tool call is blocked")
		return Result{Output: o.Adapter.Respond(v, brand.Name+": "), Verdict: v}
	}
	agent := o.Adapter.Name()
	if o.Deadline <= 0 {
		o.Deadline = DefaultDeadline
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	start := o.Now()
	ctx, cancel := context.WithTimeout(ctx, o.Deadline)
	defer cancel()

	type outcome struct {
		v  engine.Verdict
		ev audit.Event
		h  sign.Header
	}
	done := make(chan outcome, 1)
	go func() {
		ev := audit.Event{Agent: agent, Version: o.Version}
		var h sign.Header
		defer func() {
			if r := recover(); r != nil {
				done <- outcome{deny(engine.RuleInternal, "internal error in the hook, so the tool call is blocked"), ev, h}
			}
		}()
		v := evaluate(ctx, stdin, o, &ev, &h)
		done <- outcome{v, ev, h}
	}()

	var oc outcome
	select {
	case oc = <-done:
	case <-ctx.Done():
		// The evaluation may be stuck on a huge directory or a hung filesystem
		// Answer now, and let the process exit take it down
		oc = outcome{deny(engine.RuleDeadline, fmt.Sprintf("the policy decision took longer than %s, so the tool call is blocked", o.Deadline)),
			audit.Event{Agent: agent, Version: o.Version}, sign.Header{}}
	}

	v := oc.v
	checkExpiry := func() {
		if v.Decision != engine.Deny && oc.h.Expired(o.Now()) {
			v = expiredVerdict(&expiredError{oc.ev.PolicyName, oc.h})
		}
	}
	checkExpiry()
	if v.Rule == RuleUnsupportedPlatform || v.Rule == RuleVersion {
		// Every call is blocked and only the user can change that, so the user is told too
		v.Notice = v.Reason
	}
	if o.AuditPath != "" {
		ev := oc.ev
		ev.Time = start.UTC().Format(time.RFC3339Nano)
		// A reason can quote a command. Bound redaction and the append together
		// even if the decision deadline has already passed
		ev.Decision, ev.Rule, ev.Reason = string(v.Decision), v.Rule, v.Reason
		ev.DurationMs = float64(o.Now().Sub(start).Microseconds()) / 1000
		if err := appendAudit(o.AuditPath, ev, AuditLimit); err != nil {
			// The audit log is part of the contract, so a call that can't be logged is denied
			v = deny(RuleAudit, fmt.Sprintf("the audit log could not be written (%v), so the tool call is blocked", err))
		}
	}
	checkExpiry()
	return Result{Output: o.Adapter.Respond(v, brand.Name+": "), Verdict: v}
}

// appendAudit appends ev to the audit log at path and gives up after limit
// On a hung filesystem, such as a stale network home directory, the write
// would otherwise outlast the agent's hook timeout, which fails open
func appendAudit(path string, ev audit.Event, limit time.Duration) error {
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	go func() {
		ev.Reason = engine.Redact(ctx, ev.Reason)
		done <- audit.AppendFile(path, ev)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("no answer from the filesystem within %s", limit)
	}
}

// versionName describes version in a message
func versionName(version string) string {
	if version == "" {
		return "a build without a version"
	}
	return "version " + version
}

// versionVerdict blocks a binary that does not meet the policy's floor
func versionVerdict(minimum, version string) engine.Verdict {
	return deny(RuleVersion, fmt.Sprintf("the policy requires %s %s or later and this is %s, so every tool call is blocked until %s is upgraded",
		brand.DisplayName, minimum, versionName(version), brand.DisplayName))
}

func ruleOf(err error) string {
	if ae, ok := errors.AsType[*adapters.Error](err); ok {
		return ae.Rule
	}
	return adapters.RuleInvalidInput
}

func deny(rule, reason string) engine.Verdict {
	return engine.Verdict{Decision: engine.Deny, Rule: rule, Reason: reason}
}

// evaluate does everything that can take time or fail. Each failure is a deny
func evaluate(ctx context.Context, stdin io.Reader, o Options, ev *audit.Event, header *sign.Header) engine.Verdict {
	loaded := o
	if o.PublicKeyPath != "" {
		key, err := sign.LoadPublic(o.PublicKeyPath)
		if err != nil {
			return deny(RuleHookSetup, fmt.Sprintf("the policy signing key can't be read (%v), so the tool call is blocked", err))
		}
		// Keep the key path for guarding, but use these exact loaded bytes
		// for validation rather than reopening a potentially rotated key
		loaded.PublicKey, loaded.PublicKeyPath = key, ""
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxInput+1))
	switch {
	case err != nil:
		return deny(adapters.RuleInvalidInput, fmt.Sprintf("the hook input could not be read (%v), so the tool call is blocked", err))
	case len(data) > MaxInput:
		return deny(RuleInputTooLarge, fmt.Sprintf("the hook input is larger than %d bytes, so the tool call is blocked", MaxInput))
	}
	call, err := o.Adapter.Parse(data, o.Getenv)
	if err != nil {
		return deny(ruleOf(err), err.Error()+", so the tool call is blocked")
	}
	if o.AuditPath != "" {
		// Every field the agent wrote is redacted, because a directory or
		// session name can hold a credential too
		for _, f := range []struct {
			to   *string
			from string
		}{
			{&ev.Session, call.Session}, {&ev.ToolUseID, call.ToolUseID}, {&ev.AgentID, call.AgentID}, {&ev.AgentType, call.AgentType},
			{&ev.Mode, call.Mode}, {&ev.Cwd, call.Cwd}, {&ev.Tool, call.Tool}, {&ev.Project, call.Project},
		} {
			*f.to = engine.Redact(ctx, f.from)
		}
	}
	if !PlatformSupported(o.GOOS, o.Adapter.Name()) {
		// Checking with the wrong path semantics could miss a protected file
		return deny(RuleUnsupportedPlatform, UnsupportedReason(o.GOOS, o.Adapter.Name()))
	}

	compiled, name, hash, h, sigErr := loadPolicy(loaded)
	*header = h
	ev.PolicyName, ev.PolicyHash = name, hash
	var expired *expiredError
	switch {
	case errors.As(sigErr, &expired):
		return expiredVerdict(expired)
	case sigErr != nil:
		return deny(RuleSignature, fmt.Sprintf("the policy's signature can't be verified (%v), so every tool call is blocked", sigErr))
	}
	if compiled == nil {
		// Without a policy there is no way to know what is governed, so even
		// tools CyberBoar doesn't govern are blocked
		return engine.Evaluate(ctx, nil, engine.Action{})
	}
	if minimum := compiled.Policy().Spec.MinimumVersion; minimum != "" && !semver.AtLeast(o.Version, minimum) {
		// An older binary may lack checks the policy's authors rely on
		return versionVerdict(minimum, o.Version)
	}
	tw := compiled.Policy().Spec.Session.Tripwire
	var store *tripwire.Store
	if tw.On() {
		if o.StateDir == "" {
			return deny(RuleTripwireState, "the policy's tripwire is on but the hook has no state directory (set --state, XDG_STATE_HOME or HOME), so the tool call is blocked")
		}
		if call.Session == "" {
			// Without an ID, every session would share one count, and a new session wouldn't clear a lock
			return deny(RuleTripwireState, "the policy's tripwire is on but the agent gave no session ID to count denials by, so the tool call is blocked")
		}
		store = &tripwire.Store{Dir: o.StateDir, Now: o.Now}
		st, err := store.Check(o.Adapter.Name(), call.Session)
		if err != nil {
			return deny(RuleTripwireState, fmt.Sprintf("the tripwire state can't be read (%v), so the tool call is blocked", err))
		}
		if st.Locked {
			return lockedVerdict(st)
		}
	}
	guarded, err := guardedPaths(o)
	if err != nil {
		return deny(RuleGuardedPath, fmt.Sprintf("the hook's own files can't be located (%v), so the tool call is blocked", err))
	}
	var event *audit.Event
	if o.AuditPath != "" {
		event = ev
	}
	v := decide(ctx, compiled, call, protected(o), guarded, o.GOOS == "windows", event)
	if store == nil || v.Decision != engine.Deny || !tripwire.Counts(v.Rule) {
		return v
	}
	st, err := store.Record(o.Adapter.Name(), call.Session, v.Rule, tw.Limit(), tw.WindowDuration())
	if err != nil {
		return deny(RuleTripwireState, fmt.Sprintf("%s; the tripwire state can't be written (%v)", v.Reason, err))
	}
	if st.Locked {
		v.Reason += fmt.Sprintf(". This was denied call %d, so %s has now locked this session: every further tool call "+
			"will be blocked. Stop and tell the user what you were trying to do", len(st.Denials), brand.DisplayName)
	}
	return v
}

// protected lists the hook's own files that agents may not touch
// (builtin.self). They are the state directory, where an agent could undo a
// lock by changing the tripwire counts, and the audit log, which an agent
// could empty or fill with invented events for the console
func protected(o Options) []string {
	var out []string
	for _, p := range []string{o.StateDir, o.AuditPath} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// decide evaluates the call's actions and returns the strictest verdict
// windows reports whether the hook runs on Windows
func decide(ctx context.Context, compiled *engine.Compiled, call *adapters.Call, protected, guarded []string, windows bool, ev *audit.Event) engine.Verdict {
	if ev != nil {
		for _, a := range call.Actions {
			// Each field is redacted before it is truncated, so no part of a secret is left at the cut
			ev.Actions = append(ev.Actions, audit.Action{Tool: string(a.Tool), Command: audit.Truncate(engine.RedactCommand(ctx, a.Command, a.Shell)),
				Path: audit.Truncate(engine.Redact(ctx, a.Path)), Server: engine.Redact(ctx, a.MCP.Server), MCPTool: engine.Redact(ctx, a.MCP.Tool)})
		}
	}
	if call.Err != nil {
		v := deny(ruleOf(call.Err), call.Err.Error())
		v.Notice = call.Notice
		return v
	}
	var verdicts []engine.Verdict
	for _, a := range call.Actions {
		if a.Tool != engine.ToolMCP {
			a.Protected = append(a.Protected, protected...)
			a.Guarded = append(a.Guarded, guarded...)
		}
		if windows {
			// Windows paths must never be read as POSIX paths, whatever the adapter set
			a.Platform = engine.PlatformWindows
		}
		verdicts = append(verdicts, engine.Evaluate(ctx, compiled, a))
	}
	if v, ok := engine.Strictest(verdicts); ok {
		return v
	}
	return engine.Verdict{Decision: engine.Allow, Rule: RuleNothingToCheck, Reason: "the tool touches nothing the policy governs"}
}

// guardedPaths returns the absolute paths of the files in Options.Guarded,
// the policy with its signature and lock file, the signing key and the audit log
func guardedPaths(o Options) ([]string, error) {
	var out []string
	for _, p := range slices.Concat(o.Guarded, []string{o.PolicyPath, o.PolicyPath + ".sig", o.PolicyPath + ".lock", o.PublicKeyPath, o.AuditPath}) {
		if p == "" || (p == ".sig" || p == ".lock") {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		out = append(out, abs)
	}
	return out, nil
}

// lockedVerdict denies every call in a locked session
func lockedVerdict(st tripwire.State) engine.Verdict {
	last := ""
	if n := len(st.Rules); n > 0 {
		last = fmt.Sprintf(", the last by rule %s", st.Rules[n-1])
	}
	return deny(tripwire.RuleLocked, fmt.Sprintf("this session is locked after %d denied tool calls%s, which looks like a search for a way around the policy. "+
		"Every tool call is blocked until the user starts a new session or runs `%s unlock`. Stop and tell the user what you were trying to do",
		len(st.Denials), last, brand.Name))
}

// expiredError is a validly signed policy past its expiry
type expiredError struct {
	name string
	h    sign.Header
}

func (e *expiredError) Error() string {
	return fmt.Sprintf("the policy %q expired at %s (signature serial %d)", e.name, e.h.Expires.Format(sign.TimeFormat), e.h.Serial)
}

// expiredVerdict denies trust after the signed expiry, including during a decision
func expiredVerdict(e *expiredError) engine.Verdict {
	return deny(RulePolicyExpired, fmt.Sprintf("%v, so every tool call is blocked until a newer signed policy is installed (`%s pull`)", e, brand.Name))
}

// loadPolicy returns nil for a missing, unreadable or invalid policy, and
// sigErr when a public key is configured and the policy isn't validly signed
// or has expired (an *expiredError)
func loadPolicy(o Options) (c *engine.Compiled, name, hash string, header sign.Header, sigErr error) {
	if o.PolicyPath == "" {
		return nil, "", "", header, nil
	}
	data, err := boundedfile.Read(o.PolicyPath, policy.MaxSize)
	if err != nil {
		return nil, "", "", header, nil
	}
	sum := sha256.Sum256(data)
	hash = hex.EncodeToString(sum[:])
	p, err := policy.Load(data)
	if err != nil {
		return nil, "", hash, header, nil
	}
	if o.PublicKeyPath != "" {
		o.PublicKey, err = sign.LoadPublic(o.PublicKeyPath)
		if err != nil {
			return nil, p.Metadata.Name, hash, header, err
		}
	}
	if o.PublicKey != nil {
		sig, err := sign.ReadSig(o.PolicyPath)
		if err != nil {
			return nil, p.Metadata.Name, hash, header, fmt.Errorf("no signature: %w", err)
		}
		h, err := sign.Verify(o.PublicKey, p.Metadata.Name, data, sig)
		if err != nil {
			return nil, p.Metadata.Name, hash, header, err
		}
		now := time.Now
		if o.Now != nil {
			now = o.Now
		}
		header = h
		if h.Expired(now()) {
			return nil, p.Metadata.Name, hash, header, &expiredError{p.Metadata.Name, h}
		}
	}
	c, err = engine.Compile(p)
	if err != nil {
		return nil, p.Metadata.Name, hash, header, nil
	}
	return c, p.Metadata.Name, hash, header, nil
}

// Brief answers a SessionStart hook with the policy's briefing
// (spec.session.briefing). It never fails, because a briefing is advisory
// With no valid policy, it tells the agent that every call will be denied
// The answer has the shape o.Adapter's agent reads if the adapter is an
// adapters.Briefer, and otherwise the one Claude Code and Codex share
func Brief(o Options) []byte {
	out := briefing.SessionStartOutput
	if b, ok := o.Adapter.(adapters.Briefer); ok {
		out = b.SessionStartOutput
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.Adapter != nil && !PlatformSupported(o.GOOS, o.Adapter.Name()) {
		return out(UnsupportedReason(o.GOOS, o.Adapter.Name()) + ".\nTell the user before doing anything else.\n")
	}
	compiled, _, _, _, sigErr := loadPolicy(o)
	var expired *expiredError
	switch {
	case errors.As(sigErr, &expired):
		return out(briefing.NoPolicy(fmt.Sprintf("it expired at %s", expired.h.Expires.Format(sign.TimeFormat))))
	case sigErr != nil:
		return out(briefing.NoPolicy("its signature can't be verified"))
	case compiled == nil:
		return out(briefing.NoPolicy("the policy file is missing or invalid"))
	}
	if minimum := compiled.Policy().Spec.MinimumVersion; minimum != "" && !semver.AtLeast(o.Version, minimum) {
		return out(versionVerdict(minimum, o.Version).Reason + ".\nTell the user before doing anything else.\n")
	}
	return out(briefing.Text(compiled.Policy()))
}
