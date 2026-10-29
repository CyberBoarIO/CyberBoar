// Package policy parses and validates policy documents.
//
// Load is the only entry point. It either returns a fully validated Policy or
// an *Error. Callers must treat any error as "no policy" and deny.
package policy

import "time"

// Posture decides what happens to actions no rule matches.
type Posture string

const (
	// DenyListed allows anything not matched by a deny or ask rule.
	DenyListed Posture = "deny-listed"
	// AllowListed denies anything not matched by an allow rule.
	AllowListed Posture = "allow-listed"
)

// Policy is a validated policy document.
type Policy struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

// Metadata names and describes a policy.
type Metadata struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// Spec is the body of a policy.
type Spec struct {
	// MinimumVersion is the oldest release that may enforce the policy (a
	// semantic version, with or without a leading "v"), or "" for any
	// The hook denies every call when its own version is older or isn't a release version.
	MinimumVersion string   `json:"minimumVersion,omitempty"`
	Defaults       Defaults `json:"defaults"`
	Files          Files    `json:"files"`
	Commands       Commands `json:"commands"`
	MCP            Rules    `json:"mcp"`
	Audit          Audit    `json:"audit"`
	Sync           Sync     `json:"sync"`
	Session        Session  `json:"session"`
	Secrets        Secrets  `json:"secrets"`
}

// SecretsAction is what happens to an action that would write or run a credential.
type SecretsAction string

const (
	// SecretsDeny denies it (default).
	SecretsDeny SecretsAction = "deny"
	// SecretsAsk asks the user, where the agent can ask.
	SecretsAsk SecretsAction = "ask"
	// SecretsOff doesn't look for credentials. The audit log still has them redacted.
	SecretsOff SecretsAction = "off"
)

// Secrets says what to do about credentials in the files an agent writes and the commands it runs.
type Secrets struct {
	// Action is SecretsDeny when the document leaves it out.
	Action SecretsAction `json:"action,omitempty"`
	// Ignore lists the IDs of rules in package secrets not to act on
	// An ID this build doesn't know is not an error, since rule sets change between versions.
	Ignore []string `json:"ignore,omitempty"`
}

// Defaults holds settings that apply to every kind of action.
type Defaults struct {
	// Posture is DenyListed when the document leaves it out.
	Posture Posture `json:"posture"`
}

// Rules holds the patterns for one action kind, by decision.
type Rules struct {
	Allow []string `json:"allow,omitempty"`
	Ask   []string `json:"ask,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Containing decides what happens when an action touches a directory that
// contains a file a deny or ask rule protects (grep -r KEY ., tar ~).
type Containing string

const (
	// ContainingDeny treats the directory like the protected file (default).
	ContainingDeny Containing = "deny"
	// ContainingAsk asks instead of denying. An ask rule inside still asks.
	ContainingAsk Containing = "ask"
	// ContainingIgnore looks for no policy rule inside the directory.
	// The built-in rules still apply to everything in it, so a directory that
	// can't be walked whole is still denied.
	ContainingIgnore Containing = "ignore"
)

// Files holds the rules for file access, by native tools and through the shell.
type Files struct {
	Rules
	// Containing is ContainingDeny when the document leaves it out.
	Containing Containing `json:"containing,omitempty"`
}

// Commands holds the rules for shell commands.
type Commands struct {
	Rules
	// DenyInterpreters is true when the document leaves it out, so inline
	// code is denied unless a policy explicitly opts out.
	DenyInterpreters *bool `json:"denyInterpreters,omitempty"`
}

// InterpretersDenied reports whether inline code is denied.
// A nil value (a Policy not built by Load) counts as denied.
func (c Commands) InterpretersDenied() bool {
	return c.DenyInterpreters == nil || *c.DenyInterpreters
}

// Audit says where audit events go.
type Audit struct {
	Sink string `json:"sink,omitempty"`
}

// Sync configures the endpoint's background delivery and refresh intervals.
// An omitted interval or 0s means one run. The operator's --every flag wins.
type Sync struct {
	ShipEvery string `json:"shipEvery,omitempty"`
	PullEvery string `json:"pullEvery,omitempty"`
}

// ShipInterval returns the validated interval between audit uploads.
func (s Sync) ShipInterval() time.Duration {
	d, _ := time.ParseDuration(s.ShipEvery)
	return d
}

// PullInterval returns the validated interval between policy refreshes.
func (s Sync) PullInterval() time.Duration {
	d, _ := time.ParseDuration(s.PullEvery)
	return d
}

// Session holds protections that span a whole agent session.
type Session struct {
	Tripwire Tripwire `json:"tripwire"`
	Briefing Briefing `json:"briefing"`
}

// DefaultMaxDenials is the tripwire's limit when the document leaves it out.
const DefaultMaxDenials = 3

// Tripwire locks a session after repeated denials, so that an agent hunting
// for a way around a rule stops at the limit.
// It is off unless the policy has a tripwire block.
// Load fills in every default.
type Tripwire struct {
	// Enabled is true when the document has a tripwire block and leaves it
	// out, false when there is no block.
	Enabled *bool `json:"enabled,omitempty"`
	// MaxDenials is DefaultMaxDenials when the document leaves it out.
	MaxDenials int `json:"maxDenials,omitempty"`
	// Window is how far back denials count, such as "30m". If empty, they
	// count for the whole session, the stricter default.
	Window string `json:"window,omitempty"`
}

// On reports whether the tripwire is on. A nil value (a Policy not built by
// Load) counts as off, the default.
func (t Tripwire) On() bool { return t.Enabled != nil && *t.Enabled }

// Limit is the number of denials that locks the session.
func (t Tripwire) Limit() int {
	if t.MaxDenials < 1 {
		return DefaultMaxDenials
	}
	return t.MaxDenials
}

// WindowDuration returns how far back denials count, or 0 for the whole
// session. Load has validated the value.
func (t Tripwire) WindowDuration() time.Duration {
	d, _ := time.ParseDuration(t.Window)
	return d
}

// Briefing tells the agent the rules when a session starts.
type Briefing struct {
	// Enabled is true when the document leaves it out.
	Enabled *bool `json:"enabled,omitempty"`
	// Message is added to the generated briefing.
	Message string `json:"message,omitempty"`
}

// On reports whether the briefing is on. A nil value counts as on.
func (b Briefing) On() bool { return b.Enabled == nil || *b.Enabled }
