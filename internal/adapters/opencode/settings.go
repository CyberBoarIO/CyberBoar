package opencode

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// Scope is where the plugin shim is installed. Each is a file CyberBoar owns
// entirely, since opencode loads every *.js and *.ts in its plugin directories.
type Scope string

// The scopes apply installs into, by the settings file each one writes.
const (
	ScopeUser    Scope = "user"    // ~/.config/opencode/plugin/cyberboar.js (or XDG_CONFIG_HOME)
	ScopeProject Scope = "project" // <project>/.opencode/plugin/cyberboar.js (committed)
)

// HookTimeout is how long the shim waits for the hook, in seconds, before it
// kills it and blocks the call. opencode itself never times a plugin out, so
// this is the only limit. The hook's own deadline stays well below it, so
// that a slow decision is a deny with a reason rather than a timeout.
const HookTimeout = 15

// FileName is the name of the plugin file CyberBoar writes in each scope.
const FileName = brand.Name + ".js"

// ShimOptions describe the hook command the shim runs.
type ShimOptions struct {
	Scope    Scope
	Command  string // cyberboar executable, as an absolute path or a name on PATH
	Policy   string // policy path, relative to the project root for ScopeProject
	Audit    string
	State    string // the hook's --state, or "" for its default
	PubKey   string // policy signing public key, or ""
	Deadline string
	Briefing bool // add the policy's briefing to the system prompt (spec.session.briefing)
}

// HookArgs returns the arguments of the hook command.
func HookArgs(o ShimOptions) []string {
	return adapters.HookArgs("opencode", o.Policy, o.Audit, o.State, o.PubKey, o.Deadline)
}

// BriefArgs returns the arguments of the briefing command.
func BriefArgs(o ShimOptions) []string {
	return adapters.BriefArgs("opencode", o.Policy, o.PubKey)
}

//go:embed shim.js
var shimTemplate string

// Shim returns the plugin file for a scope. The command and its arguments are
// baked in as JSON string literals and run without a shell, so no path needs
// quoting and none can inject code.
func Shim(o ShimOptions) ([]byte, error) {
	lit := func(v any) string {
		// encoding/json escapes <, >, &, U+2028 and U+2029, so the literal
		// is valid JavaScript wherever it lands
		b, err := json.Marshal(v)
		if err != nil {
			panic(err) // strings and string slices always marshal
		}
		return string(b)
	}
	brief := "null"
	if o.Briefing {
		brief = lit(BriefArgs(o))
	}
	if o.Command == "" {
		return nil, errors.New("no hook command")
	}
	pairs := []string{
		"@@DISPLAY@@", brand.DisplayName,
		"@@NAME@@", brand.Name,
		"@@NAME_JSON@@", lit(brand.Name),
		"@@COMMAND@@", lit(o.Command),
		"@@HOOK_ARGS@@", lit(HookArgs(o)),
		"@@BRIEF_ARGS@@", brief,
		"@@TIMEOUT_MS@@", strconv.Itoa(HookTimeout * 1000),
		"@@PROJECT_ROOT@@", strconv.FormatBool(o.Scope == ScopeProject),
	}
	rest := shimTemplate
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(rest, pairs[i]) {
			return nil, fmt.Errorf("the plugin template has no %s", pairs[i])
		}
		rest = strings.ReplaceAll(rest, pairs[i], "")
	}
	if strings.Contains(rest, "@@") {
		return nil, errors.New("the plugin template has an unknown marker")
	}
	// The replacer makes one pass, so a marker spelled inside a value, such
	// as a path, is not replaced
	return []byte(strings.NewReplacer(pairs...).Replace(shimTemplate)), nil
}

// SessionStartOutput returns the briefing command's answer, which has
// additionalContext at the top level. The shim adds the text to the system
// prompt. Empty text gives no output.
func (Adapter) SessionStartOutput(text string) []byte {
	if text == "" {
		return nil
	}
	out, _ := json.Marshal(map[string]any{"additionalContext": text})
	return append(out, '\n')
}
