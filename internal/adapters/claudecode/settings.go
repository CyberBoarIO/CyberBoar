package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// Scope is where Claude Code settings live.
type Scope string

const (
	ScopeUser    Scope = "user"    // ~/.claude/settings.json
	ScopeProject Scope = "project" // <project>/.claude/settings.json (committed)
	ScopeLocal   Scope = "local"   // <project>/.claude/settings.local.json
	ScopeManaged Scope = "managed" // <system dir>/managed-settings.d/50-<name>.json
)

// ManagedDir is the directory Claude Code reads managed settings from on
// goos (a runtime.GOOS value).
func ManagedDir(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

// legacyManagedDir is where older Claude Code releases read managed settings
// on Windows.
const legacyManagedDir = `C:\ProgramData\ClaudeCode`

// disableAllHooks is the settings key that makes Claude Code run no hook.
const disableAllHooks = "disableAllHooks"

// HookTimeout is the Claude Code hook timeout in seconds. The hook's own
// deadline must stay well below it, because a hook killed by this timeout
// fails open.
const HookTimeout = 10

// FragmentOptions describe the hook command to install.
type FragmentOptions struct {
	Scope    Scope
	Command  string // cyberboar executable, as an absolute path or a name on PATH
	Policy   string // policy path as the hook will see it
	Audit    string // audit log path, or ""
	State    string // the hook's --state, or "" for its default
	PubKey   string // policy signing public key, or "" (unsigned policies accepted)
	Deadline string // hook --deadline, e.g. "5s"
	Lock     bool   // in managed scope, set allowManagedHooksOnly, and disableAllHooks false
}

// Fragment holds the settings CyberBoar contributes and notes on what the
// native rules can't express. The notes are reported to the user, and the
// hook still enforces what they describe.
type Fragment struct {
	Settings map[string]any
	Notes    []string
}

// ours reports whether h is a hook handler that a previous apply installed.
func ours(h map[string]any) bool {
	cmd, _ := h["command"].(string)
	args, _ := h["args"].([]any)
	if h["type"] != "command" || len(args) == 0 {
		return false
	}
	var marker string
	switch args[0] {
	case "hook":
		marker = brand.Name + ": checking policy"
	case "brief":
		marker = brand.Name + ": briefing"
	default:
		return false
	}
	// The marker survives executable renames; the basename recognizes older handlers
	return h["statusMessage"] == marker || strings.TrimSuffix(filepath.Base(cmd), ".exe") == brand.Name
}

// BuildFragment compiles a policy into Claude Code settings. They hold the
// hooks, and deny and ask permission rules as defense in depth for when the
// hook can't run. CyberBoar never adds allow rules.
func BuildFragment(p *policy.Policy, o FragmentOptions) Fragment {
	args := []any{"hook", "--policy", o.Policy}
	if o.Audit != "" {
		args = append(args, "--audit", o.Audit)
	}
	if o.State != "" {
		args = append(args, "--state", o.State)
	}
	if o.PubKey != "" {
		args = append(args, "--pubkey", o.PubKey)
	}
	args = append(args, "--deadline", o.Deadline)
	// onFailure makes Claude Code 2.1.295 and later block the call when the
	// hook can't start, crashes or times out, instead of running it
	// unchecked. Earlier releases ignore the key and keep the hook.
	hooks := map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "*",
		"hooks": []any{map[string]any{
			"type": "command", "command": o.Command, "args": args,
			"timeout": HookTimeout, "statusMessage": brand.Name + ": checking policy",
			"onFailure": "block",
		}},
	}}}
	if p.Spec.Session.Briefing.On() {
		// The briefing hook has no matcher, so it runs on every start, resume,
		// clear and compaction, and the rules survive a compacted context.
		brief := []any{"brief", "--policy", o.Policy}
		if o.PubKey != "" {
			brief = append(brief, "--pubkey", o.PubKey)
		}
		hooks["SessionStart"] = []any{map[string]any{"hooks": []any{map[string]any{
			"type": "command", "command": o.Command, "args": brief,
			"timeout": HookTimeout, "statusMessage": brand.Name + ": briefing",
		}}}}
	}
	f := Fragment{Settings: map[string]any{"hooks": hooks}}
	deny, ask := f.permissionRules(p, o.Scope)
	// The bare tool name removes the PowerShell tool from Claude's context,
	// which the hook would deny on every call anyway.
	deny = dedupe(append(append(deny, guardRules(o)...), "PowerShell"))
	perms := map[string]any{}
	if len(deny) > 0 {
		perms["deny"] = toAny(deny)
	}
	if len(ask) > 0 {
		perms["ask"] = toAny(ask)
	}
	if len(perms) > 0 {
		f.Settings["permissions"] = perms
	}
	if o.Lock && o.Scope == ScopeManaged {
		f.Settings["allowManagedHooksOnly"] = true
		// Claude Code merges every settings file and managed settings come
		// last, so this overrides a disableAllHooks that users set in their
		// own settings, in releases where that would switch managed hooks off.
		f.Settings[disableAllHooks] = false
	}
	return f
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func (f *Fragment) note(format string, args ...any) {
	f.Notes = append(f.Notes, fmt.Sprintf(format, args...))
}

// plainWords matches the command patterns that Claude Code's Bash rules can
// express, which are words separated by single spaces, with no quoting and no
// ? or [ ] wildcards.
var plainWords = regexp.MustCompile(`^[A-Za-z0-9_./@%+=:,*-]+( [A-Za-z0-9_./@%+=:,*-]+)*$`)

// inlineCode are native deny rules approximating denyInterpreters.
var inlineCode = []string{
	"sh -c", "bash -c", "zsh -c", "dash -c", "ksh -c", "eval",
	"python -c", "python3 -c", "node -e", "node -p", "perl -e", "perl -E",
	"ruby -e", "php -r", "pwsh -c", "pwsh -Command", "osascript -e",
}

func (f *Fragment) permissionRules(p *policy.Policy, scope Scope) (deny, ask []string) {
	addFile := func(list *[]string, pat string) {
		cc := nativePath(pat, scope)
		*list = append(*list, "Read("+cc+")", "Edit("+cc+")") // Read deny doesn't cover NotebookEdit
	}
	for _, pat := range p.Spec.Files.Deny {
		addFile(&deny, pat)
	}
	for _, pat := range p.Spec.Files.Ask {
		addFile(&ask, pat)
	}
	addCmd := func(list *[]string, pat string) {
		if strings.Contains(pat, "|") || !plainWords.MatchString(pat) {
			f.note("command pattern %q (pipeline, quoting or ?/[ ] wildcards) has no native equivalent; only the hook enforces it", pat)
			return
		}
		*list = append(*list, "Bash("+pat+" *)")
	}
	for _, pat := range p.Spec.Commands.Deny {
		addCmd(&deny, pat)
	}
	for _, pat := range p.Spec.Commands.Ask {
		addCmd(&ask, pat)
	}
	if p.Spec.Commands.InterpretersDenied() {
		for _, c := range inlineCode {
			deny = append(deny, "Bash("+c+" *)")
		}
		f.note("denyInterpreters: native rules cover only common spellings (%s and others); the hook covers the rest", strings.Join(inlineCode[:3], ", "))
	}
	addMCP := func(list *[]string, pat string) {
		server, tool, hasTool := strings.Cut(pat, "/")
		rule := "mcp__" + server
		if hasTool {
			rule += "__" + tool
		}
		*list = append(*list, rule)
	}
	for _, pat := range p.Spec.MCP.Deny {
		addMCP(&deny, pat)
	}
	for _, pat := range p.Spec.MCP.Ask {
		addMCP(&ask, pat)
	}
	if len(p.Spec.Files.Allow)+len(p.Spec.Commands.Allow)+len(p.Spec.MCP.Allow) > 0 || p.Spec.Defaults.Posture != policy.DenyListed {
		f.note("allow lists and allow-listed posture are enforced only by the hook (native allow rules would skip permission prompts)")
	}
	if p.Spec.Files.Containing != policy.ContainingIgnore {
		f.note("files.containing (directories that contain protected files) is enforced only by the hook")
	}
	f.note("case-insensitive matching, wrappers beyond timeout/time/nice/nohup/stdbuf, and unclassified tools are enforced only by the hook")
	return dedupe(deny), dedupe(ask)
}

// guardRules returns the rules that keep Claude's own file tools away from
// what installs the hook, as builtin.guarded does in the hook. That is every
// Claude Code settings file, the agents, skills, commands and plugins that
// can run hooks of their own, the policy and its signature, the signing key,
// the audit log and the hook binary. One Edit of .claude/settings.local.json
// would switch the hook off. The rules match these folders at any depth,
// including skills below the project, which the hook can't list in advance.
func guardRules(o FragmentOptions) []string {
	rules := []string{"Edit(//**/.claude/settings.json)", "Edit(//**/.claude/settings.local.json)",
		"Edit(//**/.claude/agents/**)", "Edit(//**/.claude/skills/**)", "Edit(//**/.claude/commands/**)",
		"Edit(//**/.claude/plugins/**)"}
	files := []string{o.Policy, o.Policy + ".sig", o.PubKey, o.Audit, o.Command}
	for _, f := range files {
		if pat, ok := nativeFile(f); ok {
			rules = append(rules, "Edit("+pat+")")
		}
	}
	return rules
}

// nativeFile returns a file's path in Claude Code's rule syntax. An absolute
// path becomes "//abs", and a Windows path takes the POSIX form Claude Code
// matches against, so C:\x becomes //c/x. A path under
// ${CLAUDE_PROJECT_DIR} becomes "/rel". Anything else, such as an empty path
// or a command name on PATH, has no rule.
func nativeFile(p string) (string, bool) {
	if rel, ok := strings.CutPrefix(p, "${CLAUDE_PROJECT_DIR}/"); ok {
		return "/" + rel, true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return "//" + strings.ToLower(p[:1]) + "/" + strings.ReplaceAll(p[3:], `\`, "/"), true
	}
	if strings.HasPrefix(p, "/") {
		return "/" + p, true
	}
	return "", false
}

func dedupe(ss []string) []string {
	var out []string
	for _, s := range ss {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// nativePath translates a CyberBoar file pattern into Claude Code's gitignore
// syntax, as "//abs", "~/home", "/project-relative" or cwd-relative. A
// project-relative pattern is used only in project and local settings, where
// "/" anchors at the project.
func nativePath(pat string, scope Scope) string {
	switch {
	case pat == "~" || strings.HasPrefix(pat, "~/"):
		return pat
	case strings.HasPrefix(pat, "/"):
		return "/" + pat
	case strings.HasPrefix(pat, "**/"):
		return "//" + pat // anywhere on the filesystem
	case scope == ScopeProject || scope == ScopeLocal:
		return "/" + pat
	default:
		// User and managed settings have no project anchor. A relative deny
		// rule there matches under the session's working directory instead.
		return pat
	}
}

// Merge adds a fragment to existing settings in the user, project or local
// scope. CyberBoar's previous hook handlers are replaced, and other hooks and
// settings are kept. Permission rules are only added, so rules from an
// earlier apply stay until removed by hand, which errs on the strict side.
//
// Settings that set disableAllHooks are refused. Claude Code runs no hook
// while any settings file sets it, so the hook would never run. The key is
// the user's choice and is left for them to remove.
func Merge(existing []byte, frag map[string]any) ([]byte, error) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(existing))
		dec.UseNumber()
		if err := dec.Decode(&settings); err != nil {
			return nil, fmt.Errorf("existing settings are not a JSON object: %w", err)
		}
		if settings == nil {
			return nil, errors.New("existing settings are null, not a JSON object")
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, errors.New("data after the JSON object")
		}
	}
	if v, ok := settings[disableAllHooks]; ok && v != nil && v != false {
		return nil, fmt.Errorf("the settings set %s, so Claude Code would run no hook; remove the key and apply again", disableAllHooks)
	}
	if err := validateSettings(settings); err != nil {
		return nil, fmt.Errorf("existing settings: %w", err)
	}
	if err := validateSettings(frag); err != nil {
		return nil, fmt.Errorf("settings fragment: %w", err)
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	// CyberBoar's handlers from an earlier apply are removed from every
	// event, so a briefing turned off in the policy is removed too.
	adapters.RemoveHandlers(hooks, ours)
	fragHooks, _ := frag["hooks"].(map[string]any)
	for event, fragGroups := range fragHooks {
		have, _ := hooks[event].([]any)
		hooks[event] = append(have, fragGroups.([]any)...)
	}
	settings["hooks"] = hooks

	if fp, ok := frag["permissions"].(map[string]any); ok {
		perms, _ := settings["permissions"].(map[string]any)
		if perms == nil {
			perms = map[string]any{}
		}
		for _, list := range []string{"deny", "ask"} {
			add, _ := fp[list].([]any)
			have, _ := perms[list].([]any)
			for _, r := range add {
				if !slices.Contains(have, r) {
					have = append(have, r)
				}
			}
			if len(have) > 0 {
				perms[list] = have
			}
		}
		settings["permissions"] = perms
	}
	return Marshal(settings)
}

// Marshal renders settings deterministically, with sorted keys and a
// two-space indent.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
