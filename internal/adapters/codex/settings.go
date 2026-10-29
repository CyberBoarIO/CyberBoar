package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/internal/winpath"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// ManagedDir is where Codex reads managed requirements (requirements.toml)
// and system configuration outside Windows.
const ManagedDir = "/etc/codex"

// WindowsManagedDir is ManagedDir on Windows: OpenAI\Codex in the
// ProgramData folder, programData, or in C:\ProgramData when it is unset.
func WindowsManagedDir(programData string) string {
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return adapters.Under(true, programData, "OpenAI", "Codex")
}

// Scope is where Codex hook configuration lives.
type Scope string

// The scopes apply installs into, by the settings file each one writes.
const (
	ScopeUser    Scope = "user"    // ~/.codex/hooks.json
	ScopeProject Scope = "project" // <repo>/.codex/hooks.json (committed)
	ScopeManaged Scope = "managed" // /etc/codex/requirements.toml
)

// HookTimeout is the Codex hook timeout in seconds. The hook's own deadline
// must stay well below it, because a hook killed by the timeout fails open.
const HookTimeout = 10

// statusMessage and briefingMessage mark CyberBoar's own handlers in hooks.json.
const (
	statusMessage   = brand.Name + ": checking policy"
	briefingMessage = brand.Name + ": briefing"
)

// FragmentOptions describe the hook command to install.
type FragmentOptions struct {
	Scope    Scope
	Command  string // cyberboar executable, as an absolute path or a name on PATH
	Policy   string // policy path, relative to the repository root for ScopeProject
	Audit    string
	State    string // the hook's --state, or "" for its default
	PubKey   string // policy signing public key, or ""
	Deadline string
	Lock     bool // in managed scope, set allow_managed_hooks_only
	Briefing bool // install the SessionStart briefing (the policy's spec.session.briefing)
	// Windows makes the hook a command line for cmd.exe, which Codex runs
	// hooks with on Windows; its paths are Windows paths (CheckWindows).
	Windows bool
}

// HookCommand returns the shell command line Codex runs for the hook. Codex
// runs hook commands through a shell in the session cwd.
// A project-scope policy is found from the git root, as the Codex docs recommend.
func HookCommand(o FragmentOptions) string {
	q := quoter(o)
	cmd := program(o) + " hook --agent codex --policy " + policyArg(o)
	if o.Audit != "" {
		cmd += " --audit " + q(o.Audit)
	}
	if o.State != "" {
		cmd += " --state " + q(o.State)
	}
	if o.PubKey != "" {
		cmd += " --pubkey " + q(o.PubKey)
	}
	return cmd + " --deadline " + q(o.Deadline)
}

// policyArg returns the --policy value as the shell sees it.
func policyArg(o FragmentOptions) string {
	if o.Scope == ScopeProject && !o.Windows {
		return `"$(git rev-parse --show-toplevel)"/` + adapters.ShellQuote(o.Policy)
	}
	return quoter(o)(o.Policy)
}

// BriefCommand returns the shell command line for the SessionStart briefing.
func BriefCommand(o FragmentOptions) string {
	cmd := program(o) + " brief --agent codex --policy " + policyArg(o)
	if o.PubKey != "" {
		cmd += " --pubkey " + quoter(o)(o.PubKey)
	}
	return cmd
}

// quoter returns how a value is quoted in the hook's command line: for a
// POSIX shell, or on Windows in double quotes, which PowerShell, cmd.exe and
// the program's own argument parsing all take literally (CheckWindows).
func quoter(o FragmentOptions) func(string) string {
	if o.Windows {
		return func(s string) string { return `"` + s + `"` }
	}
	return adapters.ShellQuote
}

// program returns the hook's executable as its command line starts. On
// Windows it stays unquoted: PowerShell reads a quoted first word as a
// string, not a command (CheckWindows).
func program(o FragmentOptions) string {
	if o.Windows {
		return o.Command
	}
	return adapters.ShellQuote(o.Command)
}

// bareProgram matches the program paths that PowerShell and cmd.exe both
// read as one plain word.
var bareProgram = regexp.MustCompile(`^[\p{L}\p{N}_.~:\\-]+$`)

// BareWindowsProgram reports whether path can start the hook's command line
// on Windows unquoted (CheckWindows).
func BareWindowsProgram(path string) bool {
	return bareProgram.MatchString(path)
}

// CheckWindows reports a hook that can't be installed on Windows. Codex runs
// it in the session's shell, PowerShell (pwsh -NoProfile -Command), and
// without one with `cmd.exe /C "…"`. The program must be a plain word, since
// PowerShell reads a quoted first word as a string, and cmd.exe can't take
// the call operator (&) that would make it a command. The other values go in
// double quotes, which stay literal in both unless they hold a quote
// (PowerShell also counts “ ” „), a $ or ` (PowerShell expands them), a % (cmd
// expands %VAR%) or a line break, or end in a backslash, which would escape
// the closing quote. There is no git root to find a project's policy from either.
func CheckWindows(o FragmentOptions) error {
	if o.Scope == ScopeProject {
		return errors.New("--scope project is not supported for Codex on Windows, which runs hooks in PowerShell or cmd.exe, where the policy can't be found from the git root; use --scope user")
	}
	if !BareWindowsProgram(o.Command) {
		return fmt.Errorf("%q can't start a Codex hook on Windows, where PowerShell and cmd.exe run it: put %s.exe in a folder "+
			"whose path has only letters, digits and _ . ~ - (no spaces), or pass that path with --command", o.Command, brand.Name)
	}
	for _, v := range []string{o.Policy, o.Audit, o.State, o.PubKey, o.Deadline} {
		if strings.ContainsAny(v, "\"“”„$`%\r\n") || strings.HasSuffix(v, `\`) {
			return fmt.Errorf("%q can't be written into a Codex hook command line on Windows (no quotes, $, `, %%, line breaks or a trailing \\)", v)
		}
	}
	return nil
}

func handler(o FragmentOptions) map[string]any {
	return withWindows(o, map[string]any{"type": "command", "command": HookCommand(o), "timeout": HookTimeout, "statusMessage": statusMessage})
}

func briefHandler(o FragmentOptions) map[string]any {
	return withWindows(o, map[string]any{"type": "command", "command": BriefCommand(o), "timeout": HookTimeout, "statusMessage": briefingMessage})
}

// withWindows gives a Windows handler its command as commandWindows too,
// which Codex runs instead of command on Windows.
func withWindows(o FragmentOptions, h map[string]any) map[string]any {
	if o.Windows {
		h["commandWindows"] = h["command"]
	}
	return h
}

// MergeHooksJSON adds CyberBoar's PreToolUse handler to a hooks.json,
// replacing one a previous apply installed and keeping everything else.
func MergeHooksJSON(existing []byte, o FragmentOptions) ([]byte, error) {
	doc := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(existing))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("existing hooks.json is not a JSON object: %w", err)
		}
		if doc == nil {
			return nil, errors.New("existing hooks.json is null, not a JSON object")
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, errors.New("data after the JSON object")
		}
	}
	hooks := map[string]any{}
	if value, present := doc["hooks"]; present {
		var ok bool
		hooks, ok = value.(map[string]any)
		if !ok {
			return nil, errors.New("existing hooks.json: hooks is not an object")
		}
	}
	if err := validateHooks(hooks); err != nil {
		return nil, err
	}
	// CyberBoar's handlers from an earlier apply are removed from every
	// event, so a briefing turned off in the policy is removed too
	adapters.RemoveHandlers(hooks, func(h map[string]any) bool {
		return h["statusMessage"] == statusMessage || h["statusMessage"] == briefingMessage
	})
	// The handler has no matcher, so it runs for every tool, including MCP tools and apply_patch
	pre, _ := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{"hooks": []any{handler(o)}})
	if o.Briefing {
		// The briefing has no matcher, so it runs on startup, resume, clear, compact and fork
		start, _ := hooks["SessionStart"].([]any)
		hooks["SessionStart"] = append(start, map[string]any{"hooks": []any{briefHandler(o)}})
	}
	doc["hooks"] = hooks
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// validateHooks checks retained event groups and handlers before the merge changes them.
// Unknown properties and events are preserved.
func validateHooks(hooks map[string]any) error {
	for _, event := range slices.Sorted(maps.Keys(hooks)) {
		groups, ok := hooks[event].([]any)
		if !ok {
			return fmt.Errorf("hooks.%s is not a list", event)
		}
		for i, value := range groups {
			where := fmt.Sprintf("hooks.%s[%d]", event, i)
			group, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s is not an object", where)
			}
			if matcher, present := group["matcher"]; present && matcher != nil {
				if _, ok := matcher.(string); !ok {
					return fmt.Errorf("%s.matcher is not a string", where)
				}
			}
			handlers, ok := group["hooks"].([]any)
			if !ok {
				return fmt.Errorf("%s.hooks is not a list", where)
			}
			for j, value := range handlers {
				where := fmt.Sprintf("%s.hooks[%d]", where, j)
				handler, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("%s is not an object", where)
				}
				if err := validateHandler(handler, where); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateHandler(handler map[string]any, where string) error {
	kind, ok := handler["type"].(string)
	if !ok {
		return fmt.Errorf("%s.type is not a string", where)
	}
	var required []string
	switch kind {
	case "command":
		required = []string{"command"}
	case "mcp_tool":
		required = []string{"server", "tool"}
		if input, present := handler["input"]; present && input != nil {
			if _, ok := input.(map[string]any); !ok {
				return fmt.Errorf("%s.input is not an object", where)
			}
		}
	case "prompt", "agent":
		// Codex parses these definitions even though it currently skips running them
		required = []string{"prompt"}
	default:
		return fmt.Errorf("%s.type %q is unsupported", where, kind)
	}
	for _, field := range required {
		text, ok := handler[field].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("%s.%s must be a nonempty string", where, field)
		}
	}
	for _, field := range []string{"statusMessage", "commandWindows", "model"} {
		if value, present := handler[field]; present && value != nil {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s.%s is not a string", where, field)
			}
		}
	}
	for _, field := range []string{"timeout", "additionalContextLimit"} {
		if value, present := handler[field]; present && value != nil {
			if _, ok := value.(json.Number); !ok {
				return fmt.Errorf("%s.%s is not a number", where, field)
			}
		}
	}
	if value, present := handler["async"]; present {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s.async is not a boolean", where)
		}
	}
	return nil
}

// RequirementsHeader starts every requirements.toml this package writes, so a
// later apply knows it may replace the file.
const RequirementsHeader = "# Generated by `" + brand.Name + " apply --agent codex --scope managed`; changes are overwritten.\n"

// literalWords matches the command patterns that Codex's prefix_rule can
// express, which are plain words with no globs, quotes or pipelines.
var literalWords = regexp.MustCompile(`^[A-Za-z0-9_./@%+=:,-]+( [A-Za-z0-9_./@%+=:,-]+)*$`)

// Requirements builds /etc/codex/requirements.toml. It installs the hook as a
// managed hook, which policy trusts and the user can't disable, pins hooks
// on, and adds the policy's literal command deny and ask rules as
// prefix_rules, which Codex enforces even if the hook can't run. The notes it
// returns list what only the hook enforces.
func Requirements(p *policy.Policy, o FragmentOptions) ([]byte, []string) {
	var b strings.Builder
	var notes []string
	b.WriteString(RequirementsHeader)
	if o.Lock {
		b.WriteString("allow_managed_hooks_only = true\n")
	}
	b.WriteString("\n[features]\nhooks = true\n")
	switch _, abs, _ := winpath.Path(o.Command); {
	case o.Windows && abs:
		fmt.Fprintf(&b, "\n[hooks]\nwindows_managed_dir = %s\n", tomlString(o.Command[:strings.LastIndexAny(o.Command, `\/`)]))
	case !o.Windows && filepath.IsAbs(o.Command):
		fmt.Fprintf(&b, "\n[hooks]\nmanaged_dir = %s\n", tomlString(filepath.Dir(o.Command)))
	}
	command := func(line string) string {
		s := "command = " + tomlString(line) + "\n"
		if o.Windows {
			s += "command_windows = " + tomlString(line) + "\n"
		}
		return s
	}
	b.WriteString("\n[[hooks.PreToolUse]]\n\n[[hooks.PreToolUse.hooks]]\n")
	fmt.Fprintf(&b, "type = \"command\"\n%stimeout = %d\nstatusMessage = %s\n",
		command(HookCommand(o)), HookTimeout, tomlString(statusMessage))
	if p.Spec.Session.Briefing.On() {
		b.WriteString("\n[[hooks.SessionStart]]\n\n[[hooks.SessionStart.hooks]]\n")
		fmt.Fprintf(&b, "type = \"command\"\n%stimeout = %d\nstatusMessage = %s\n",
			command(BriefCommand(o)), HookTimeout, tomlString(briefingMessage))
	}

	var rules []string
	add := func(pat, decision string) {
		if !literalWords.MatchString(pat) {
			notes = append(notes, fmt.Sprintf("command pattern %q (pipeline, quoting or wildcards) has no prefix_rule equivalent; only the hook enforces it", pat))
			return
		}
		var toks []string
		for w := range strings.FieldsSeq(pat) {
			toks = append(toks, "{ token = "+tomlString(w)+" }")
		}
		rules = append(rules, fmt.Sprintf("  { pattern = [%s], decision = %s, justification = %s },",
			strings.Join(toks, ", "), tomlString(decision), tomlString(brand.Name+" policy "+p.Metadata.Name+": "+pat)))
	}
	for _, pat := range p.Spec.Commands.Deny {
		add(pat, "forbidden")
	}
	for _, pat := range p.Spec.Commands.Ask {
		add(pat, "prompt")
	}
	if len(rules) > 0 {
		b.WriteString("\n[rules]\nprefix_rules = [\n" + strings.Join(rules, "\n") + "\n]\n")
	}
	notes = append(notes,
		"prefix_rules match case-sensitively and only simple command chains; the hook covers the rest",
		"file rules, MCP rules, denyInterpreters and allow lists are enforced only by the hook")
	return []byte(b.String()), notes
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
