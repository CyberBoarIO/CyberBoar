package policy

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"cyberboar.dev/cyberboar/internal/policy/cmdpattern"
)

// validatePatterns checks what the schema cannot, which is pattern syntax and
// patterns that would load fine but never match anything, a silent no-op rule
// A file pattern is checked in the form translateDrive gives it, and an error
// quotes it as written
func validatePatterns(p *Policy) error {
	for _, l := range ruleLists("spec.files", p.Spec.Files.Rules) {
		for i, pat := range l.patterns {
			if err := validateFilePattern(translateDrive(pat)); err != nil {
				return newError(CodePattern, fmt.Sprintf("%s[%d]", l.path, i), "%q: %v", pat, err)
			}
		}
	}
	for _, l := range ruleLists("spec.mcp", p.Spec.MCP) {
		for i, pat := range l.patterns {
			if err := validateMCPPattern(pat); err != nil {
				return newError(CodePattern, fmt.Sprintf("%s[%d]", l.path, i), "%q: %v", pat, err)
			}
		}
	}
	for _, l := range ruleLists("spec.commands", p.Spec.Commands.Rules) {
		for i, pat := range l.patterns {
			cp, err := cmdpattern.Parse(pat)
			if err == nil && l.path == "spec.commands.allow" && len(cp.Stages) > 1 {
				err = fmt.Errorf("allow rules must be single commands; every command in a pipeline is checked on its own")
			}
			if err != nil {
				return newError(CodePattern, fmt.Sprintf("%s[%d]", l.path, i), "%q: %v", pat, err)
			}
		}
	}
	return nil
}

type ruleList struct {
	path     string
	patterns []string
}

// ruleLists returns each rule list with its document path, in a fixed order
func ruleLists(prefix string, r Rules) []ruleList {
	return []ruleList{{prefix + ".allow", r.Allow}, {prefix + ".ask", r.Ask}, {prefix + ".deny", r.Deny}}
}

// validateFilePattern enforces the anchoring forms of file patterns: "/abs",
// "~/home-relative", "**/anywhere", or workspace-relative
func validateFilePattern(pat string) error {
	rest := pat
	switch {
	case pat == "~":
		return nil
	case strings.HasPrefix(pat, "~/"):
		rest = pat[2:]
	case strings.HasPrefix(pat, "~"):
		return fmt.Errorf(`only "~/" (the current user's home) is supported`)
	case strings.HasPrefix(pat, "/"):
		rest = pat[1:]
	case len(pat) >= 2 && pat[1] == ':' && isLetter(pat[0]):
		// translateDrive leaves C:x, which is relative to that drive's
		// current directory. Read as workspace-relative, it would never match
		return fmt.Errorf(`a drive-relative path depends on the drive's current directory; use a drive path such as %c:\x or /%c/x`, pat[0], pat[0]|0x20)
	case strings.HasPrefix(pat, `\\`):
		return fmt.Errorf("UNC paths are not supported")
	}
	if err := checkBackslashes(pat); err != nil {
		return err
	}
	for _, alt := range leadingAlternatives(pat) {
		if strings.HasPrefix(alt, "~") || strings.HasPrefix(alt, "/") || strings.HasPrefix(alt, "**/") ||
			len(alt) >= 2 && alt[1] == ':' && isLetter(alt[0]) {
			return fmt.Errorf(`a pattern that starts with "{" is relative to the workspace, and so is its alternative %q: write it as a pattern of its own`, alt)
		}
	}
	if strings.HasSuffix(pat, "/") {
		return fmt.Errorf(`trailing "/" never matches; to match a directory's contents, end with "/**"`)
	}
	for _, seg := range strings.Split(rest, "/") {
		switch seg {
		case "":
			return fmt.Errorf(`empty path segment ("//") never matches`)
		case ".", "..":
			return fmt.Errorf(`%q segments never match; paths are cleaned before matching`, seg)
		}
	}
	if !doublestar.ValidatePattern(rest) {
		return fmt.Errorf("malformed glob")
	}
	return nil
}

// checkBackslashes refuses a "\" outside a bracket expression. Drive paths
// have been rewritten by translateDrive, and anywhere else a "\"
// escapes the next character, so a pattern written with Windows separators
// quietly becomes another one: "**\.env*" is "**.env*", a name at the
// workspace root, and "config\*.json" names a literal "config*.json". Windows
// names can't hold the characters worth escaping, and a bracket expression
// such as [*] matches them literally on other systems
func checkBackslashes(pat string) error {
	inClass := false
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; {
		case c == '\\' && !inClass:
			return fmt.Errorf(`a backslash escapes the next character outside a drive path such as C:\x, so separate names with "/" and write a literal * ? [ { } or , in brackets, such as [*]`)
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		}
	}
	return nil
}

// leadingAlternatives returns the alternatives of a brace group at the start
// of pat, and those of groups at the start of an alternative, in order. It
// returns nil when pat doesn't start with a group or the group doesn't close,
// which doublestar.ValidatePattern reports
func leadingAlternatives(pat string) []string {
	if !strings.HasPrefix(pat, "{") {
		return nil
	}
	var alts []string
	depth, inClass, from := 0, false, 1
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; {
		case c == '\\':
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '{':
			depth++
		case c == ',' && depth == 1:
			alts = append(alts, pat[from:i])
			from = i + 1
		case c == '}':
			if depth--; depth == 0 {
				alts = append(alts, pat[from:i])
				var nested []string
				for _, a := range alts {
					nested = append(nested, leadingAlternatives(a)...)
				}
				return append(alts, nested...)
			}
		}
	}
	return nil
}

// validateMCPPattern checks each "server" or "tool" segment is a valid glob
// The schema has already enforced the "server" / "server/tool" shape
func validateMCPPattern(pat string) error {
	for _, seg := range strings.Split(pat, "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("malformed glob")
		}
	}
	return nil
}

// MinTripwireWindow is the shortest tripwire window
// A shorter one would reset the count between two quick retries
const MinTripwireWindow = time.Minute

// Endpoint intervals bound the request rate even when the policy sets it
const (
	MinShipInterval = time.Second
	MinPullInterval = 10 * time.Second
)

func validateSync(p *Policy) error {
	for _, interval := range []struct {
		field, value string
		minimum      time.Duration
	}{
		{"shipEvery", p.Spec.Sync.ShipEvery, MinShipInterval},
		{"pullEvery", p.Spec.Sync.PullEvery, MinPullInterval},
	} {
		if interval.value == "" {
			continue
		}
		d, err := time.ParseDuration(interval.value)
		if err != nil || d != 0 && d < interval.minimum {
			return newError(CodePattern, "spec.sync."+interval.field, "%q: must be a Go duration of at least %s, or 0s for one run", interval.value, interval.minimum)
		}
	}
	return nil
}

// validateSession checks what the schema cannot about session settings
func validateSession(p *Policy) error {
	w := p.Spec.Session.Tripwire.Window
	if w == "" {
		return nil
	}
	d, err := time.ParseDuration(w)
	if err != nil || d < MinTripwireWindow {
		return newError(CodePattern, "spec.session.tripwire.window", "%q: the window must be at least %s (leave it out to count the whole session)", w, MinTripwireWindow)
	}
	return nil
}

// translateDrivePatterns applies translateDrive to every file pattern
func translateDrivePatterns(r *Rules) {
	for _, list := range [][]string{r.Allow, r.Ask, r.Deny} {
		for i, pat := range list {
			list[i] = translateDrive(pat)
		}
	}
}

// translateDrive rewrites a file pattern written as a Windows drive path,
// C:\x or C:/x, into the engine's form /c/x, and returns any other pattern
// unchanged. After a drive, "\" separates names, so it can't escape a glob
// character there. Windows names can't hold * or ?, and a [ or { in such a
// pattern is glob syntax
func translateDrive(pat string) string {
	if len(pat) >= 3 && pat[1] == ':' && isLetter(pat[0]) && (pat[2] == '\\' || pat[2] == '/') {
		return "/" + strings.ToLower(pat[:1]) + "/" + strings.ReplaceAll(pat[3:], `\`, "/")
	}
	return pat
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
