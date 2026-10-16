package engine

import (
	"fmt"
	"path"
	"strings"
	"unicode/utf16"

	"cyberboar.dev/cyberboar/internal/fold"
	"cyberboar.dev/cyberboar/internal/policy"
)

// mcpRule is a compiled MCP rule. id is the rule ID verdicts report
type mcpRule struct {
	id           string
	server, tool string // globs, where tool "" matches every tool
	// The globs as they match names an agent rewrote (MCPCall.Names)
	opencodeServer, opencodeTool             string
	copilotServer, copilotTool               string
	copilotUnicodeServer, copilotUnicodeTool string
	codexServer, codexTool                   string
}

// mcpRules holds the compiled MCP rules by kind
type mcpRules struct {
	deny, ask, allow []mcpRule
}

// compileMCPRules compiles the MCP patterns of a policy. Rule IDs number each
// list from zero: mcp.deny[0], mcp.ask[0] and so on
func compileMCPRules(r policy.Rules) mcpRules {
	build := func(list string, pats []string) []mcpRule {
		out := make([]mcpRule, len(pats))
		for i, p := range pats {
			server, tool, _ := strings.Cut(p, "/")
			out[i] = mcpRule{id: fmt.Sprintf("mcp.%s[%d]", list, i), server: server, tool: tool,
				opencodeServer: opencodeGlob(server), opencodeTool: opencodeGlob(tool),
				copilotServer: copilotGlob(server, false), copilotTool: copilotGlob(tool, false),
				copilotUnicodeServer: copilotGlob(server, true), copilotUnicodeTool: copilotGlob(tool, true),
				codexServer: codexGlob(server), codexTool: codexGlob(tool)}
		}
		return out
	}
	return mcpRules{deny: build("deny", r.Deny), ask: build("ask", r.Ask), allow: build("allow", r.Allow)}
}

// match reports whether the rule covers the call. Every rule matches its
// globs as written against the names as written. With folded (deny and ask
// rules), the folded globs against the folded names also count, which ignores
// case. Folding a bracket expression can change what it holds ([A-z] becomes
// [a-z]), so the folded form only adds matches to the written one. For
// names an agent rewrote, deny and ask rules also match with their globs
// rewritten the same way, so a rule for write.file still covers write_file
func (r mcpRule) match(c MCPCall, folded bool) bool {
	ok, err := r.matchNames(r.server, r.tool, c, folded)
	if err == nil && !ok && folded {
		switch c.Names {
		case NamesOpencode:
			ok, err = r.matchNames(r.server, r.opencodeTool, c, folded)
		case NamesClaudeCode:
			// The server is as configured when the hook input names it
			ok, err = r.matchNames(r.server, r.opencodeTool, c, folded)
			if err == nil && !ok {
				ok, err = r.matchNames(r.opencodeServer, r.opencodeTool, c, folded)
			}
		case NamesCopilot:
			server, tool := r.copilotServer, r.copilotTool
			// Punycode can move the literals around a wildcard. Widen only
			// names that could contain an encoded part
			if strings.Contains(strings.ToLower(c.Server), "xn--") {
				server = r.copilotUnicodeServer
			}
			if strings.Contains(strings.ToLower(c.Tool), "xn--") {
				tool = r.copilotUnicodeTool
			}
			if len(c.Server)+1+len(c.Tool) >= copilotNameMax {
				tool = "" // the tool's name may have been cut short
			}
			ok, err = r.matchNames(server, tool, c, folded)
		case NamesCodex:
			ok, err = r.matchCodex(c, folded)
		}
	}
	if err != nil {
		// Patterns are validated at load, so an error here is a bug
		// It counts as a match only for deny and ask rules
		return folded
	}
	return ok
}

func (r mcpRule) matchNames(rs, rt string, c MCPCall, folded bool) (bool, error) {
	ok, err := matchMCP(rs, rt, c.Server, c.Tool)
	if err == nil && !ok && folded {
		ok, err = matchMCP(fold.String(rs), fold.String(rt), fold.String(c.Server), fold.String(c.Tool))
	}
	return ok, err
}

// copilotNameMax is the length Copilot CLI cuts server-tool names to
const copilotNameMax = 64

// matchCodex matches Codex's names. Codex adds "_" and 12 hex digits to a name
// that would collide with another or be too long, after cutting it short, so
// a server with that suffix also matches without it, and a tool with it may
// be any tool of the server
func (r mcpRule) matchCodex(c MCPCall, folded bool) (bool, error) {
	tool := r.codexTool
	if codexHashed(c.Tool) {
		tool = ""
	}
	ok, err := r.matchNames(r.codexServer, tool, c, folded)
	if err == nil && !ok && codexHashed(c.Server) {
		c.Server = c.Server[:len(c.Server)-codexHashLen]
		ok, err = r.matchNames(r.codexServer, tool, c, folded)
	}
	return ok, err
}

// codexHashLen is the length of Codex's hash suffix, "_" and 12 hex digits
const codexHashLen = 13

func codexHashed(name string) bool {
	if len(name) < codexHashLen || name[len(name)-codexHashLen] != '_' {
		return false
	}
	for _, c := range name[len(name)-codexHashLen+1:] {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// opencodeGlob rewrites a tool glob the way opencode rewrites tool names: a
// literal character outside [A-Za-z0-9_-] becomes "_", or "__" if UTF-16
// needs two code units for it. A "?" becomes "?*" so it also covers a
// character that became "__"
func opencodeGlob(p string) string {
	return substGlob(p, nameChar, "?*", func(r rune) string {
		if utf16.RuneLen(r) == 2 {
			return "__"
		}
		return "_"
	})
}

// codexGlob rewrites a server or tool glob the way Codex rewrites MCP names
// (sanitize_responses_api_tool_name in codex-rs): a literal character outside
// [A-Za-z0-9_], "-" among them, becomes "_"
func codexGlob(p string) string {
	return substGlob(p, codexChar, "?", func(rune) string { return "_" })
}

// substGlob replaces each literal character of a glob that keep refuses with
// sub of it, and each "?" with question. A bracket expression that could match
// such a character, or that is negated, becomes "*", which only matches more.
// The result serves deny and ask rules, where matching more is the safe side
func substGlob(p string, keep func(rune) bool, question string, sub func(rune) string) string {
	var b strings.Builder
	lit := func(r rune) {
		if keep(r) {
			b.WriteRune(r)
		} else {
			b.WriteString(sub(r))
		}
	}
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case '*':
			b.WriteRune(r)
		case '?':
			b.WriteString(question)
		case '\\':
			if i+1 < len(rs) {
				i++
				if keep(rs[i]) {
					b.WriteByte('\\')
				}
				lit(rs[i])
			}
		case '[':
			end, plain := bracket(rs[i+1:], keep)
			if end < 0 {
				// Not valid: the policy loader rejects it
				b.WriteString(string(rs[i:]))
				return b.String()
			}
			if plain {
				b.WriteString(string(rs[i : i+end+2]))
			} else {
				b.WriteByte('*')
			}
			i += end + 1
		default:
			lit(r)
		}
	}
	return b.String()
}

// bracket returns the index of the "]" that closes a bracket expression whose
// body starts rs, or -1, and whether the expression only holds characters
// keep accepts and isn't negated. A range counts as plain when both ends
// are letters of one case or both are digits
// The syntax is path.Match's
func bracket(rs []rune, keep func(rune) bool) (end int, plain bool) {
	i := 0
	plain = true
	if i < len(rs) && rs[i] == '^' {
		plain = false
		i++
	}
	char := func() (rune, bool) {
		if i < len(rs) && rs[i] == '\\' {
			i++
		}
		if i >= len(rs) {
			return 0, false
		}
		i++
		return rs[i-1], true
	}
	for n := 0; ; n++ {
		if i >= len(rs) {
			return -1, false
		}
		if rs[i] == ']' && n > 0 {
			return i, plain
		}
		lo, ok := char()
		hi := lo
		if ok && i < len(rs) && rs[i] == '-' {
			i++
			hi, ok = char()
		}
		switch {
		case !ok:
			return -1, false
		case lo == hi && !keep(lo), lo != hi && !sameClass(lo, hi):
			plain = false
		}
	}
}

// copilotGlob over-approximates how Copilot CLI rewrites a server or tool
// glob. Copilot replaces an ASCII character outside [A-Za-z0-9_-] with "-",
// and writes a part of the name that holds a non-ASCII character in punycode,
// which moves its characters. So every such ASCII character becomes "*", and
// so does each run between them that holds a non-ASCII character, or a
// bracket expression that could match one. "*" only matches more, which is
// the safe side for deny and ask rules. For a reported name with punycode,
// wildcards may stand for Unicode too, so their whole run becomes "*"
func copilotGlob(p string, punycode bool) string {
	var b, run strings.Builder
	wild := false // the run must become "*"
	flush := func() {
		if wild {
			b.WriteByte('*')
		} else {
			b.WriteString(run.String())
		}
		run.Reset()
		wild = false
	}
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '*' || r == '?':
			run.WriteRune(r)
			wild = wild || punycode
		case r == '\\' && i+1 < len(rs):
			i++
			switch e := rs[i]; {
			case nameChar(e):
				run.WriteRune('\\')
				run.WriteRune(e)
			case e < 0x80:
				flush()
				b.WriteByte('*')
			default:
				wild = true
			}
		case r == '[':
			end, plain := bracket(rs[i+1:], nameChar)
			if end < 0 {
				run.WriteString(string(rs[i:])) // not valid: the policy loader rejects it
				i = len(rs)
				continue
			}
			if plain {
				run.WriteString(string(rs[i : i+end+2]))
			} else {
				wild = true
			}
			i += end + 1
		case nameChar(r):
			run.WriteRune(r)
		case r < 0x80:
			flush()
			b.WriteByte('*')
		default:
			wild = true
		}
	}
	flush()
	return b.String()
}

// codexChar reports whether Codex keeps r in an MCP name
func codexChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
}

func nameChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-'
}

func sameClass(lo, hi rune) bool {
	for _, c := range [][2]rune{{'a', 'z'}, {'A', 'Z'}, {'0', '9'}} {
		if lo >= c[0] && hi <= c[1] {
			return true
		}
	}
	return false
}

// matchMCP reports whether the server glob rs and the tool glob rt cover server and tool
// An empty rt covers every tool
func matchMCP(rs, rt, server, tool string) (bool, error) {
	ok, err := path.Match(rs, server)
	if err != nil || !ok || rt == "" {
		return ok, err
	}
	return path.Match(rt, tool)
}

// firstMCP returns the ID of the first rule that covers the call
func firstMCP(rules []mcpRule, c MCPCall, folded bool) (string, bool) {
	for _, r := range rules {
		if r.match(c, folded) {
			return r.id, true
		}
	}
	return "", false
}

// evalMCP decides a call to an MCP tool
func (c *Compiled) evalMCP(a Action) Verdict {
	name := a.MCP.Server + "/" + a.MCP.Tool
	if id, ok := firstMCP(c.mcp.deny, a.MCP, true); ok {
		return deny(id, fmt.Sprintf("the MCP tool %s is blocked by policy rule %s; do not attempt alternative ways to call it", name, id))
	}
	if id, ok := firstMCP(c.mcp.ask, a.MCP, true); ok {
		return Verdict{Decision: Ask, Rule: id, Reason: fmt.Sprintf("the MCP tool %s needs confirmation (policy rule %s)", name, id)}
	}
	if !c.allowListed(c.policy.Spec.MCP) {
		return allowNoRule()
	}
	if id, ok := firstMCP(c.mcp.allow, a.MCP, false); ok {
		return Verdict{Decision: Allow, Rule: id, Reason: "allowed by policy rule " + id}
	}
	return deny(RulePostureAllowListed, fmt.Sprintf("the MCP tool %s is not on the MCP allow list; do not attempt alternative ways to call it", name))
}
