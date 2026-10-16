package codex

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// In code mode, the model writes a JavaScript script (the custom tool `exec`)
// that calls tools itself, for example
//
//	const r = await tools.exec_command({cmd:"pwd",workdir:"src"});
//	text(r.output);
//
// Codex hooks each nested call, with a tool_use_id that starts with "exec-",
// but the nested call's arguments are only in the script, which the
// transcript holds. The adapter trusts a script only when it is nothing but
// straight-line awaited tool calls with literal arguments. The call the hook
// sees must then be one of them, and no aliasing, computed arguments or
// dead-code decoys can exist. With any other script, the directory and shell
// are unknown, and the call is denied

// scriptCall is one `tools.NAME(args...)` call in a code-mode script
type scriptCall struct {
	name string
	args []any // decoded literals
}

var errScript = errors.New("the code-mode script is not plain literal tool calls")

// parseScript parses the restricted grammar:
//
//	script := { stmt }
//	stmt   := ( ("const"|"let"|"var") IDENT "=" )? "await" call ";"?
//	        | "text" "(" textArg { "+" textArg } ")" ";"?
//	textArg := path | "JSON" "." "stringify" "(" path ")" | string | template
//	template := a backtick string whose ${...} parts are only paths
//	call   := "tools" "." IDENT "(" [ value { "," value } ] ")"
//	path   := IDENT { "." IDENT }
//	value  := JSON literal, with bare identifiers allowed as object keys
func parseScript(src string) (calls []scriptCall, err error) {
	defer func() {
		if recover() != nil {
			calls, err = nil, errScript // a parser bug must never mean "trusted"
		}
	}()
	p := &scriptParser{src: src}
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			return calls, nil
		}
		if p.err != nil {
			return nil, p.err
		}
		switch w := p.ident(); w {
		case "const", "let", "var":
			p.ident()
			p.expect("=")
			if p.ident() != "await" {
				return nil, errScript
			}
			calls = append(calls, p.call())
		case "await":
			calls = append(calls, p.call())
		case "text":
			p.expect("(")
			p.textArg()
			for p.err == nil && p.peek() == '+' {
				p.pos++
				p.textArg()
			}
			p.expect(")")
		default:
			return nil, errScript
		}
		p.skipSpace()
		if p.pos < len(p.src) && p.src[p.pos] == ';' {
			p.pos++
		}
		if p.err != nil {
			return nil, p.err
		}
	}
}

type scriptParser struct {
	src string
	pos int
	err error
}

func (p *scriptParser) fail() { p.err = errScript }

func (p *scriptParser) skipSpace() {
	for p.pos < len(p.src) && strings.IndexByte(" \t\r\n", p.src[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *scriptParser) ident() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) {
		c := rune(p.src[p.pos])
		if c == '_' || c == '$' || unicode.IsLetter(c) && c < 128 || p.pos > start && unicode.IsDigit(c) {
			p.pos++
			continue
		}
		break
	}
	if start == p.pos {
		p.fail()
	}
	return p.src[start:p.pos]
}

func (p *scriptParser) expect(s string) {
	p.skipSpace()
	if p.pos > len(p.src) || !strings.HasPrefix(p.src[p.pos:], s) {
		p.fail()
		return
	}
	p.pos += len(s)
}

func (p *scriptParser) peek() byte {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

// textArg parses what text() may print, which is values and never calls to tools
func (p *scriptParser) textArg() {
	switch p.peek() {
	case '"':
		p.str()
	case '`':
		p.template()
	default:
		if first := p.ident(); first == "JSON" {
			p.expect(".")
			if p.ident() != "stringify" {
				p.fail()
			}
			p.expect("(")
			p.path()
			p.expect(")")
		} else {
			p.pathRest()
		}
	}
}

// template parses `...${path}...` with no nested templates or expressions
func (p *scriptParser) template() {
	p.pos++ // opening backtick
	for p.pos < len(p.src) && p.err == nil {
		switch {
		case p.src[p.pos] == '\\':
			p.pos += 2
		case p.src[p.pos] == '`':
			p.pos++
			return
		case strings.HasPrefix(p.src[p.pos:], "${"):
			p.pos += 2
			p.path()
			p.expect("}")
		default:
			p.pos++
		}
	}
	p.fail()
}

func (p *scriptParser) path() {
	p.ident()
	p.pathRest()
}

func (p *scriptParser) pathRest() {
	for p.peek() == '.' {
		p.pos++
		p.ident()
	}
}

func (p *scriptParser) call() scriptCall {
	if p.ident() != "tools" {
		p.fail()
	}
	p.expect(".")
	c := scriptCall{name: p.ident()}
	p.expect("(")
	if p.peek() != ')' {
		for {
			c.args = append(c.args, p.value(0))
			if p.peek() != ',' {
				break
			}
			p.pos++
		}
	}
	p.expect(")")
	return c
}

// value parses a literal. depth bounds its nesting
func (p *scriptParser) value(depth int) any {
	if depth > 16 || p.err != nil {
		p.fail()
		return nil
	}
	switch c := p.peek(); {
	case c == '"':
		return p.str()
	case c == '{':
		p.pos++
		obj := map[string]any{}
		for p.peek() != '}' {
			var key string
			if p.peek() == '"' {
				key = p.str()
			} else {
				key = p.ident()
			}
			if _, dup := obj[key]; dup {
				p.fail() // with duplicates, which one wins is up to the JS engine
				return nil
			}
			p.expect(":")
			obj[key] = p.value(depth + 1)
			if p.peek() != ',' {
				break
			}
			p.pos++
			if p.err != nil {
				return nil
			}
		}
		p.expect("}")
		return obj
	case c == '[':
		p.pos++
		var arr []any
		for p.peek() != ']' {
			arr = append(arr, p.value(depth+1))
			if p.peek() != ',' {
				break
			}
			p.pos++
			if p.err != nil {
				return nil
			}
		}
		p.expect("]")
		return arr
	default:
		// Numbers, true, false and null must be spelled as in JSON
		start := p.pos
		for p.pos < len(p.src) && strings.IndexByte(",}] \t\r\n)", p.src[p.pos]) < 0 {
			p.pos++
		}
		var v any
		if err := json.Unmarshal([]byte(p.src[start:p.pos]), &v); err != nil {
			p.fail()
			return nil
		}
		if _, isStr := v.(string); isStr {
			p.fail()
		}
		return v
	}
}

// str parses a double-quoted string with JSON escapes (JS-only escapes such
// as \x41 or \u{41} make the script untrusted)
func (p *scriptParser) str() string {
	p.skipSpace()
	start := p.pos
	p.pos++
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\\':
			p.pos += 2
			if p.pos > len(p.src) {
				p.fail()
				return ""
			}
			continue
		case '"':
			p.pos++
			var s string
			if err := json.Unmarshal([]byte(p.src[start:p.pos]), &s); err != nil {
				p.fail()
			}
			return s
		case '\n':
			p.fail()
			return ""
		}
		p.pos++
	}
	p.fail()
	return ""
}

// callFromScript finds the exec_command call in a code-mode script that the
// hook is asking about (its cmd equals the hook's command)
// All matching calls must agree on workdir, shell and environment_id
func callFromScript(src, cmd string) (*execCall, error) {
	calls, err := parseScript(src)
	if err != nil {
		return nil, callError("%v", err)
	}
	var found *execCall
	for _, c := range calls {
		if c.name != "exec_command" {
			continue
		}
		if len(c.args) != 1 {
			return nil, callError("a code-mode exec_command call has %d arguments", len(c.args))
		}
		obj, ok := c.args[0].(map[string]any)
		if !ok {
			return nil, callError("a code-mode exec_command argument is not an object")
		}
		if err := checkArgKeys(slices.Collect(maps.Keys(obj))); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(obj)
		var ec execCall
		if err := json.Unmarshal(raw, &ec); err != nil {
			return nil, callError("a code-mode exec_command call has unexpected arguments (%v)", err)
		}
		if ec.Cmd != cmd {
			continue
		}
		if found != nil && (deref(found.Workdir) != deref(ec.Workdir) || deref(found.Shell) != deref(ec.Shell) ||
			deref(found.EnvironmentID) != deref(ec.EnvironmentID)) {
			return nil, callError("the code-mode script runs this command in more than one way")
		}
		if found != nil && found.Tty != nil && *found.Tty {
			ec.Tty = found.Tty // any of the calls may be the one with a terminal
		}
		found = &ec
	}
	if found == nil {
		return nil, callError("the code-mode script has no literal exec_command call for this command")
	}
	return found, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
