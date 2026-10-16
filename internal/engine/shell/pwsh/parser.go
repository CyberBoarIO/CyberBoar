package pwsh

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

// Error reports a command line this package can't read, because of a syntax
// error, a construct it refuses (Refused) or a limit
// It wraps shell.ErrUnparseable, or shell.ErrTooLarge or shell.ErrTooComplex for a
// limit, so the engine treats it as it treats bash it can't analyze
type Error struct {
	Offset  int // in UTF-16 units, as PowerShell counts
	Msg     string
	Refused bool // valid PowerShell this package doesn't analyze
	limit   error
}

// Error returns the message, prefixed with the offset in UTF-16 units
func (e *Error) Error() string {
	if e.Refused {
		return fmt.Sprintf("PowerShell at offset %d: not analyzed: %s", e.Offset, e.Msg)
	}
	return fmt.Sprintf("PowerShell at offset %d: %s", e.Offset, e.Msg)
}

// Unwrap returns the shell error the engine knows
func (e *Error) Unwrap() error {
	if e.limit != nil {
		return e.limit
	}
	return shell.ErrUnparseable
}

// maxNesting bounds the parser's recursion. Each level of parentheses, braces
// or nested statements costs a few units. PowerShell's own limit is the size
// of its stack
const maxNesting = 200

// Parse parses a PowerShell command line as PowerShell's
// Parser.ParseInput does, into a ScriptBlock. It fails, wrapping
// shell.ErrUnparseable, on anything PowerShell would report as an error and
// on constructs this package refuses to analyze (see docs/powershell.md)
// Whatever PowerShell would run is either read the way PowerShell reads it,
// or not at all. Input over shell.MaxBytes, or with more than
// shell.MaxCommands commands, fails with the shell package's limit errors
func Parse(src string) (sb *ScriptBlock, err error) {
	if len(src) > shell.MaxBytes {
		return nil, &Error{Msg: "command line is too large", limit: shell.ErrTooLarge}
	}
	if !utf8.ValidString(src) {
		return nil, &Error{Msg: "command line is not valid UTF-8"}
	}
	if i := strings.IndexByte(src, 0); i >= 0 {
		return nil, &Error{Offset: len(utf16.Encode([]rune(src[:i]))), Msg: "NUL in a command line", Refused: true}
	}
	u := utf16.Encode([]rune(src))
	p := &parser{lx: &lexer{src: u}, src: u}
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(*Error)
			if !ok {
				panic(r)
			}
			sb, err = nil, e
		}
	}()
	sb = p.scriptBlockRule(nil, false)
	if e := check(sb); e != nil {
		return nil, e
	}
	return sb, nil
}

type parser struct {
	lx           *lexer
	src          []uint16 // the whole input, while lx may scan a string's $(...)
	lines        []int    // the offsets in src where lines start, built by column
	ungot        *token
	disableComma bool
	depth        int
	commands     int
}

func (p *parser) fail(t *token, msg string) { panic(&Error{Offset: t.pos, Msg: msg}) }

func (p *parser) refuse(t *token, msg string) {
	panic(&Error{Offset: t.pos, Msg: msg, Refused: true})
}

func (p *parser) enter(t *token) {
	p.depth++
	if p.depth > maxNesting {
		panic(&Error{Offset: t.pos, Msg: "nested too deeply", limit: shell.ErrTooComplex})
	}
}

func (p *parser) leave() { p.depth-- }

func (p *parser) counted(at int) {
	p.commands++
	if p.commands > shell.MaxCommands {
		panic(&Error{Offset: at, Msg: "too many commands", limit: shell.ErrTooComplex})
	}
}

// Token handling follows Parser.cs. There is one token of lookahead, which is
// scanned again when the mode changes, since it may read differently

func (p *parser) nextToken() *token {
	t := p.ungot
	if t == nil {
		t = p.lx.next()
	}
	p.ungot = nil
	return t
}

func (p *parser) peekToken() *token {
	if p.ungot == nil {
		p.ungot = p.lx.next()
	}
	return p.ungot
}

func (p *parser) skipToken()          { p.ungot = nil }
func (p *parser) ungetToken(t *token) { p.ungot = t }

func (p *parser) setMode(m mode) {
	if m != p.lx.mode && p.ungot != nil && !p.ungot.kind.is(kindParseModeInvariant) {
		p.resync(p.ungot.pos)
	}
	p.lx.mode = m
}

func (p *parser) resync(start int) {
	p.ungot = nil
	p.lx.resync(start)
}

// restorePoint returns the position to resync to, which is the lookahead's
// start if there is one
func (p *parser) restorePoint() int {
	if p.ungot != nil {
		return p.ungot.pos
	}
	return p.lx.restorePoint()
}

func (p *parser) skipNewlines() {
	if p.ungot == nil || p.ungot.kind == tokNewLine {
		p.ungot = nil
		p.lx.skipNewlines(false)
	}
}

func (p *parser) skipNewlinesAndSemicolons() {
	if p.ungot == nil || p.ungot.kind == tokNewLine || p.ungot.kind == tokSemi {
		p.ungot = nil
		p.lx.skipNewlines(true)
	}
}

func (p *parser) nextMemberAccessToken(allowLBracket bool) *token {
	if p.ungot != nil {
		return nil
	}
	return p.lx.memberAccessOperator(allowLBracket)
}

func (p *parser) nextInvokeMemberToken() *token {
	if p.ungot != nil {
		return nil
	}
	return p.lx.invokeMemberOpenParen()
}

func (p *parser) nextLBracket() *token {
	if p.ungot != nil {
		if p.ungot.kind == tokLBracket {
			return p.nextToken()
		}
		return nil
	}
	return p.lx.lBracket()
}

func extent(start, end *token) Extent { return Extent{Start: start.pos, End: end.endPos} }

func endOf(n Node) int { return n.Span().End }

// column is PowerShell's column number of an offset, counted from 1
// Lines end at \n, \r\n or a lone \r
func (p *parser) column(off int) int {
	if p.lines == nil {
		p.lines = []int{0}
		for j, c := range p.src {
			if c == '\n' || c == '\r' && (j+1 >= len(p.src) || p.src[j+1] != '\n') {
				p.lines = append(p.lines, j+1)
			}
		}
	}
	i := sort.SearchInts(p.lines, off+1) - 1
	return off - p.lines[i] + 1
}

// scriptExtent returns the whole input's extent, which is a script's own
func (p *parser) scriptExtent() Extent { return Extent{End: len(p.src)} }

// Script blocks and statements

func (p *parser) scriptBlockRule(lCurly *token, isFilter bool) *ScriptBlock {
	p.skipNewlines()
	if lCurly == nil {
		t := p.peekToken()
		if t.isKeyword("using") {
			p.refuse(t, "using statements are not analyzed")
		}
		p.resync(t.pos)
	}
	rp := p.lx.restorePoint()
	param := p.paramBlockRule()
	if param == nil {
		p.resync(rp)
	}
	p.skipNewlinesAndSemicolons()
	return p.scriptBlockBodyRule(lCurly, param, isFilter)
}

func (p *parser) paramBlockRule() *ParamBlock {
	p.skipNewlines()
	candidates := p.attributeListRule(false)
	p.skipNewlines()
	paramTok := p.peekToken()
	if !paramTok.isKeyword("param") {
		return nil
	}
	p.skipToken()
	p.skipNewlines()
	lParen := p.nextToken()
	if lParen.kind != tokLParen {
		p.ungetToken(lParen)
		return nil
	}
	params := p.parameterListRule()
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a param block")
	}
	pb := &ParamBlock{Extent: extent(paramTok, rParen), Parameters: params}
	for _, a := range candidates {
		attr, ok := a.(*Attribute)
		if !ok {
			p.fail(paramTok, "a type can't come before param")
		}
		pb.Attributes = append(pb.Attributes, attr)
	}
	return pb
}

func (p *parser) parameterListRule() []*Parameter {
	var params []*Parameter
	var comma *token
	for {
		param := p.parameterRule()
		if param == nil {
			if comma != nil {
				p.fail(comma, "missing a parameter after ,")
			}
			break
		}
		params = append(params, param)
		p.skipNewlines()
		comma = p.peekToken()
		if comma.kind != tokComma {
			break
		}
		p.skipToken()
	}
	return params
}

func (p *parser) parameterRule() *Parameter {
	oldComma, oldMode := p.disableComma, p.lx.mode
	defer func() {
		p.disableComma = oldComma
		p.setMode(oldMode)
	}()
	p.disableComma = true
	p.setMode(modeExpression)
	p.skipNewlines()
	attrs := p.attributeListRule(false)
	p.skipNewlines()
	t := p.nextToken()
	if t.kind != tokVariable && t.kind != tokSplattedVariable {
		p.ungetToken(t)
		if attrs != nil {
			p.fail(t, "missing a parameter variable after its attributes")
		}
		return nil
	}
	param := &Parameter{Extent: extent(t, t), Attributes: attrs, Name: p.variable(t)}
	if attrs != nil {
		param.Start = attrs[0].Pos()
	}
	p.skipNewlines()
	if eq := p.peekToken(); eq.kind == tokEquals {
		p.skipToken()
		p.skipNewlines()
		param.Default = p.expressionRule()
		if param.Default == nil {
			p.fail(eq, "missing a default value after =")
		}
		param.End = endOf(param.Default)
	}
	return param
}

func (p *parser) attributeListRule(inExpressionMode bool) []AttributeBase {
	var attrs []AttributeBase
	for a := p.attributeRule(); a != nil; a = p.attributeRule() {
		attrs = append(attrs, a)
		if _, ok := a.(*Attribute); !inExpressionMode || ok {
			p.skipNewlines()
		}
	}
	return attrs
}

func (p *parser) attributeRule() AttributeBase {
	lBracket := p.nextLBracket()
	if lBracket == nil {
		return nil
	}
	p.enter(lBracket)
	defer p.leave()
	p.skipNewlines()
	typeName := p.typeNameRule(true)
	if typeName == nil {
		p.fail(lBracket, "missing a type name after [")
	}
	t := p.nextToken()
	if t.kind == tokLParen {
		p.skipNewlines()
		attr := &Attribute{Type: typeName}
		oldMode := p.lx.mode
		p.setMode(modeExpression)
		p.attributeArgumentsRule(attr)
		p.setMode(oldMode)
		p.skipNewlines()
		if rParen := p.nextToken(); rParen.kind != tokRParen {
			p.fail(rParen, "missing ) in an attribute")
		}
		p.skipNewlines()
		rBracket := p.nextToken()
		if rBracket.kind != tokRBracket {
			p.fail(rBracket, "missing ] at the end of an attribute")
		}
		attr.Extent = extent(lBracket, rBracket)
		return attr
	}
	if t.kind != tokRBracket {
		p.fail(t, "missing ] at the end of a type")
	}
	return &TypeConstraint{Extent: extent(lBracket, t), TypeName: typeName}
}

func (p *parser) attributeArgumentsRule(attr *Attribute) {
	oldComma := p.disableComma
	defer func() { p.disableComma = oldComma }()
	p.disableComma = true
	seen := map[string]bool{}
	var comma *token
	for {
		p.skipNewlines()
		nameTok := p.peekToken()
		name := p.simpleNameRule()
		var expr Expression
		if name != nil {
			if t := p.peekToken(); t.kind == tokEquals {
				p.skipToken()
				p.skipNewlines()
				expr = p.expressionRule()
				if expr == nil {
					p.fail(t, "missing a value after = in an attribute")
				}
			}
			if seen[name.Value] {
				p.fail(nameTok, "an attribute argument named twice")
			}
			seen[name.Value] = true
			arg := &NamedAttributeArgument{Extent: name.Extent, Name: name.Value, Value: expr, Omitted: expr == nil}
			if expr != nil {
				arg.End = endOf(expr)
			}
			attr.Named = append(attr.Named, arg)
		} else if expr = p.expressionRule(); expr != nil {
			attr.Positional = append(attr.Positional, expr)
		} else if comma != nil {
			p.fail(comma, "missing an attribute argument after ,")
		}
		p.skipNewlines()
		comma = p.peekToken()
		if comma.kind != tokComma {
			break
		}
		p.skipToken()
	}
}

func (p *parser) typeNameRule(allowAssembly bool) *TypeName {
	oldMode := p.lx.mode
	defer p.setMode(oldMode)
	p.setMode(modeTypeName)
	t := p.nextToken()
	if t.kind != tokIdentifier {
		p.ungetToken(t)
		return nil
	}
	return p.finishTypeNameRule(t, false, allowAssembly)
}

func (p *parser) finishTypeNameRule(name *token, unbracketedGenericArg, allowAssembly bool) *TypeName {
	p.enter(name)
	defer p.leave()
	t := p.peekToken()
	if t.kind == tokLBracket {
		p.skipToken()
		p.skipNewlines()
		t = p.nextToken()
		switch t.kind {
		case tokRBracket, tokComma:
			return p.completeArrayTypeName(&TypeName{Extent: extent(name, name), Name: name.text}, t, unbracketedGenericArg)
		case tokLBracket, tokIdentifier:
			return p.genericTypeNameRule(name, t, unbracketedGenericArg)
		}
		p.fail(t, "unexpected token in a type name")
	}
	if t.kind == tokComma && allowAssembly && !unbracketedGenericArg {
		p.skipToken()
		p.lx.assemblyNameSpec()
	}
	return &TypeName{Extent: extent(name, name), Name: name.text}
}

func (p *parser) singleGenericArgument(first *token) *TypeName {
	if first.kind == tokIdentifier {
		return p.finishTypeNameRule(first, true, true)
	}
	t := p.nextToken()
	if t.kind != tokIdentifier {
		p.fail(t, "missing a type name")
	}
	tn := p.finishTypeNameRule(t, false, true)
	if rb := p.nextToken(); rb.kind != tokRBracket {
		p.fail(rb, "missing ] at the end of a type")
	}
	return tn
}

func (p *parser) genericTypeArgumentsRule(first *token) ([]*TypeName, *token) {
	args := []*TypeName{p.singleGenericArgument(first)}
	for {
		p.skipNewlines()
		last := p.nextToken()
		if last.kind != tokComma {
			return args, last
		}
		p.skipNewlines()
		t := p.peekToken()
		if t.kind != tokIdentifier && t.kind != tokLBracket {
			p.fail(t, "missing a type name after ,")
		}
		p.skipToken()
		args = append(args, p.singleGenericArgument(t))
	}
}

func (p *parser) genericTypeNameRule(name, first *token, unbracketedGenericArg bool) *TypeName {
	args, rBracket := p.genericTypeArgumentsRule(first)
	if rBracket.kind != tokRBracket {
		p.fail(rBracket, "missing ] at the end of a generic type")
	}
	tn := &TypeName{Extent: extent(name, rBracket), Name: name.text, Generic: args}
	t := p.peekToken()
	if t.kind == tokLBracket {
		p.skipToken()
		return p.completeArrayTypeName(tn, p.nextToken(), unbracketedGenericArg)
	}
	if t.kind == tokComma && !unbracketedGenericArg {
		p.skipToken()
		p.lx.assemblyNameSpec()
	}
	return tn
}

func (p *parser) completeArrayTypeName(elem *TypeName, firstAfterLBracket *token, unbracketedGenericArg bool) *TypeName {
	for {
		switch firstAfterLBracket.kind {
		case tokComma:
			dim := 1
			t := firstAfterLBracket
			for t.kind == tokComma {
				dim++
				t = p.nextToken()
			}
			if dim > 32 || t.kind != tokRBracket {
				p.fail(t, "bad array type")
			}
			elem.Array = append(elem.Array, dim)
		case tokRBracket:
			elem.Array = append(elem.Array, 1)
		default:
			p.fail(firstAfterLBracket, "missing ] in an array type")
		}
		t := p.peekToken()
		if !unbracketedGenericArg && t.kind == tokComma {
			p.skipToken()
			p.lx.assemblyNameSpec()
		}
		if t.kind != tokLBracket {
			return elem
		}
		p.skipToken()
		firstAfterLBracket = p.nextToken()
	}
}

func (p *parser) completeScriptBlockBody(lCurly *token) *token {
	t := p.nextToken()
	if lCurly != nil {
		if t.kind != tokRCurly {
			p.fail(t, "missing } at the end of a script block")
		}
		return t
	}
	if t.kind != tokEndOfInput {
		p.fail(t, "unexpected token "+t.text)
	}
	return t
}

func (p *parser) scriptBlockBodyRule(lCurly *token, param *ParamBlock, isFilter bool) *ScriptBlock {
	t := p.peekToken()
	if t.kind == tokKeyword {
		switch t.keyword {
		case "begin", "process", "end", "dynamicparam", "clean":
			return p.namedBlockListRule(lCurly, param, isFilter)
		}
	}
	start := t
	if lCurly != nil {
		start = lCurly
	}
	body := &StatementBlock{}
	p.statementListRule(body)
	end := p.completeScriptBlockBody(lCurly)
	// PowerShell's extent for the body runs from the param block to the last statement
	// An empty body without a param block spans what is
	// between its braces if the character after the { is in a different
	// column from the }, and keeps PowerShell's empty extent otherwise
	empty := len(body.Statements)+len(body.Traps) == 0
	switch {
	case param != nil && empty:
		body.Extent = param.Extent
	case param != nil:
		body.Start = param.Start
	case empty && lCurly != nil && p.column(lCurly.endPos) != p.column(end.pos):
		body.Extent = Extent{Start: lCurly.endPos, End: max(end.pos-1, 0)}
	}
	sb := &ScriptBlock{Extent: extent(start, end), Param: param, Filter: isFilter}
	if lCurly == nil {
		sb.Extent = p.scriptExtent()
	}
	if isFilter {
		sb.ProcessBlock = body
	} else {
		sb.EndBlock = body
	}
	return sb
}

func (p *parser) namedBlockListRule(lCurly *token, param *ParamBlock, isFilter bool) *ScriptBlock {
	sb := &ScriptBlock{Param: param, Filter: isFilter, NamedBlocks: true}
	start := lCurly
	for {
		name := p.nextToken()
		if start == nil {
			start = name
		}
		var slot **StatementBlock
		switch {
		case name.kind == tokRCurly || name.kind == tokEndOfInput:
			p.ungetToken(name)
			end := p.completeScriptBlockBody(lCurly)
			sb.Extent = extent(start, end)
			if lCurly == nil {
				sb.Extent = p.scriptExtent()
			}
			return sb
		case name.isKeyword("begin"):
			slot = &sb.BeginBlock
		case name.isKeyword("process"):
			slot = &sb.ProcessBlock
		case name.isKeyword("end"):
			slot = &sb.EndBlock
		case name.isKeyword("clean"):
			// Clean blocks are new in PowerShell 7.3
			// In 5.1, clean is a command name.
			p.refuse(name, "clean blocks are not analyzed")
		case name.isKeyword("dynamicparam"):
			p.refuse(name, "dynamicparam blocks are not analyzed")
		default:
			p.fail(name, "a script block with named blocks can only hold named blocks")
		}
		body := p.statementBlockRule()
		if body == nil {
			p.fail(name, "missing { after "+name.text)
		}
		if *slot != nil {
			p.fail(name, "a script block can't have two "+name.keyword+" blocks")
		}
		body.Start = name.pos
		*slot = body
		p.skipNewlinesAndSemicolons()
	}
}

func (p *parser) statementBlockRule() *StatementBlock {
	p.skipNewlines()
	lCurly := p.nextToken()
	if lCurly.kind != tokLCurly {
		p.ungetToken(lCurly)
		return nil
	}
	body := &StatementBlock{}
	p.statementListRule(body)
	rCurly := p.nextToken()
	if rCurly.kind != tokRCurly {
		p.fail(rCurly, "missing } at the end of a block")
	}
	body.Extent = extent(lCurly, rCurly)
	return body
}

// statementListRule parses statements into body and sets its extent to span them, first to last
// With no statements, it leaves the extent zero, which is PowerShell's empty extent
func (p *parser) statementListRule(body *StatementBlock) {
	p.skipNewlinesAndSemicolons()
	for first := true; ; first = false {
		s := p.statementRule()
		if s == nil {
			return
		}
		if first {
			body.Start = s.Pos()
		}
		body.End = endOf(s)
		if trap, ok := s.(*Trap); ok {
			body.Traps = append(body.Traps, trap)
		} else {
			body.Statements = append(body.Statements, s)
		}
		p.skipNewlinesAndSemicolons()
		if t := p.peekToken(); t.kind == tokRParen || t.kind == tokRCurly {
			return
		}
	}
}

func (p *parser) statementRule() Statement {
	t := p.nextToken()
	p.enter(t)
	defer p.leave()
	attributed := false
	restore := 0
	if t.kind == tokGeneric && t.text[0] == '[' {
		restore = t.pos
		p.resync(t.pos)
		attrs := p.attributeListRule(false)
		t = p.nextToken()
		if attrs != nil {
			if t.kind == tokKeyword {
				p.refuse(t, "attributes before a statement are not analyzed")
			}
			p.resync(restore)
			t = p.nextToken()
			attributed = true
		}
	}
	if t.kind == tokKeyword {
		switch t.keyword {
		case "if":
			return p.ifStatementRule(t)
		case "switch":
			return p.switchStatementRule(t)
		case "foreach":
			return p.foreachStatementRule(t)
		case "for":
			return p.forStatementRule(t)
		case "while":
			return p.whileStatementRule(t)
		case "do":
			return p.doWhileStatementRule(t)
		case "function", "filter":
			return p.functionDeclarationRule(t)
		case "return", "throw", "exit":
			pl := p.pipelineChainRule()
			f := &Flow{Extent: extent(t, t), Keyword: t.keyword, Pipeline: pl}
			if pl != nil {
				f.End = endOf(pl)
			}
			return f
		case "break", "continue":
			label := p.labelOrKeyRule()
			f := &Flow{Extent: extent(t, t), Keyword: t.keyword, Label: label}
			if label != nil {
				f.End = endOf(label)
			}
			return f
		case "trap":
			return p.trapStatementRule(t)
		case "try":
			return p.tryStatementRule(t)
		case "workflow", "parallel", "sequence", "data", "configuration", "class", "enum", "using":
			p.refuse(t, t.keyword+" is not analyzed")
		case "from", "define", "var":
			p.fail(t, t.keyword+" is a reserved keyword")
		}
	}
	switch t.kind {
	case tokLabel:
		p.refuse(t, "loop labels are not analyzed")
	case tokEndOfInput:
		if attributed {
			p.resync(restore)
			return p.pipelineChainRule()
		}
		p.ungetToken(t)
		return nil
	}
	if attributed {
		p.resync(restore)
	} else {
		p.ungetToken(t)
	}
	if s := p.pipelineChainRule(); s != nil {
		return s
	}
	return nil
}

func (p *parser) simpleNameRule() *StringConstant {
	p.lx.wantSimpleName = true
	t := p.peekToken()
	p.lx.wantSimpleName = false
	if t.kind == tokIdentifier {
		p.skipToken()
		return &StringConstant{Extent: extent(t, t), Value: t.text, Kind: BareWord}
	}
	return nil
}

func (p *parser) labelOrKeyRule() Expression {
	if name := p.simpleNameRule(); name != nil {
		return name
	}
	if t := p.peekToken(); t.kind != tokNewLine && t.kind != tokSemi {
		old := p.disableComma
		p.disableComma = true
		e := p.unaryExpressionRule(false)
		p.disableComma = old
		return e
	}
	return nil
}

func (p *parser) ifStatementRule(ifTok *token) Statement {
	s := &If{}
	keyword := ifTok
	for {
		p.skipNewlines()
		if lParen := p.nextToken(); lParen.kind != tokLParen {
			p.fail(lParen, "missing ( after "+keyword.text)
		}
		p.skipNewlines()
		cond := p.pipelineChainRule()
		if cond == nil {
			p.fail(keyword, "missing a condition after "+keyword.text)
		}
		p.skipNewlines()
		if rParen := p.nextToken(); rParen.kind != tokRParen {
			p.fail(rParen, "missing ) after the condition")
		}
		p.skipNewlines()
		body := p.statementBlockRule()
		if body == nil {
			p.fail(keyword, "missing { after the condition")
		}
		s.Clauses = append(s.Clauses, IfClause{Condition: cond, Body: body})
		s.Extent = Extent{Start: ifTok.pos, End: body.End}
		rp := p.restorePoint()
		p.skipNewlines()
		keyword = p.peekToken()
		if keyword.isKeyword("elseif") {
			p.skipToken()
			continue
		}
		if keyword.isKeyword("else") {
			p.skipToken()
			p.skipNewlines()
			s.Else = p.statementBlockRule()
			if s.Else == nil {
				p.fail(keyword, "missing { after else")
			}
			s.End = s.Else.End
		} else {
			p.resync(rp)
		}
		return s
	}
}

func (p *parser) switchStatementRule(switchTok *token) Statement {
	s := &Switch{}
	p.skipNewlines()
	for t := p.peekToken(); t.kind == tokParameter; t = p.peekToken() {
		p.skipToken()
		if !isASCII(t.param) {
			p.refuse(t, "a switch flag written with letters outside ASCII")
		}
		flag := strings.ToLower(t.param)
		switch {
		case strings.HasPrefix("regex", flag):
			s.Regex, s.Wildcard = true, false
		case strings.HasPrefix("wildcard", flag):
			s.Wildcard, s.Regex = true, false
		case strings.HasPrefix("exact", flag):
			s.Regex, s.Wildcard = false, false
		case strings.HasPrefix("casesensitive", flag):
			s.CaseSensitive = true
		case strings.HasPrefix("parallel", flag), strings.HasPrefix("file", flag):
			p.refuse(t, "switch -file and -parallel are not analyzed")
		default:
			p.fail(t, "invalid switch flag -"+t.param)
		}
	}
	lParen := p.peekToken()
	if lParen.kind != tokLParen {
		p.fail(lParen, "missing ( after switch")
	}
	p.skipToken()
	p.skipNewlines()
	s.Condition = p.pipelineChainRule()
	if s.Condition == nil {
		p.fail(lParen, "missing a value after switch (")
	}
	p.skipNewlines()
	if rParen := p.nextToken(); rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a switch statement")
	}
	p.skipNewlines()
	lCurly := p.nextToken()
	if lCurly.kind != tokLCurly {
		p.fail(lCurly, "missing { in a switch statement")
	}
	p.skipNewlines()
	for {
		t := p.peekToken()
		var cond Expression
		isDefault := t.isKeyword("default")
		if isDefault {
			p.skipToken()
		} else if cond = p.singleCommandArgument(ctxSwitchCondition); cond == nil {
			p.fail(t, "missing a switch clause")
		}
		body := p.statementBlockRule()
		if body == nil {
			p.fail(t, "missing { in a switch clause")
		}
		if isDefault {
			if s.Default != nil {
				p.fail(t, "a switch with two default clauses")
			}
			s.Default = body
		} else {
			s.Clauses = append(s.Clauses, SwitchClause{Condition: cond, Body: body})
		}
		p.skipNewlinesAndSemicolons()
		t = p.peekToken()
		if t.kind == tokRCurly {
			p.skipToken()
			s.Extent = extent(switchTok, t)
			return s
		}
		if t.kind == tokEndOfInput {
			p.fail(t, "missing } at the end of a switch statement")
		}
	}
}

func (p *parser) foreachStatementRule(foreachTok *token) Statement {
	p.skipNewlines()
	if t := p.peekToken(); t.kind == tokParameter {
		p.refuse(t, "foreach flags are not analyzed")
	}
	if lParen := p.nextToken(); lParen.kind != tokLParen {
		p.fail(lParen, "missing ( after foreach")
	}
	p.skipNewlines()
	v := p.nextToken()
	if v.kind != tokVariable && v.kind != tokSplattedVariable {
		p.fail(v, "missing a variable after foreach (")
	}
	s := &Foreach{Variable: p.variable(v)}
	p.skipNewlines()
	if in := p.nextToken(); !in.isKeyword("in") {
		p.fail(in, "missing in after the foreach variable")
	}
	p.skipNewlines()
	s.Condition = p.pipelineChainRule()
	if s.Condition == nil {
		p.fail(v, "missing a value after in")
	}
	p.skipNewlines()
	if rParen := p.nextToken(); rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a foreach statement")
	}
	s.Body = p.statementBlockRule()
	if s.Body == nil {
		p.fail(foreachTok, "missing { in a foreach statement")
	}
	s.Extent = Extent{Start: foreachTok.pos, End: s.Body.End}
	return s
}

func (p *parser) forStatementRule(forTok *token) Statement {
	p.skipNewlines()
	if lParen := p.nextToken(); lParen.kind != tokLParen {
		p.fail(lParen, "missing ( after for")
	}
	s := &For{}
	p.skipNewlines()
	s.Initializer = p.pipelineChainRule()
	if p.peekToken().kind == tokSemi {
		p.nextToken()
	}
	p.skipNewlines()
	s.Condition = p.pipelineChainRule()
	if p.peekToken().kind == tokSemi {
		p.nextToken()
	}
	p.skipNewlines()
	s.Iterator = p.pipelineChainRule()
	p.skipNewlines()
	if rParen := p.nextToken(); rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a for statement")
	}
	s.Body = p.statementBlockRule()
	if s.Body == nil {
		p.fail(forTok, "missing { in a for statement")
	}
	s.Extent = Extent{Start: forTok.pos, End: s.Body.End}
	return nilIfEmptyStatements(s)
}

// nilIfEmptyStatements keeps absent parts of a for statement as nil interfaces
func nilIfEmptyStatements(s *For) *For {
	for _, st := range []*Statement{&s.Initializer, &s.Condition, &s.Iterator} {
		if *st != nil && isNilStatement(*st) {
			*st = nil
		}
	}
	return s
}

func isNilStatement(s Statement) bool {
	switch v := s.(type) {
	case *Pipeline:
		return v == nil
	case *PipelineChain:
		return v == nil
	case *Assignment:
		return v == nil
	}
	return false
}

func (p *parser) whileStatementRule(whileTok *token) Statement {
	p.skipNewlines()
	if lParen := p.nextToken(); lParen.kind != tokLParen {
		p.fail(lParen, "missing ( after while")
	}
	p.skipNewlines()
	s := &While{Condition: p.pipelineChainRule()}
	if s.Condition == nil {
		p.fail(whileTok, "missing a condition after while (")
	}
	p.skipNewlines()
	if rParen := p.nextToken(); rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a while statement")
	}
	p.skipNewlines()
	s.Body = p.statementBlockRule()
	if s.Body == nil {
		p.fail(whileTok, "missing { in a while statement")
	}
	s.Extent = Extent{Start: whileTok.pos, End: s.Body.End}
	return s
}

func (p *parser) doWhileStatementRule(doTok *token) Statement {
	s := &DoLoop{Body: p.statementBlockRule()}
	if s.Body == nil {
		p.fail(doTok, "missing { after do")
	}
	p.skipNewlines()
	kw := p.nextToken()
	if !kw.isKeyword("while") && !kw.isKeyword("until") {
		p.fail(kw, "missing while or until after do { }")
	}
	s.Until = kw.keyword == "until"
	p.skipNewlines()
	if lParen := p.nextToken(); lParen.kind != tokLParen {
		p.fail(lParen, "missing ( after "+kw.text)
	}
	p.skipNewlines()
	s.Condition = p.pipelineChainRule()
	if s.Condition == nil {
		p.fail(kw, "missing a condition after "+kw.text)
	}
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a do statement")
	}
	s.Extent = extent(doTok, rParen)
	return s
}

func (p *parser) functionDeclarationRule(fnTok *token) Statement {
	p.skipNewlines()
	name := p.nextToken()
	switch name.kind {
	case tokPipe, tokLParen, tokLCurly, tokAtParen, tokAtCurly, tokRCurly, tokRParen, tokEndOfInput,
		tokSemi, tokRedirection, tokRedirectInStd, tokAndAnd, tokOrOr, tokAmpersand, tokVariable,
		tokSplattedVariable, tokHereStringExpandable, tokHereStringLiteral, tokStringLiteral,
		tokStringExpandable:
		p.fail(name, "missing a name after "+fnTok.text)
	}
	f := &FunctionDefinition{Name: name.text, Filter: fnTok.keyword == "filter"}
	if name.kind == tokGeneric {
		f.Name = name.value
	}
	p.skipNewlines()
	if lParen := p.peekToken(); lParen.kind == tokLParen {
		p.skipToken()
		f.Parameters = p.parameterListRule()
		p.skipNewlines()
		if rParen := p.nextToken(); rParen.kind != tokRParen {
			p.fail(rParen, "missing ) in a function's parameter list")
		}
		p.skipNewlines()
	}
	lCurly := p.nextToken()
	if lCurly.kind != tokLCurly {
		p.fail(lCurly, "missing a function body")
	}
	f.Body = p.scriptBlockRule(lCurly, f.Filter)
	f.Extent = Extent{Start: fnTok.pos, End: f.Body.End}
	return f
}

func (p *parser) trapStatementRule(trapTok *token) Statement {
	rp := p.lx.restorePoint()
	p.skipNewlines()
	s := &Trap{}
	if a := p.attributeRule(); a != nil {
		if tc, ok := a.(*TypeConstraint); ok {
			s.Type = tc
		} else {
			p.resync(rp)
		}
	}
	s.Body = p.statementBlockRule()
	if s.Body == nil {
		p.fail(trapTok, "missing { in a trap statement")
	}
	s.Extent = Extent{Start: trapTok.pos, End: s.Body.End}
	return s
}

func (p *parser) catchBlockRule() *Catch {
	p.skipNewlines()
	catchTok := p.nextToken()
	if !catchTok.isKeyword("catch") {
		p.ungetToken(catchTok)
		return nil
	}
	c := &Catch{}
	var comma *token
	for {
		rp := p.lx.restorePoint()
		p.skipNewlines()
		a := p.attributeRule()
		if a == nil {
			if comma != nil {
				p.fail(comma, "missing a type after ,")
			}
			break
		}
		tc, ok := a.(*TypeConstraint)
		if !ok {
			p.resync(rp)
			break
		}
		c.Types = append(c.Types, tc)
		p.skipNewlines()
		comma = p.peekToken()
		if comma.kind != tokComma {
			break
		}
		p.skipToken()
	}
	c.Body = p.statementBlockRule()
	if c.Body == nil {
		p.fail(catchTok, "missing { in a catch clause")
	}
	c.Extent = Extent{Start: catchTok.pos, End: c.Body.End}
	return c
}

func (p *parser) tryStatementRule(tryTok *token) Statement {
	p.skipNewlines()
	s := &Try{Body: p.statementBlockRule()}
	if s.Body == nil {
		p.fail(tryTok, "missing { after try")
	}
	s.Extent = Extent{Start: tryTok.pos, End: s.Body.End}
	for c := p.catchBlockRule(); c != nil; c = p.catchBlockRule() {
		s.Catches = append(s.Catches, c)
		s.End = c.End
	}
	p.skipNewlines()
	if t := p.peekToken(); t.isKeyword("finally") {
		p.skipToken()
		s.Finally = p.statementBlockRule()
		if s.Finally == nil {
			p.fail(t, "missing { after finally")
		}
		s.End = s.Finally.End
	}
	if len(s.Catches) == 0 && s.Finally == nil {
		p.fail(tryTok, "a try statement needs a catch or a finally")
	}
	return s
}

// Pipelines

func (p *parser) pipelineChainRule() Statement {
	t := p.peekToken()
	p.enter(t)
	defer p.leave()
	oldMode := p.lx.mode
	p.setMode(modeExpression)
	expr := p.expressionRule()
	var assign *token
	if expr != nil {
		if t := p.peekToken(); t.kind.is(kindAssignmentOperator) {
			if t.kind == tokQuestionQuestionEquals {
				p.refuse(t, "??= is not analyzed")
			}
			p.skipToken()
			assign = t
		}
	}
	p.setMode(oldMode)
	if assign != nil {
		p.skipNewlines()
		right := p.statementRule()
		if right == nil {
			p.fail(assign, "missing a value after "+assign.text)
		}
		if pl, ok := right.(*Pipeline); ok && !pl.Background && len(pl.Elements) == 1 {
			if ce, ok := pl.Elements[0].(*CommandExpression); ok {
				right = ce
			}
		}
		return &Assignment{Extent: Extent{Start: expr.Pos(), End: endOf(right)}, Left: expr, Operator: kindName(assign), Right: right}
	}
	var chain Statement
	var chainOp *token
	start := expr
	for {
		var next *Pipeline
		if start != nil {
			next = p.pipelineRule(start)
			start = nil
		} else {
			next = p.pipelineRule(nil)
		}
		if next == nil {
			if chainOp == nil {
				return nil
			}
			p.fail(chainOp, "missing a pipeline after "+chainOp.text)
		}
		t := p.peekToken()
		background := false
		switch t.kind {
		case tokAndAnd, tokOrOr:
			p.skipToken()
			p.skipNewlines()
		case tokAmpersand:
			p.skipToken()
			if t2 := p.peekToken(); t2.kind == tokAndAnd || t2.kind == tokOrOr {
				p.fail(t2, "a background pipeline can't be chained")
			}
			background = true
			fallthrough
		default:
			if chain == nil {
				next.Background = background
				return next
			}
			return &PipelineChain{Extent: Extent{Start: chain.Pos(), End: next.End}, Left: chain, Right: next,
				Operator: kindName(chainOp), Background: background}
		}
		if chain == nil {
			chain = next
		} else {
			chain = &PipelineChain{Extent: Extent{Start: chain.Pos(), End: next.End}, Left: chain, Right: next, Operator: kindName(chainOp)}
		}
		chainOp = t
		if p.peekToken().kind == tokEndOfInput {
			p.fail(t, "missing a pipeline after "+t.text)
		}
	}
}

func (p *parser) pipelineRule(start Expression) *Pipeline {
	pl := &Pipeline{}
	expr := start
	var nextTok *token
	for {
		if expr == nil {
			oldMode := p.lx.mode
			p.setMode(modeExpression)
			expr = p.expressionRule()
			p.setMode(oldMode)
		}
		var cmd CommandBase
		if expr != nil {
			if len(pl.Elements) > 0 {
				p.fail(p.peekToken(), "expressions are only allowed as the first element of a pipeline")
			}
			var redirs [7]Redirection
			end := endOf(expr)
			for t := p.peekToken(); t.kind == tokRedirection || t.kind == tokRedirectInStd; t = p.peekToken() {
				p.skipToken()
				end = endOf(p.redirectionRule(t, &redirs))
			}
			ce := &CommandExpression{Extent: Extent{Start: expr.Pos(), End: end}, Expression: expr, Redirections: collect(redirs)}
			p.counted(expr.Pos())
			cmd = ce
		} else if c := p.commandRule(); c != nil {
			cmd = c
		}
		if cmd != nil {
			pl.Elements = append(pl.Elements, cmd)
		} else if len(pl.Elements) > 0 || p.peekToken().kind == tokPipe {
			p.fail(p.peekToken(), "an empty pipe element")
		}
		expr = nil
		nextTok = p.peekToken()
		if nextTok.kind == tokNewLine && p.lx.isPipeContinuation(nextTok.end) {
			p.skipNewlines()
			nextTok = p.peekToken()
		}
		switch nextTok.kind {
		case tokSemi, tokNewLine, tokRParen, tokRCurly, tokEndOfInput, tokAndAnd, tokOrOr, tokAmpersand:
			if len(pl.Elements) == 0 {
				return nil
			}
			pl.Extent = Extent{Start: pl.Elements[0].Pos(), End: endOf(pl.Elements[len(pl.Elements)-1])}
			return pl
		case tokPipe:
			p.skipToken()
			p.skipNewlines()
			if t := p.peekToken(); t.kind == tokEndOfInput {
				p.fail(t, "an empty pipe element")
			}
		default:
			p.fail(nextTok, "unexpected token "+nextTok.text)
		}
	}
}

func collect(redirs [7]Redirection) []Redirection {
	var out []Redirection
	for _, r := range redirs {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}

// redirectionRule reads a redirection's target
// PowerShell keeps one per stream, in stream order
func (p *parser) redirectionRule(t *token, redirs *[7]Redirection) Redirection {
	var r Redirection
	var from Stream
	if t.kind == tokRedirectInStd || !t.merging {
		file := p.singleCommandArgument(ctxFileName)
		if file == nil {
			p.fail(t, "missing a file after a redirection")
		}
		if t.kind == tokRedirectInStd {
			p.fail(t, "the < operator is reserved for future use")
		}
		r = &FileRedirection{Extent: Extent{Start: t.pos, End: endOf(file)}, From: t.from, Append: t.append, Location: file}
		from = t.from
	} else {
		if t.to != StreamOutput || t.from == t.to {
			p.fail(t, "redirection "+t.text+" is not supported")
		}
		r = &MergingRedirection{Extent: extent(t, t), From: t.from, To: t.to}
		from = t.from
	}
	if redirs[from] != nil {
		p.fail(t, "the "+from.String()+" stream is already redirected")
	}
	redirs[from] = r
	return r
}

type argContext uint8

const (
	ctxCommandName                argContext = 0x01
	ctxCommandNameAfterInvocation argContext = 0x02 | ctxCommandName
	ctxFileName                   argContext = 0x04
	ctxCommandArgument            argContext = 0x08
	ctxSwitchCondition            argContext = 0x10
)

func (p *parser) singleCommandArgument(ctx argContext) Expression {
	if t := p.peekToken(); t.kind == tokComma || t.kind == tokEndOfInput {
		return nil
	}
	oldMode := p.lx.mode
	defer p.setMode(oldMode)
	p.setMode(modeCommand)
	return p.commandArgument(ctx, p.nextToken())
}

func isVerbatim(t *token) bool {
	switch t.kind {
	case tokGeneric, tokStringLiteral, tokStringExpandable, tokHereStringLiteral, tokHereStringExpandable:
		return t.value == "--%"
	}
	return false
}

func (p *parser) commandArgument(ctx argContext, t *token) Expression {
	var args []Expression
	var comma *token
	for {
		var expr Expression
		switch t.kind {
		case tokPipe, tokRCurly, tokRParen, tokEndOfInput, tokNewLine, tokSemi, tokRedirection,
			tokRedirectInStd, tokAndAnd, tokOrOr, tokAmpersand, tokMinusMinus, tokComma:
			p.ungetToken(t)
			if comma == nil {
				return nil
			}
			p.fail(comma, "missing an expression after ,")
		case tokSplattedVariable, tokVariable, tokNumber, tokHereStringExpandable, tokStringExpandable,
			tokHereStringLiteral, tokStringLiteral, tokLParen, tokDollarParen, tokAtParen, tokAtCurly, tokLCurly:
			p.ungetToken(t)
			expr = p.primaryExpressionRule(true)
		case tokGeneric:
			if isVerbatim(t) {
				p.refuse(t, "--% (stop-parsing) is not analyzed")
			}
			if t.isExpandable && ctx != ctxCommandName {
				expr = &ExpandableString{Extent: extent(t, t), Value: t.value, Format: t.format, Kind: BareWord,
					Nested: p.nestedExpressions(t)}
			} else {
				expr = &StringConstant{Extent: extent(t, t), Value: t.value, Kind: BareWord}
			}
		default:
			expr = &StringConstant{Extent: extent(t, t), Value: t.text, Kind: BareWord}
		}
		if ctx != ctxCommandArgument {
			return expr
		}
		next := p.peekToken()
		if next.kind != tokComma {
			if args == nil {
				return expr
			}
			args = append(args, expr)
			return &ArrayLiteral{Extent: Extent{Start: args[0].Pos(), End: endOf(expr)}, Elements: args}
		}
		comma = next
		args = append(args, expr)
		p.skipToken()
		p.skipNewlines()
		t = p.nextToken()
	}
}

func (p *parser) commandRule() *Command {
	oldMode := p.lx.mode
	defer p.setMode(oldMode)
	p.setMode(modeCommand)
	t := p.nextToken()
	first := t
	c := &Command{}
	ctx := ctxCommandName
	switch t.kind {
	case tokDot:
		c.Invocation = "."
		t = p.nextToken()
		ctx = ctxCommandNameAfterInvocation
	case tokAmpersand:
		c.Invocation = "&"
		t = p.nextToken()
		ctx = ctxCommandNameAfterInvocation
	}
	end := first.endPos
	sawDashDash := false
	var redirs [7]Redirection
scan:
	for {
		switch t.kind {
		case tokPipe, tokRCurly, tokRParen, tokEndOfInput, tokNewLine, tokSemi, tokAndAnd, tokOrOr, tokAmpersand:
			p.ungetToken(t)
			break scan
		case tokMinusMinus:
			if sawDashDash {
				c.Elements = append(c.Elements, &StringConstant{Extent: extent(t, t), Value: t.text, Kind: BareWord})
			} else {
				c.Elements = append(c.Elements, &CommandParameter{Extent: extent(t, t), Name: "-"})
			}
			sawDashDash = true
			end = t.endPos
		case tokComma:
			p.fail(t, "missing an argument before ,")
		case tokParameter:
			if ctx&ctxCommandName != 0 || sawDashDash {
				c.Elements = append(c.Elements, &StringConstant{Extent: extent(t, t), Value: t.text, Kind: BareWord})
				end = t.endPos
				break
			}
			param := &CommandParameter{Extent: extent(t, t), Name: t.param}
			if t.usedColon && p.peekToken().kind != tokComma {
				param.Argument = p.commandArgument(ctxCommandArgument, p.nextToken())
				if param.Argument == nil {
					p.fail(t, "missing an argument for -"+t.param)
				}
				param.End = endOf(param.Argument)
			}
			c.Elements = append(c.Elements, param)
			end = param.End
		case tokRedirection, tokRedirectInStd:
			if ctx&ctxCommandName == 0 {
				r := p.redirectionRule(t, &redirs)
				end = endOf(r)
				break
			}
			c.Elements = append(c.Elements, &StringConstant{Extent: extent(t, t), Value: t.text, Kind: BareWord})
			end = t.endPos
		default:
			if isVerbatim(t) {
				p.refuse(t, "--% (stop-parsing) is not analyzed")
			}
			arg := p.commandArgument(ctx, t)
			c.Elements = append(c.Elements, arg)
			end = endOf(arg)
		}
		ctx = ctxCommandArgument
		t = p.nextToken()
	}
	if len(c.Elements) == 0 {
		if c.Invocation != "" {
			p.fail(first, "missing a command after "+c.Invocation)
		}
		return nil
	}
	p.counted(first.pos)
	c.Extent = Extent{Start: first.pos, End: end}
	c.Redirections = collect(redirs)
	return c
}

// Expressions

// expressionRule is ExpressionRule
// PowerShell's takes a flag that ends a number at ? or : which only the branches of a ternary expression set
// Ternary expressions are refused, so the flag is left out
func (p *parser) expressionRule() Expression {
	oldMode := p.lx.mode
	defer p.setMode(oldMode)
	p.setMode(modeExpression)
	cond := p.binaryExpressionRule()
	if cond == nil {
		return nil
	}
	if t := p.peekToken(); t.kind == tokQuestionMark {
		p.refuse(t, "the ternary operator is not analyzed")
	}
	return cond
}

func (p *parser) binaryExpressionRule() Expression {
	oldMode := p.lx.mode
	defer p.setMode(oldMode)
	p.setMode(modeExpression)
	expr := p.arrayLiteralRule(false)
	if expr == nil {
		return nil
	}
	t := p.peekToken()
	if !t.kind.is(kindBinaryOperator) {
		if t.kind == tokParameter {
			p.fail(t, "unexpected token "+t.text)
		}
		return expr
	}
	p.skipToken()
	operands := []Expression{expr}
	ops := []*token{t}
	prec := t.kind.precedence()
	for {
		if t.kind == tokQuestionQuestion {
			p.refuse(t, "?? is not analyzed")
		}
		p.skipNewlines()
		e := p.arrayLiteralRule(true)
		if e == nil {
			p.fail(t, "missing an expression after "+t.text)
		}
		operands = append(operands, e)
		t = p.nextToken()
		if !t.kind.is(kindBinaryOperator) {
			p.ungetToken(t)
			if t.kind == tokParameter {
				p.fail(t, "unexpected token "+t.text)
			}
			break
		}
		newPrec := t.kind.precedence()
		for newPrec <= prec {
			rhs, lhs := operands[len(operands)-1], operands[len(operands)-2]
			op := ops[len(ops)-1]
			operands = append(operands[:len(operands)-2], binary(lhs, op, rhs))
			ops = ops[:len(ops)-1]
			if len(ops) == 0 {
				break
			}
			prec = ops[len(ops)-1].kind.precedence()
		}
		ops = append(ops, t)
		prec = newPrec
	}
	rhs := operands[len(operands)-1]
	for i := len(ops) - 1; i >= 0; i-- {
		rhs = binary(operands[i], ops[i], rhs)
	}
	return rhs
}

func binary(lhs Expression, op *token, rhs Expression) Expression {
	return &Binary{Extent: Extent{Start: lhs.Pos(), End: endOf(rhs)}, Operator: kindName(op), Left: lhs, Right: rhs}
}

func (p *parser) arrayLiteralRule(endTernary bool) Expression {
	last := p.unaryExpressionRule(endTernary)
	if last == nil {
		return nil
	}
	comma := p.peekToken()
	if comma.kind != tokComma || p.disableComma {
		return last
	}
	values := []Expression{last}
	for comma.kind == tokComma {
		p.skipToken()
		p.skipNewlines()
		last = p.unaryExpressionRule(true)
		if last == nil {
			p.fail(comma, "missing an expression after ,")
		}
		values = append(values, last)
		comma = p.peekToken()
	}
	return &ArrayLiteral{Extent: Extent{Start: values[0].Pos(), End: endOf(last)}, Elements: values}
}

func (p *parser) unaryExpressionRule(endTernary bool) Expression {
	oldSigned, oldTernary := p.lx.allowSignedNumbers, p.lx.ternaryEndsNumber
	p.lx.allowSignedNumbers = true
	p.lx.ternaryEndsNumber = endTernary
	if p.ungot != nil && (p.ungot.kind == tokMinus || (endTernary && p.ungot.kind == tokGeneric)) {
		p.resync(p.ungot.pos)
	}
	t := p.peekToken()
	p.lx.allowSignedNumbers, p.lx.ternaryEndsNumber = oldSigned, oldTernary
	p.enter(t)
	defer p.leave()
	var expr Expression
	switch {
	case t.kind.is(kindUnaryOperator):
		if p.disableComma && t.kind == tokComma {
			return nil
		}
		p.skipToken()
		p.skipNewlines()
		child := p.unaryExpressionRule(true)
		if child == nil {
			p.fail(t, "missing an expression after "+t.text)
		}
		if t.kind == tokComma {
			expr = &ArrayLiteral{Extent: Extent{Start: t.pos, End: endOf(child)}, Elements: []Expression{child}}
		} else {
			expr = &Unary{Extent: Extent{Start: t.pos, End: endOf(child)}, Operator: kindName(t), Child: child}
		}
	case t.kind == tokLBracket:
		attrs := p.attributeListRule(true)
		if attrs == nil {
			return nil
		}
		// Each attribute nests the expression one level deeper
		for range attrs {
			p.enter(t)
		}
		defer func() { p.depth -= len(attrs) }()
		last := attrs[len(attrs)-1]
		if attr, ok := last.(*Attribute); ok {
			p.skipNewlines()
			child := p.unaryExpressionRule(true)
			if child == nil {
				p.fail(t, "an attribute must be followed by an expression")
			}
			expr = &AttributedExpression{Extent: Extent{Start: attr.Start, End: endOf(child)}, Attribute: attr, Child: child}
		} else {
			tc := last.(*TypeConstraint)
			var mat *token
			if p.ungot == nil {
				mat = p.nextMemberAccessToken(false)
			}
			if mat != nil {
				expr = p.checkPostPrimaryExpressionOperators(mat, &TypeExpression{Extent: tc.Extent, Type: tc.TypeName})
			} else if t := p.peekToken(); t.kind != tokNewLine && t.kind != tokComma {
				if child := p.unaryExpressionRule(true); child != nil {
					expr = &Convert{Extent: Extent{Start: tc.Start, End: endOf(child)}, Type: tc, Child: child}
				}
			}
			if expr == nil {
				expr = &TypeExpression{Extent: tc.Extent, Type: tc.TypeName}
			}
		}
		for i := len(attrs) - 2; i >= 0; i-- {
			switch a := attrs[i].(type) {
			case *TypeConstraint:
				expr = &Convert{Extent: Extent{Start: a.Start, End: endOf(expr)}, Type: a, Child: expr}
			case *Attribute:
				expr = &AttributedExpression{Extent: Extent{Start: a.Start, End: endOf(expr)}, Attribute: a, Child: expr}
			}
		}
	default:
		expr = p.primaryExpressionRule(true)
	}
	if expr != nil {
		t := p.peekToken()
		if t.kind == tokPlusPlus || t.kind == tokMinusMinus {
			p.skipToken()
			expr = &Unary{Extent: Extent{Start: expr.Pos(), End: t.endPos}, Operator: "Postfix" + kindName(t), Child: expr}
		}
	}
	return expr
}

func (p *parser) variable(t *token) *Variable {
	if name, drive := splitVariablePath(t.path); strings.EqualFold(drive, "using") && name != "" {
		p.refuse(t, "$using: variables are not analyzed")
	}
	return &Variable{Extent: extent(t, t), Path: t.path, Splatted: t.kind == tokSplattedVariable}
}

func (p *parser) primaryExpressionRule(withMemberAccess bool) Expression {
	t := p.nextToken()
	p.enter(t)
	defer p.leave()
	var expr Expression
	switch t.kind {
	case tokSplattedVariable, tokVariable:
		expr = p.variable(t)
	case tokNumber:
		expr = &Constant{Extent: extent(t, t), Text: t.text, Value: t.number}
	case tokHereStringExpandable, tokStringExpandable:
		expr = p.expandableStringRule(t)
	case tokHereStringLiteral:
		expr = &StringConstant{Extent: extent(t, t), Value: t.value, Kind: SingleQuotedHereString}
	case tokStringLiteral:
		expr = &StringConstant{Extent: extent(t, t), Value: t.value, Kind: SingleQuoted}
	case tokLParen:
		expr = p.parenthesizedExpressionRule(t)
	case tokAtParen, tokDollarParen:
		expr = p.subExpressionRule(t)
	case tokAtCurly:
		expr = p.hashExpressionRule(t)
	case tokLCurly:
		expr = p.scriptBlockExpressionRule(t)
	default:
		p.ungetToken(t)
		return nil
	}
	if !withMemberAccess {
		return expr
	}
	return p.checkPostPrimaryExpressionOperators(p.nextMemberAccessToken(true), expr)
}

func (p *parser) checkPostPrimaryExpressionOperators(t *token, expr Expression) Expression {
	for t != nil {
		p.skipNewlines()
		switch t.kind {
		case tokQuestionDot, tokQuestionLBracket:
			p.refuse(t, "null-conditional member access is not analyzed")
		case tokDot, tokColonColon:
			expr = p.memberAccessRule(expr, t)
		case tokLBracket:
			expr = p.elementAccessRule(expr, t)
		}
		t = p.nextMemberAccessToken(true)
	}
	return expr
}

func (p *parser) hashExpressionRule(atCurly *token) Expression {
	p.skipNewlines()
	h := &Hashtable{}
	for {
		pair, ok := p.keyValuePair()
		if !ok {
			break
		}
		h.Pairs = append(h.Pairs, pair)
		if t := p.peekToken(); t.kind != tokNewLine && t.kind != tokSemi {
			break
		}
		p.skipNewlinesAndSemicolons()
	}
	rCurly := p.nextToken()
	if rCurly.kind != tokRCurly {
		p.fail(rCurly, "missing } at the end of a hash literal")
	}
	h.Extent = extent(atCurly, rCurly)
	return h
}

func (p *parser) keyValuePair() (KeyValue, bool) {
	oldMode := p.lx.mode
	p.setMode(modeExpression)
	key := p.labelOrKeyRule()
	if key == nil {
		p.setMode(oldMode)
		return KeyValue{}, false
	}
	eq := p.nextToken()
	p.setMode(oldMode)
	if eq.kind != tokEquals {
		p.fail(eq, "missing = in a hash literal")
	}
	p.setMode(modeCommand)
	p.skipNewlines()
	value := p.statementRule()
	if value == nil {
		p.fail(eq, "missing a value in a hash literal")
	}
	p.setMode(oldMode)
	return KeyValue{Key: key, Value: value}, true
}

func (p *parser) scriptBlockExpressionRule(lCurly *token) Expression {
	oldComma, oldMode := p.disableComma, p.lx.mode
	defer func() {
		p.disableComma = oldComma
		p.setMode(oldMode)
	}()
	p.disableComma = false
	p.setMode(modeCommand)
	p.skipNewlines()
	sb := p.scriptBlockRule(lCurly, false)
	return &ScriptBlockExpression{Extent: sb.Extent, Block: sb}
}

func (p *parser) subExpressionRule(first *token) Expression {
	oldComma, oldMode := p.disableComma, p.lx.mode
	defer func() {
		p.disableComma = oldComma
		p.setMode(oldMode)
	}()
	p.disableComma = false
	p.setMode(modeCommand)
	p.skipNewlines()
	body := &StatementBlock{}
	p.statementListRule(body)
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.kind != tokRParen {
		p.fail(rParen, "missing ) at the end of a subexpression")
	}
	if first.kind == tokDollarParen {
		return &SubExpression{Extent: extent(first, rParen), Body: body}
	}
	return &ArrayExpression{Extent: extent(first, rParen), Body: body}
}

func (p *parser) parenthesizedExpressionRule(lParen *token) Expression {
	oldComma, oldMode := p.disableComma, p.lx.mode
	defer func() {
		p.disableComma = oldComma
		p.setMode(oldMode)
	}()
	p.setMode(modeCommand)
	p.disableComma = false
	p.skipNewlines()
	pl := p.pipelineChainRule()
	if pl == nil {
		p.fail(lParen, "missing an expression after (")
	}
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.kind != tokRParen {
		p.fail(rParen, "missing ) at the end of an expression")
	}
	return &Paren{Extent: extent(lParen, rParen), Pipeline: pl}
}

// nestedExpressions parses the $variables and $(...) of an expandable string
// The lexer cut each subexpression's text by counting parentheses
// PowerShell parses one primary expression from that text and ignores the
// rest, and so does this parser
func (p *parser) nestedExpressions(t *token) []Expression {
	var out []Expression
	for _, n := range t.nested {
		if n.kind == tokVariable {
			out = append(out, p.variable(n))
			continue
		}
		outer, outerUngot := p.lx, p.ungot
		p.lx = &lexer{src: n.sub, offset: n.subOffset, skipped: n.skipped, mode: outer.mode,
			allowSignedNumbers: outer.allowSignedNumbers, ternaryEndsNumber: outer.ternaryEndsNumber}
		p.ungot = nil
		e := p.primaryExpressionRule(true)
		p.lx, p.ungot = outer, outerUngot
		out = append(out, e)
	}
	return out
}

func (p *parser) expandableStringRule(t *token) Expression {
	kind, constKind := DoubleQuoted, DoubleQuoted
	if t.kind == tokHereStringExpandable {
		kind, constKind = DoubleQuotedHereString, DoubleQuotedHereString
	}
	if len(t.nested) == 0 {
		return &StringConstant{Extent: extent(t, t), Value: t.value, Kind: constKind}
	}
	return &ExpandableString{Extent: extent(t, t), Value: t.value, Format: t.format, Kind: kind,
		Nested: p.nestedExpressions(t)}
}

func (p *parser) memberNameRule() CommandElement {
	if name := p.simpleNameRule(); name != nil {
		return name
	}
	if t := p.peekToken(); t.kind.is(kindUnaryOperator) || t.kind == tokLBracket {
		if e := p.unaryExpressionRule(false); e != nil {
			return e
		}
		return nil
	}
	if e := p.primaryExpressionRule(false); e != nil {
		return e
	}
	return nil
}

func (p *parser) memberAccessRule(target Expression, op *token) Expression {
	member := p.memberNameRule()
	if member == nil {
		p.fail(op, "missing a property name after "+op.text)
	}
	static := op.kind == tokColonColon
	if p.ungot == nil {
		rp := p.lx.restorePoint()
		generic, rBracket := p.genericMethodArgumentsRule(rp)
		if lParen := p.nextInvokeMemberToken(); lParen != nil {
			if generic {
				p.refuse(lParen, "generic method calls are not analyzed")
			}
			return p.memberInvokeRule(target, lParen, member, static)
		} else if rBracket {
			p.resync(rp)
		}
	}
	return &Member{Extent: Extent{Start: target.Pos(), End: endOf(member)}, Target: target, Member: member, Static: static}
}

// genericMethodArgumentsRule reads the [T] of $x.Method[T](...), which is new in PowerShell 7.3
// It reports whether type arguments were read and whether a ] closed them.
func (p *parser) genericMethodArgumentsRule(rp int) (bool, bool) {
	lBracket := p.nextToken()
	if lBracket.kind != tokLBracket {
		p.resync(rp)
		return false, false
	}
	oldMode := p.lx.mode
	p.setMode(modeTypeName)
	p.skipNewlines()
	first := p.nextToken()
	read, closed := false, false
	if first.kind == tokIdentifier {
		_, rBracket := p.genericTypeArgumentsRule(first)
		if rBracket.kind != tokRBracket {
			p.fail(rBracket, "missing ] in generic method arguments")
		}
		read, closed = true, true
	}
	p.setMode(oldMode)
	if !read {
		p.resync(rp)
	}
	return read, closed
}

func (p *parser) memberInvokeRule(target Expression, lParen *token, member CommandElement, static bool) Expression {
	m := &InvokeMember{Target: target, Member: member, Static: static}
	if lParen.kind == tokLParen {
		end := p.invokeParamParenListRule(lParen, m)
		m.Extent = Extent{Start: target.Pos(), End: end}
		return m
	}
	p.skipNewlines()
	block := p.scriptBlockExpressionRule(lParen)
	m.Arguments = []Expression{block}
	m.Extent = Extent{Start: target.Pos(), End: endOf(block)}
	return m
}

func (p *parser) invokeParamParenListRule(lParen *token, m *InvokeMember) int {
	oldComma := p.disableComma
	defer func() { p.disableComma = oldComma }()
	p.disableComma = true
	var comma *token
	for {
		p.skipNewlines()
		arg := p.expressionRule()
		if arg == nil {
			if comma != nil {
				p.fail(comma, "missing an argument after ,")
			}
			break
		}
		m.Arguments = append(m.Arguments, arg)
		p.skipNewlines()
		comma = p.nextToken()
		if comma.kind != tokComma {
			p.ungetToken(comma)
			comma = nil
			break
		}
	}
	p.skipNewlines()
	rParen := p.nextToken()
	if rParen.kind != tokRParen {
		p.fail(rParen, "missing ) in a method call")
	}
	return rParen.endPos
}

func (p *parser) elementAccessRule(target Expression, lBracket *token) Expression {
	p.skipNewlines()
	oldComma := p.disableComma
	p.disableComma = false
	index := p.expressionRule()
	p.disableComma = oldComma
	if index == nil {
		p.fail(lBracket, "missing an index after [")
	}
	p.skipNewlines()
	rBracket := p.nextToken()
	if rBracket.kind != tokRBracket {
		p.fail(rBracket, "missing ] after an index")
	}
	return &Index{Extent: Extent{Start: target.Pos(), End: rBracket.endPos}, Target: target, Index: index}
}
