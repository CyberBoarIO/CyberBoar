package pwsh

import (
	"math"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// The lexer is a port of PowerShell's Tokenizer (tokenizer.cs), as far as the
// parser needs it. It keeps the original's structure and names, so the two can
// be read side by side. What a word is depends on the mode the parser asks for
// (command, expression or type name), and the lexer decides it character by
// character exactly as PowerShell does. Where PowerShell reports an error, the
// lexer stops with fail. A command line PowerShell can't parse runs nothing,
// and the engine denies one this package can't read
// What PowerShell accepts but this package doesn't analyze stops the lexer with refuse

type mode uint8

const (
	modeCommand mode = iota
	modeExpression
	modeTypeName
)

type lexer struct {
	src    []uint16
	offset int // offset of src[0] in the whole input, for nested scans
	// skipped lists, in increasing order, the whole input's offsets of the
	// characters a subexpression's text dropped ("" read as "), as
	// PowerShell's SkippedCharOffsets does, so offsets map back to the
	// input. It is a list rather than a set over the whole input, so that a
	// string with thousands of $(...) costs memory in proportion to the
	// characters they drop, not to the input once for each of them
	skipped  []int
	cur      int // _currentIndex, which can pass len(src) by one, as in GetChar
	tokStart int
	mode     mode

	allowSignedNumbers bool
	ternaryEndsNumber  bool
	wantSimpleName     bool
}

func (l *lexer) getChar() uint16 {
	c := l.cur
	l.cur++
	if c >= len(l.src) {
		return 0
	}
	return l.src[c]
}

func (l *lexer) ungetChar() { l.cur-- }

func (l *lexer) peekChar() uint16 {
	if l.cur >= len(l.src) {
		return 0
	}
	return l.src[l.cur]
}

func (l *lexer) skipChar() { l.cur++ }

// atEOF reports whether getChar has returned the end of input
// The input holds no NUL (Parse refuses it), so a 0 from getChar always means the end
func (l *lexer) atEOF() bool { return l.cur > len(l.src) }

func (l *lexer) text(start, end int) string {
	if end > len(l.src) {
		end = len(l.src)
	}
	if start > end {
		start = end
	}
	return decode(l.src[start:end])
}

func decode(s []uint16) string { return string(utf16.Decode(s)) }

func (l *lexer) fail(at int, msg string) { panic(&Error{Offset: l.offset + at, Msg: msg}) }

func (l *lexer) refuse(at int, msg string) {
	panic(&Error{Offset: l.offset + at, Msg: msg, Refused: true})
}

func (l *lexer) newToken(kind tokenKind) *token {
	end := l.cur
	if end > len(l.src) {
		end = len(l.src)
	}
	pos, endPos := l.extent(l.tokStart, end)
	return &token{kind: kind, start: l.tokStart, end: end, pos: pos, endPos: endPos,
		text: l.text(l.tokStart, end)}
}

// extent is Tokenizer.CurrentExtent. It maps local offsets to the whole
// input's, counting the characters a subexpression's text dropped
func (l *lexer) extent(start, end int) (int, int) {
	pos := l.whole(start)
	// newToken clamps end to the source, so a token read past the end of
	// input can start after it ends. Its end then moves with its start
	if end < start {
		return pos, end + pos - start
	}
	return pos, l.whole(end)
}

// whole maps the local offset k to the whole input. The result is the first
// offset at or after l.offset with k characters between the two that a
// subexpression's text didn't drop. Each lookup is a binary search, so
// mapping every token's extent stays cheap on a long input
func (l *lexer) whole(k int) int {
	s := l.skipped
	first := sort.SearchInts(s, l.offset)
	// The dropped character s[first+i] lies before the result exactly when
	// s[first+i]-i < l.offset+k. That value never decreases with i, since
	// the offsets are distinct and increasing, so the ones before the
	// result are a prefix of s[first:]
	n := sort.Search(len(s)-first, func(i int) bool { return s[first+i]-i >= l.offset+k })
	return l.offset + k + n
}

// skipNewlines is Tokenizer.SkipNewlines. It skips whitespace, comments, line
// continuations, newlines and, if skipSemis is set, semicolons
func (l *lexer) skipNewlines(skipSemis bool) {
	for {
		c := l.getChar()
		switch c {
		case ' ', '\t', '\f', '\v', noBreakSpace, nextLine:
			l.skipWhiteSpace()
			continue
		case '\r', '\n':
			l.normalizeCRLF(c)
			continue
		case ';':
			if skipSemis {
				continue
			}
		case '#':
			l.tokStart = l.cur - 1
			l.scanLineComment()
			continue
		case '<':
			if l.peekChar() == '#' {
				l.tokStart = l.cur - 1
				l.skipChar()
				l.scanBlockComment()
				continue
			}
		case '`':
			c1 := l.getChar()
			if c1 == '\n' || c1 == '\r' {
				l.normalizeCRLF(c1)
				continue
			}
			if isDotNetWhiteSpace(c1) {
				l.skipWhiteSpace()
				continue
			}
			l.ungetChar()
		default:
			if isWhitespace(c) {
				l.skipWhiteSpace()
				continue
			}
		}
		l.ungetChar()
		return
	}
}

func (l *lexer) skipWhiteSpace() {
	for isWhitespace(l.peekChar()) {
		l.skipChar()
	}
}

func (l *lexer) normalizeCRLF(c uint16) {
	if c == '\r' && l.peekChar() == '\n' {
		l.skipChar()
	}
}

// resync moves back to a token's start, to scan it again in another mode
// start is an offset in the whole input, mapped back as Tokenizer.Resync
// does, including its counting of dropped characters only before start-1
func (l *lexer) resync(start int) {
	adjustment := l.offset
	if n := sort.SearchInts(l.skipped, start-1) - sort.SearchInts(l.skipped, l.offset); n > 0 {
		adjustment += n
	}
	l.cur = start - adjustment
	if l.cur > len(l.src)+1 {
		l.cur = len(l.src) + 1
	} else if l.cur < 0 {
		l.cur = 0
	}
}

// restorePoint is Tokenizer.GetRestorePoint
// It returns the current position as an offset in the whole input, for resync
func (l *lexer) restorePoint() int {
	l.tokStart = l.cur
	pos, _ := l.extent(l.cur, l.cur)
	return pos
}

// isPipeContinuation is Tokenizer.IsPipeContinuation
// It reports whether the newline that ends at offset end is followed, on a later line,
// by a | that continues the pipeline
// PowerShell 7.2 and later read the lines that way
// Windows PowerShell 5.1 fails to parse them, so it runs nothing.
func (l *lexer) isPipeContinuation(end int) bool {
	if end >= len(l.src) {
		return false
	}
	lastNonWhitespaceIsNewline := true
	i := end
	s := l.src
	for i < len(s)-1 {
		c := s[i]
		if isWhitespace(c) {
			i++
			continue
		}
		if c == '\n' || c == '\r' {
			if lastNonWhitespaceIsNewline {
				return false
			}
			lastNonWhitespaceIsNewline = true
			if c == '\r' && s[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			continue
		}
		lastNonWhitespaceIsNewline = false
		if c == '#' {
			i = skipLineComment(s, i+1)
			continue
		}
		if c == '<' && s[i+1] == '#' {
			i = skipBlockComment(s, i+2)
			continue
		}
		return c == '|'
	}
	return s[len(s)-1] == '|'
}

func skipLineComment(s []uint16, i int) int {
	for ; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			break
		}
	}
	return i
}

func skipBlockComment(s []uint16, i int) int {
	for ; i < len(s); i++ {
		if s[i] == '#' && i+1 < len(s) && s[i+1] == '>' {
			return i + 2
		}
	}
	return i
}

// backtick is Tokenizer.Backtick. It returns the character that a backtick
// followed by c stands for. `e and `u{...} are PowerShell 7 escapes that 5.1
// reads as the letters e and u, so the two versions would run different
// strings, and backtick refuses them
func (l *lexer) backtick(c uint16) uint16 {
	switch c {
	case '0':
		return 0
	case 'a':
		return 7
	case 'b':
		return 8
	case 'e', 'u':
		l.refuse(l.cur-2, "the escapes `e and `u{...} mean different things in Windows PowerShell 5.1 and PowerShell 7")
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'v':
		return '\v'
	}
	return c
}

// scanLineComment skips a # comment
// A comment that starts with "requires" is a #Requires statement, which can
// load modules and stop the script, so it is refused
func (l *lexer) scanLineComment() {
	start := l.cur
	for {
		c := l.getChar()
		if c == '\r' || c == '\n' || (c == 0 && l.atEOF()) {
			l.ungetChar()
			break
		}
	}
	if l.cur-start >= 8 && strings.EqualFold(l.text(start, start+8), "requires") {
		l.refuse(start-1, "#Requires is not analyzed")
	}
}

func (l *lexer) scanBlockComment() {
	errorIndex := l.cur - 2
	for {
		c := l.getChar()
		if c == '#' && l.peekChar() == '>' {
			l.skipChar()
			return
		}
		if c == '\r' {
			l.normalizeCRLF(c)
		} else if c == 0 && l.atEOF() {
			l.fail(errorIndex, "missing #> at the end of a block comment")
		}
	}
}

// scanStringLiteral appends the rest of a single-quoted string to sb
func (l *lexer) scanStringLiteral(sb *[]uint16) {
	errorIndex := l.cur - 1
	c := l.getChar()
	for c != 0 || !l.atEOF() {
		if isSingleQuote(c) {
			if !isSingleQuote(l.peekChar()) {
				break
			}
			c = l.getChar()
		}
		*sb = append(*sb, c)
		c = l.getChar()
	}
	if c == 0 {
		l.fail(errorIndex, "missing ' at the end of a string")
	}
}

// scanSubExpression scans a $(...) inside an expandable string, counting
// parentheses only, as PowerShell does. The parser reads the text later
func (l *lexer) scanSubExpression(hereString bool) *token {
	l.tokStart = l.cur - 2
	sb := []uint16{'$', '('}
	parens := 1
	var skipped []int
	for parens > 0 {
		c := l.getChar()
		switch {
		case c == '(':
			sb = append(sb, c)
			parens++
		case c == ')':
			sb = append(sb, c)
			parens--
		case c == '`' || isDoubleQuote(c):
			if c1 := l.peekChar(); !hereString && isDoubleQuote(c1) {
				l.skipChar()
				sb = append(sb, c1)
				skipped = append(skipped, l.cur-2+l.offset)
			} else {
				sb = append(sb, c)
			}
		case c == 0 && l.atEOF():
			l.fail(l.tokStart, "missing ) at the end of a $( subexpression")
		default:
			sb = append(sb, c)
		}
	}
	t := l.newToken(tokSubExpr)
	t.sub = sb
	t.subOffset = t.pos
	t.skipped = l.skipped
	if len(skipped) > 0 {
		// As in PowerShell, the new offsets replace the enclosing scan's
		// They increase, as l.cur only moves forward here
		t.skipped = skipped
	}
	return t
}

// expandable collects a string with expansions as the lexer scans it. value
// is the text with escapes removed and the expansions as written. format is
// PowerShell's format string, which its compiler formats with the -f
// operator at run time. It is the literal text with its braces doubled and
// {0}, {1}, ... in place of the expansions, which nested holds in order
type expandable struct {
	value, format []uint16
	nested        []*token
}

// add appends a literal character
func (s *expandable) add(c uint16) {
	s.value = append(s.value, c)
	s.format = append(s.format, c)
	if c == '{' || c == '}' {
		s.format = append(s.format, c)
	}
}

func (l *lexer) scanStringExpandableInto(s *expandable) {
	errorIndex := l.cur - 1
	c := l.getChar()
	for ; c != 0 || !l.atEOF(); c = l.getChar() {
		if isDoubleQuote(c) {
			if !isDoubleQuote(l.peekChar()) {
				break
			}
			c = l.getChar()
		} else if c == '$' {
			if l.scanDollarInStringExpandable(s, false) {
				continue
			}
		} else if c == '`' {
			if c1 := l.peekChar(); c1 != 0 {
				l.skipChar()
				c = l.backtick(c1)
			}
		}
		s.add(c)
	}
	if c == 0 {
		l.fail(errorIndex, `missing " at the end of a string`)
	}
}

func (l *lexer) scanDollarInStringExpandable(s *expandable, hereString bool) bool {
	dollarIndex := l.cur - 1
	c1 := l.peekChar()
	saveTokStart, saveMode := l.tokStart, l.mode
	l.mode = modeExpression
	var t *token
	if c1 == '(' {
		l.skipChar()
		t = l.scanSubExpression(hereString)
	} else if isVariableStart(c1) || c1 == '{' {
		l.tokStart = l.cur - 1
		t = l.scanVariable(false, true)
	}
	l.tokStart, l.mode = saveTokStart, saveMode
	if t == nil {
		return false
	}
	s.value = append(s.value, l.src[dollarIndex:l.cur]...)
	s.format = append(s.format, '{')
	for _, d := range strconv.Itoa(len(s.nested)) {
		s.format = utf16.AppendRune(s.format, d)
	}
	s.format = append(s.format, '}')
	s.nested = append(s.nested, t)
	return true
}

func (l *lexer) stringExpandableToken(kind tokenKind, s *expandable) *token {
	t := l.newToken(kind)
	t.value = decode(s.value)
	t.format = decode(s.format)
	t.nested = s.nested
	return t
}

// scanAfterHereStringHeader checks that a here-string's @' or @" ends its line
func (l *lexer) scanAfterHereStringHeader() {
	headerOffset := l.cur - 2
	c := l.getChar()
	for isWhitespace(c) {
		c = l.getChar()
	}
	switch {
	case c == '\r':
		l.normalizeCRLF(c)
	case c == '\n':
	case c == 0 && l.atEOF():
		l.fail(headerOffset, "missing the end of a here-string")
	default:
		l.fail(l.cur-1, "a here-string's header must end its line")
	}
}

// scanPossibleHereStringFooter is Tokenizer.ScanPossibleHereStringFooter. It
// reports whether the line that starts here begins with '@ or "@, the footer
// that ends the here-string. A footer after whitespace doesn't end it.
// falseFooter records the first such footer, so that if the input ends
// before a real one, the error points at it, as PowerShell's error does.
func (l *lexer) scanPossibleHereStringFooter(test func(uint16) bool, add func(uint16), falseFooter *int) bool {
	c := l.getChar()
	if test(c) && l.peekChar() == '@' {
		l.skipChar()
		return true
	}
	for isWhitespace(c) {
		add(c)
		c = l.getChar()
	}
	if c == '\r' || c == '\n' || (c == 0 && l.atEOF()) {
		l.ungetChar()
		return false
	}
	if test(c) && l.peekChar() == '@' {
		add(c)
		if *falseFooter == -1 {
			*falseFooter = l.cur - 1
		}
		add(l.getChar())
	} else {
		l.ungetChar()
	}
	return false
}

func (l *lexer) hereStringEOF(headerOffset, falseFooter int) {
	if falseFooter != -1 {
		l.fail(falseFooter, "a here-string's closing quote must start its line")
	}
	l.fail(headerOffset, "missing the end of a here-string")
}

func (l *lexer) scanHereStringLiteral() *token {
	headerOffset := l.cur - 2
	falseFooter := -1
	l.scanAfterHereStringHeader()
	var sb []uint16
	add := func(c uint16) { sb = append(sb, c) }
	if !l.scanPossibleHereStringFooter(isSingleQuote, add, &falseFooter) {
		for {
			c := l.getChar()
			if c == '\r' || c == '\n' {
				n := len(sb)
				sb = append(sb, c)
				if c == '\r' && l.peekChar() == '\n' {
					l.skipChar()
					sb = append(sb, '\n')
				}
				if l.scanPossibleHereStringFooter(isSingleQuote, add, &falseFooter) {
					sb = sb[:n]
					break
				}
			} else if c != 0 || !l.atEOF() {
				sb = append(sb, c)
			} else {
				l.hereStringEOF(headerOffset, falseFooter)
			}
		}
	}
	t := l.newToken(tokHereStringLiteral)
	t.value = decode(sb)
	return t
}

func (l *lexer) scanHereStringExpandable() *token {
	headerOffset := l.cur - 2
	falseFooter := -1
	l.scanAfterHereStringHeader()
	var s expandable
	if !l.scanPossibleHereStringFooter(isDoubleQuote, s.add, &falseFooter) {
		for {
			c := l.getChar()
			if c == '\r' || c == '\n' {
				n, fn := len(s.value), len(s.format)
				s.add(c)
				if c == '\r' && l.peekChar() == '\n' {
					l.skipChar()
					s.add('\n')
				}
				if l.scanPossibleHereStringFooter(isDoubleQuote, s.add, &falseFooter) {
					s.value, s.format = s.value[:n], s.format[:fn]
					break
				}
				continue
			}
			if c == '$' {
				if l.scanDollarInStringExpandable(&s, true) {
					continue
				}
			} else if c == '`' {
				if c1 := l.peekChar(); c1 != 0 {
					l.skipChar()
					c = l.backtick(c1)
				}
			}
			if c != 0 || !l.atEOF() {
				s.add(c)
			} else {
				l.hereStringEOF(headerOffset, falseFooter)
			}
		}
	}
	return l.stringExpandableToken(tokHereStringExpandable, &s)
}

// scanVariable is Tokenizer.ScanVariable, after the $ or @
func (l *lexer) scanVariable(splatted, inStringExpandable bool) *token {
	errorStart := l.cur
	var sb []uint16
	c := l.getChar()
	if c == '{' {
		for {
			c = l.getChar()
			if c == '}' {
				break
			}
			switch {
			case c == '`':
				c1 := l.getChar()
				if c1 == 0 && l.atEOF() {
					l.ungetChar()
					l.fail(errorStart, "missing } at the end of a ${...} variable")
				}
				c = l.backtick(c1)
			case isDoubleQuote(c):
				if inStringExpandable {
					c1 := l.getChar()
					if c1 == 0 && l.atEOF() {
						l.ungetChar()
						l.fail(errorStart, "missing } at the end of a ${...} variable")
					}
					if isDoubleQuote(c1) {
						c = c1
					} else {
						l.ungetChar()
					}
				}
			case c == '{':
				l.fail(l.cur, "a { in a ${...} variable name must be escaped with a backtick")
			case c == 0 && l.atEOF():
				l.ungetChar()
				l.fail(errorStart, "missing } at the end of a ${...} variable")
			}
			sb = append(sb, c)
		}
		if len(sb) == 0 {
			l.fail(l.cur-1, "empty ${} variable")
		}
		if l.mode == modeCommand {
			if c1 := l.peekChar(); !forceStartNewToken(c1) && c1 != '.' && c1 != '[' {
				l.cur = l.tokStart
				return l.scanGenericToken(nil)
			}
		}
		path := decode(sb)
		if unqualified(path) == "" {
			l.fail(l.tokStart, "invalid ${...} variable")
		}
		t := l.newToken(tokVariable)
		t.path = path
		return t
	}
	if !isVariableStart(c) {
		l.ungetChar()
		return l.scanGenericToken([]uint16{'$'})
	}
	sb = append(sb, c)
	if c != '$' && c != '?' && c != '^' {
	scan:
		for {
			c = l.getChar()
			switch {
			case c < 128 && (has(c, traitIdentifierStart|traitDigit) || c == '?'):
				sb = append(sb, c)
			case c == ':':
				if l.peekChar() == ':' {
					l.ungetChar()
					break scan
				}
				sb = append(sb, c)
			case c == 0 || c == '\t' || c == '\r' || c == '\n' || c == ' ' || c == '&' || c == '(' ||
				c == ')' || c == ',' || c == ';' || c == '{' || c == '}' || c == '|' || c == '.' ||
				c == '[' || c == '=':
				l.ungetChar()
				break scan
			case isLetterOrDigit(c):
				sb = append(sb, c)
			case l.mode == modeCommand && !forceStartNewToken(c):
				l.cur = l.tokStart
				return l.scanGenericToken(nil)
			default:
				l.ungetChar()
				break scan
			}
		}
	} else if l.mode == modeCommand && !forceStartNewToken(l.peekChar()) {
		l.cur = l.tokStart
		return l.scanGenericToken(nil)
	}
	path := decode(sb)
	if unqualified(path) == "" {
		l.fail(l.tokStart, "invalid variable reference")
	}
	kind := tokVariable
	if splatted {
		kind = tokSplattedVariable
	}
	t := l.newToken(kind)
	t.path = path
	return t
}

// scanParameter is Tokenizer.ScanParameter, after the dash
func (l *lexer) scanParameter() *token {
	var sb []uint16
	sawColon := false
scan:
	for {
		c := l.getChar()
		if isWhitespace(c) {
			l.ungetChar()
			break
		}
		switch {
		case c == '{' || c == '}' || c == '(' || c == ')' || c == ';' || c == ',' || c == '|' ||
			c == '&' || c == '.' || c == '[' || c == '\r' || c == '\n' || c == 0:
			l.ungetChar()
			break scan
		case c == ':':
			sawColon = true
			if l.mode != modeCommand {
				l.ungetChar()
			}
			break scan
		case c < 128 && has(c, traitIdentifierStart) && c != '_':
			sb = append(sb, c)
		case isSingleQuote(c) || isDoubleQuote(c):
			l.ungetChar()
			if l.mode == modeCommand {
				return l.scanGenericToken(append([]uint16{l.src[l.tokStart]}, sb...))
			}
			break scan
		default:
			if l.mode != modeCommand {
				l.ungetChar()
				break scan
			}
			sb = append(sb, c)
		}
	}
	name := decode(sb)
	if l.mode == modeExpression {
		if kind, op, ok := lookupOperator(name); ok {
			t := l.newToken(kind)
			t.op = op
			return t
		}
	}
	if name == "" {
		return l.newToken(tokMinus)
	}
	t := l.newToken(tokParameter)
	t.param = name
	t.usedColon = sawColon
	return t
}

// lookupOperator finds an operator word case-insensitively. In expression
// mode scanParameter only collects ASCII letters, so case folding outside
// ASCII never comes into it
func lookupOperator(name string) (tokenKind, string, bool) {
	kind, ok := operators[strings.ToLower(name)]
	return kind, strings.ToLower(name), ok
}

func lookupKeyword(l *lexer, word string) (string, bool) {
	if isASCII(word) {
		k := strings.ToLower(word)
		return k, keywords[k]
	}
	// .NET's case-insensitive comparison has mapped letters outside ASCII
	// onto ASCII ones differently across versions (ſ onto s, ı onto i, the
	// Kelvin sign U+212A onto k), so a word that could be a keyword that way
	// is refused
	if keywords[foldToASCII(word)] {
		l.refuse(l.tokStart, "a keyword written with letters outside ASCII")
	}
	return "", false
}

// foldToASCII lowers ASCII letters and replaces each other letter by an
// ASCII one its upper case, lower case or case folding reaches, if any
func foldToASCII(word string) string {
	var b strings.Builder
	for _, r := range word {
		b.WriteRune(asciiCase(r))
	}
	return b.String()
}

func asciiCase(r rune) rune {
	for _, c := range []rune{r, unicode.ToUpper(r), unicode.ToLower(r)} {
		if c < utf8.RuneSelf {
			return unicode.ToLower(c)
		}
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < utf8.RuneSelf {
			return unicode.ToLower(f)
		}
	}
	return r
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (l *lexer) checkOperatorInCommandMode(prefix []uint16, kind tokenKind) *token {
	if l.mode == modeCommand && !forceStartNewToken(l.peekChar()) {
		return l.scanGenericToken(prefix)
	}
	return l.newToken(kind)
}

// scanGenericToken is Tokenizer.ScanGenericToken. It scans a word in command
// mode, after the characters in sb, up to a character that starts a new
// token. Quoted parts join their contents to the word, and a $ expansion
// makes it expandable
func (l *lexer) scanGenericToken(sb []uint16) *token {
	// PowerShell copies the characters already scanned, and the contents of
	// a single-quoted part, into the format string without doubling their braces
	// The format string is what runs, so it is built the same way
	s := expandable{value: sb, format: slices.Clone(sb)}
	c := l.getChar()
	for ; !forceStartNewToken(c); c = l.getChar() {
		switch {
		case c == '`':
			if c1 := l.peekChar(); c1 != 0 {
				l.skipChar()
				c = l.backtick(c1)
			}
		case isSingleQuote(c):
			n := len(s.value)
			l.scanStringLiteral(&s.value)
			s.format = append(s.format, s.value[n:]...)
			continue
		case isDoubleQuote(c):
			l.scanStringExpandableInto(&s)
			continue
		case c == '$':
			if l.scanDollarInStringExpandable(&s, false) {
				continue
			}
		}
		s.add(c)
	}
	l.ungetChar()
	t := l.newToken(tokGeneric)
	t.value = decode(s.value)
	if len(s.nested) > 0 {
		t.format = decode(s.format)
		t.nested = s.nested
		t.isExpandable = true
	}
	return t
}

func (l *lexer) scanDecimalDigits(sb *[]uint16) int {
	n := 0
	for c := l.peekChar(); isDecimalDigit(c); c = l.peekChar() {
		n++
		l.skipChar()
		*sb = append(*sb, c)
	}
	return n
}

func (l *lexer) scanExponent(sb *[]uint16, signIndex *int, notNumber *bool) {
	if c := l.peekChar(); c == '+' || isDash(c) {
		l.skipChar()
		*signIndex = len(*sb)
		*sb = append(*sb, c)
	}
	if l.scanDecimalDigits(sb) == 0 {
		*notNumber = true
	}
}

func (l *lexer) scanNumberAfterDot(sb *[]uint16, signIndex *int, notNumber *bool) {
	l.scanDecimalDigits(sb)
	if c := l.peekChar(); c == 'e' || c == 'E' {
		l.skipChar()
		*sb = append(*sb, c)
		l.scanExponent(sb, signIndex, notNumber)
	}
}

type numberScan struct {
	digits     string // as ScanNumberHelper leaves it, with a dash sign normalized to '-'
	hex        bool
	binary     bool
	real       bool
	suffix     bool
	multiplier int64
}

// scanNumberHelper is Tokenizer.ScanNumberHelper
// It reports false when the characters aren't a number at all
func (l *lexer) scanNumberHelper(first uint16) (n numberScan, ok bool) {
	n.multiplier = 1
	notNumber := false
	signIndex := -1
	var sb []uint16
	if isDash(first) || first == '+' {
		sb = append(sb, first)
		first = l.getChar()
	}
	if first == '.' {
		sb = append(sb, '.')
		l.scanNumberAfterDot(&sb, &signIndex, &notNumber)
		n.real = true
	} else {
		c := l.peekChar()
		if first == '0' && (c == 'x' || c == 'X' || c == 'b' || c == 'B') {
			l.skipChar()
			if c == 'x' || c == 'X' {
				sb = append(sb, '0')
				for c := l.peekChar(); isHexDigit(c); c = l.peekChar() {
					l.skipChar()
					sb = append(sb, c)
				}
				n.hex = true
			} else {
				for c := l.peekChar(); isBinaryDigit(c); c = l.peekChar() {
					l.skipChar()
					sb = append(sb, c)
				}
				if len(sb) == 0 {
					notNumber = true
				}
				n.binary = true
			}
		} else {
			sb = append(sb, first)
			l.scanDecimalDigits(&sb)
			switch c := l.peekChar(); c {
			case '.':
				l.skipChar()
				if l.peekChar() == '.' {
					l.ungetChar()
				} else {
					sb = append(sb, c)
					n.real = true
					l.scanNumberAfterDot(&sb, &signIndex, &notNumber)
				}
			case 'e', 'E':
				l.skipChar()
				sb = append(sb, c)
				n.real = true
				l.scanExponent(&sb, &signIndex, &notNumber)
			}
		}
	}
	c := l.peekChar()
	if isTypeSuffix(c) {
		l.skipChar()
		n.suffix = true
		unsigned := c == 'u' || c == 'U'
		c = l.peekChar()
		if isTypeSuffix(c) {
			l.skipChar()
			if !unsigned || !(c == 'l' || c == 'L' || c == 's' || c == 'S' || c == 'y' || c == 'Y') {
				notNumber = true
			}
			c = l.peekChar()
		}
	}
	if isMultiplier(c) {
		l.skipChar()
		switch c | 0x20 {
		case 'k':
			n.multiplier = 1 << 10
		case 'm':
			n.multiplier = 1 << 20
		case 'g':
			n.multiplier = 1 << 30
		case 't':
			n.multiplier = 1 << 40
		case 'p':
			n.multiplier = 1 << 50
		}
		if c1 := l.peekChar(); c1 == 'b' || c1 == 'B' {
			l.skipChar()
			c = l.peekChar()
		} else {
			notNumber = true
		}
	}
	if !forceStartNewToken(c) {
		if l.mode != modeExpression || !forceStartNewTokenAfterNumber(c, l.ternaryEndsNumber) {
			notNumber = true
		}
	}
	if notNumber {
		return n, false
	}
	if signIndex != -1 && isDash(sb[signIndex]) {
		sb[signIndex] = '-'
	}
	if isDash(sb[0]) {
		sb[0] = '-'
	}
	n.digits = decode(sb)
	return n, true
}

// scanNumber is Tokenizer.ScanNumber. Numbers with a type suffix (1d, 2ul,
// 3n) and binary numbers (0b101, PowerShell 7 only) are refused, since
// nothing an agent runs needs them. A number PowerShell can't convert is a
// word in command mode and an error in expression mode, as in PowerShell. We
// keep values that fit in an int64 or a finite float64 and refuse numbers
// PowerShell would hold in a decimal, a BigInteger or an infinity, and hex
// numbers with a multiplier
func (l *lexer) scanNumber(first uint16) *token {
	n, ok := l.scanNumberHelper(first)
	if !ok {
		l.cur = l.tokStart
		return l.scanGenericToken(nil)
	}
	if n.suffix || n.binary {
		l.refuse(l.tokStart, "numbers with a type suffix and binary numbers are not analyzed")
	}
	value, status := numberValue(n)
	switch status {
	case numberRefused:
		l.refuse(l.tokStart, "a number too large to analyze")
	case numberInvalid:
		if l.mode != modeExpression {
			l.cur = l.tokStart
			return l.scanGenericToken(nil)
		}
		l.fail(l.tokStart, "bad numeric constant")
	}
	t := l.newToken(tokNumber)
	t.number = value
	return t
}

// Number is a numeric constant
// It is the integer Int, or the real Float when Real is set
type Number struct {
	Int   int64
	Real  bool
	Float float64
}

const (
	numberOK      = iota
	numberInvalid // PowerShell can't convert it either
	numberRefused // PowerShell can convert it, but this package doesn't
)

// numberValue is TryGetNumberValue for numbers without a suffix
func numberValue(n numberScan) (Number, int) {
	s := n.digits
	if n.real {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
				return Number{}, numberRefused
			}
			return Number{}, numberInvalid
		}
		f *= float64(n.multiplier)
		if math.IsInf(f, 0) {
			return Number{}, numberRefused
		}
		return Number{Real: true, Float: f}, numberOK
	}
	neg := false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		s = s[1:]
	}
	if n.hex {
		if n.multiplier != 1 {
			return Number{}, numberRefused
		}
		// PowerShell prepends a 0, and drops it again when exactly 8 or 16
		// hex digits follow, so the top digit is a sign: 0xFFFFFFFF is -1
		width := 8
		if len(s) >= 16 {
			width = 16
		}
		if len(s) == width+1 {
			s = s[1:]
		}
		v, ok := new(big.Int).SetString(s, 16)
		if !ok {
			return Number{}, numberInvalid
		}
		if bits := len(s) * 4; len(s) == 8 || len(s) == 16 {
			if v.Bit(bits-1) == 1 {
				v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
			}
		}
		if neg {
			v.Neg(v)
		}
		if !v.IsInt64() {
			return Number{}, numberInvalid
		}
		return Number{Int: v.Int64()}, numberOK
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return Number{}, numberInvalid
	}
	if neg {
		v.Neg(v)
	}
	v.Mul(v, big.NewInt(n.multiplier))
	if !v.IsInt64() {
		return Number{}, numberRefused
	}
	return Number{Int: v.Int64()}, numberOK
}

// scanDot is Tokenizer.ScanDot, after a dot.
func (l *lexer) scanDot() *token {
	c := l.peekChar()
	if c == '.' {
		l.skipChar()
		c = l.peekChar()
		if l.mode == modeCommand && !forceStartNewToken(c) {
			l.ungetChar()
			return l.scanGenericToken([]uint16{'.'})
		}
		return l.newToken(tokDotDot)
	}
	if isDecimalDigit(c) {
		return l.scanNumber('.')
	}
	if l.mode == modeCommand && !forceStartNewToken(c) && c != '$' && c != '"' && c != '\'' {
		return l.scanGenericToken([]uint16{'.'})
	}
	return l.newToken(tokDot)
}

// scanIdentifier is Tokenizer.ScanIdentifier, for a word that starts with a
// letter. In command mode, the word is a keyword or an identifier when a token
// boundary follows it, and otherwise the start of a generic word
func (l *lexer) scanIdentifier(first uint16) *token {
	sb := []uint16{first}
	var c uint16
	for {
		c = l.getChar()
		if !isIdentifierFollow(c) {
			l.ungetChar()
			break
		}
		sb = append(sb, c)
	}
	if l.mode == modeTypeName {
		return l.scanTypeName()
	}
	if !l.wantSimpleName && l.mode == modeCommand && !forceStartNewToken(c) {
		return l.scanGenericToken(sb)
	}
	if !l.wantSimpleName && l.mode == modeCommand {
		// inlinescript is a keyword only inside a workflow, which is refused
		if k, ok := lookupKeyword(l, decode(sb)); ok && k != "inlinescript" {
			t := l.newToken(tokKeyword)
			t.keyword = k
			return t
		}
	}
	return l.newToken(tokIdentifier)
}

func (l *lexer) scanTypeName() *token {
	for {
		c := l.getChar()
		switch {
		case c == '.' || c == '`' || c == '_' || c == '+' || c == '#' || c == '\\':
			continue
		case isLetterOrDigit(c):
			continue
		}
		l.ungetChar()
		break
	}
	return l.newToken(tokIdentifier)
}

// scanLabel is Tokenizer.ScanLabel, after a colon in command mode
func (l *lexer) scanLabel() *token {
	c := l.getChar()
	if !isIdentifierStart(c) {
		if c == 0 {
			l.ungetChar()
			t := l.newToken(tokGeneric)
			t.value = ":"
			return t
		}
		l.ungetChar()
		return l.scanGenericToken([]uint16{':'})
	}
	sb := []uint16{}
	for isIdentifierFollow(c) {
		sb = append(sb, c)
		c = l.getChar()
	}
	if l.mode == modeCommand && !forceStartNewToken(c) {
		sb = append(append([]uint16{':'}, sb...), c)
		return l.scanGenericToken(sb)
	}
	l.ungetChar()
	t := l.newToken(tokLabel)
	t.value = decode(sb)
	return t
}

// memberAccessOperator is Tokenizer.GetMemberAccessOperator
// It returns the operator that follows an expression with nothing but block comments in
// between: ., ::, ?., or, if allowLBracket is set, [ or ?[
// It returns nil if there is none
func (l *lexer) memberAccessOperator(allowLBracket bool) *token {
	c := l.peekChar()
	for c == '<' {
		l.tokStart = l.cur
		l.skipChar()
		if l.peekChar() != '#' {
			l.ungetChar()
			return nil
		}
		l.skipChar()
		l.scanBlockComment()
		c = l.peekChar()
	}
	switch {
	case c == '.':
		l.tokStart = l.cur
		l.skipChar()
		c = l.peekChar()
		if c != '.' {
			if l.mode == modeCommand && (isWhitespace(c) || c == 0 || c == '\r' || c == '\n') {
				l.ungetChar()
				return nil
			}
			return l.newToken(tokDot)
		}
		l.ungetChar()
	case c == ':':
		l.tokStart = l.cur
		l.skipChar()
		if l.peekChar() == ':' {
			l.skipChar()
			c = l.peekChar()
			if l.mode == modeCommand && (isWhitespace(c) || c == 0 || c == '\r' || c == '\n') {
				l.ungetChar()
				l.ungetChar()
				return nil
			}
			return l.newToken(tokColonColon)
		}
		l.ungetChar()
	case c == '[' && allowLBracket:
		l.tokStart = l.cur
		l.skipChar()
		return l.newToken(tokLBracket)
	case c == '?':
		l.tokStart = l.cur
		l.skipChar()
		c = l.peekChar()
		if c == '.' {
			l.skipChar()
			return l.newToken(tokQuestionDot)
		}
		if c == '[' && allowLBracket {
			l.skipChar()
			return l.newToken(tokQuestionLBracket)
		}
		l.ungetChar()
	}
	return nil
}

// invokeMemberOpenParen is Tokenizer.GetInvokeMemberOpenParen
// It returns the ( or { that opens a method call's arguments, or nil
// Either must follow the member name directly
func (l *lexer) invokeMemberOpenParen() *token {
	switch l.peekChar() {
	case '(':
		l.tokStart = l.cur
		l.skipChar()
		return l.newToken(tokLParen)
	case '{':
		l.tokStart = l.cur
		l.skipChar()
		return l.newToken(tokLCurly)
	}
	return nil
}

// lBracket is Tokenizer.GetLBracket, which reads the [ of an attribute
// Whitespace and comments may come before it
func (l *lexer) lBracket() *token {
	resyncPoint := l.cur
	resyncIfMemberAccess := false
	for {
		l.tokStart = l.cur
		c := l.getChar()
		switch {
		case c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == noBreakSpace || c == nextLine:
			resyncIfMemberAccess = true
			l.skipWhiteSpace()
			continue
		case c == '#':
			resyncIfMemberAccess = true
			l.scanLineComment()
			continue
		case c == '<':
			if l.peekChar() == '#' {
				resyncIfMemberAccess = false
				l.skipChar()
				l.scanBlockComment()
				continue
			}
			l.ungetChar()
		case c == '[':
			return l.newToken(tokLBracket)
		case c == '.' || c == ':':
			if resyncIfMemberAccess {
				// PowerShell passes this local position where Resync
				// expects an offset in the whole input. Inside a
				// string's $(...), that lands elsewhere, and this port
				// does the same so that it reads the line as PowerShell does
				l.resync(resyncPoint)
			} else {
				l.ungetChar()
			}
		default:
			if isWhitespace(c) {
				resyncIfMemberAccess = true
				l.skipWhiteSpace()
				continue
			}
			l.ungetChar()
		}
		return nil
	}
}

// assemblyNameSpec is Tokenizer.GetAssemblyNameSpec
// Assembly-qualified type names load assemblies by name, so they are refused
func (l *lexer) assemblyNameSpec() {
	l.refuse(l.cur, "assembly-qualified type names are not analyzed")
}

func (l *lexer) redirection(from Stream, appendTo bool, explicit bool) *token {
	if explicit && l.mode == modeExpression {
		l.ungetChar()
		if appendTo {
			l.ungetChar()
		}
		t := l.newToken(tokNumber)
		t.number = Number{Int: int64(from)}
		return t
	}
	t := l.newToken(tokRedirection)
	t.from, t.append = from, appendTo
	return t
}

func (l *lexer) merging(from, to Stream) *token {
	t := l.newToken(tokRedirection)
	t.from, t.to, t.merging = from, to, true
	return t
}

// next is Tokenizer.NextToken
func (l *lexer) next() *token {
	for {
		l.tokStart = l.cur
		c := l.getChar()
		switch {
		case c == ' ' || c == '\t' || c == '\f' || c == '\v' || c == noBreakSpace || c == nextLine:
			l.skipWhiteSpace()
			continue
		case isSingleQuote(c):
			var sb []uint16
			l.scanStringLiteral(&sb)
			t := l.newToken(tokStringLiteral)
			t.value = decode(sb)
			return t
		case isDoubleQuote(c):
			var s expandable
			l.scanStringExpandableInto(&s)
			return l.stringExpandableToken(tokStringExpandable, &s)
		case c == '@':
			c1 := l.getChar()
			switch {
			case c1 == '{':
				return l.newToken(tokAtCurly)
			case c1 == '(':
				return l.newToken(tokAtParen)
			case isSingleQuote(c1):
				return l.scanHereStringLiteral()
			case isDoubleQuote(c1):
				return l.scanHereStringExpandable()
			}
			l.ungetChar()
			if isVariableStart(c1) {
				return l.scanVariable(true, false)
			}
			l.fail(l.cur-1, "unrecognized token @")
		case c == '#':
			l.scanLineComment()
			continue
		case c == '\n':
			return l.newToken(tokNewLine)
		case c == '\r':
			l.normalizeCRLF(c)
			return l.newToken(tokNewLine)
		case c == '`':
			c1 := l.getChar()
			if c1 == '\r' {
				l.normalizeCRLF(c1)
			}
			if c1 == '\n' || c1 == '\r' {
				continue
			}
			if isDotNetWhiteSpace(c1) {
				l.skipWhiteSpace()
				continue
			}
			if c1 == 0 && l.atEOF() {
				l.fail(l.cur, "a backtick at the end of the input")
			}
			return l.scanGenericToken([]uint16{l.backtick(c1)})
		case c == '=':
			return l.checkOperatorInCommandMode([]uint16{c}, tokEquals)
		case c == '+':
			c1 := l.peekChar()
			switch {
			case c1 == '+':
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokPlusPlus)
			case c1 == '=':
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokPlusEquals)
			case l.allowSignedNumbers && (isDotNetDigit(c1) || c1 == '.'):
				return l.scanNumber(c)
			}
			return l.checkOperatorInCommandMode([]uint16{c}, tokPlus)
		case isDash(c):
			c1 := l.peekChar()
			switch {
			case isDash(c1):
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokMinusMinus)
			case c1 == '=':
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokMinusEquals)
			case isLetter(c1) || c1 == '_' || c1 == '?':
				return l.scanParameter()
			case l.allowSignedNumbers && (isDotNetDigit(c1) || c1 == '.'):
				return l.scanNumber(c)
			}
			return l.checkOperatorInCommandMode([]uint16{c}, tokMinus)
		case c == '*':
			c1 := l.peekChar()
			if c1 == '=' {
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokMultiplyEquals)
			}
			if c1 == '>' {
				l.skipChar()
				c1 = l.peekChar()
				if c1 == '>' {
					l.skipChar()
					return l.redirection(StreamAll, true, false)
				}
				if c1 == '&' {
					l.skipChar()
					if l.peekChar() == '1' {
						l.skipChar()
						return l.merging(StreamAll, StreamOutput)
					}
					l.ungetChar()
				}
				return l.redirection(StreamAll, false, false)
			}
			return l.checkOperatorInCommandMode([]uint16{c}, tokMultiply)
		case c == '/':
			if c1 := l.peekChar(); c1 == '=' {
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokDivideEquals)
			}
			return l.checkOperatorInCommandMode([]uint16{c}, tokDivide)
		case c == '%':
			if c1 := l.peekChar(); c1 == '=' {
				l.skipChar()
				return l.checkOperatorInCommandMode([]uint16{c, c1}, tokRemainderEquals)
			}
			return l.checkOperatorInCommandMode([]uint16{c}, tokRem)
		case c == '$':
			if l.peekChar() == '(' {
				l.skipChar()
				return l.newToken(tokDollarParen)
			}
			return l.scanVariable(false, false)
		case c == '<':
			if l.peekChar() == '#' {
				l.skipChar()
				l.scanBlockComment()
				continue
			}
			return l.newToken(tokRedirectInStd)
		case c == '>':
			if l.peekChar() == '>' {
				l.skipChar()
				return l.redirection(StreamOutput, true, false)
			}
			return l.redirection(StreamOutput, false, false)
		case c < 128 && has(c, traitIdentifierStart):
			return l.scanIdentifier(c)
		case c == '(':
			return l.newToken(tokLParen)
		case c == ')':
			return l.newToken(tokRParen)
		case c == '[':
			if l.mode == modeCommand && !forceStartNewToken(l.peekChar()) {
				return l.scanGenericToken([]uint16{'['})
			}
			return l.newToken(tokLBracket)
		case c == ']':
			return l.newToken(tokRBracket)
		case c == '{':
			return l.newToken(tokLCurly)
		case c == '}':
			return l.newToken(tokRCurly)
		case c == '.':
			return l.scanDot()
		case c == ';':
			return l.newToken(tokSemi)
		case c == ',':
			return l.newToken(tokComma)
		case c == '0' || c == '7' || c == '8' || c == '9':
			return l.scanNumber(c)
		case c >= '1' && c <= '6':
			if l.peekChar() == '>' {
				from := Stream(c - '0')
				l.skipChar()
				c1 := l.peekChar()
				if c1 == '>' {
					l.skipChar()
					return l.redirection(from, true, true)
				}
				if c1 == '&' {
					l.skipChar()
					if c1 = l.peekChar(); c1 == '1' || c1 == '2' {
						l.skipChar()
						return l.merging(from, Stream(c1-'0'))
					}
					l.ungetChar()
				}
				return l.redirection(from, false, true)
			}
			return l.scanNumber(c)
		case c == '&':
			if l.peekChar() == '&' {
				l.skipChar()
				return l.newToken(tokAndAnd)
			}
			return l.newToken(tokAmpersand)
		case c == '|':
			if l.peekChar() == '|' {
				l.skipChar()
				return l.newToken(tokOrOr)
			}
			return l.newToken(tokPipe)
		case c == '!':
			c1 := l.peekChar()
			if (l.mode == modeCommand && !forceStartNewToken(c1)) ||
				(l.mode == modeExpression && isIdentifierStart(c1)) {
				return l.scanGenericToken([]uint16{c})
			}
			if l.mode == modeExpression && (isDotNetDigit(c1) || c1 == '.') {
				_, ok := l.scanNumberHelper(c)
				l.cur = l.tokStart
				c = l.getChar()
				if !ok {
					return l.scanGenericToken([]uint16{c})
				}
			}
			return l.newToken(tokExclaim)
		case c == ':':
			if l.peekChar() == ':' {
				l.skipChar()
				if l.mode == modeCommand && !l.wantSimpleName && !forceStartNewToken(l.peekChar()) {
					return l.scanGenericToken([]uint16{':', ':'})
				}
				return l.newToken(tokColonColon)
			}
			if l.mode == modeCommand {
				return l.scanLabel()
			}
			return l.newToken(tokColon)
		case c == '?' && l.mode == modeExpression:
			if l.peekChar() == '?' {
				l.skipChar()
				if l.peekChar() == '=' {
					l.skipChar()
					return l.newToken(tokQuestionQuestionEquals)
				}
				return l.newToken(tokQuestionQuestion)
			}
			return l.newToken(tokQuestionMark)
		case c == 0 && l.atEOF():
			n := len(l.src)
			return &token{kind: tokEndOfInput, start: l.tokStart + 1, end: l.tokStart + 1, pos: l.offset + n, endPos: l.offset + n}
		default:
			if isWhitespace(c) {
				l.skipWhiteSpace()
				continue
			}
			if isLetter(c) {
				return l.scanIdentifier(c)
			}
			return l.scanGenericToken([]uint16{c})
		}
	}
}

// unqualified is VariablePath.UnqualifiedPath, the name after any scope or drive prefix
func unqualified(path string) string {
	p, _ := splitVariablePath(path)
	return p
}

// splitVariablePath is the VariablePath constructor. It returns the name
// without its scope or drive, and the drive ("env" for $env:X) when the path
// is drive-qualified. Like the constructor, it recognizes only one scope prefix
func splitVariablePath(path string) (name, drive string) {
	colon := -1
	if path != "" {
		scope := map[byte]string{'g': "global", 'l': "local", 'p': "private", 's': "script", 'v': "variable"}[path[0]|0x20]
		if scope != "" && len(path) > len(scope) && asciiEqualFold(path[:len(scope)], scope) && path[len(scope)] == ':' {
			colon = len(scope)
		}
	}
	if colon == -1 {
		colon = strings.IndexByte(path, ':')
		if colon > 0 {
			drive = path[:colon]
		}
	}
	if colon == -1 {
		return path, ""
	}
	return path[colon+1:], drive
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
