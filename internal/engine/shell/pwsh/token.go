package pwsh

import "strings"

// tokenKind follows PowerShell's TokenKind, keeping only the kinds the lexer
// produces. Keywords share one kind and carry their text in token.keyword.
type tokenKind uint8

const (
	tokUnknown tokenKind = iota
	tokVariable
	tokSplattedVariable
	tokParameter
	tokNumber
	tokLabel
	tokIdentifier
	tokGeneric
	tokNewLine
	tokEndOfInput
	tokStringLiteral
	tokStringExpandable
	tokHereStringLiteral
	tokHereStringExpandable
	tokLParen
	tokRParen
	tokLCurly
	tokRCurly
	tokLBracket
	tokRBracket
	tokAtParen
	tokAtCurly
	tokDollarParen
	tokSemi
	tokAndAnd
	tokOrOr
	tokAmpersand
	tokPipe
	tokComma
	tokMinusMinus
	tokPlusPlus
	tokDotDot
	tokColonColon
	tokDot
	tokExclaim
	tokMultiply
	tokDivide
	tokRem
	tokPlus
	tokMinus
	tokEquals
	tokPlusEquals
	tokMinusEquals
	tokMultiplyEquals
	tokDivideEquals
	tokRemainderEquals
	tokRedirection // file or merging redirection
	tokRedirectInStd
	tokFormat
	tokNot
	tokBnot
	tokAnd
	tokOr
	tokXor
	tokBand
	tokBor
	tokBxor
	tokJoin
	tokComparison // -eq, -like, -replace, -is, -as, -shl and the like, named in token.op
	tokIsplit
	tokCsplit
	tokColon
	tokQuestionMark
	tokQuestionQuestion
	tokQuestionQuestionEquals
	tokQuestionDot
	tokQuestionLBracket
	tokKeyword
	tokSubExpr // an unscanned $(...) inside an expandable string
)

// Traits of token kinds, from PowerShell's TokenFlags table.
const (
	kindParseModeInvariant = 1 << iota
	kindUnaryOperator
	kindBinaryOperator
	kindAssignmentOperator
)

func (k tokenKind) traits() int {
	switch k {
	case tokNewLine, tokEndOfInput, tokStringLiteral, tokStringExpandable, tokHereStringLiteral,
		tokHereStringExpandable, tokLParen, tokRParen, tokLCurly, tokRCurly, tokRBracket, tokAtParen,
		tokAtCurly, tokDollarParen, tokSemi, tokAndAnd, tokOrOr, tokAmpersand, tokPipe,
		tokRedirectInStd:
		return kindParseModeInvariant
	case tokComma:
		return kindParseModeInvariant | kindUnaryOperator
	case tokMinusMinus, tokPlusPlus, tokExclaim, tokNot, tokBnot:
		return kindUnaryOperator
	case tokPlus, tokMinus, tokJoin, tokIsplit, tokCsplit:
		return kindUnaryOperator | kindBinaryOperator
	case tokDotDot, tokMultiply, tokDivide, tokRem, tokFormat, tokAnd, tokOr, tokXor, tokBand, tokBor,
		tokBxor, tokComparison, tokQuestionQuestion:
		return kindBinaryOperator
	case tokEquals, tokPlusEquals, tokMinusEquals, tokMultiplyEquals, tokDivideEquals,
		tokRemainderEquals, tokQuestionQuestionEquals:
		return kindAssignmentOperator
	}
	return 0
}

func (k tokenKind) is(trait int) bool { return k.traits()&trait != 0 }

// precedence returns a binary operator's precedence, from PowerShell's TokenFlags.BinaryPrecedence values.
func (k tokenKind) precedence() int {
	switch k {
	case tokAnd, tokOr, tokXor:
		return 1
	case tokBand, tokBor, tokBxor:
		return 2
	case tokJoin, tokIsplit, tokCsplit, tokComparison:
		return 5
	case tokQuestionQuestion:
		return 7
	case tokPlus, tokMinus:
		return 9
	case tokMultiply, tokDivide, tokRem:
		return 10
	case tokFormat:
		return 12
	case tokDotDot:
		return 13
	}
	return 0
}

// keywords is the tokenizer's keyword table. A word in it is a keyword only
// in command mode, and only when a token boundary follows it. Elsewhere it is
// a plain word.
var keywords = map[string]bool{}

func init() {
	for k := range strings.FieldsSeq(`elseif if else switch foreach from in for while until do try
		catch finally trap data return continue break exit throw begin process end dynamicparam
		function filter param class define var using workflow parallel sequence inlinescript
		configuration public private static interface enum namespace module type assembly command
		hidden base default clean`) {
		keywords[k] = true
	}
}

// operators maps the words after a dash in expression mode to their kinds.
// Comparison-like operators share tokComparison, and their token keeps the
// word in token.op.
var operators = map[string]tokenKind{
	"bnot": tokBnot, "not": tokNot, "f": tokFormat, "and": tokAnd, "band": tokBand, "or": tokOr,
	"bor": tokBor, "xor": tokXor, "bxor": tokBxor, "join": tokJoin, "split": tokIsplit,
	"isplit": tokIsplit, "csplit": tokCsplit,
}

func init() {
	for k := range strings.FieldsSeq(`eq ieq ceq ne ine cne ge ige cge gt igt cgt lt ilt clt le ile
		cle like ilike clike notlike inotlike cnotlike match imatch cmatch notmatch inotmatch
		cnotmatch replace ireplace creplace contains icontains ccontains notcontains inotcontains
		cnotcontains in iin cin notin inotin cnotin isnot is as shl shr`) {
		operators[k] = tokComparison
	}
}

// Stream is a redirection's stream, numbered as PowerShell's RedirectionStream.
type Stream int

// The streams, in PowerShell's order. StreamAll is the * of *> and *>&1.
const (
	StreamAll Stream = iota
	StreamOutput
	StreamError
	StreamWarning
	StreamVerbose
	StreamDebug
	StreamInformation
)

var streamNames = [...]string{"All", "Output", "Error", "Warning", "Verbose", "Debug", "Information"}

// String returns the stream's name in PowerShell's RedirectionStream.
func (s Stream) String() string { return streamNames[s] }

type token struct {
	kind         tokenKind
	start, end   int    // in the lexer's source, in UTF-16 units
	pos, endPos  int    // the same, in the whole input
	text         string // the source text
	value        string // for strings and generic words, the text without quotes and escapes
	format       string // for expandable strings and words, PowerShell's format string
	nested       []*token
	param        string // parameter name without the dash
	usedColon    bool
	path         string // variable path as written, without $ or braces
	number       Number
	from, to     Stream // redirections
	append       bool
	merging      bool
	op           string // for tokComparison, the operator word in lower case
	sub          []uint16
	subOffset    int   // offset of sub's first unit in the whole input
	skipped      []int // the whole input's offsets of the characters sub dropped
	keyword      string
	isExpandable bool // generic word with nested variables or subexpressions
}

func (t *token) isKeyword(k string) bool { return t.kind == tokKeyword && t.keyword == k }

var kindNames = map[tokenKind]string{
	tokAndAnd: "AndAnd", tokOrOr: "OrOr", tokComma: "Comma", tokMinusMinus: "MinusMinus",
	tokPlusPlus: "PlusPlus", tokDotDot: "DotDot", tokExclaim: "Exclaim", tokMultiply: "Multiply",
	tokDivide: "Divide", tokRem: "Rem", tokPlus: "Plus", tokMinus: "Minus", tokEquals: "Equals",
	tokPlusEquals: "PlusEquals", tokMinusEquals: "MinusEquals", tokMultiplyEquals: "MultiplyEquals",
	tokDivideEquals: "DivideEquals", tokRemainderEquals: "RemainderEquals", tokFormat: "Format",
	tokNot: "Not", tokBnot: "Bnot", tokAnd: "And", tokOr: "Or", tokXor: "Xor", tokBand: "Band",
	tokBor: "Bor", tokBxor: "Bxor", tokJoin: "Join", tokIsplit: "Isplit", tokCsplit: "Csplit",
}

var comparisonNames = map[string]string{
	"eq": "Ieq", "ieq": "Ieq", "ceq": "Ceq", "ne": "Ine", "ine": "Ine", "cne": "Cne",
	"ge": "Ige", "ige": "Ige", "cge": "Cge", "gt": "Igt", "igt": "Igt", "cgt": "Cgt",
	"lt": "Ilt", "ilt": "Ilt", "clt": "Clt", "le": "Ile", "ile": "Ile", "cle": "Cle",
	"like": "Ilike", "ilike": "Ilike", "clike": "Clike", "notlike": "Inotlike",
	"inotlike": "Inotlike", "cnotlike": "Cnotlike", "match": "Imatch", "imatch": "Imatch",
	"cmatch": "Cmatch", "notmatch": "Inotmatch", "inotmatch": "Inotmatch", "cnotmatch": "Cnotmatch",
	"replace": "Ireplace", "ireplace": "Ireplace", "creplace": "Creplace", "contains": "Icontains",
	"icontains": "Icontains", "ccontains": "Ccontains", "notcontains": "Inotcontains",
	"inotcontains": "Inotcontains", "cnotcontains": "Cnotcontains", "in": "Iin", "iin": "Iin",
	"cin": "Cin", "notin": "Inotin", "inotin": "Inotin", "cnotin": "Cnotin", "is": "Is",
	"isnot": "IsNot", "as": "As", "shl": "Shl", "shr": "Shr",
}

// kindName returns the operator's name in PowerShell's TokenKind, such as
// Plus, Ieq, Format or AndAnd. The syntax tree names operators this way.
func kindName(t *token) string {
	if t.kind == tokComparison {
		return comparisonNames[t.op]
	}
	return kindNames[t.kind]
}
