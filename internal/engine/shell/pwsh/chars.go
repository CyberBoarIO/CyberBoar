package pwsh

import "unicode"

// Character classes, ported from PowerShell's CharTraits.cs
// The lexer works on UTF-16 code units, as PowerShell does, so a character outside the Basic
// Multilingual Plane is two units, and each unit is classified alone
// A surrogate is neither a letter nor a space

const (
	traitIdentifierStart = 1 << iota
	traitMultiplierStart
	traitTypeSuffix
	traitWhitespace
	traitNewline
	traitHexDigit
	traitDigit
	traitVarNameFirst
	traitForceStartNewToken
	traitForceStartNewAssemblyNameSpecToken
	traitForceStartNewTokenAfterNumber
)

const (
	noBreakSpace     = 0x00a0
	nextLine         = 0x0085
	enDash           = 0x2013
	emDash           = 0x2014
	horizontalBar    = 0x2015
	quoteSingleLeft  = 0x2018
	quoteSingleRight = 0x2019
	quoteSingleBase  = 0x201a
	quoteReversed    = 0x201b
	quoteDoubleLeft  = 0x201c
	quoteDoubleRight = 0x201d
	quoteLowDouble   = 0x201e
)

var traits = func() [128]uint16 {
	var t [128]uint16
	const newToken = traitForceStartNewToken | traitForceStartNewAssemblyNameSpecToken
	t[0] = newToken
	for _, c := range "\t\v\f " {
		t[c] = traitWhitespace | newToken
	}
	t['\n'] = traitNewline | newToken
	t['\r'] = traitNewline | newToken
	for _, c := range "!#%*+-./<>" {
		t[c] = traitForceStartNewTokenAfterNumber
	}
	t['='] = traitForceStartNewAssemblyNameSpecToken | traitForceStartNewTokenAfterNumber
	t[']'] = traitForceStartNewAssemblyNameSpecToken | traitForceStartNewTokenAfterNumber
	for _, c := range "&(){|};" {
		t[c] = traitForceStartNewToken
	}
	t[','] = newToken
	for _, c := range "$:?^" {
		t[c] = traitVarNameFirst
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = traitDigit | traitHexDigit | traitVarNameFirst
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = traitIdentifierStart | traitVarNameFirst
		t[c+'a'-'A'] = traitIdentifierStart | traitVarNameFirst
	}
	t['_'] = traitIdentifierStart | traitVarNameFirst
	for _, c := range "ABCDEFabcdef" {
		t[c] |= traitHexDigit
	}
	for _, c := range "DLNSUYdlnsuy" {
		t[c] |= traitTypeSuffix
	}
	for _, c := range "GKMPTgkmpt" {
		t[c] |= traitMultiplierStart
	}
	return t
}()

func has(c uint16, trait uint16) bool { return c < 128 && traits[c]&trait != 0 }

// isWhitespace is CharExtensions.IsWhitespace, for which newlines are not whitespace.
func isWhitespace(c uint16) bool {
	switch {
	case c < 128:
		return has(c, traitWhitespace)
	case c <= 256:
		return c == noBreakSpace || c == nextLine
	}
	return isSeparator(c)
}

// isSeparator is .NET's char.IsSeparator, which is true for the categories Zs, Zl and Zp.
func isSeparator(c uint16) bool {
	r := rune(c)
	return unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp)
}

// isDotNetWhiteSpace is .NET's char.IsWhiteSpace, which, unlike isWhitespace, includes newlines.
func isDotNetWhiteSpace(c uint16) bool {
	switch c {
	case '\t', '\n', '\v', '\f', '\r', ' ', nextLine, noBreakSpace:
		return true
	}
	return c > 0xff && isSeparator(c)
}

func isDash(c uint16) bool {
	return c == '-' || c == enDash || c == emDash || c == horizontalBar
}

func isSingleQuote(c uint16) bool {
	return c == '\'' || c == quoteSingleLeft || c == quoteSingleRight || c == quoteSingleBase || c == quoteReversed
}

func isDoubleQuote(c uint16) bool {
	return c == '"' || c == quoteDoubleLeft || c == quoteDoubleRight || c == quoteLowDouble
}

// isLetter and isLetterOrDigit are .NET's char.IsLetter and IsLetterOrDigit
// (categories L*, and L* or Nd). They decide more than where a variable name
// ends. They also decide whether $ or @ starts a variable, whether a dash
// starts a parameter, and whether a word is an identifier or a generic token.
// Go's tables (unicode.Version) may follow a different Unicode version than
// the .NET a given PowerShell runs on, and Windows PowerShell 5.1 runs on .NET
// Framework, whose tables are much older. A line with a letter added between
// the two versions then reads differently. A dash followed by U+1C80, a letter
// since Unicode 9.0, starts a parameter here. A PowerShell whose tables
// predate the letter passes the two as a bare word, a positional argument,
// and reads $a followed by U+1C80 as the variable $a and then text.
func isLetter(c uint16) bool { return unicode.IsLetter(rune(c)) }

func isLetterOrDigit(c uint16) bool {
	return unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))
}

func isDotNetDigit(c uint16) bool { return unicode.IsDigit(rune(c)) }

func isVariableStart(c uint16) bool {
	if c < 128 {
		return has(c, traitVarNameFirst)
	}
	return isLetterOrDigit(c)
}

func isIdentifierStart(c uint16) bool {
	if c < 128 {
		return has(c, traitIdentifierStart)
	}
	return isLetter(c)
}

func isIdentifierFollow(c uint16) bool {
	if c < 128 {
		return has(c, traitIdentifierStart|traitDigit)
	}
	return isLetterOrDigit(c)
}

func isHexDigit(c uint16) bool     { return has(c, traitHexDigit) }
func isDecimalDigit(c uint16) bool { return c >= '0' && c <= '9' }
func isBinaryDigit(c uint16) bool  { return c == '0' || c == '1' }
func isTypeSuffix(c uint16) bool   { return has(c, traitTypeSuffix) }
func isMultiplier(c uint16) bool   { return has(c, traitMultiplierStart) }

func forceStartNewToken(c uint16) bool {
	if c < 128 {
		return has(c, traitForceStartNewToken)
	}
	return isWhitespace(c)
}

func forceStartNewTokenAfterNumber(c uint16, ternary bool) bool {
	if c < 128 {
		if has(c, traitForceStartNewTokenAfterNumber) {
			return true
		}
		return ternary && (c == '?' || c == ':')
	}
	return isDash(c)
}
