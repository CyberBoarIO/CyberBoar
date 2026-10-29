// Package limits holds the limits and errors the shell analyzers share: bash
// in package shell and PowerShell's parser in package pwsh, which package
// shell builds on. Both report a command line they can't read in full with
// these errors, and the engine denies each.
package limits

import "errors"

// Limits. Anything beyond them is refused, not truncated.
const (
	MaxBytes    = 64 << 10 // command line size
	MaxDepth    = 8        // nesting of code in code: sh -c 'eval "…"'
	MaxCommands = 256      // simple commands, including nested ones
)

// Errors for a command line that can't be read in full: longer than
// MaxBytes, not valid syntax (wrapped with the parser's message), or past
// MaxDepth, MaxCommands or another limit of the analysis.
var (
	ErrTooLarge    = errors.New("command line is too large to analyze")
	ErrUnparseable = errors.New("command line is not valid shell syntax")
	ErrTooComplex  = errors.New("command line is too complex to analyze")
)
