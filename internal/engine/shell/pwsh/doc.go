// Package pwsh parses PowerShell command lines as PowerShell itself does, so
// the engine can check them with the rules it applies to bash
// (docs/powershell.md). The lexer and parser are ports of PowerShell 7's
// tokenizer.cs and Parser.cs, and the tree mirrors its
// System.Management.Automation.Language AST, extents in UTF-16 units
// included. The parser's output is checked against PowerShell's own parser,
// as docs/powershell.md describes. The adapted source is copyright Microsoft
// Corporation and licensed under MIT; see LICENSE.PowerShell
//
// Parse fails closed. What PowerShell reports as a syntax error, what this
// package refuses to analyze (Error.Refused) and what is over a limit all
// come back as an error the engine denies
package pwsh
