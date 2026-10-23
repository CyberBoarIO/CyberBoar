package pwsh

import (
	"errors"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell/limits"
)

// Every construct Parse refuses (docs/powershell.md "Refused") fails closed:
// an *Error marked Refused that wraps limits.ErrUnparseable, so the engine denies the line
// Each refusal in the lexer and the parser has a case here;
// the differential can't show them, since PowerShell accepts them all
func TestRefused(t *testing.T) {
	for _, in := range []string{
		"\"`e[31m\"",                    // `e: 5.1 reads e
		"\"`u{2028}\"",                  // `u{…}: 5.1 reads u{2028}
		"#Requires -RunAsAdministrator", // #Requires
		"#requires -Modules x\nls",
		"\u017Fwitch (1) { }",              // ſ folds onto s in some .NET versions: switch
		"brea\u212A",                       // K (Kelvin) onto k: break
		"\u0131f (1) { }",                  // dotless ı onto I: if
		"1d", "1l", "1u", "1y", "1s", "1n", // type suffixes
		"0b101", "0x10kb", // binary, hex with a multiplier
		"9223372036854775808", "1e400", // too large
		"[System.Int32, mscorlib]::MaxValue", // assembly-qualified
		"using namespace System.IO",
		"using module x",
		"{ clean { ls } }", "function f { clean { } }",
		"function f { dynamicparam { } end { } }",
		"[CmdletBinding()] if (1) { }",
		"class C { }", "enum E { A }", "data { 'x' }", "workflow w { }", "parallel { }",
		"sequence { }", "configuration c { }",
		":outer while (1) { break outer }",
		"switch -\u212Aase (1) { }", // non-ASCII flag
		"switch -file x { a { } }", "switch -parallel (1) { }",
		"foreach -parallel ($x in 1) { }",
		"$x ??= 1",
		"echo --% & del x", "& cmd --% /c dir", "cmd /c --% dir",
		"$a ? 1 : 2",
		"$a ?? 'b'",
		"Invoke-Command { $using:x }",
		"${a}?.b", "${a}?[0]",
		"$x.M[int]()",
		"ls \x00", // NUL
	} {
		_, err := Parse(in)
		var pe *Error
		if !errors.As(err, &pe) || !pe.Refused || !errors.Is(err, limits.ErrUnparseable) {
			t.Errorf("%q: want a refusal wrapping ErrUnparseable, got %v", in, err)
		}
	}
}

// Syntax errors fail closed too: an *Error, not Refused, wrapping limits.ErrUnparseable
func TestSyntaxErrors(t *testing.T) {
	for _, in := range []string{
		"(", ")", "{", "}", "[", "\"", "'", "@'\nx", "@\"\nx", "$(", "@(", "@{", "${",
		"if", "if (", "if ($x)", "if ($x) {", "while ($x)", "do { }", "for (", "0x1FFFFFFFFFFFFFFFF",
		"switch ($x)", "switch ($x) { }", "switch -nope ($x) { }", "foreach ($x) { }",
		"function", "function f", "try { }", "try { } catch [", "trap",
		"$x =", "1 +", "-not", "ls |", "ls &&", "ls >", "ls 2>&3", "ls <x", "[int", "[int]::",
		"$x.", "$x[", "$x.y(", "param(", "param($a,)", "[Parameter(]$a",
		"begin { } ls", "end { } end { }", "{a} b", "1 = 2", "$x, 1 += 2", "(1)++",
		"@x", "ls -a:@x", "[Parameter()]1", "@{a=1; A=2}", "@{1=1; '1'=2}",
		"from x", "define x", "var x", "\xff", "ls \xc3",
	} {
		_, err := Parse(in)
		var pe *Error
		if !errors.As(err, &pe) || pe.Refused || !errors.Is(err, limits.ErrUnparseable) {
			t.Errorf("%q: want a syntax error wrapping ErrUnparseable, got %v", in, err)
		}
	}
}

// The limits are the bash analyzer's: input size, nesting, and commands
func TestLimits(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"size":            {strings.Repeat("a", limits.MaxBytes+1), limits.ErrTooLarge},
		"parentheses":     {strings.Repeat("(", 300) + "1" + strings.Repeat(")", 300), limits.ErrTooComplex},
		"script blocks":   {strings.Repeat("{", 300) + strings.Repeat("}", 300), limits.ErrTooComplex},
		"if statements":   {strings.Repeat("if (1) {", 200) + strings.Repeat("}", 200), limits.ErrTooComplex},
		"subexpressions":  {strings.Repeat(`"$(`, 200) + strings.Repeat(`)"`, 200), limits.ErrTooComplex},
		"attributes":      {strings.Repeat("[int]", 300) + "$x", limits.ErrTooComplex},
		"unary operators": {strings.Repeat("-not ", 300) + "$x", limits.ErrTooComplex},
		"commands":        {strings.Repeat("ls;", limits.MaxCommands+1), limits.ErrTooComplex},
		"pipeline":        {strings.Repeat("ls|", limits.MaxCommands) + "ls", limits.ErrTooComplex},
	} {
		_, err := Parse(tc.in)
		var pe *Error
		if !errors.As(err, &pe) || !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
	if _, err := Parse(strings.Repeat("ls;", limits.MaxCommands)); err != nil {
		t.Errorf("%d commands: %v", limits.MaxCommands, err)
	}
	if _, err := Parse(strings.Repeat("(", 50) + "1" + strings.Repeat(")", 50)); err != nil {
		t.Errorf("50 parentheses: %v", err)
	}
}

func TestErrorOffset(t *testing.T) {
	_, err := Parse("ls; é; $x ?? 1")
	var pe *Error
	if !errors.As(err, &pe) || pe.Offset != 10 {
		t.Fatalf("got %v, want the offset of ?? in UTF-16 units (10)", err)
	}
	if !strings.Contains(err.Error(), "offset 10") || !strings.Contains(err.Error(), "not analyzed") {
		t.Errorf("message: %v", err)
	}
}

func TestVariableNameAndDrive(t *testing.T) {
	for _, tc := range []struct{ in, name, drive string }{
		{"$x", "x", ""},
		{"$env:PATH", "PATH", "env"},
		{"$Global:x", "x", ""},
		{"${c:\\x}", "\\x", "c"},
		{"$script:env:x", "env:x", ""},
	} {
		sb, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		var v *Variable
		Inspect(sb, func(n Node) bool {
			if x, ok := n.(*Variable); ok {
				v = x
			}
			return true
		})
		if v == nil {
			t.Fatalf("%s: no variable node", tc.in)
		}
		_, drive := splitVariablePath(v.Path)
		if v.Name() != tc.name || drive != tc.drive {
			t.Errorf("%s: got %+v, want name %q drive %q", tc.in, v, tc.name, tc.drive)
		}
	}
}

// Inspect visits every node once, parents before children, in source order
func TestInspect(t *testing.T) {
	sb, err := Parse(`if ($a) { ls -r "x$y" | sort } else { $z = @{k = 1} }`)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	last := -1
	Inspect(sb, func(n Node) bool {
		switch v := n.(type) {
		case *Command:
			kinds = append(kinds, "cmd")
		case *Variable:
			kinds = append(kinds, "$"+v.Path)
			if v.Start < last {
				t.Errorf("$%s visited after offset %d", v.Path, last)
			}
			last = v.Start
		}
		return true
	})
	if got := strings.Join(kinds, " "); got != "$a cmd $y cmd $z" {
		t.Errorf("got %s", got)
	}
}
