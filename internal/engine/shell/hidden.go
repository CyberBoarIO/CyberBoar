package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Hidden code: some constructs evaluate a word's run-time value as code, or as
// a name the shell then looks up. A value that holds $(…) or a backquote runs
// its command when the shell evaluates it, and the analysis can't see that
// value: vars.go follows only plain literal values, and the word may have run-
// time parts. So such a construct asks. When the line also holds that code as
// literal text, the code is inline code, and denyInterpreters denies it.
// Arithmetic asks only when a name it reads may hold something other than a
// number (names.go).

// readArgOpts are the options of read that take an argument, and mapfileArgOpts
// those of mapfile and readarray, where -t is a flag. unset takes none
var readArgOpts = set("-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u")
var mapfileArgOpts = set("-c", "-C", "-d", "-n", "-O", "-s", "-u")

// Why a declaration, an integer parameter or a name reference asks
const (
	integerWhat     = "an integer variable, whose value is evaluated as arithmetic"
	nameRefWhat     = "a name reference, whose target is looked up on each use"
	dynamicWhat     = "a declaration of a name that is dynamic or subscripted"
	subscriptedWhat = "a subscripted name in test -v, printf -v, unset or read"
)

// hiddenCode records the constructs in f that evaluate a run-time value as code
// or as a name: prompt expansion, indirect expansion, arithmetic on a name, and
// a subscripted name given to test -v, printf -v, unset or read
func (a *analyzer) hiddenCode(f *syntax.File) {
	safe := a.safeNames(f)
	var whats []string
	add := func(what string) { whats = append(whats, what) }
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.ParamExp:
			switch {
			case x.Exp != nil && x.Exp.Op == syntax.OtherParamOps && x.Exp.Word.Lit() == "P":
				add("prompt expansion ${…@P}")
			case x.Excl && x.Names == 0:
				add("indirect expansion ${!…}")
			case x.Flags != nil:
				add("a zsh ${(…)} expansion, which may evaluate its value")
			case x.Index != nil && !safe.arithSafe(x.Index):
				add("arithmetic in a subscript")
			case x.Slice != nil && (!safe.arithSafe(x.Slice.Offset) || !safe.arithSafe(x.Slice.Length)):
				add("arithmetic in a substring")
			}
		case *syntax.ArithmExp:
			if !safe.arithSafe(x.X) {
				add("arithmetic on a name")
			}
		case *syntax.ArithmCmd:
			if !safe.arithSafe(x.X) {
				add("arithmetic on a name")
			}
		case *syntax.CStyleLoop:
			if !safe.arithSafe(x.Init) || !safe.arithSafe(x.Cond) || !safe.arithSafe(x.Post) {
				add("arithmetic on a name")
			}
		case *syntax.LetClause:
			for _, e := range x.Exprs {
				if !safe.arithSafe(e) {
					add("arithmetic on a name")
					break
				}
			}
		case *syntax.BinaryTest:
			if arithTestOp(x.Op) && (!safe.arithSafe(x.X) || !safe.arithSafe(x.Y)) {
				add("arithmetic test")
			}
		case *syntax.UnaryTest:
			if w, ok := x.X.(*syntax.Word); ok && x.Op == syntax.TsVarSet {
				a.nameWord(w, add)
			}
		case *syntax.Assign:
			if x.Index != nil && !safe.arithSafe(x.Index) {
				add("arithmetic in a subscript")
			}
			if x.Name != nil && zshIntegers[x.Name.Value] && !a.numberWord(x.Value) {
				add("an assignment to a zsh integer parameter, whose value is evaluated as arithmetic")
			}
		case *syntax.DeclClause:
			if x.Variant.Value == "nameref" {
				add(nameRefWhat)
			}
			for _, as := range x.Args {
				if as.Name == nil && as.Value != nil {
					a.declWord(as.Value, add)
				}
			}
		case *syntax.CallExpr:
			a.nameArgs(x.Args, safe, add)
		}
		return true
	})
	if len(whats) == 0 {
		return
	}
	code := hasLiteralCode(f)
	seen := map[string]bool{} // one entry per kind, however many constructs of it
	for _, what := range whats {
		if seen[what] {
			continue
		}
		seen[what] = true
		a.hidden = append(a.hidden, what)
		if code {
			a.code = append(a.code, Code{What: what})
		}
	}
}

// nameArgs records the name arguments of the commands that look a name up with
// its subscript: a subscript is evaluated as arithmetic, and test or [ compare
// their operands as integers. It also records the declarations that make a
// name an integer or a name reference
func (a *analyzer) nameArgs(words []*syntax.Word, safe *nameSafety, add func(string)) {
	if len(words) == 0 {
		return
	}
	switch words[0].Lit() {
	case "test", "[":
		for i := 1; i < len(words); i++ {
			switch {
			case words[i].Lit() == "-v" && i+1 < len(words):
				a.nameWord(words[i+1], add)
			case arithOps[words[i].Lit()]:
				// the operands on either side are evaluated as arithmetic
				if !safe.arithSafe(words[i-1]) || i+1 < len(words) && !safe.arithSafe(words[i+1]) {
					add("arithmetic test")
				}
			}
		}
	case "printf", "print":
		a.printName(words, add)
	case "unset", "read", "readarray", "mapfile":
		takes := readArgOpts
		switch words[0].Lit() {
		case "unset":
			takes = nil
		case "readarray", "mapfile":
			takes = mapfileArgOpts
		}
		for i := 1; i < len(words); i++ {
			s := words[i].Lit()
			if takes[s] {
				i++ // the option's argument
				continue
			}
			if strings.HasPrefix(s, "-") {
				continue
			}
			a.nameWord(words[i], add)
		}
	case "declare", "typeset", "local", "export", "readonly", "nameref":
		for _, w := range words[1:] {
			a.declWord(w, add)
		}
	case "integer", "float":
		if len(words) > 1 {
			add(integerWhat)
		}
	}
}

// nameWord reports a name argument that could be a subscripted name: one with
// a [ in it, or one only known at run time, which could be any name
func (a *analyzer) nameWord(w *syntax.Word, add func(string)) {
	if s, ok := a.literalWord(w); !ok || strings.Contains(s, "[") {
		add(subscriptedWhat)
	}
}

// printName records the name that printf -v or print -v assigns. The option
// can take the name in the next word (-v a[1]) or attached (-va[1]), and it can
// sit in a cluster (-rv), so the options are read as writer reads them. A word
// that could be an option but isn't literal could name anything
func (a *analyzer) printName(words []*syntax.Word, add func(string)) {
	for i := 1; i < len(words); i++ {
		s, ok := a.literalWord(words[i])
		if !ok {
			if l, isLit := words[i].Parts[0].(*syntax.Lit); !isLit || strings.HasPrefix(l.Value, "-") {
				add(subscriptedWhat)
			}
			return // a format or a value: the options are over
		}
		if !strings.HasPrefix(s, "-") || s == "-" || s == "--" {
			return
		}
		for j := 1; j < len(s); j++ {
			switch {
			case s[j] == 'v' && j == len(s)-1:
				if i+1 < len(words) {
					a.nameWord(words[i+1], add)
				}
				return
			case s[j] == 'v':
				if strings.Contains(s[j+1:], "[") {
					add(subscriptedWhat)
				}
				return
			case strings.IndexByte(argOptions[words[0].Lit()], s[j]) >= 0:
				// another option with an argument: the rest of this word or the next one
				if j == len(s)-1 {
					i++
				}
				j = len(s)
			}
		}
	}
}

// declWord checks an argument of declare, local, export and the like. A flag
// -n makes a name reference and -i an integer. A name must be literal, since
// a dynamic one could be any name, and a subscripted one is evaluated
func (a *analyzer) declWord(w *syntax.Word, add func(string)) {
	if s, ok := a.literalWord(w); ok && strings.HasPrefix(s, "-") {
		if strings.Contains(s, "n") {
			add(nameRefWhat)
		}
		if strings.Contains(s, "i") {
			add(integerWhat)
		}
		return
	}
	if name, ok := a.declName(w); !ok || strings.Contains(name, "[") {
		add(dynamicWhat)
	}
}

// declName returns the name in a declaration argument, the text before its =
// or the whole word without one. ok is false when that text is not literal
func (a *analyzer) declName(w *syntax.Word) (string, bool) {
	if s, ok := a.literalWord(w); ok {
		if i := strings.IndexByte(s, '='); i >= 0 {
			s = s[:i]
		}
		return s, true
	}
	prefix := ""
	for _, part := range w.Parts {
		l, ok := part.(*syntax.Lit)
		if !ok {
			break
		}
		prefix += l.Value
	}
	i := strings.IndexByte(prefix, '=')
	if i < 0 {
		return "", false
	}
	return prefix[:i], true
}

// numberWord reports whether w is absent or a literal number
func (a *analyzer) numberWord(w *syntax.Word) bool {
	if w == nil {
		return true
	}
	s, ok := a.literalWord(w)
	return ok && plainNumber(s)
}

// arithTestOp reports whether a [[ ]] operator compares integers
func arithTestOp(op syntax.BinTestOperator) bool {
	switch op {
	case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
		return true
	}
	return false
}

// hasLiteralCode reports whether f holds code as text: $( or a backquote in a
// literal or single-quoted word. Such text is code only once a value expands it
// (as in y='$(cmd)'; : "${y@P}"), so it is what makes a hidden construct inline code
func hasLiteralCode(f *syntax.File) bool {
	found := false
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Lit:
			found = found || codeText(x.Value)
		case *syntax.SglQuoted:
			// $'…' escapes can spell a $ or a parenthesis, so any ( counts
			found = found || codeText(x.Value) || x.Dollar && strings.ContainsAny(x.Value, "(`")
		}
		return !found
	})
	return found
}

// codeText reports whether s has $( or a backquote in it
func codeText(s string) bool {
	return strings.Contains(s, "$(") || strings.Contains(s, "`")
}
