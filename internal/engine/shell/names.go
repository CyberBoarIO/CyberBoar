package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Arithmetic reads the value of each name it mentions, and a value that isn't a
// number is evaluated as an expression: x='a[$(cmd)]'; echo $((x)) runs cmd. So
// an arithmetic evaluation asks only when a name it reads can hold something
// other than a number. A name nothing on the line writes comes from the
// environment, which the agent can't set in a fresh shell. A name the line
// writes is safe when each write stores a number, an arithmetic result, or a
// plain word, and the names that value reads are safe too. A write the analysis
// can't follow (a function, a declaration, a command that may assign), and a
// persistent shell, make no name safe.

// nameWrite is one write of a name on the line: ok when the value it stores is
// a number, an arithmetic result or a plain word, and deps are the names that
// value reads.
type nameWrite struct {
	ok   bool
	deps []string
}

// nameSafety tells which names on a line an arithmetic evaluation can read.
type nameSafety struct {
	wild   bool                   // a write the analysis can't follow: no name is safe
	writes map[string][]nameWrite // the writes of each name on the line
	safe   map[string]bool        // the written names that are safe
}

// specialNumbers are the special parameters that always hold a number.
var specialNumbers = set("#", "?", "$", "!")

// safeNames works out which names of f are safe to read in arithmetic.
func (a *analyzer) safeNames(f *syntax.File) *nameSafety {
	s := &nameSafety{writes: map[string][]nameWrite{}}
	if a.persistent {
		s.wild = true
		return s
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if s.wild {
			return false
		}
		switch x := n.(type) {
		case *syntax.FuncDecl, *syntax.CoprocClause, *syntax.DeclClause:
			s.wild = true
		case *syntax.CallExpr:
			if len(x.Args) > 0 && a.writer(x.Args) {
				s.wild = true
			}
		case *syntax.Assign:
			s.assign(a, x)
		case *syntax.BinaryArithm:
			if arithAssign(x.Op) {
				name, ok := arithName(x.X)
				if !ok {
					s.wild = true
					break
				}
				deps, ok := readNames(x.Y)
				s.add(name, nameWrite{ok, append(deps, name)})
			}
		case *syntax.UnaryArithm:
			if x.Op == syntax.Inc || x.Op == syntax.Dec {
				name, ok := arithName(x.X)
				if !ok {
					s.wild = true
					break
				}
				s.add(name, nameWrite{true, []string{name}})
			}
		case *syntax.WordIter:
			s.loop(a, x)
		case *syntax.ParamExp:
			if x.Exp != nil && (x.Exp.Op == syntax.AssignUnset || x.Exp.Op == syntax.AssignUnsetOrNull) {
				if x.Param == nil {
					s.wild = true
					break
				}
				s.add(x.Param.Value, nameWrite{})
			}
		case *syntax.Redirect:
			if x.N != nil && strings.HasPrefix(x.N.Value, "{") {
				s.wild = true // {fd}>file assigns fd
			}
		}
		return !s.wild
	})
	if !s.wild {
		s.settle()
	}
	return s
}

// assign records the write of an assignment on the line.
func (s *nameSafety) assign(a *analyzer, x *syntax.Assign) {
	if x.Name == nil {
		s.wild = true // declare "$v=…"
		return
	}
	name := x.Name.Value
	if x.Index != nil || x.Array != nil || x.Append || x.Naked {
		s.add(name, nameWrite{}) // an element, an array, or +=: a string
		return
	}
	if x.Value == nil {
		s.add(name, nameWrite{ok: true}) // NAME=: the empty string is 0
		return
	}
	if len(x.Value.Parts) == 1 {
		if e, ok := x.Value.Parts[0].(*syntax.ArithmExp); ok {
			deps, ok := readNames(e.X)
			s.add(name, nameWrite{ok, deps})
			return
		}
	}
	v, ok := a.literalWord(x.Value)
	switch {
	case ok && plainNumber(v):
		s.add(name, nameWrite{ok: true})
	case ok && plainName(v):
		s.add(name, nameWrite{ok: true, deps: []string{v}}) // the shell reads the word as a name
	default:
		s.add(name, nameWrite{})
	}
}

// loop records the writes of a for loop's variable: each item is a number or a
// plain word. Without items the loop runs over the positional parameters.
func (s *nameSafety) loop(a *analyzer, x *syntax.WordIter) {
	name := x.Name.Value
	if len(x.Items) == 0 {
		s.add(name, nameWrite{})
		return
	}
	var deps []string
	ok := true
	for _, w := range x.Items {
		v, lit := a.literalWord(w)
		switch {
		case lit && plainNumber(v):
		case lit && plainName(v):
			deps = append(deps, v)
		default:
			ok = false
		}
	}
	s.add(name, nameWrite{ok, deps})
}

func (s *nameSafety) add(name string, w nameWrite) {
	s.writes[name] = append(s.writes[name], w)
}

// settle works out which written names are safe. It starts from all of them
// safe and drops any with a write that isn't, until nothing changes, so a name
// that reads itself (n=$((n+1))) stays safe when its other writes are.
func (s *nameSafety) settle() {
	s.safe = map[string]bool{}
	for name := range s.writes {
		s.safe[name] = true
	}
	for changed := true; changed; {
		changed = false
		for name, ws := range s.writes {
			for _, w := range ws {
				if s.safe[name] && !(w.ok && s.allSafe(w.deps)) {
					s.safe[name] = false
					changed = true
				}
			}
		}
	}
}

// allSafe reports whether every name in names is safe.
func (s *nameSafety) allSafe(names []string) bool {
	for _, name := range names {
		if s.wild {
			return false
		}
		if _, written := s.writes[name]; written && !s.safe[name] {
			return false
		}
	}
	return true
}

// arithSafe reports whether arithmetic on n reads only safe names. A nil n
// (an omitted part of a C-style loop or substring) reads nothing.
func (s *nameSafety) arithSafe(n syntax.Node) bool {
	if n == nil {
		return true
	}
	names, ok := readNames(n)
	return ok && s.allSafe(names)
}

// readNames returns the names that arithmetic on n reads. ok is false when n
// holds more than names, numbers and operators: a substitution, a positional
// parameter, or a parameter with an operator or subscript.
func readNames(n syntax.Node) (names []string, ok bool) {
	ok = true
	syntax.Walk(n, func(m syntax.Node) bool {
		switch x := m.(type) {
		case *syntax.Lit:
			// a $, a backquote or a backslash in literal text is code or escaped code
			if strings.ContainsAny(x.Value, "$`\\") {
				ok = false
			}
			names = append(names, identsIn(x.Value)...)
		case *syntax.SglQuoted:
			ok = false // quoted text is evaluated as arithmetic too: let 'a[$(cmd)]'
		case *syntax.ParamExp:
			switch {
			case !plainParam(x):
				ok = false
			case specialNumbers[x.Param.Value]:
			case plainName(x.Param.Value):
				names = append(names, x.Param.Value)
			default:
				ok = false
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			ok = false
		}
		return ok
	})
	return names, ok
}

// arithAssign reports whether an arithmetic operator assigns its left operand.
func arithAssign(op syntax.BinAritOperator) bool {
	switch op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn, syntax.QuoAssgn,
		syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn, syntax.XorAssgn, syntax.ShlAssgn,
		syntax.ShrAssgn, syntax.PowAssgn:
		return true
	}
	return false
}

// arithName returns the name that an assignment or increment in arithmetic
// writes. ok is false for anything else, such as an element of an array.
func arithName(e syntax.ArithmExpr) (string, bool) {
	w, ok := e.(*syntax.Word)
	if !ok {
		return "", false
	}
	name := w.Lit()
	return name, plainName(name)
}

// identsIn returns the names in arithmetic text: a letter or _, then letters,
// digits or _.
func identsIn(s string) []string {
	var names []string
	for i := 0; i < len(s); {
		if !identStart(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && identChar(s[j]) {
			j++
		}
		names = append(names, s[i:j])
		i = j
	}
	return names
}

// plainName reports whether s is a name: a letter or _, then letters, digits or _.
func plainName(s string) bool {
	if s == "" || !identStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !identChar(s[i]) {
			return false
		}
	}
	return true
}

// plainNumber reports whether s is an integer, optionally negative, or empty
// (which arithmetic reads as 0).
func plainNumber(s string) bool {
	return strings.Trim(strings.TrimPrefix(s, "-"), "0123456789") == ""
}

func identStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func identChar(c byte) bool {
	return identStart(c) || c >= '0' && c <= '9'
}
