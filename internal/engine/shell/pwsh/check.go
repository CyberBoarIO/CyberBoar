package pwsh

// This file ports the part of PowerShell's SemanticChecks
// (SemanticChecks.cs) that rejects a command line by its shape alone. The
// checks run after parsing, as PowerShell runs them. PowerShell runs nothing
// when one fails, so they only keep Parse from analyzing what would never
// run. The checks that need types resolved ([ref] and [void] constraints,
// automatic variables, attribute names) or .NET's number formatting are left
// out, and what they would reject is analyzed as written

import "strconv"

// check returns the first post-parse error in the tree, or nil.
func check(sb *ScriptBlock) *Error {
	var err *Error
	var walk func(n, parent Node)
	walk = func(n, parent Node) {
		if err != nil {
			return
		}
		switch v := n.(type) {
		case *Assignment:
			err = checkAssignmentTarget(v.Left, v.Operator == "Equals", "the left of an assignment must be something to assign to")
		case *Unary:
			switch v.Operator {
			case "PlusPlus", "MinusMinus", "PostfixPlusPlus", "PostfixMinusMinus":
				err = checkAssignmentTarget(v.Child, false, "++ and -- need a variable or a property")
			}
		case *Hashtable:
			err = checkDuplicateKeys(v)
		case *AttributedExpression:
			err = checkAttributed(v)
		case *Variable:
			if _, ok := parent.(*Command); v.Splatted && !ok {
				err = &Error{Offset: v.Start, Msg: "@" + v.Path + " can only splat a command's arguments"}
			}
		}
		for _, c := range children(n) {
			walk(c, n)
		}
	}
	walk(sb, nil)
	return err
}

// checkAssignmentTarget is CheckAssignmentTarget. It accepts a variable, a
// property, an element, a list of them for a plain =, and any of these in
// parentheses or under a type constraint or an attribute.
func checkAssignmentTarget(e Expression, simple bool, msg string) *Error {
	switch v := e.(type) {
	case *ArrayLiteral:
		if !simple {
			return &Error{Offset: v.Start, Msg: msg}
		}
		for _, el := range v.Elements {
			if err := checkAssignmentTarget(el, true, msg); err != nil {
				return err
			}
		}
		return nil
	case *Paren:
		if pure := pureExpression(v.Pipeline); pure != nil {
			return checkAssignmentTarget(pure, simple, msg)
		}
		return &Error{Offset: v.Pipeline.Pos(), Msg: msg}
	case *Convert:
		return checkAssignmentTarget(v.Child, simple, msg)
	case *AttributedExpression:
		return checkAssignmentTarget(v.Child, simple, msg)
	case *Variable, *Member, *InvokeMember, *Index:
		return nil
	}
	return &Error{Offset: e.Pos(), Msg: msg}
}

// pureExpression is PipelineAst.GetPureExpression. It returns the
// expression of a pipeline that is one expression without redirections, and
// nil for any other statement.
func pureExpression(s Statement) Expression {
	p, ok := s.(*Pipeline)
	if !ok || len(p.Elements) != 1 {
		return nil
	}
	if ce, ok := p.Elements[0].(*CommandExpression); ok && len(ce.Redirections) == 0 {
		return ce.Expression
	}
	return nil
}

// checkDuplicateKeys is the check in VisitHashtable for a key written twice.
// It compares keys as PowerShell does, ignoring case, but only where Go is
// sure to agree. Strings compare with ASCII case folding only. Integers
// compare as their decimal text, as in PowerShell, so @{1=1; "1"=2} has a
// duplicate key.
func checkDuplicateKeys(h *Hashtable) *Error {
	seen := map[string]bool{}
	for _, kv := range h.Pairs {
		var key string
		switch k := kv.Key.(type) {
		case *StringConstant:
			key = asciiLower(k.Value)
		case *Constant:
			if k.Value.Real {
				continue
			}
			key = strconv.FormatInt(k.Value.Int, 10)
		default:
			continue
		}
		if seen[key] {
			return &Error{Offset: kv.Key.Pos(), Msg: "a key written twice in a hash literal"}
		}
		seen[key] = true
	}
	return nil
}

// checkAttributed is VisitAttributedExpression. An attribute other than a
// type constraint may only stand before a variable, with any number of
// attributes and type constraints between the two.
func checkAttributed(a *AttributedExpression) *Error {
	for e := Expression(a); ; {
		switch v := e.(type) {
		case *AttributedExpression:
			e = v.Child
			continue
		case *Convert:
			e = v.Child
			continue
		case *Variable:
			return nil
		}
		return &Error{Offset: a.Start, Msg: "an attribute on something other than a variable"}
	}
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
