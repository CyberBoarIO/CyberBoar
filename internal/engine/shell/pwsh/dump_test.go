package pwsh

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// dump writes the tree in the form scripts/pwsh-ast.ps1 writes PowerShell's
// own: Type{properties}(children), with PowerShell's type names and its
// children in source order. The Go tree is smaller than PowerShell's (no
// NamedBlockAst, no TypeConstraintAst nodes of their own), so dump adds
// those back where PowerShell has them
func dump(sb *ScriptBlock) string {
	var b strings.Builder
	scriptBlockNode(sb).write(&b)
	return b.String()
}

type dnode struct {
	typ   string
	props string
	ext   Extent
	kids  []*dnode
}

func (d *dnode) write(b *strings.Builder) {
	fmt.Fprintf(b, "%s@%d-%d", d.typ, d.ext.Start, d.ext.End)
	if d.props != "" {
		b.WriteString("{" + d.props + "}")
	}
	if len(d.kids) == 0 {
		return
	}
	b.WriteByte('(')
	for i, k := range d.kids {
		if i > 0 {
			b.WriteByte(' ')
		}
		k.write(b)
	}
	b.WriteByte(')')
}

// sorted orders children as the dump script does, by start then end offset
func sortedNodes(kids []*dnode) []*dnode {
	slices.SortStableFunc(kids, func(a, b *dnode) int {
		return cmp.Or(cmp.Compare(a.ext.Start, b.ext.Start), cmp.Compare(a.ext.End, b.ext.End))
	})
	return kids
}

func quoted(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func psBool(v bool) string {
	if v {
		return "True"
	}
	return "False"
}

var stringKindNames = [...]string{"BareWord", "SingleQuoted", "DoubleQuoted", "SingleQuotedHereString", "DoubleQuotedHereString"}

func (k StringKind) String() string { return stringKindNames[k] }

func scriptBlockNode(sb *ScriptBlock) *dnode {
	d := &dnode{typ: "ScriptBlockAst", ext: sb.Extent}
	if sb.Param != nil {
		d.kids = append(d.kids, node(sb.Param))
	}
	var blocks []*dnode
	for _, nb := range []struct {
		kind string
		body *StatementBlock
	}{{"Begin", sb.BeginBlock}, {"Process", sb.ProcessBlock}, {"End", sb.EndBlock}} {
		if nb.body == nil {
			continue
		}
		blocks = append(blocks, &dnode{
			typ: "NamedBlockAst", props: nb.kind + ";" + psBool(!sb.NamedBlocks),
			ext: nb.body.Extent, kids: statements(nb.body),
		})
	}
	d.kids = sortedNodes(append(d.kids, blocks...))
	return d
}

// statements are a block's statements and traps, in source order
func statements(b *StatementBlock) []*dnode {
	var kids []*dnode
	for _, s := range b.Statements {
		kids = append(kids, node(s))
	}
	for _, t := range b.Traps {
		kids = append(kids, node(t))
	}
	return sortedNodes(kids)
}

func typeConstraint(t *TypeConstraint) *dnode {
	return &dnode{typ: "TypeConstraintAst", props: quoted(fullName(t.TypeName)), ext: t.Extent}
}

// fullName is PowerShell's ITypeName.FullName: the name as written, generic
// arguments in brackets, then the array ranks
func fullName(t *TypeName) string {
	s := t.Name
	if len(t.Generic) > 0 {
		args := make([]string, len(t.Generic))
		for i, g := range t.Generic {
			args[i] = fullName(g)
		}
		s += "[" + strings.Join(args, ",") + "]"
	}
	for _, rank := range t.Array {
		s += "[" + strings.Repeat(",", rank-1) + "]"
	}
	return s
}

var invocationNames = map[string]string{"": "Unknown", "&": "Ampersand", ".": "Dot"}

var flowNames = map[string]string{
	"return": "ReturnStatementAst", "exit": "ExitStatementAst", "throw": "ThrowStatementAst",
	"break": "BreakStatementAst", "continue": "ContinueStatementAst",
}

func switchFlags(s *Switch) string {
	var f []string
	if s.Regex {
		f = append(f, "Regex")
	}
	if s.Wildcard {
		f = append(f, "Wildcard")
	}
	if s.CaseSensitive {
		f = append(f, "CaseSensitive")
	}
	if len(f) == 0 {
		return "None"
	}
	return strings.Join(f, ", ")
}

func node(n Node) *dnode {
	d := &dnode{ext: n.Span()}
	add := func(ns ...Node) {
		for _, c := range ns {
			if c != nil && !isNil(c) {
				d.kids = append(d.kids, node(c))
			}
		}
	}
	block := func(b *StatementBlock) {
		if b != nil {
			d.kids = append(d.kids, &dnode{typ: "StatementBlockAst", ext: b.Extent, kids: statements(b)})
		}
	}
	switch v := n.(type) {
	case *ScriptBlock:
		return scriptBlockNode(v)
	case *ParamBlock:
		d.typ = "ParamBlockAst"
		for _, a := range v.Attributes {
			add(a)
		}
		for _, p := range v.Parameters {
			add(p)
		}
	case *Parameter:
		d.typ = "ParameterAst"
		for _, a := range v.Attributes {
			add(a)
		}
		add(v.Name, v.Default)
	case *Attribute:
		d.typ, d.props = "AttributeAst", quoted(fullName(v.Type))
		for _, e := range v.Positional {
			add(e)
		}
		for _, a := range v.Named {
			add(a)
		}
	case *NamedAttributeArgument:
		d.typ, d.props = "NamedAttributeArgumentAst", quoted(v.Name)+";"+psBool(v.Omitted)
		if v.Omitted {
			d.kids = append(d.kids, &dnode{typ: "ConstantExpressionAst", props: quoted(v.Name), ext: v.Extent})
		} else {
			add(v.Value)
		}
	case *TypeConstraint:
		return typeConstraint(v)
	case *Pipeline:
		d.typ, d.props = "PipelineAst", psBool(v.Background)
		for _, e := range v.Elements {
			add(e)
		}
	case *PipelineChain:
		d.typ, d.props = "PipelineChainAst", v.Operator+";"+psBool(v.Background)
		add(v.Left, v.Right)
	case *Assignment:
		d.typ, d.props = "AssignmentStatementAst", v.Operator
		add(v.Left, v.Right)
	case *If:
		d.typ = "IfStatementAst"
		for _, c := range v.Clauses {
			add(c.Condition)
			block(c.Body)
		}
		block(v.Else)
	case *Switch:
		d.typ, d.props = "SwitchStatementAst", switchFlags(v)
		add(v.Condition)
		for _, c := range v.Clauses {
			add(c.Condition)
			block(c.Body)
		}
		block(v.Default)
	case *Foreach:
		d.typ = "ForEachStatementAst"
		add(v.Variable, v.Condition)
		block(v.Body)
	case *For:
		d.typ = "ForStatementAst"
		add(v.Initializer, v.Condition, v.Iterator)
		block(v.Body)
	case *While:
		d.typ = "WhileStatementAst"
		add(v.Condition)
		block(v.Body)
	case *DoLoop:
		d.typ = "DoWhileStatementAst"
		if v.Until {
			d.typ = "DoUntilStatementAst"
		}
		block(v.Body)
		add(v.Condition)
	case *Try:
		d.typ = "TryStatementAst"
		block(v.Body)
		for _, c := range v.Catches {
			add(c)
		}
		block(v.Finally)
	case *Catch:
		d.typ = "CatchClauseAst"
		for _, t := range v.Types {
			d.kids = append(d.kids, typeConstraint(t))
		}
		block(v.Body)
	case *Trap:
		d.typ = "TrapStatementAst"
		if v.Type != nil {
			d.kids = append(d.kids, typeConstraint(v.Type))
		}
		block(v.Body)
	case *FunctionDefinition:
		d.typ, d.props = "FunctionDefinitionAst", quoted(v.Name)+";"+psBool(v.Filter)
		for _, p := range v.Parameters {
			add(p)
		}
		add(v.Body)
	case *Flow:
		d.typ = flowNames[v.Keyword]
		add(v.Pipeline, v.Label)
	case *Command:
		d.typ, d.props = "CommandAst", invocationNames[v.Invocation]
		for _, e := range v.Elements {
			add(e)
		}
		for _, r := range v.Redirections {
			add(r)
		}
	case *CommandExpression:
		d.typ = "CommandExpressionAst"
		add(v.Expression)
		for _, r := range v.Redirections {
			add(r)
		}
	case *CommandParameter:
		d.typ, d.props = "CommandParameterAst", quoted(v.Name)
		add(v.Argument)
	case *FileRedirection:
		d.typ, d.props = "FileRedirectionAst", v.From.String()+";"+psBool(v.Append)
		add(v.Location)
	case *MergingRedirection:
		d.typ, d.props = "MergingRedirectionAst", v.From.String()+";"+v.To.String()
	case *StringConstant:
		d.typ, d.props = "StringConstantExpressionAst", quoted(v.Value)+";"+v.Kind.String()
	case *ExpandableString:
		d.typ, d.props = "ExpandableStringExpressionAst", quoted(v.Value)+";"+v.Kind.String()
		for _, e := range v.Nested {
			add(e)
		}
	case *Constant:
		d.typ, d.props = "ConstantExpressionAst", quoted(v.Text)
	case *Variable:
		d.typ, d.props = "VariableExpressionAst", quoted(v.Path)+";"+psBool(v.Splatted)
	case *SubExpression:
		d.typ = "SubExpressionAst"
		block(v.Body)
	case *ArrayExpression:
		d.typ = "ArrayExpressionAst"
		block(v.Body)
	case *Paren:
		d.typ = "ParenExpressionAst"
		add(v.Pipeline)
	case *ScriptBlockExpression:
		d.typ = "ScriptBlockExpressionAst"
		add(v.Block)
	case *Hashtable:
		d.typ = "HashtableAst"
		for _, p := range v.Pairs {
			add(p.Key, p.Value)
		}
	case *ArrayLiteral:
		d.typ = "ArrayLiteralAst"
		for _, e := range v.Elements {
			add(e)
		}
	case *Binary:
		d.typ, d.props = "BinaryExpressionAst", v.Operator
		add(v.Left, v.Right)
	case *Unary:
		d.typ, d.props = "UnaryExpressionAst", v.Operator
		add(v.Child)
	case *Convert:
		d.typ = "ConvertExpressionAst"
		d.kids = append(d.kids, typeConstraint(v.Type))
		add(v.Child)
	case *TypeExpression:
		d.typ, d.props = "TypeExpressionAst", quoted(fullName(v.Type))
	case *AttributedExpression:
		d.typ = "AttributedExpressionAst"
		add(v.Attribute, v.Child)
	case *Member:
		d.typ, d.props = "MemberExpressionAst", psBool(v.Static)
		add(v.Target, v.Member)
	case *InvokeMember:
		d.typ, d.props = "InvokeMemberExpressionAst", psBool(v.Static)
		add(v.Target, v.Member)
		for _, e := range v.Arguments {
			add(e)
		}
	case *Index:
		d.typ = "IndexExpressionAst"
		add(v.Target, v.Index)
	default:
		panic(fmt.Sprintf("dump: unknown node %T", n))
	}
	d.kids = sortedNodes(d.kids)
	return d
}
