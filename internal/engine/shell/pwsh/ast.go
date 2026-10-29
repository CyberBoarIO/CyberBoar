package pwsh

// The syntax tree mirrors PowerShell's System.Management.Automation.Language
// AST, with the same names minus the Ast suffix, so a reader can check one
// against the other. It holds only what the analysis needs. It keeps no
// tokens, and an extent is a start and an end offset in UTF-16 units, as
// PowerShell's Extent.StartOffset counts them

// Node is any node of the tree.
type Node interface {
	// Pos returns the node's start offset in UTF-16 units.
	Pos() int
	// Span returns the node's extent.
	Span() Extent
}

// Extent is a node's position in the input, as start and end offsets in UTF-16 units.
type Extent struct {
	Start, End int
}

// Pos returns the start offset.
func (e Extent) Pos() int { return e.Start }

// Span returns the extent itself.
func (e Extent) Span() Extent { return e }

// Statement is a statement, such as a pipeline, an assignment, a flow
// statement, a loop or a function definition.
type Statement interface {
	Node
	statement()
}

// Expression is an expression. Every expression can be a command element.
type Expression interface {
	CommandElement
	expression()
}

// CommandElement is an element of a command, either an Expression or a CommandParameter.
type CommandElement interface {
	Node
	commandElement()
}

// ScriptBlock is the body of a script block, which is the whole input, a
// function's body or a { ... } literal. When NamedBlocks is false, the body's
// statements are its EndBlock, or its ProcessBlock for a filter.
type ScriptBlock struct {
	Extent
	Param        *ParamBlock
	BeginBlock   *StatementBlock
	ProcessBlock *StatementBlock
	EndBlock     *StatementBlock
	Filter       bool
	NamedBlocks  bool // written as begin { ... } process { ... } end { ... }
}

// ParamBlock is a param(...) block and the attributes before it, such as [CmdletBinding()].
type ParamBlock struct {
	Extent
	Attributes []*Attribute
	Parameters []*Parameter
}

// Parameter is one parameter of a param block or a function.
type Parameter struct {
	Extent
	Attributes []AttributeBase
	Name       *Variable
	Default    Expression
}

// AttributeBase is an Attribute or a TypeConstraint.
type AttributeBase interface {
	Node
	attribute()
}

// Attribute is [Name(args)].
type Attribute struct {
	Extent
	Type       *TypeName
	Positional []Expression
	Named      []*NamedAttributeArgument
}

// NamedAttributeArgument is Name = value in an attribute.
// A Name written without a value means $true.
type NamedAttributeArgument struct {
	Extent
	Name    string
	Value   Expression // nil when omitted
	Omitted bool
}

// TypeConstraint is [Type] before a variable or an expression.
type TypeConstraint struct {
	Extent
	TypeName *TypeName
}

// TypeName is a type as written, with its name, its generic arguments, and
// the ranks of the arrays around it, innermost first. For [int[][,]], Name is
// int and Array is [1, 2].
type TypeName struct {
	Extent
	Name    string
	Generic []*TypeName
	Array   []int
}

// StatementBlock is a { ... } body. Traps holds the trap statements among
// its statements, and Statements holds the others.
type StatementBlock struct {
	Extent
	Statements []Statement
	Traps      []*Trap
}

// Pipeline is commands joined by |.
// Background is a trailing & (PowerShell 7).
type Pipeline struct {
	Extent
	Elements   []CommandBase
	Background bool
}

// PipelineChain is two pipelines joined by && or || (PowerShell 7).
// Left is a Pipeline or another PipelineChain.
type PipelineChain struct {
	Extent
	Left       Statement
	Right      *Pipeline
	Operator   string // "AndAnd" or "OrOr"
	Background bool
}

// Assignment is target = value, or += and the other compound forms.
// As in PowerShell, a value that is a lone expression is its CommandExpression,
// not a Pipeline.
type Assignment struct {
	Extent
	Left     Expression
	Operator string
	Right    Statement
}

// If is if/elseif/else.
type If struct {
	Extent
	Clauses []IfClause
	Else    *StatementBlock
}

// IfClause is a condition and the block it guards.
type IfClause struct {
	Condition Statement
	Body      *StatementBlock
}

// Switch is a switch statement.
type Switch struct {
	Extent
	Regex, Wildcard, CaseSensitive bool
	Condition                      Statement
	Clauses                        []SwitchClause
	Default                        *StatementBlock
}

// SwitchClause is a value to match and its block.
type SwitchClause struct {
	Condition Expression
	Body      *StatementBlock
}

// Foreach is foreach ($v in ...) { ... }.
type Foreach struct {
	Extent
	Variable  *Variable
	Condition Statement
	Body      *StatementBlock
}

// For is for (init; condition; iterator) { ... }. Any of the three parts may be nil.
type For struct {
	Extent
	Initializer, Condition, Iterator Statement
	Body                             *StatementBlock
}

// While is while (...) { ... }.
type While struct {
	Extent
	Condition Statement
	Body      *StatementBlock
}

// DoLoop is do { ... } while (...), or do { ... } until (...) when Until is set.
type DoLoop struct {
	Extent
	Body      *StatementBlock
	Until     bool
	Condition Statement
}

// Try is try/catch/finally.
type Try struct {
	Extent
	Body    *StatementBlock
	Catches []*Catch
	Finally *StatementBlock
}

// Catch is a catch clause. A clause without Types catches every error.
type Catch struct {
	Extent
	Types []*TypeConstraint
	Body  *StatementBlock
}

// Trap is trap [Type] { ... }.
type Trap struct {
	Extent
	Type *TypeConstraint // nil traps every error
	Body *StatementBlock
}

// FunctionDefinition is function or filter Name (params) { ... }.
type FunctionDefinition struct {
	Extent
	Name       string
	Filter     bool
	Parameters []*Parameter
	Body       *ScriptBlock
}

// Flow is return, exit or throw with an optional pipeline, or break or
// continue with an optional label.
type Flow struct {
	Extent
	Keyword  string // "return", "exit", "throw", "break" or "continue"
	Pipeline Statement
	Label    Expression
}

func (*Pipeline) statement()           {}
func (*PipelineChain) statement()      {}
func (*Assignment) statement()         {}
func (*If) statement()                 {}
func (*Switch) statement()             {}
func (*Foreach) statement()            {}
func (*For) statement()                {}
func (*While) statement()              {}
func (*DoLoop) statement()             {}
func (*Try) statement()                {}
func (*Trap) statement()               {}
func (*FunctionDefinition) statement() {}
func (*Flow) statement()               {}

// CommandBase is a pipeline element, either a Command or a CommandExpression.
type CommandBase interface {
	Node
	commandBase()
	// Redirects returns the element's redirections.
	Redirects() []Redirection
}

// Command is a command call. Elements holds its name and arguments as written.
// Invocation is "&" or "." when the command was invoked with that operator, and empty otherwise.
type Command struct {
	Extent
	Invocation   string
	Elements     []CommandElement
	Redirections []Redirection
}

// CommandExpression is an expression used as a pipeline's first element.
type CommandExpression struct {
	Extent
	Expression   Expression
	Redirections []Redirection
}

func (*Command) commandBase()           {}
func (*CommandExpression) commandBase() {}

// A CommandExpression is a statement on its own as an assignment's value.
func (*Command) statement()           {}
func (*CommandExpression) statement() {}

// Redirects returns the command's redirections.
func (c *Command) Redirects() []Redirection { return c.Redirections }

// Redirects returns the expression's redirections.
func (c *CommandExpression) Redirects() []Redirection { return c.Redirections }

// CommandParameter is -Name, or -Name:value with Argument set.
type CommandParameter struct {
	Extent
	Name     string
	Argument Expression
}

func (*CommandParameter) commandElement() {}

// Redirection is a FileRedirection or a MergingRedirection.
type Redirection interface {
	Node
	redirection()
}

// FileRedirection is n> file or n>> file.
type FileRedirection struct {
	Extent
	From     Stream
	Append   bool
	Location Expression
}

// MergingRedirection is n>&1.
type MergingRedirection struct {
	Extent
	From, To Stream
}

func (*FileRedirection) redirection()    {}
func (*MergingRedirection) redirection() {}

// StringKind says how a string was written.
type StringKind uint8

// The ways to write a string.
const (
	BareWord StringKind = iota
	SingleQuoted
	DoubleQuoted
	SingleQuotedHereString
	DoubleQuotedHereString
)

// StringConstant is a string without expansions.
// It is a bare word, a single-quoted string, or a double-quoted string with nothing to expand, and
// Value has its quotes and escapes removed.
type StringConstant struct {
	Extent
	Value string
	Kind  StringKind
}

// ExpandableString is a string with $variables or $(...) in it
// Value is the text with escapes removed and the expansions as written, and Nested
// holds the expansions in order. Value can't tell an expansion from the same
// text written with an escaped $, so "$x `$x" and "`$x $x" have the same
// Value. Format tells them apart. It is the format string PowerShell builds
// for the string, "{0} $x" and "$x {0}" here, which its compiler formats with
// the -f operator to get the string's value at run time. Format is built
// exactly as PowerShell builds it. In a bare word, PowerShell doesn't double
// the braces of a single-quoted part or of an escaped first character, so
// the word's value can then differ from what its text suggests, or fail to format.
type ExpandableString struct {
	Extent
	Value  string
	Format string
	Kind   StringKind
	Nested []Expression
}

// Constant is a number.
type Constant struct {
	Extent
	Text  string
	Value Number
}

// Variable is $name, ${name} or @name (Splatted).
type Variable struct {
	Extent
	Path     string // as written, with any scope or drive, as in env:PATH
	Splatted bool
}

// Name returns the variable's name without its scope or drive.
func (v *Variable) Name() string { return unqualified(v.Path) }

// Drive returns the drive the variable is read from, "env" for $env:PATH and
// "c" for ${c:\x}, or "" for a plain variable or one with only a scope.
func (v *Variable) Drive() string {
	_, drive := splitVariablePath(v.Path)
	return drive
}

// SubExpression is $(...).
type SubExpression struct {
	Extent
	Body *StatementBlock
}

// ArrayExpression is @(...).
type ArrayExpression struct {
	Extent
	Body *StatementBlock
}

// Paren is (...), holding a pipeline or an assignment.
type Paren struct {
	Extent
	Pipeline Statement
}

// ScriptBlockExpression is a { ... } literal.
type ScriptBlockExpression struct {
	Extent
	Block *ScriptBlock
}

// Hashtable is @{ key = value; ... }.
type Hashtable struct {
	Extent
	Pairs []KeyValue
}

// KeyValue is one entry of a Hashtable.
type KeyValue struct {
	Key   Expression
	Value Statement
}

// ArrayLiteral is a, b, c (or ,a).
type ArrayLiteral struct {
	Extent
	Elements []Expression
}

// Binary is left op right. Operator is the operator's name in PowerShell's
// TokenKind, such as Plus, Ieq, Format or DotDot. As in PowerShell, -eq and
// -ieq are both Ieq.
type Binary struct {
	Extent
	Operator    string
	Left, Right Expression
}

// Unary is op child, or child op for a postfix ++ or --. Operator is the
// operator's name in PowerShell's TokenKind: Not, Exclaim, Bnot, Minus, Plus,
// PlusPlus, MinusMinus, Join, Isplit or Csplit, or PostfixPlusPlus or
// PostfixMinusMinus for a postfix operator.
type Unary struct {
	Extent
	Operator string
	Postfix  bool
	Child    Expression
}

// Convert is [Type] child.
type Convert struct {
	Extent
	Type  *TypeConstraint
	Child Expression
}

// TypeExpression is a type literal, written [Type].
type TypeExpression struct {
	Extent
	Type *TypeName
}

// AttributedExpression is [Attribute(...)] child, as in a param block's [ValidateNotNull()][string]$x.
type AttributedExpression struct {
	Extent
	Attribute *Attribute
	Child     Expression
}

// Member is target.member or target::member (Static).
type Member struct {
	Extent
	Target Expression
	Member CommandElement // a StringConstant for a plain name
	Static bool
}

// InvokeMember is target.member(args), or target.member{ ... } with the block as the one argument.
type InvokeMember struct {
	Extent
	Target    Expression
	Member    CommandElement
	Arguments []Expression
	Static    bool
}

// Index is target[index].
type Index struct {
	Extent
	Target, Index Expression
}

func (*StringConstant) expression()        {}
func (*ExpandableString) expression()      {}
func (*Constant) expression()              {}
func (*Variable) expression()              {}
func (*SubExpression) expression()         {}
func (*ArrayExpression) expression()       {}
func (*Paren) expression()                 {}
func (*ScriptBlockExpression) expression() {}
func (*Hashtable) expression()             {}
func (*ArrayLiteral) expression()          {}
func (*Binary) expression()                {}
func (*Unary) expression()                 {}
func (*Convert) expression()               {}
func (*TypeExpression) expression()        {}
func (*AttributedExpression) expression()  {}
func (*Member) expression()                {}
func (*InvokeMember) expression()          {}
func (*Index) expression()                 {}

func (*StringConstant) commandElement()        {}
func (*ExpandableString) commandElement()      {}
func (*Constant) commandElement()              {}
func (*Variable) commandElement()              {}
func (*SubExpression) commandElement()         {}
func (*ArrayExpression) commandElement()       {}
func (*Paren) commandElement()                 {}
func (*ScriptBlockExpression) commandElement() {}
func (*Hashtable) commandElement()             {}
func (*ArrayLiteral) commandElement()          {}
func (*Binary) commandElement()                {}
func (*Unary) commandElement()                 {}
func (*Convert) commandElement()               {}
func (*TypeExpression) commandElement()        {}
func (*AttributedExpression) commandElement()  {}
func (*Member) commandElement()                {}
func (*InvokeMember) commandElement()          {}
func (*Index) commandElement()                 {}

func (*Attribute) attribute()      {}
func (*TypeConstraint) attribute() {}

// Children returns n's child nodes in the order Inspect visits them.
func Children(n Node) []Node { return children(n) }

// Inspect walks the tree in depth-first order. It calls f(n) and, if f
// returns true, walks n's children in source order.
// Unlike go/ast.Inspect, it never calls f(nil).
func Inspect(n Node, f func(Node) bool) {
	if n == nil || isNil(n) || !f(n) {
		return
	}
	for _, c := range children(n) {
		Inspect(c, f)
	}
}

func isNil(n Node) bool {
	switch v := n.(type) {
	case *ScriptBlock:
		return v == nil
	case *StatementBlock:
		return v == nil
	case *ParamBlock:
		return v == nil
	case *TypeName:
		return v == nil
	}
	return false
}

func children(n Node) []Node {
	var out []Node
	add := func(ns ...Node) {
		for _, c := range ns {
			if c != nil && !isNil(c) {
				out = append(out, c)
			}
		}
	}
	addExprs := func(es []Expression) {
		for _, e := range es {
			add(e)
		}
	}
	switch v := n.(type) {
	case *ScriptBlock:
		if v.Param != nil {
			add(v.Param)
		}
		for _, b := range []*StatementBlock{v.BeginBlock, v.ProcessBlock, v.EndBlock} {
			if b != nil {
				add(b)
			}
		}
	case *ParamBlock:
		for _, a := range v.Attributes {
			add(a)
		}
		for _, p := range v.Parameters {
			add(p)
		}
	case *Parameter:
		for _, a := range v.Attributes {
			add(a)
		}
		add(v.Name)
		if v.Default != nil {
			add(v.Default)
		}
	case *Attribute:
		addExprs(v.Positional)
		for _, a := range v.Named {
			add(a)
		}
	case *NamedAttributeArgument:
		if v.Value != nil {
			add(v.Value)
		}
	case *StatementBlock:
		for _, s := range v.Statements {
			add(s)
		}
		for _, t := range v.Traps {
			add(t)
		}
	case *Pipeline:
		for _, e := range v.Elements {
			add(e)
		}
	case *PipelineChain:
		add(v.Left, v.Right)
	case *Assignment:
		add(v.Left, v.Right)
	case *If:
		for _, c := range v.Clauses {
			add(c.Condition, c.Body)
		}
		if v.Else != nil {
			add(v.Else)
		}
	case *Switch:
		add(v.Condition)
		for _, c := range v.Clauses {
			add(c.Condition, c.Body)
		}
		if v.Default != nil {
			add(v.Default)
		}
	case *Foreach:
		add(v.Variable, v.Condition, v.Body)
	case *For:
		for _, s := range []Statement{v.Initializer, v.Condition, v.Iterator} {
			if s != nil {
				add(s)
			}
		}
		add(v.Body)
	case *While:
		add(v.Condition, v.Body)
	case *DoLoop:
		add(v.Body, v.Condition)
	case *Try:
		add(v.Body)
		for _, c := range v.Catches {
			add(c)
		}
		if v.Finally != nil {
			add(v.Finally)
		}
	case *Catch:
		add(v.Body)
	case *Trap:
		add(v.Body)
	case *FunctionDefinition:
		for _, p := range v.Parameters {
			add(p)
		}
		add(v.Body)
	case *Flow:
		if v.Pipeline != nil {
			add(v.Pipeline)
		}
		if v.Label != nil {
			add(v.Label)
		}
	case *Command:
		for _, e := range v.Elements {
			add(e)
		}
		for _, r := range v.Redirections {
			add(r)
		}
	case *CommandExpression:
		add(v.Expression)
		for _, r := range v.Redirections {
			add(r)
		}
	case *CommandParameter:
		if v.Argument != nil {
			add(v.Argument)
		}
	case *FileRedirection:
		add(v.Location)
	case *ExpandableString:
		addExprs(v.Nested)
	case *SubExpression:
		add(v.Body)
	case *ArrayExpression:
		add(v.Body)
	case *Paren:
		add(v.Pipeline)
	case *ScriptBlockExpression:
		add(v.Block)
	case *Hashtable:
		for _, p := range v.Pairs {
			add(p.Key, p.Value)
		}
	case *ArrayLiteral:
		addExprs(v.Elements)
	case *Binary:
		add(v.Left, v.Right)
	case *Unary:
		add(v.Child)
	case *Convert:
		add(v.Child)
	case *AttributedExpression:
		add(v.Attribute, v.Child)
	case *Member:
		add(v.Target, v.Member)
	case *InvokeMember:
		add(v.Target, v.Member)
		addExprs(v.Arguments)
	case *Index:
		add(v.Target, v.Index)
	}
	return out
}
