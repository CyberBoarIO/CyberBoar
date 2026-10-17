package shell

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Variables a command line sets for itself. In `f=/x/file.txt; wc -l "$f"`
// the value of $f is known before anything runs, so the path is checked as
// /x/file.txt instead of as a word only known at run time
// Only what can't go wrong is followed:
//
//   - the assignment is a statement of its own (NAME=value, no command), at
//     the top level of the line or in an && chain there
//   - its value is literal: quotes, escapes, $HOME and variables already
//     known, but no substitution, glob or array, and no ~ after a colon
//   - nothing else on the line writes the name: no other assignment, no
//     declaration, loop variable, ${name=…} or {name}> redirection
//   - nothing on the line can write a variable behind the analysis' back:
//     no function, eval, source, alias, trap, read and the like, no
//     arithmetic at all (it evaluates the values of the names it reads, and
//     [[ -eq ]] is arithmetic too), and no command whose name is only known
//     at run time
//   - the name isn't one the shell treats specially (IFS, PATH, PWD, …)
//   - the shell is not persistent: there, an alias or a DEBUG trap from an
//     earlier command could assign the name between the two statements
//
// Code that a nested shell runs (sh -c '…') knows only its own variables

// writesVars are commands that may assign a variable, or change the shell
// so that something else does
var writesVars = set("read", "readarray", "mapfile", "getopts", "let", "source", ".", "eval",
	"alias", "trap", "enable", "declare", "typeset", "local", "export", "readonly", "unset", "coproc",
	// zsh
	"vared", "zparseopts", "zstyle", "getln", "integer", "float", "private", "zmodload",
	"emulate", "autoload", "functions", "noglob")

// assignOption is the option letter with which a command assigns the
// variable it names: printf -v, zsh's print -v, wait -p
var assignOption = map[string]byte{"printf": 'v', "print": 'v', "wait": 'p'}

// argOptions are the options of those commands that take an argument
var argOptions = map[string]string{"printf": "v", "print": "CufvxX", "wait": "p"}

// writer reports whether a command may assign a variable: one of writesVars,
// one with its assignOption, or command and builtin running one of them. Its
// name, and the options of these commands, must be known to tell
func (a *analyzer) writer(words []*syntax.Word) bool {
	if len(words) == 0 {
		return false
	}
	name, ok := a.literalWord(words[0])
	if !ok || writesVars[name] {
		return true
	}
	if opt, ok := assignOption[name]; ok {
		// The options, in clusters (wait -np) and past other options'
		// arguments (print -C 3 -v f), end at the first other word or --
		args := argOptions[name]
		for i := 1; i < len(words); i++ {
			s, ok := a.literalWord(words[i])
			switch {
			case !ok:
				return true // could be an option
			case s == "--" || s == "-" || !strings.HasPrefix(s, "-"):
				return false
			}
			for j := 1; j < len(s); j++ {
				if s[j] == opt {
					return true
				}
				if strings.IndexByte(args, s[j]) >= 0 {
					if j == len(s)-1 {
						i++ // the argument is the next word
					}
					break // or the rest of this one
				}
			}
		}
		return false
	}
	if name != "command" && name != "builtin" {
		return false
	}
	// Their options end at the first word that isn't one, or after --
	for i, w := range words[1:] {
		s, ok := a.literalWord(w)
		switch {
		case !ok:
			return true // could be an option
		case s == "--":
			return a.writer(words[2+i:])
		case !strings.HasPrefix(s, "-") || s == "-":
			return a.writer(words[1+i:])
		}
	}
	return false
}

// specialVars are names bash or zsh treat specially: their value can differ
// from what was assigned, an assignment can fail, or they change how the
// shell reads what follows
var specialVars = set("HOME", "IFS", "PATH", "CDPATH", "PWD", "OLDPWD", "ENV", "BASH_ENV",
	"SHELLOPTS", "BASHOPTS", "GLOBIGNORE", "POSIXLY_CORRECT", "PS1", "PS2", "PS3", "PS4",
	"PROMPT_COMMAND", "RANDOM", "SRANDOM", "SECONDS", "LINENO", "EPOCHSECONDS", "EPOCHREALTIME",
	"BASHPID", "PPID", "UID", "EUID", "GROUPS", "HOSTNAME", "HOSTTYPE", "OSTYPE", "MACHTYPE",
	"OPTIND", "OPTARG", "OPTERR", "REPLY", "FUNCNAME", "PIPESTATUS", "MAPFILE", "DIRSTACK",
	"HISTCMD", "HISTFILE", "TMOUT", "SHLVL", "SHELL", "COLUMNS", "LINES", "TMPDIR", "_",
	// zsh
	"path", "cdpath", "fpath", "manpath", "mailpath", "module_path", "psvar", "watch", "status",
	"pipestatus", "argv", "options", "parameters", "commands", "functions", "aliases", "reply",
	"match", "mbegin", "mend", "MATCH", "MBEGIN", "MEND", "ERRNO", "ZDOTDIR", "TTY", "TTYIDLE",
	"USERNAME", "LOGNAME", "signals", "prompt", "PROMPT", "PROMPT2", "PROMPT3", "PROMPT4", "RPROMPT")

func specialVar(name string) bool {
	return specialVars[name] || strings.HasPrefix(name, "BASH") || strings.HasPrefix(name, "COMP_") ||
		strings.HasPrefix(name, "READLINE_") || strings.HasPrefix(name, "LC_") || name == "LANG"
}

// lineVars is what the analysis knows about the variables of one script
type lineVars struct {
	at map[*syntax.Stmt]map[string]string // the variables known in each statement
	// quotedOnly: IFS is assigned on the line, so unquoted uses split unpredictably
	quotedOnly bool
}

// knownVars works out which variables each statement of f knows
func (a *analyzer) knownVars(f *syntax.File) lineVars {
	if a.persistent {
		return lineVars{}
	}
	writes := map[string]int{}
	bad := false
	syntax.Walk(f, func(n syntax.Node) bool {
		if bad {
			return false
		}
		switch x := n.(type) {
		case *syntax.Assign:
			if x.Name == nil {
				bad = true // declare "$v=…"
			} else {
				writes[x.Name.Value]++
			}
		case *syntax.DeclClause:
			switch x.Variant.Value {
			case "export", "readonly":
				for _, as := range x.Args {
					if as.Name == nil || as.Naked && as.Value != nil {
						bad = true
					}
				}
			default:
				bad = true // declare -n and friends: a name reference writes another name
			}
		case *syntax.FuncDecl, *syntax.LetClause, *syntax.CoprocClause:
			bad = true
		case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.CStyleLoop:
			// Arithmetic can assign without an assignment in sight: the value
			// of a name it reads is itself evaluated (x='f=0'; (( x )))
			bad = true
		case *syntax.BinaryTest:
			switch x.Op {
			case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
				bad = true // [[ 1 -eq f=0 ]] evaluates both sides as arithmetic
			}
		case *syntax.WordIter:
			writes[x.Name.Value] += 2 // a loop variable
		case *syntax.ParamExp:
			if x.Index != nil || x.Slice != nil {
				bad = true // an index or a slice is arithmetic too
			}
			if x.Exp != nil && (x.Exp.Op == syntax.AssignUnset || x.Exp.Op == syntax.AssignUnsetOrNull) && x.Param != nil {
				writes[x.Param.Value] += 2
			}
		case *syntax.Redirect:
			bad = bad || x.N != nil && strings.HasPrefix(x.N.Value, "{") // {fd}>file assigns fd
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				break
			}
			bad = a.writer(x.Args)
		}
		return true
	})
	if bad {
		return lineVars{}
	}
	lv := lineVars{at: map[*syntax.Stmt]map[string]string{}, quotedOnly: writes["IFS"] > 0}
	saved, savedQuoted := a.vars, a.varsQuotedOnly
	a.varsQuotedOnly = lv.quotedOnly
	defer func() { a.vars, a.varsQuotedOnly = saved, savedQuoted }()
	line := map[string]string{} // known from here to the end of the line
	for _, top := range f.Stmts {
		chain := andChain(top)
		known := line
		for i, st := range chain {
			mark(lv.at, st, known)
			set, ok := a.assignment(st, known, writes)
			if !ok {
				continue
			}
			known = cloneWith(known, set)
			if i == 0 {
				line = cloneWith(line, set) // the first link always runs
			}
		}
	}
	return lv
}

// andChain returns the statements of an && chain in the order they run, or st itself
func andChain(st *syntax.Stmt) []*syntax.Stmt {
	b, ok := st.Cmd.(*syntax.BinaryCmd)
	if !ok || b.Op != syntax.AndStmt || st.Negated || st.Background || st.Coprocess || len(st.Redirs) > 0 {
		return []*syntax.Stmt{st}
	}
	return append(andChain(b.X), andChain(b.Y)...)
}

// mark records vars for st and every statement nested in it
func mark(at map[*syntax.Stmt]map[string]string, st *syntax.Stmt, vars map[string]string) {
	syntax.Walk(st, func(n syntax.Node) bool {
		if s, ok := n.(*syntax.Stmt); ok {
			at[s] = vars
		}
		return true
	})
}

func cloneWith(m, add map[string]string) map[string]string {
	out := make(map[string]string, len(m)+len(add))
	for k, v := range m {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

// assignment returns what st assigns when it is a plain NAME=value statement
// whose every value is known, given the variables known before it
// Bash assigns left to right, so a value may use a name set before it in st
func (a *analyzer) assignment(st *syntax.Stmt, known map[string]string, writes map[string]int) (map[string]string, bool) {
	c, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(c.Args) > 0 || len(c.Assigns) == 0 || st.Negated || st.Background || st.Coprocess || len(st.Redirs) > 0 {
		return nil, false
	}
	out := map[string]string{}
	for _, as := range c.Assigns {
		name := as.Name.Value
		if as.Append || as.Naked || as.Index != nil || as.Array != nil || writes[name] != 1 || specialVar(name) {
			continue
		}
		a.vars = cloneWith(known, out)
		v, ok := a.assignedValue(as.Value)
		if !ok {
			continue
		}
		out[name] = v
	}
	return out, len(out) > 0
}

// assignedValue returns the value a NAME=word assignment stores, when it is
// known. An assignment's value is neither split nor globbed, and has ~
// expanded at its start and after every colon. Only a leading ~ is read
// here, so a value with :~ is left unknown, and so is a glob, which fields
// would leave as it is but bash would leave literal
func (a *analyzer) assignedValue(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true // NAME=
	}
	if strings.Contains(wordSrc(w), ":~") || a.classify(w) != Lit {
		return "", false
	}
	f, err := a.fields(w)
	if err != nil || len(f) != 1 || strings.HasPrefix(f[0], "=") { // zsh reads =cmd as a path
		return "", false
	}
	return f[0], true
}

// literalWord returns the value of a word with no run-time parts
func (a *analyzer) literalWord(w *syntax.Word) (string, bool) {
	if a.classify(w) != Lit {
		return "", false
	}
	f, err := a.fields(w)
	if err != nil || len(f) != 1 {
		return "", false
	}
	return f[0], true
}

// splitSafe reports whether an unquoted expansion of v is v itself: one
// field that no glob, extended glob or zsh option changes
func splitSafe(v string) bool {
	return v != "" && !strings.ContainsAny(v, " \t\n*?[]()|!@+\\{}~=#^")
}

// varsEnviron is the environment words are expanded in: the line's own
// variables where they are known, then HOME
type varsEnviron struct {
	a    *analyzer
	base expand.Environ
}

func (e varsEnviron) Get(name string) expand.Variable {
	if v, ok := e.a.vars[name]; ok {
		return expand.Variable{Set: true, Kind: expand.String, Str: v}
	}
	return e.base.Get(name)
}

func (e varsEnviron) Each(f func(name string, vr expand.Variable) bool) {
	for name, v := range e.a.vars {
		if !f(name, expand.Variable{Set: true, Kind: expand.String, Str: v}) {
			return
		}
	}
	e.base.Each(f)
}
