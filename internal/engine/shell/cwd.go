package shell

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// dir is the working directory a statement runs in: an absolute path (not
// cleaned, so symlinks resolve like the kernel's) or unknown
type dir struct {
	path  string
	known bool
	// posix is the directory in Git Bash's own form when it was reached
	// through one of its mounts (/tmp); "" when that is path (Windows only)
	posix string
	// alt is the other directory the shell may be in, when a cd's ".."
	// left a symbolic link: path is the shell's logical reading, alt the
	// kernel's (POSIX only)
	alt string
}

var unknownDir = dir{}

// either is the directory after one of two paths ran: known only if both agree
func either(a, b dir) dir {
	if a == b {
		return a
	}
	return unknownDir
}

// cwdPass records the directory every statement runs in, following literal
// cd/pushd with the shell's scoping. Anything uncertain becomes unknown
type cwdPass struct {
	a       *analyzer
	of      map[*syntax.Stmt]dir
	cdFuncs map[string]bool // functions defined here whose body changes directory
}

func (a *analyzer) newCwdPass(f *syntax.File) *cwdPass {
	p := &cwdPass{a: a, of: map[*syntax.Stmt]dir{}, cdFuncs: map[string]bool{}}
	a.scanEnvChanges(f)
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.FuncDecl:
			if x.Name != nil && changesDir(x.Body) { // "()cd" parses with no name
				p.cdFuncs[x.Name.Value] = true
			}
		case *syntax.CallExpr:
			// shopt and alias themselves, or after builtin, command and the like
			args := a.words(x.Args)
			if i := litIndex(args, "shopt"); i >= 0 {
				for _, o := range args[i+1:] {
					a.shoptOption(o)
				}
			}
			if i := litIndex(args, "alias"); i >= 0 {
				for _, e := range args[i+1:] {
					if e.Kind == Lit && strings.Contains(e.Text, "=") {
						if a.sawAliases == nil {
							a.sawAliases = map[string]bool{}
						}
						a.sawAliases[e.Text] = true
					}
				}
			}
		}
		return true
	})
	return p
}

// changesDir reports a cd, pushd or popd anywhere in n
func changesDir(n syntax.Node) bool {
	found := false
	syntax.Walk(n, func(x syntax.Node) bool {
		if c, ok := x.(*syntax.CallExpr); ok {
			for _, w := range c.Args {
				switch w.Lit() {
				case "cd", "pushd", "popd":
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// outcome is where a statement leaves the shell: ok if it succeeded (what the
// next command of an && chain starts in), any whatever happened (what the next
// statement after ; starts in; a cd may fail)
type outcome struct {
	ok, any dir
}

func same(d dir) outcome { return outcome{d, d} }

func (p *cwdPass) list(stmts []*syntax.Stmt, d dir) outcome {
	o := same(d)
	for _, st := range stmts {
		o = p.stmt(st, o.any)
	}
	return o
}

// stmt records d for st and everything nested in it
func (p *cwdPass) stmt(st *syntax.Stmt, d dir) outcome {
	p.of[st] = d
	p.a.vars = p.a.varsAt[st]
	for _, r := range st.Redirs {
		p.nested(r, d)
	}
	o := same(d)
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		for _, as := range c.Assigns {
			p.nested(as, d)
		}
		for _, w := range c.Args {
			p.nested(w, d)
		}
		p.a.vars = p.a.varsAt[st] // a nested statement may have set its own
		o = p.call(c, d)
	case *syntax.Subshell:
		p.list(c.Stmts, d)
	case *syntax.Block:
		o = p.list(c.Stmts, d)
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.AndStmt: // Y runs only if X succeeded
			x := p.stmt(c.X, d)
			y := p.stmt(c.Y, x.ok)
			o = outcome{y.ok, either(x.any, y.any)}
		case syntax.OrStmt: // Y runs only if X failed
			x := p.stmt(c.X, d)
			y := p.stmt(c.Y, x.any)
			o = outcome{either(x.ok, y.ok), either(x.any, y.any)}
		default: // lastpipe may keep the final side in the current shell
			p.stmt(c.X, d)
			y := p.stmt(c.Y, d)
			if p.a.lastpipe {
				o = outcome{either(d, y.ok), either(d, y.any)}
			}
		}
	case *syntax.IfClause:
		o = p.ifClause(c, d)
	case *syntax.WhileClause:
		o = p.loop(d, func(d dir) dir { return p.list(c.Do, p.list(c.Cond, d).any).any })
	case *syntax.ForClause:
		p.nested(c.Loop, d)
		o = p.loop(d, func(d dir) dir { return p.list(c.Do, d).any })
	case *syntax.CaseClause:
		p.nested(c.Word, d)
		next := d
		for _, item := range c.Items {
			i := p.list(item.Stmts, next)
			o = outcome{either(o.ok, i.ok), either(o.any, i.any)}
			if item.Op == syntax.Fallthrough || item.Op == syntax.Resume || item.Op == syntax.ResumeKorn {
				// A fall-through path may reach later items, while an
				// independently matched item still starts in d
				next = either(next, i.any)
			}
		}
	case *syntax.FuncDecl:
		p.stmt(c.Body, unknownDir) // runs wherever it's called from
	case *syntax.TimeClause:
		if c.Stmt != nil {
			o = p.stmt(c.Stmt, d)
		}
	case *syntax.CoprocClause:
		p.stmt(c.Stmt, d)
	case nil:
	default: // declarations, tests, arithmetic: only nested substitutions
		p.nested(c, d)
	}
	if st.Background {
		return same(d) // runs in a subshell
	}
	return o
}

func (p *cwdPass) ifClause(c *syntax.IfClause, d dir) outcome {
	cond := p.list(c.Cond, d)
	then := p.list(c.Then, cond.ok)
	other := outcome{cond.any, cond.any}
	if c.Else != nil {
		other = p.ifClause(c.Else, cond.any)
	}
	return outcome{either(then.ok, other.ok), either(then.any, other.any)}
}

// loop runs body once; if it changes the directory, later iterations start
// elsewhere, so the body is recorded again with an unknown directory
func (p *cwdPass) loop(d dir, body func(dir) dir) outcome {
	if after := body(d); after != d {
		body(unknownDir)
		return same(unknownDir)
	}
	return same(d)
}

// nested records d for statements inside substitutions in n; they run in
// subshells, so they don't change d
func (p *cwdPass) nested(n syntax.Node, d dir) {
	if n == nil {
		return
	}
	syntax.Walk(n, func(x syntax.Node) bool {
		switch s := x.(type) {
		case *syntax.CmdSubst:
			p.list(s.Stmts, d)
			return false
		case *syntax.ProcSubst:
			p.list(s.Stmts, d)
			return false
		}
		return true
	})
}

// call returns where a simple command leaves the shell
func (p *cwdPass) call(c *syntax.CallExpr, d dir) outcome {
	u, err := p.a.unwrapAll(p.a.normalize(p.a.words(c.Args)), 0)
	if err != nil {
		return same(unknownDir)
	}
	inner := u.layers[len(u.layers)-1]
	if len(inner) == 0 || inner[0].Kind != Lit {
		return same(d)
	}
	for _, l := range u.layers {
		if len(l) == 0 || l[0].Kind != Lit {
			continue
		}
		for _, body := range p.a.aliasBodies(l[0].Text) {
			if mayChangeDir(body) {
				return same(unknownDir)
			}
		}
	}
	switch name := inner[0].Text; {
	case name == "cd" || name == "pushd":
		to := p.cd(inner[1:], d)
		return outcome{to, either(to, d)} // a cd can fail and leave the shell where it was
	case name == "popd" || name == "source" || name == "." || p.cdFuncs[name]:
		return same(unknownDir)
	case name == "eval":
		if text, _ := join(inner[1:]); mayChangeDir(text) {
			return same(unknownDir)
		}
	}
	return same(d)
}

// mayChangeDir reports code that may change directory (eval, an alias):
// any mention of cd, pushd or popd counts
func mayChangeDir(code string) bool {
	return strings.Contains(code, "cd") || strings.Contains(code, "pushd") || strings.Contains(code, "popd")
}

// cd returns the directory after `cd ARGS`
func (p *cwdPass) cd(args []Elem, d dir) dir {
	for len(args) > 0 && args[0].Kind == Lit && strings.HasPrefix(args[0].Text, "-") && args[0].Text != "-" {
		if args[0].Text == "--" {
			args = args[1:]
			break
		}
		args = args[1:] // -L, -P, -e, -@
	}
	if len(args) == 0 {
		if p.a.homeUnsure {
			return unknownDir
		}
		return dir{path: p.a.home, known: true}
	}
	t := args[0]
	switch {
	case t.Kind != Lit || t.Text == "-":
		return unknownDir
	case p.a.windows:
		if readWinWord(t.Text, gitBashNames).kind == winRel && p.a.cdUnsure && !startsDot(t.Text) {
			return unknownDir // CDPATH or cdable_vars may send it elsewhere
		}
		return p.a.winCd(t.Text, d)
	case path.IsAbs(t.Text):
		return p.a.posixCd(t.Text, dir{})
	case p.a.cdUnsure && !startsDot(t.Text):
		return unknownDir // CDPATH or cdable_vars may send it elsewhere
	case !d.known:
		return unknownDir
	default:
		return p.a.posixCd(t.Text, d)
	}
}

// posixCd returns the directory `cd to` moves to from d (zero for an
// absolute to). Shells apply ".." to the path as written (cd -L), so that
// link/.. is the directory holding the link, where the kernel goes to the
// target's parent. That is also where cd -P, set -P or zsh's chase_links
// go, and bash when the logical directory doesn't exist, so where a ".."
// leaves a link both readings are kept
func (a *analyzer) posixCd(to string, d dir) dir {
	full := to
	next := dir{known: true}
	if !path.IsAbs(to) {
		full = d.path + "/" + to
		if d.alt != "" {
			next.alt = d.alt + "/" + to
		}
	}
	if !hasDotDot(to) {
		next.path = full
		return next
	}
	if next.alt != "" {
		return unknownDir // a third reading; not followed
	}
	next.path = path.Clean(full)
	if a.dotDotLeavesLink(full) {
		next.alt = full
	}
	return next
}

// dotDotLeavesLink reports a ".." in the absolute path p that follows a
// symbolic link, or a name that can't be checked
func (a *analyzer) dotDotLeavesLink(p string) bool {
	cur := "/"
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".":
		case "..":
			if cur == "/" {
				continue
			}
			fi, err := a.fs.Lstat(cur)
			if err != nil && !errors.Is(err, fs.ErrNotExist) || err == nil && fi.Mode()&fs.ModeSymlink != 0 {
				return true
			}
			cur = path.Dir(cur)
		default:
			cur = joinDir(cur, c)
		}
	}
	return false
}

// startsDot reports a cd argument bash never looks up in CDPATH
func startsDot(s string) bool {
	return s == "." || s == ".." || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

func litIndex(args []Elem, word string) int {
	return slices.IndexFunc(args, func(e Elem) bool { return e.Kind == Lit && e.Text == word })
}

// aliasBodies returns the bodies of the aliases called name, in order; none
// while name's own body is being analyzed
func (a *analyzer) aliasBodies(name string) []string {
	if a.expanding[name] {
		return nil
	}
	var out []string
	for def := range a.aliases {
		if n, body, _ := strings.Cut(def, "="); n == name {
			out = append(out, body)
		}
	}
	slices.Sort(out)
	return out
}

// shoptOption notes a shopt option that changes what globs match or where
// cd goes. One known only at run time may be any of them
func (a *analyzer) shoptOption(o Elem) {
	switch {
	case o.Kind != Lit:
		a.mayChangeShell()
	case o.Text == "dotglob":
		a.sawGlobs.dotglob = true
	case o.Text == "globstar":
		a.sawGlobs.globstar = true
	case o.Text == "nocaseglob":
		a.sawGlobs.nocaseglob = true
	case o.Text == "cdable_vars":
		a.sawCd = true
	case o.Text == "lastpipe":
		a.sawLastpipe = true
	}
}

// mayChangeShell notes code that may set any variable or shell option
func (a *analyzer) mayChangeShell() {
	a.sawHome, a.sawCd = true, true
	a.sawGlobs = globOpts{true, true, true}
	a.sawLastpipe = true
}

// setsVars are commands that may assign a variable named by an argument
var setsVars = set("read", "readarray", "mapfile", "export", "declare", "typeset", "local",
	"readonly", "unset", "getopts", "let", "source", ".", "eval", "shopt")

// scanEnvChanges notes code that may change HOME (sawHome), how cd resolves
// names (sawCd: CDPATH, cdable_vars) or what globs match (GLOBIGNORE,
// BASHOPTS). It over-approximates: any literal mentioning one of them other
// than a plain read of $HOME counts, and so does a run-time word given to a
// command that assigns variables
func (a *analyzer) scanEnvChanges(f *syntax.File) {
	reads := map[*syntax.Lit]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if pe, ok := n.(*syntax.ParamExp); ok && pe.Param != nil && pe.Exp == nil {
			reads[pe.Param] = true
		}
		return true
	})
	note := func(s string) {
		a.sawHome = a.sawHome || strings.Contains(s, "HOME")
		a.sawCd = a.sawCd || strings.Contains(s, "CDPATH")
		a.sawGlobs.dotglob = a.sawGlobs.dotglob || strings.Contains(s, "GLOBIGNORE") // set, it turns on dotglob
		if strings.Contains(s, "BASHOPTS") {
			a.mayChangeShell() // bash turns on the options it lists at start-up
		}
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Lit:
			if !reads[x] {
				note(x.Value)
			}
		case *syntax.SglQuoted:
			// eval 'HOME=x' is analyzed too, but printf -v 'HOME' is not code
			// $'\110OME' is HOME as well
			// An escape shells read differently could be anything
			if v, ok := ansiC(x, true); ok {
				note(v)
			} else {
				a.mayChangeShell()
			}
		case *syntax.CallExpr:
			// export HO""ME=x: quotes split the name into several Lits
			for _, e := range a.words(x.Args) {
				if e.Kind == Lit {
					note(e.Text)
				}
			}
			assigns := false
			for _, w := range x.Args {
				assigns = assigns || setsVars[w.Lit()] && w.Lit() != "printf" || w.Lit() == "-v"
			}
			for _, w := range x.Args {
				if assigns && w.Lit() == "" && len(w.Parts) > 0 && !isQuotedLit(w) {
					a.mayChangeShell()
				}
			}
			if len(x.Args) > 0 && (x.Args[0].Lit() == "source" || x.Args[0].Lit() == ".") {
				a.mayChangeShell() // the sourced file may set anything
			}
		case *syntax.DeclClause:
			for _, as := range x.Args {
				if !as.Naked || as.Name != nil || as.Value == nil {
					continue
				}
				if as.Value.Lit() == "" && !isQuotedLit(as.Value) {
					a.mayChangeShell() // declare "$v=…"
				}
				for _, e := range a.word(as.Value) {
					if e.Kind == Lit {
						note(e.Text)
					}
				}
			}
		}
		return true
	})
}

// isQuotedLit reports a word made only of literal and single-quoted parts
func isQuotedLit(w *syntax.Word) bool {
	for _, p := range w.Parts {
		switch p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, in := range p.(*syntax.DblQuoted).Parts {
				if _, ok := in.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
