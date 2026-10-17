// Package shell turns a shell command line into the commands it may run
//
// It parses the command line and finds every simple command anywhere in it:
// lists, pipelines, subshells, command and process substitutions, function
// bodies, and code passed to shells and wrappers (`sh -c`, `eval`, `sudo`,
// `xargs`, …). Nothing is executed. Where the analysis can't know what runs,
// it says so (Many elements, unknown layers) instead of guessing
package shell

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
)

// Limits. Anything beyond them is refused, not truncated
const (
	MaxBytes    = 64 << 10 // command line size
	MaxDepth    = 8        // nesting of code in code: sh -c 'eval "…"'
	MaxCommands = 256      // simple commands, including nested ones
	maxUnwrap   = 16       // wrappers around one command: sudo nice timeout …
)

// Errors Analyze returns for a command line it can't read in full: longer
// than MaxBytes, not valid shell syntax (wrapped with the parser's message),
// or past MaxDepth, MaxCommands or the wrapper limit. The engine denies each
// Literals also uses ErrTooLarge and ErrTooComplex for its expansion limits
var (
	ErrTooLarge    = errors.New("command line is too large to analyze")
	ErrUnparseable = errors.New("command line is not valid shell syntax")
	ErrTooComplex  = errors.New("command line is too complex to analyze")
)

// Command is one simple command. Layers are the argv forms to check: as
// written, then each command a wrapper runs ("sudo nice ls" has three)
// A layer of a single Many element means "could be anything"
type Command struct {
	Layers [][]Elem
}

// Code is one place where text on the command line becomes code
type Code struct {
	What     string // the construct, for messages: "python -c", "ssh -o proxycommand"
	Analyzed bool   // shell code whose commands were analyzed; false: unknown
}

// Analysis is the result of Analyze
type Analysis struct {
	Commands []Command
	// Code lists inline code: code passed to shells and interpreters, and
	// command lines that aren't a single plain command. Values that name a
	// single plain command (GIT_EDITOR=true) are not listed; that command is
	Code []Code
	// Files lists every path the command line may touch
	Files []FileRef
	feeds []commandSet
}

// Feeds reports whether command from's output can reach command to's input,
// through pipes, substitutions or shells in between
func (an *Analysis) Feeds(from, to int) bool {
	row := an.feeds[from]
	_ = an.feeds[to] // retain the matrix's bounds check on both indices
	return row.has(to)
}

type analyzer struct {
	expandCfg *expand.Config
	home      string
	fs        osfs.FS
	windows   bool // paths are read as Git Bash on Windows does (fs.Windows)
	mounts    map[string]string
	// Set on a second pass when the command line may change HOME (so ~,
	// $HOME and a bare cd are unknown) or CDPATH/cdable_vars (so `cd name`
	// may go elsewhere than ./name). saw* record what the first pass found
	homeUnsure, cdUnsure bool
	sawHome, sawCd       bool
	// Glob options set anywhere apply to every glob, the same way
	globs, sawGlobs globOpts
	// lastpipe may run the final pipeline command in the current shell
	lastpipe, sawLastpipe bool
	// Aliases defined anywhere ("name=body"): bash expands them in the
	// lines after, so their bodies run wherever the name is a command
	aliases, sawAliases map[string]bool
	// Aliases whose body is being analyzed: bash doesn't expand an alias
	// again inside its own expansion (alias ls='ls -la')
	expanding map[string]bool
	// persistent: later commands run in the same shell (Options.Persistent)
	persistent bool
	// The variables the line set itself (vars.go): those in each statement
	// of the current script and those known in the statement being analyzed
	vars           map[string]string
	varsAt         map[*syntax.Stmt]map[string]string
	varsQuotedOnly bool
	cmds           []Command
	code           []Code
	files          []FileRef
	edges          []commandSet
	// Code run by a shell or wrapper inherits its stdin and stdout, so
	// whatever feeds the outer command feeds the inner ones, and vice versa
	transparent []transparent
}

type transparent struct {
	outer int
	inner []int
}

var unknownLayer = []Elem{{Kind: Many, Text: "*"}}

// Analyze finds every command src may run and every path it may touch
// home is the value of ~ and $HOME; cwd is the absolute directory it starts in
func Analyze(src, home, cwd string) (*Analysis, error) {
	return analyze(src, home, dir{path: cwd, known: true}, false, false, osfs.FS{}, nil)
}

// Options are what else is known about where a command runs
type Options struct {
	Cwd        string // the starting directory, unless CwdUnknown
	CwdUnknown bool
	CDPath     bool // CDPATH is set in the environment
	// Persistent says earlier commands ran in the same shell. They may have
	// set HOME, CDPATH and glob options, and an alias defined here may be
	// used later with any arguments
	Persistent bool
	// FS reaches the filesystem (glob expansion); the zero value is POSIX.
	FS osfs.FS
	// Mounts is Git Bash's mount table on Windows: mount point (/, /tmp) to
	// the directory in the engine's form, "" when that directory is unknown.
	// Nil means the table is unknown, and paths outside a drive are refused
	Mounts map[string]string
}

// AnalyzeWith is Analyze with Options
func AnalyzeWith(src, home string, o Options) (*Analysis, error) {
	start := dir{path: o.Cwd, known: true}
	if o.CwdUnknown {
		start = unknownDir
	}
	return analyze(src, home, start, o.CDPath, o.Persistent, o.FS, o.Mounts)
}

func analyze(src, home string, start dir, cdPath, persistent bool, fsys osfs.FS, mounts map[string]string) (*Analysis, error) {
	if len(src) > MaxBytes {
		return nil, ErrTooLarge
	}
	homeUnsure, cdUnsure := persistent, cdPath || persistent
	lastpipe := persistent
	var globs globOpts
	if persistent {
		globs = globOpts{true, true, true}
	}
	var aliases map[string]bool
	for {
		a := &analyzer{
			home:        home,
			fs:          fsys,
			windows:     fsys.Windows,
			mounts:      mounts,
			homeUnsure:  homeUnsure,
			cdUnsure:    cdUnsure,
			globs:       globs,
			sawGlobs:    globs,
			lastpipe:    lastpipe,
			sawLastpipe: lastpipe,
			aliases:     aliases,
			sawAliases:  maps.Clone(aliases),
			persistent:  persistent,
		}
		a.expandCfg = &expand.Config{Env: varsEnviron{a: a, base: expand.ListEnviron("HOME=" + home)}}
		if _, err := a.script(src, 0, start); err != nil {
			return nil, err
		}
		// Code anywhere (even in eval or sh -c) may change HOME or CDPATH for
		// what runs after it: analyze everything again assuming it did
		if a.sawHome && !homeUnsure || a.sawCd && !cdUnsure || a.sawGlobs != globs || a.sawLastpipe != lastpipe || len(a.sawAliases) != len(aliases) {
			homeUnsure, cdUnsure = homeUnsure || a.sawHome, cdUnsure || a.sawCd
			globs, aliases = a.sawGlobs, a.sawAliases
			lastpipe = a.sawLastpipe
			continue
		}
		return &Analysis{Commands: a.cmds, Code: a.code, Files: a.files, feeds: a.closure()}, nil
	}
}

func (a *analyzer) script(src string, depth int, start dir) ([]int, error) {
	if depth > MaxDepth {
		return nil, ErrTooComplex
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnparseable, err)
	}
	// Each script knows only its own variables
	saved, savedAt, savedQuoted := a.vars, a.varsAt, a.varsQuotedOnly
	defer func() { a.vars, a.varsAt, a.varsQuotedOnly = saved, savedAt, savedQuoted }()
	a.vars = nil
	lv := a.knownVars(f)
	a.varsAt, a.varsQuotedOnly = lv.at, lv.quotedOnly
	pass := a.newCwdPass(f)
	pass.list(f.Stmts, start)
	ids := map[*syntax.Stmt]int{}
	var all []int
	syntax.Walk(f, func(n syntax.Node) bool {
		if err != nil {
			return false
		}
		st, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		a.vars = a.varsAt[st]
		d := pass.of[st] // unknown if the pass didn't reach it
		a.files = append(a.files, a.redirectRefs(st, d)...)
		switch c := st.Cmd.(type) {
		case *syntax.DeclClause: // export NAME=VALUE, declare, local, …
			err = a.bareAssignments(c.Args, depth, d)
			return err == nil
		case *syntax.CallExpr:
			if len(c.Args) == 0 { // NAME=VALUE on its own
				err = a.bareAssignments(c.Assigns, depth, d)
				return err == nil
			}
		}
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		var id int
		if id, err = a.command(st, call, depth, pass); err == nil {
			ids[st] = id
			all = append(all, id)
		}
		return err == nil
	})
	if err != nil {
		return nil, err
	}
	a.linkFile(f, ids)
	return all, nil
}

// command records one simple command, analysing any code it runs
func (a *analyzer) command(st *syntax.Stmt, call *syntax.CallExpr, depth int, pass *cwdPass) (int, error) {
	if len(a.cmds) >= MaxCommands {
		return 0, ErrTooComplex
	}
	raw := a.words(call.Args)
	u, err := a.unwrapAll(a.normalize(raw), 0)
	if err != nil {
		return 0, err
	}
	id := len(a.cmds)
	a.cmds = append(a.cmds, Command{Layers: u.layers})
	unknown := u.unknown
	d := pass.of[st]
	a.files = append(a.files, a.fileRefs(raw, u, d, a.globs)...)
	// What the wrapped command runs, it runs in the directory it was given
	d = a.innerDir(u, d)
	for _, e := range u.files { // files named inside a sed or awk script
		a.wordRefs(e, d, globOpts{}, false, func(r FileRef) {
			r.Accessed, r.Contents = true, true
			a.files = append(a.files, r)
		})
	}

	for _, r := range u.code {
		if unknown, err = a.runCode(id, r, depth, unknown, d); err != nil {
			return 0, err
		}
	}
	for _, r := range u.cmdLines {
		if unknown, err = a.runCommandLine(id, r, depth, unknown, d); err != nil {
			return 0, err
		}
	}
	if u.stdin != nil {
		src, known := a.stdinScript(st)
		switch {
		case !known:
			a.code = append(a.code, Code{What: u.stdin.what})
			unknown = true
		case src != nil:
			r := codeRun{what: u.stdin.what, text: src.text, foreign: u.stdin.foreign, start: u.stdin.start}
			if unknown, err = a.runCode(id, r, depth, unknown, d); err != nil {
				return 0, err
			}
		}
	}
	if unknown, err = a.assignments(id, call.Assigns, depth, unknown, d); err != nil {
		return 0, err
	}
	for _, e := range u.assigns {
		name, value, _ := strings.Cut(e.Text, "=")
		if unknown, err = a.envVar(id, name, Elem{Kind: Lit, Text: value}, depth, unknown, d); err != nil {
			return 0, err
		}
	}
	if unknown {
		if err := a.markUnknown(id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// innerDir is the directory the innermost command of u runs in, when the shell is in d
func (a *analyzer) innerDir(u unwrapResult, d dir) dir {
	for _, e := range u.dirs {
		switch {
		case e.Kind != Lit:
			d = unknownDir
		case a.windows:
			d = a.winCd(e.Text, d)
		case path.IsAbs(e.Text):
			d = dir{path: e.Text, known: true}
		case d.known:
			d = dir{path: joinDir(d.path, e.Text), known: true}
		}
	}
	return d
}

// runCode handles inline code: shell code is analyzed, anything else (or code
// only known at run time) makes the command unknown
func (a *analyzer) runCode(id int, r codeRun, depth int, unknown bool, d dir) (bool, error) {
	if r.start != nil {
		d = *r.start
	}
	if r.foreign || r.dynamic {
		a.code = append(a.code, Code{What: r.what})
		return true, nil
	}
	a.code = append(a.code, Code{What: r.what, Analyzed: true})
	if r.alias != "" && !a.expanding[r.alias] {
		if a.expanding == nil {
			a.expanding = map[string]bool{}
		}
		a.expanding[r.alias] = true
		defer delete(a.expanding, r.alias)
	}
	inner, err := a.script(r.text, depth+1, d)
	if err == nil && id >= 0 {
		a.transparent = append(a.transparent, transparent{id, inner})
	}
	return unknown, err
}

// runCommandLine handles a value run as a command line
// A single plain command is only a command; anything more is also inline code
func (a *analyzer) runCommandLine(id int, r codeRun, depth int, unknown bool, d dir) (bool, error) {
	if r.start != nil {
		d = *r.start
	}
	if r.dynamic {
		a.code = append(a.code, Code{What: r.what})
		return true, nil
	}
	if !isPlainCommand(r.text) {
		a.code = append(a.code, Code{What: r.what, Analyzed: true})
	}
	inner, err := a.script(r.text, depth+1, d)
	if err == nil && id >= 0 {
		a.transparent = append(a.transparent, transparent{id, inner})
	}
	return unknown, err
}

// isPlainCommand reports a single simple command: words only, no operators,
// redirections, assignments or expansions
func isPlainCommand(text string) bool {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil || len(f.Stmts) != 1 {
		return false
	}
	st := f.Stmts[0]
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(call.Assigns) > 0 || len(st.Redirs) > 0 ||
		st.Negated || st.Background || st.Coprocess || st.Disown {
		return false
	}
	plain := true
	syntax.Walk(st, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ParamExp, *syntax.ArithmExp, *syntax.ExtGlob:
			plain = false
		}
		return plain
	})
	return plain
}

// assignments checks NAME=VALUE settings for variables that run or load code
// id is the command they apply to, or -1 for a bare assignment or export
func (a *analyzer) assignments(id int, as []*syntax.Assign, depth int, unknown bool, d dir) (bool, error) {
	for _, as := range as {
		if as.Name == nil || as.Value == nil {
			continue
		}
		var value Elem
		if elems := a.word(as.Value); len(elems) == 1 {
			value = elems[0]
		} else {
			value = Elem{Kind: Many, Text: "*"}
		}
		var err error
		if unknown, err = a.envVar(id, as.Name.Value, value, depth, unknown, d); err != nil {
			return unknown, err
		}
	}
	return unknown, nil
}

// bareAssignments handles assignments without a command (NAME=VALUE, export)
func (a *analyzer) bareAssignments(as []*syntax.Assign, depth int, d dir) error {
	unknown, err := a.assignments(-1, as, depth, false, d)
	if err != nil {
		return err
	}
	if unknown {
		return a.markUnknown(-1)
	}
	return nil
}

func (a *analyzer) envVar(id int, name string, value Elem, depth int, unknown bool, d dir) (bool, error) {
	switch {
	case shellEnvVars[name]:
		return a.runCommandLine(id, codeRun{what: name, text: value.Text, dynamic: value.Kind != Lit}, depth, unknown, d)
	case isForeignEnvVar(name):
		a.code = append(a.code, Code{What: name})
		return true, nil
	}
	return unknown, nil
}

// markUnknown adds a "could be anything" layer to command id, or, for id < 0,
// a command of its own
func (a *analyzer) markUnknown(id int) error {
	if id >= 0 {
		a.cmds[id].Layers = append(a.cmds[id].Layers, unknownLayer)
		return nil
	}
	if len(a.cmds) >= MaxCommands {
		return ErrTooComplex
	}
	a.cmds = append(a.cmds, Command{Layers: [][]Elem{unknownLayer}})
	return nil
}

type unwrapResult struct {
	layers [][]Elem
	// dirs are the directories wrappers move into (env -C a env -C b), and
	// layers[dirFrom:] run in the last of them; dirFrom is -1 without one
	dirs     []Elem
	dirFrom  int
	code     []codeRun
	cmdLines []codeRun
	stdin    *stdinRun
	assigns  []Elem
	files    []Elem
	unknown  bool
}

func (r *unwrapResult) merge(u unwrapped) {
	r.code = append(r.code, u.code...)
	r.cmdLines = append(r.cmdLines, u.cmdLines...)
	r.assigns = append(r.assigns, u.assigns...)
	r.files = append(r.files, u.files...)
	if u.stdin != nil {
		r.stdin = u.stdin
	}
	r.unknown = r.unknown || u.unknown
}

// unwrapAll follows wrappers from argv inwards, collecting every layer
func (a *analyzer) unwrapAll(argv []Elem, depth int) (unwrapResult, error) {
	res := unwrapResult{layers: [][]Elem{argv}, dirFrom: -1}
	cur := argv
	for n := 0; ; n++ {
		if n > maxUnwrap || depth > maxUnwrap {
			return res, ErrTooComplex
		}
		if len(cur) == 0 || cur[0].Kind != Lit {
			return res, nil
		}
		for _, body := range a.aliasBodies(cur[0].Text) {
			r := joinedCode("alias "+cur[0].Text, append([]Elem{{Kind: Lit, Text: body}}, cur[1:]...))
			r.alias = cur[0].Text
			res.merge(unwrapped{code: []codeRun{r}})
		}
		fn := lookupWrapper(cur[0].Text)
		if fn == nil {
			return res, nil
		}
		u := fn(a, cur[0].Text, cur[1:])
		res.merge(u)
		if u.dir != nil {
			if res.dirFrom < 0 {
				res.dirFrom = len(res.layers) // the layers after this one
				if u.replace {
					res.dirFrom--
				}
			}
			res.dirs = append(res.dirs, *u.dir)
		}
		for _, e := range u.extra {
			sub, err := a.unwrapAll(a.normalize(e), depth+1)
			if err != nil {
				return res, err
			}
			res.layers = append(res.layers, sub.layers...)
			res.merge(unwrapped{code: sub.code, cmdLines: sub.cmdLines, stdin: sub.stdin, assigns: sub.assigns, files: sub.files, unknown: sub.unknown})
		}
		if len(u.next) == 0 {
			return res, nil
		}
		next := a.normalize(u.next)
		if slices.Equal(next, cur) {
			return res, nil // a wrapper that reveals nothing new
		}
		if u.replace {
			res.layers[len(res.layers)-1] = next
		} else {
			res.layers = append(res.layers, next)
		}
		cur = next
	}
}

// stdinScript returns the code a shell reads from stdin: nil with known=true
// for a plain file (not analyzed, like any script file), known=false when the
// code comes from a pipe or anything else only known at run time
func (a *analyzer) stdinScript(st *syntax.Stmt) (src *codeRun, known bool) {
	var last *syntax.Redirect
	for _, r := range st.Redirs {
		if r.N != nil && r.N.Value != "0" {
			continue
		}
		switch r.Op {
		case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			last = r
		}
	}
	if last == nil {
		return nil, false // inherited stdin: a pipe, or whatever the agent passes
	}
	switch last.Op {
	case syntax.Hdoc, syntax.DashHdoc:
		if last.Hdoc == nil {
			return &codeRun{}, true
		}
		if a.hasDynamicPart(last.Hdoc) {
			return nil, false
		}
		text, err := expand.Document(a.expandCfg, last.Hdoc)
		return &codeRun{text: text}, err == nil
	case syntax.WordHdoc:
		elems := a.word(last.Word)
		if len(elems) != 1 || elems[0].Kind != Lit {
			return nil, false
		}
		return &codeRun{text: elems[0].Text}, true
	case syntax.RdrIn, syntax.RdrInOut:
		if a.hasDynamicPart(last.Word) {
			return nil, false // e.g. bash < <(curl …)
		}
		return nil, true
	default: // <&N: another descriptor
		return nil, false
	}
}

// linkFile records which commands feed which: pipes, and command/process
// substitutions into the command that uses them
func (a *analyzer) linkFile(f *syntax.File, ids map[*syntax.Stmt]int) {
	var spans map[syntax.Node]commandSpan
	var order []int
	cmdsIn := func(n syntax.Node) []int {
		if n == nil {
			return nil
		}
		if spans == nil {
			spans, order = indexCommands(f, ids)
		}
		// The AST index stores each queried node's command ids as a preorder
		// span, so linkFile can recover the same Walk order without re-walking
		// overlapping subtrees such as successive pipeline prefixes
		span := spans[n]
		return order[span.start:span.end]
	}
	substitutions := func(n syntax.Node, targets []int) {
		syntax.Walk(n, func(m syntax.Node) bool {
			switch s := m.(type) {
			case *syntax.CmdSubst:
				a.link(cmdsIn(s), targets)
			case *syntax.ProcSubst:
				if s.Op == syntax.CmdOut { // >(…) reads the command's output
					a.link(targets, cmdsIn(s))
				} else {
					a.link(cmdsIn(s), targets)
				}
			}
			return true
		})
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				a.link(cmdsIn(x.X), cmdsIn(x.Y))
			}
		case *syntax.Stmt:
			if id, ok := ids[x]; ok {
				substitutions(x, []int{id})
			} else if x.Cmd != nil && len(x.Redirs) > 0 {
				targets := cmdsIn(x.Cmd)
				for _, r := range x.Redirs {
					substitutions(r, targets)
				}
			}
		}
		return true
	})
}

func (a *analyzer) link(from, to []int) {
	if len(from) == 0 || len(to) == 0 {
		return
	}
	if len(a.edges) < len(a.cmds) {
		a.edges = append(a.edges, make([]commandSet, len(a.cmds)-len(a.edges))...)
	}
	var targets commandSet
	for _, t := range to {
		targets.add(t)
	}
	for _, f := range from {
		// Each row is a source command; its bits are the commands it feeds
		row := targets
		row[f/64] &^= uint64(1) << uint(f%64) // no direct self edges
		a.edges[f].merge(row)
	}
}

// closure computes the transitive "feeds" relation, including through code
// run by shells and wrappers
func (a *analyzer) closure() []commandSet {
	n := len(a.cmds)
	m := make([]commandSet, n)
	if len(a.edges) == 0 {
		return m // transparency alone does not introduce a feeds relation
	}
	copy(m, a.edges)
	// Wrapper transparency can add reachability after a closure pass, and those
	// new paths can in turn imply more transparent links. Repeat until no such
	// links are added. Transparency is propagated from existing reachability
	// across the wrapper boundary rather than modeled as ordinary edges: an
	// isolated wrapper must not create a feeds relation by itself
	for changed := true; changed; {
		changed = false
		for k := 0; k < n; k++ {
			for i := 0; i < n; i++ {
				if !m[i].has(k) {
					continue
				}
				m[i].merge(m[k])
			}
		}
		for _, t := range a.transparent {
			for x := 0; x < n; x++ {
				for _, in := range t.inner {
					if m[x].has(t.outer) && x != in && !m[x].has(in) {
						m[x].add(in)
						changed = true
					}
					if m[t.outer].has(x) && x != in && !m[in].has(x) {
						m[in].add(x)
						changed = true
					}
				}
			}
		}
	}
	return m
}
