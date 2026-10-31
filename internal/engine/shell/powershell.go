package shell

import (
	"errors"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"mvdan.cc/sh/v3/expand"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/engine/shell/pwsh"
	"cyberboar.dev/cyberboar/internal/fold"
)

// PowerShell. The command line is parsed as PowerShell parses it (package
// pwsh) and read into the same Analysis as bash, so the engine applies the
// same rules. The analysis reads a subset (docs/powershell.md): programs,
// the cmdlets in pscmdlets.go, and the constructs that run code. A command
// whose name is only known at run time could be anything, as in bash

// AnalyzePowerShell is AnalyzeWith for a PowerShell command line.
func AnalyzePowerShell(src, home string, o Options) (*Analysis, error) {
	if len(src) > MaxBytes {
		return nil, ErrTooLarge
	}
	start := dir{path: o.Cwd, known: true}
	if o.CwdUnknown {
		start = unknownDir
	}
	// An alias or function an earlier command line defined in a persistent
	// session may stand for any name
	anyAlias, drives := o.Persistent, o.Persistent
	var aliases map[string]bool
	for {
		a := &psAnalyzer{
			analyzer: &analyzer{home: home, fs: o.FS, windows: o.FS.Windows, mounts: o.Mounts, persistent: o.Persistent},
			anyAlias: anyAlias, sawAnyAlias: anyAlias,
			aliases: aliases, sawAliases: maps.Clone(aliases),
			drives: drives, sawDrives: drives,
		}
		a.expandCfg = &expand.Config{Env: varsEnviron{a: a.analyzer, base: expand.ListEnviron("HOME=" + home)}}
		if _, err := a.psScript(src, 0, start); err != nil {
			return nil, err
		}
		// An alias defined anywhere may be used anywhere after it: read
		// everything again with that name unknown
		if a.sawAnyAlias != anyAlias || len(a.sawAliases) != len(aliases) || a.sawDrives != drives {
			anyAlias, aliases, drives = a.sawAnyAlias, a.sawAliases, a.sawDrives
			continue
		}
		return &Analysis{Commands: a.cmds, Code: a.code, Hidden: a.hidden, Files: a.files, feeds: a.closure()}, nil
	}
}

type psAnalyzer struct {
	*analyzer
	src []uint16 // the script being read, in PowerShell's UTF-16 offsets
	// Aliases defined at run time: names (folded) whose command could be
	// anything, or any name at all. saw* collect them for the next pass.
	aliases, sawAliases   map[string]bool
	anyAlias, sawAnyAlias bool
	// A drive defined at run time (New-PSDrive) may stand for any
	// directory, so a cmdlet's path on a drive could be any path.
	drives, sawDrives bool
	// err is the first error of a step that records no error itself (fail).
	err error
}

// fail keeps the first error for psScript to return.
func (a *psAnalyzer) fail(err error) {
	if a.err == nil {
		a.err = err
	}
}

// psScript reads one script: the command line, or code it runs
// (Invoke-Expression 'code'). It returns the ids of its commands.
func (a *psAnalyzer) psScript(src string, depth int, start dir) ([]int, error) {
	if depth > MaxDepth {
		return nil, ErrTooComplex
	}
	sb, err := pwsh.Parse(src)
	if err != nil {
		return nil, err // a *pwsh.Error wraps the shell error it stands for
	}
	saved, savedPS := a.src, a.powershell
	defer func() { a.src, a.powershell = saved, savedPS }()
	a.src = utf16.Encode([]rune(src))
	a.powershell = true

	dirs := a.psDirs(sb, start)
	piped := map[*pwsh.Command]pwsh.CommandBase{} // a command after a pipe, and the element before it
	pwsh.Inspect(sb, func(n pwsh.Node) bool {
		if p, ok := n.(*pwsh.Pipeline); ok {
			for i := 1; i < len(p.Elements); i++ {
				if c, ok := p.Elements[i].(*pwsh.Command); ok {
					piped[c] = p.Elements[i-1]
				}
			}
		}
		return true
	})
	ids := map[*pwsh.Command]int{}
	var all []int
	var inner []transparent
	pwsh.Inspect(sb, func(n pwsh.Node) bool {
		if err != nil {
			return false
		}
		switch v := n.(type) {
		case *pwsh.Command:
			var id int
			var in []int
			if id, in, err = a.psCommand(v, piped[v], depth, dirs[v]); err == nil && id >= 0 {
				ids[v] = id
				all = append(all, id)
				if len(in) > 0 {
					inner = append(inner, transparent{id, in})
				}
			}
			if err == nil {
				a.psRedirections(v.Redirections, dirs[v])
			}
		case *pwsh.CommandExpression:
			a.psRedirections(v.Redirections, dirs[v])
		case *pwsh.InvokeMember:
			err = a.psInvokeMember(v)
		case *pwsh.Convert:
			if v.Type == nil || v.Type.TypeName == nil {
				break
			}
			if t := strings.TrimPrefix(fold.String(v.Type.TypeName.Name), "system."); t == "scriptblock" || t == "management.automation.scriptblock" {
				err = a.psForeign("a [scriptblock] cast")
			}
		case *pwsh.Assignment:
			err = a.psAssignment(v)
		case *pwsh.Variable:
			a.psVariable(v, false, unknownDir)
		}
		if err == nil {
			err = a.err
		}
		return err == nil
	})
	if err != nil {
		return nil, err
	}
	a.transparent = append(a.transparent, inner...)
	a.psLink(sb, ids)
	return all, nil
}

// psForeign records code the analysis can't read, which makes a command
// that could be anything.
func (a *psAnalyzer) psForeign(what string) error {
	a.code = append(a.code, Code{What: what})
	return a.markUnknown(-1)
}

// psSource returns n as written, cut to maxSrc bytes.
func (a *psAnalyzer) psSource(n pwsh.Node) string {
	e := n.Span()
	if e.Start < 0 || e.End > len(a.src) || e.Start > e.End {
		return ""
	}
	s := string(utf16.Decode(a.src[e.Start:e.End]))
	if len(s) > maxSrc {
		cut := maxSrc
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// psCommand records one command and what it runs. It returns its id, or -1
// for a script block run in place (& { … }), whose commands are its own,
// and the ids of code it runs (Invoke-Expression).
func (a *psAnalyzer) psCommand(c *pwsh.Command, piped pwsh.CommandBase, depth int, d dir) (int, []int, error) {
	if _, ok := c.Elements[0].(*pwsh.ScriptBlockExpression); ok && c.Invocation != "" {
		return -1, nil, nil
	}
	if len(a.cmds) >= MaxCommands {
		return 0, nil, ErrTooComplex
	}
	name, lit := a.psName(c)
	args := c.Elements[1:]
	if !lit {
		argv := append([]Elem{{Kind: Many, Text: "*", Src: a.psSource(c.Elements[0])}}, a.psArgv(args, false, d)...)
		id := a.addCommand([][]Elem{argv})
		a.psGenericRefs(argv[1:], d, psRead, piped != nil)
		return id, nil, nil
	}
	folded := fold.String(name)
	canon, isCmdlet := a.psResolve(name, c.Invocation)
	var id int
	var inner []int
	var err error
	switch {
	case isCmdlet:
		id, inner, err = a.psCmdletCall(c, canon, piped, depth, d)
		if legacy, ok := psLegacyAliases[folded]; ok && err == nil && canon == legacy {
			// Windows PowerShell's alias, or PowerShell 7's program
			err = a.psNative(id, c, name, d, depth)
		}
	default:
		id = a.addCommand(nil)
		err = a.psNative(id, c, name, d, depth)
	}
	if err != nil {
		return 0, nil, err
	}
	if a.anyAlias || a.aliases[folded] {
		if err := a.markUnknown(id); err != nil {
			return 0, nil, err
		}
	}
	return id, inner, nil
}

// addCommand records a command with layers and returns its id.
func (a *psAnalyzer) addCommand(layers [][]Elem) int {
	a.cmds = append(a.cmds, Command{Layers: layers})
	return len(a.cmds) - 1
}

// psName returns a command's name, when it is written as a literal: a bare
// word, or a quoted string after & or .
func (a *psAnalyzer) psName(c *pwsh.Command) (string, bool) {
	if s, ok := c.Elements[0].(*pwsh.StringConstant); ok {
		return s.Value, true
	}
	return "", false
}

// psResolve finds the cmdlet a name runs, by alias or by name, with or
// without its module (Microsoft.PowerShell.Management\Remove-Item). A name
// that is a path, or that is dot-sourced, runs a script or a program.
func (a *psAnalyzer) psResolve(name, invocation string) (string, bool) {
	if invocation == "." {
		return "", false
	}
	if i := strings.LastIndexByte(name, '\\'); i > 0 && !strings.ContainsAny(name[:i], `/\:`) && !strings.Contains(name[:i], "..") {
		name = name[i+1:] // Module\Cmdlet
	}
	if strings.ContainsAny(name, `/\:`) {
		return "", false
	}
	f := fold.String(name)
	if canon, ok := psAliases[f]; ok && (a.windows || !psUnixAliases[f]) {
		return canon, true
	}
	if canon, ok := psLegacyAliases[f]; ok && a.windows {
		return canon, true
	}
	if c, ok := psCmdlets[f]; ok {
		return c.name, true
	}
	if _, ok := psVerbNoun(name); ok {
		return name, true // a cmdlet or function not in the table
	}
	return "", false
}

// psArgv converts a command's arguments to argv elements, as written. For a
// program, a value PowerShell may pass as more than one word, or as none
// (an empty string, which Windows PowerShell drops), is Many. d is the
// directory the command runs in.
func (a *psAnalyzer) psArgv(args []pwsh.CommandElement, native bool, d dir) []Elem {
	var out []Elem
	for _, e := range args {
		switch v := e.(type) {
		case *pwsh.CommandParameter:
			if v.Name == "-" {
				out = append(out, Elem{Kind: Lit, Text: "--"})
				continue
			}
			flag := "-" + v.Name
			if v.Argument == nil {
				out = append(out, Elem{Kind: Lit, Text: flag})
				continue
			}
			if val := a.psElems(v.Argument); len(val) == 1 && val[0].Kind == Lit {
				out = append(out, Elem{Kind: Lit, Text: flag + ":" + val[0].Text})
			} else {
				out = append(out, Elem{Kind: One, Text: flag + ":*", Src: a.psSource(v)})
			}
		case pwsh.Expression:
			elems := a.psElems
			if native && a.windows {
				elems = func(e pwsh.Expression) []Elem { return a.psWindowsNative(e, d) }
			}
			for _, el := range elems(v) {
				if native && el.Kind == Lit && (el.Text == "" || strings.Contains(el.Text, `"`)) {
					el = Elem{Kind: Many, Text: "*", Src: el.Text}
				}
				out = append(out, el)
			}
		}
	}
	return out
}

// psElems converts one argument to the words it stands for.
func (a *psAnalyzer) psElems(e pwsh.Expression) []Elem {
	switch v := e.(type) {
	case *pwsh.StringConstant:
		if !a.windows && v.Kind == pwsh.BareWord && psHasWildcard(v.Value) {
			return []Elem{{Kind: Many, Text: v.Value, Glob: true}} // pwsh expands it for programs outside Windows
		}
		return []Elem{{Kind: Lit, Text: v.Value}}
	case *pwsh.ExpandableString:
		shape := psShape(v.Format)
		return []Elem{{Kind: One, Text: shape, Shape: shape, Src: a.psSource(v)}}
	case *pwsh.Constant:
		if v.Text != "" && strings.Trim(v.Text, "0123456789") == "" {
			return []Elem{{Kind: Lit, Text: v.Text}}
		}
		return []Elem{{Kind: One, Text: "*", Src: a.psSource(v)}}
	case *pwsh.ArrayLiteral:
		var out []Elem
		for _, el := range v.Elements {
			out = append(out, a.psElems(el)...)
		}
		return out
	case *pwsh.ScriptBlockExpression:
		return []Elem{{Kind: One, Text: "*", Src: a.psSource(v)}}
	}
	return []Elem{{Kind: Many, Text: "*", Src: a.psSource(e)}}
}

// psShape is the glob an expandable string's value matches: its format
// with each expansion as "*", or "*" when its literal parts hold a glob
// character of their own.
func psShape(format string) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		switch {
		case (c == '{' || c == '}') && i+1 < len(format) && format[i+1] == c:
			b.WriteByte(c)
			i++
		case c == '{':
			j := strings.IndexByte(format[i:], '}')
			if j < 0 {
				return "*"
			}
			b.WriteByte('*')
			i += j
		case strings.IndexByte(`*?[\`, c) >= 0:
			return "*"
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// psWindowsNative converts one argument to a program on Windows as psElems
// does, with what PowerShell does to a bare word: ~ (PowerShell 7.6 and later)
// and a wildcard as psNativeTilde and nativeGlobs say. Each element of an
// array is a word of its own.
func (a *psAnalyzer) psWindowsNative(e pwsh.Expression, d dir) []Elem {
	words := []pwsh.Expression{e}
	if v, ok := e.(*pwsh.ArrayLiteral); ok {
		words = v.Elements
	}
	var out []Elem
	for _, w := range words {
		s, ok := w.(*pwsh.StringConstant)
		if !ok || s.Kind != pwsh.BareWord {
			out = append(out, a.psElems(w)...)
			continue
		}
		text, ok := a.psNativeTilde(s.Value, d)
		switch {
		case !ok:
			out = append(out, Elem{Kind: One, Text: "*", Src: s.Value})
		case psHasWildcard(text):
			// PowerShell passes it on, and many programs expand it (findstr, Git's tools)
			out = append(out, Elem{Kind: Many, Text: strings.ReplaceAll(text, `\`, "/"), Glob: true})
		default:
			out = append(out, Elem{Kind: Lit, Text: text})
		}
	}
	return out
}

// psNativeTilde returns the word PowerShell passes to a program on Windows for
// the bare word w. PowerShell 7.6 and later start ~, ~\… and ~/… in the home
// folder; older versions pass them as written. It reports false when the two
// can be different files: the home folder or working directory is unknown, or
// the working directory has an entry named ~.
func (a *psAnalyzer) psNativeTilde(w string, d dir) (string, bool) {
	rest, ok := strings.CutPrefix(w, "~")
	if !ok || rest != "" && rest[0] != '/' && rest[0] != '\\' {
		return w, true
	}
	if a.home == "" || !d.known {
		return "", false
	}
	if _, err := a.fs.Lstat(joinDir(d.path, "~")); !errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	return a.psTilde(w)[0], true
}

func psHasWildcard(s string) bool { return strings.ContainsAny(s, "*?[") }

// psGlobs is how PowerShell matches a wildcard: without case, and names that
// start with a dot are names like any other.
var psGlobs = globOpts{dotglob: true, nocaseglob: true}

// nativeGlobs is how a program PowerShell runs sees a wildcard. On Windows
// PowerShell passes it on and the program matches it as Windows does, as
// psGlobs does; elsewhere PowerShell expands it as bash does.
func (a *psAnalyzer) nativeGlobs() globOpts {
	if a.windows {
		return psGlobs
	}
	return globOpts{}
}

// psNative records a program, a script file or a function: its words are
// read as bash's are for a program (fileRefs), and the wrappers it is
// (npx, cmd /c) are followed. id is the command to record it in. A path to
// it starting with ~ is in the home folder, as PowerShell resolves it.
func (a *psAnalyzer) psNative(id int, c *pwsh.Command, name string, d dir, depth int) error {
	raw := append([]Elem{{Kind: Lit, Text: a.psTilde(name)[0]}}, a.psArgv(c.Elements[1:], true, d)...)
	return a.psProgram(id, raw, d, depth)
}

// psProgram records argv run as a program in d, following its wrappers.
func (a *psAnalyzer) psProgram(id int, raw []Elem, d dir, depth int) error {
	u, err := a.unwrapAll(a.normalize(raw), 0)
	if err != nil {
		return err
	}
	a.cmds[id].Layers = append(a.cmds[id].Layers, u.layers...)
	a.files = append(a.files, a.fileRefs(raw, u, d, a.nativeGlobs())...)
	d = a.innerDir(u, d)
	for _, e := range u.files {
		a.wordRefs(e, d, a.nativeGlobs(), false, func(r FileRef) {
			r.Accessed, r.Contents = true, true
			a.files = append(a.files, r)
		})
	}
	unknown := u.unknown
	for _, r := range u.code {
		if unknown, err = a.runCode(id, r, depth, unknown, d); err != nil {
			return err
		}
	}
	for _, r := range u.cmdLines {
		if unknown, err = a.runCommandLine(id, r, depth, unknown, d); err != nil {
			return err
		}
	}
	if u.stdin != nil {
		// A shell reading code from its input, which here is a pipeline or
		// whatever the agent passes: only known at run time
		a.code = append(a.code, Code{What: u.stdin.what})
		unknown = true
	}
	for _, e := range u.assigns {
		name, value, _ := strings.Cut(e.Text, "=")
		if unknown, err = a.envVar(id, name, Elem{Kind: Lit, Text: value}, depth, unknown, d); err != nil {
			return err
		}
	}
	if unknown {
		return a.markUnknown(id)
	}
	return nil
}

// psGenericRefs checks each word of a command the analysis doesn't know as
// a path it uses as use says. piped: it may take paths from a pipeline too.
func (a *psAnalyzer) psGenericRefs(args []Elem, d dir, use psUse, piped bool) {
	add := a.psAdder(use)
	for _, e := range args {
		if e.Kind == Lit {
			if flag, val, ok := strings.Cut(e.Text, ":"); ok && strings.HasPrefix(flag, "-") {
				e.Text = val // -Path:x
			}
			a.fail(a.psEnvWord(e.Text, use))
		}
		a.wordRefs(e, d, psGlobs, use == psPrint, add)
	}
	if piped && use != psPrint {
		add(FileRef{Display: "paths read from the pipeline"})
	}
}

// psAdder returns a function that records a path used as use says.
func (a *psAnalyzer) psAdder(use psUse) func(FileRef) {
	return func(r FileRef) {
		r.Accessed = use != psPrint
		r.Contents = use == psRead || use == psWrite || use == psModify
		r.Modifies = use == psModify
		a.files = append(a.files, r)
	}
}

// psBound is a cmdlet's arguments bound to its parameters.
type psBound struct {
	values   map[*psParam][]pwsh.CommandElement
	switches map[*psParam]bool
}

// psBind binds a cmdlet's arguments as PowerShell's binder does, for the
// parameters the table lists: by name or a unique prefix, then by
// position. ok is false for anything else (an unknown parameter, splatting,
// too many positional arguments).
func psBind(c *psCmdlet, args []pwsh.CommandElement) (b psBound, ok bool) {
	b = psBound{values: map[*psParam][]pwsh.CommandElement{}, switches: map[*psParam]bool{}}
	var positional []pwsh.CommandElement
	for i := 0; i < len(args); i++ {
		switch v := args[i].(type) {
		case *pwsh.CommandParameter:
			if v.Name == "-" {
				positional = append(positional, args[i+1:]...)
				i = len(args)
				continue
			}
			p := c.param(v.Name)
			if p == nil {
				return b, false
			}
			if _, dup := b.values[p]; dup || b.switches[p] {
				return b, false
			}
			switch {
			case p.isSwitch:
				b.switches[p] = true
			case v.Argument != nil:
				b.values[p] = []pwsh.CommandElement{v.Argument}
			case i+1 < len(args):
				if _, isParam := args[i+1].(*pwsh.CommandParameter); isParam {
					return b, false
				}
				i++
				b.values[p] = []pwsh.CommandElement{args[i]}
			default:
				return b, false
			}
		case *pwsh.Variable:
			if v.Splatted {
				return b, false
			}
			positional = append(positional, v)
		default:
			positional = append(positional, v)
		}
	}
	next := 0
	for _, e := range positional {
		for next < len(c.positional) {
			if _, taken := b.values[c.params[fold.String(c.positional[next])]]; !taken {
				break
			}
			next++
		}
		if next == len(c.positional) {
			return b, false
		}
		b.values[c.params[fold.String(c.positional[next])]] = []pwsh.CommandElement{e}
		next++
	}
	return b, true
}

// value returns the words bound to the parameter called name.
func (a *psAnalyzer) value(c *psCmdlet, b psBound, name string) ([]Elem, bool) {
	vals, ok := b.values[c.params[fold.String(name)]]
	if !ok {
		return nil, false
	}
	var out []Elem
	for _, v := range vals {
		if e, ok := v.(pwsh.Expression); ok {
			out = append(out, a.psElems(e)...)
		}
	}
	return out, true
}

// psCmdletCall records a cmdlet and the paths it uses.
func (a *psAnalyzer) psCmdletCall(c *pwsh.Command, canon string, piped pwsh.CommandBase, depth int, d dir) (int, []int, error) {
	args := c.Elements[1:]
	written := fold.String(c.Elements[0].(*pwsh.StringConstant).Value)
	argv := a.psArgv(args, false, d)
	layers := [][]Elem{append([]Elem{{Kind: Lit, Text: c.Elements[0].(*pwsh.StringConstant).Value}}, argv...)}
	if written != fold.String(canon) {
		layers = append(layers, append([]Elem{{Kind: Lit, Text: canon}}, argv...))
	}
	id := a.addCommand(layers)
	if _, legacy := psLegacyAliases[written]; !legacy {
		a.cmds[id].Aliases = len(layers) - 1
	}
	spec, known := psCmdlets[fold.String(canon)]
	var b psBound
	bound := false
	if known && spec.params != nil {
		b, bound = psBind(spec, args)
	}
	varSpec, vars := spec, b
	if !bound {
		varSpec, vars = psCommonParams, psCommonVariables(args)
	}
	if err := a.psNamedVariables(varSpec, vars, d); err != nil {
		return 0, nil, err
	}
	if !known {
		// Verb-Noun the table doesn't know: every word may be a path, and so
		// may what a pipeline gives it
		for _, r := range psRunsBlocks {
			if strings.EqualFold(r, canon) {
				if err := a.psBlockRunner(id, r, args); err != nil {
					return 0, nil, err
				}
			}
		}
		if strings.EqualFold(canon, "Add-Type") {
			if err := a.psAddType(id, args); err != nil {
				return 0, nil, err
			}
		}
		use := psRead
		if v, _ := psVerbNoun(canon); psModifyVerbs[v] {
			use = psModify
		}
		a.psGenericRefs(argv, d, use, piped != nil)
		return id, nil, nil
	}
	if spec.use == psPrint && spec.params == nil {
		a.psGenericRefs(argv, d, psPrint, false)
		return id, nil, a.psPrintCmdlet(id, spec.name, args)
	}
	if !bound {
		// Read every word as a path, as for an unknown command
		a.psGenericRefs(argv, d, spec.use, piped != nil && spec.pipePaths)
		return id, nil, a.psUnbound(id, canon)
	}
	var inner []int
	var err error
	switch canon {
	case "Invoke-WebRequest", "Invoke-RestMethod":
		a.psWebURI(spec, b, d)
		a.psWebForm(spec, b)
	case "Invoke-Expression":
		inner, err = a.psInvokeExpression(id, spec, b, depth, d)
		return id, inner, err
	case "Start-Process":
		return id, nil, a.psStartProcess(id, spec, b, d, depth)
	case "New-Object":
		return id, nil, a.psNewObject(spec, b)
	case "Set-Alias", "New-Alias":
		a.psDefineAlias(spec, b)
		return id, nil, nil
	case "New-PSDrive":
		a.sawDrives = true
		a.hidden = append(a.hidden, "a drive defined at run time (New-PSDrive)")
	case "Invoke-Item":
		// It opens each item with its program, and runs it if it is one
		vals, ok := a.value(spec, b, "Path")
		if !ok {
			vals, ok = a.value(spec, b, "LiteralPath")
		}
		for _, e := range vals {
			if e.Kind != Lit || !ok {
				return id, nil, a.markUnknown(id)
			}
			a.cmds[id].Layers = append(a.cmds[id].Layers, a.normalize([]Elem{e}))
		}
		if !ok {
			return id, nil, a.markUnknown(id)
		}
	}
	a.psBoundRefs(canon, spec, b, d, piped)
	return id, nil, nil
}

// psVariableParams are the parameters that name a variable for the cmdlet
// to set: the common ones, Tee-Object's and the web cmdlets'.
var psVariableParams = []string{"ErrorVariable", "WarningVariable", "InformationVariable", "OutVariable",
	"PipelineVariable", "Variable", "SessionVariable", "ResponseHeadersVariable", "StatusCodeVariable"}

// psNamedVariables checks the variables a cmdlet is told to set. A name
// with a drive is set through it, as in ${C:\x} = …: env: sets an
// environment variable, a FileSystem drive writes a file. A name only
// known at run time could be any.
func (a *psAnalyzer) psNamedVariables(spec *psCmdlet, b psBound, d dir) error {
	for _, param := range psVariableParams {
		vals, _ := a.value(spec, b, param)
		for _, e := range vals {
			if e.Kind != Lit {
				a.hidden = append(a.hidden, "a variable named at run time (-"+param+" "+e.Shown()+")")
				continue
			}
			v := &pwsh.Variable{Path: strings.TrimPrefix(e.Text, "+")} // +name appends
			if fold.String(v.Drive()) == "env" {
				if err := a.psSetEnv(v.Name(), Elem{Kind: Many, Text: "*"}); err != nil {
					return err
				}
				continue
			}
			a.psVariable(v, true, d)
		}
	}
	return nil
}

// psCommonVariables finds the common parameters that name variables among
// the arguments of a cmdlet whose other parameters aren't bound (a print
// cmdlet, one the table doesn't list), for psNamedVariables.
func psCommonVariables(args []pwsh.CommandElement) psBound {
	b := psBound{values: map[*psParam][]pwsh.CommandElement{}}
	for i, e := range args {
		p, ok := e.(*pwsh.CommandParameter)
		if !ok {
			continue
		}
		param := psCommonParams.param(p.Name)
		switch {
		case param == nil || !slices.Contains(psVariableParams, param.name):
		case p.Argument != nil:
			b.values[param] = append(b.values[param], p.Argument)
		case i+1 < len(args):
			b.values[param] = append(b.values[param], args[i+1])
		}
	}
	return b
}

// psWebURI records the file Windows PowerShell 5.1's Invoke-WebRequest and
// Invoke-RestMethod read for -Uri: a file: URL, or a drive or UNC path,
// which .NET takes as one. A URI only known at run time may be one too,
// unless it starts with http://, https:// or ftp://.
func (a *psAnalyzer) psWebURI(spec *psCmdlet, b psBound, d dir) {
	vals, _ := a.value(spec, b, "Uri")
	for _, e := range vals {
		if e.Kind != Lit {
			if !psRemoteURI(e.Text) {
				a.psAdder(psRead)(FileRef{Display: e.Shown(), Shape: e.Shape, Src: e.Src})
			}
			continue
		}
		if p, ok := psFileURI(e.Text); ok {
			a.psPathWord(Elem{Kind: Lit, Text: p}, d, false, psRead)
		}
	}
}

// psWebForm records the files -Form uploads: each value that is a file
// object (Get-ChildItem's output), which only a string or a number is not.
func (a *psAnalyzer) psWebForm(spec *psCmdlet, b psBound) {
	vals, ok := b.values[spec.params["form"]]
	if !ok {
		return
	}
	var h *pwsh.Hashtable
	if len(vals) == 1 {
		h, _ = vals[0].(*pwsh.Hashtable)
	}
	for i := 0; h == nil || i < len(h.Pairs); i++ {
		if h == nil || a.psStatementValue(h.Pairs[i].Value).Kind == Many {
			a.psAdder(psRead)(FileRef{Display: "the files -Form uploads"})
			return
		}
	}
}

func psRemoteURI(s string) bool {
	for _, scheme := range []string{"http://", "https://", "ftp://"} {
		if len(s) >= len(scheme) && strings.EqualFold(s[:len(scheme)], scheme) {
			return true
		}
	}
	return false
}

// psFileURI returns the local path .NET's Uri reads s as: a drive or UNC
// path as it is, or a file: URL's path, decoded as curl decodes it, with
// a host other than localhost as a UNC server and file://C:/x as C:/x.
func psFileURI(s string) (string, bool) {
	t := strings.ReplaceAll(s, `\`, "/")
	if len(t) >= 3 && isASCIILetter(t[0]) && t[1] == ':' && t[2] == '/' || strings.HasPrefix(t, "//") {
		return s, true
	}
	if len(s) < 5 || !strings.EqualFold(s[:5], "file:") {
		return "", false
	}
	rest, host := s[5:], ""
	if r, ok := strings.CutPrefix(rest, "//"); ok {
		var path string
		host, path, _ = strings.Cut(r, "/")
		rest = "/" + path
	}
	p, ok := fileURLPath("file:" + rest)
	if !ok {
		return "", false
	}
	if len(p) >= 3 && p[0] == '/' && isASCIILetter(p[1]) && p[2] == ':' {
		p = p[1:] // file:///C:/x
	}
	switch {
	case host == "" || strings.EqualFold(host, "localhost"):
	case len(host) == 2 && isASCIILetter(host[0]) && host[1] == ':':
		p = host + p
	default:
		p = "//" + host + p
	}
	return p, true
}

// psUnbound handles a cmdlet whose arguments couldn't be bound: those that
// run code could run any.
func (a *psAnalyzer) psUnbound(id int, canon string) error {
	switch canon {
	case "Invoke-Expression", "New-Object":
		a.code = append(a.code, Code{What: canon})
		return a.markUnknown(id)
	case "New-PSDrive":
		a.sawDrives = true
		a.hidden = append(a.hidden, "a drive defined at run time (New-PSDrive)")
	case "Start-Process", "Invoke-Item":
		return a.markUnknown(id) // a program only known at run time
	case "Set-Alias", "New-Alias":
		a.sawAnyAlias = true
	}
	return nil
}

// psBoundRefs records the paths a bound cmdlet uses.
func (a *psAnalyzer) psBoundRefs(canon string, spec *psCmdlet, b psBound, d dir, piped pwsh.CommandBase) {
	// The paths a pipeline may give it bind to -Path or -LiteralPath
	sourceBound := false
	for _, p := range spec.list {
		if !p.path {
			continue
		}
		vals, ok := a.value(spec, b, p.name)
		if !ok {
			continue
		}
		if p.name == "Path" || p.name == "LiteralPath" {
			sourceBound = true
		}
		if canon == "Rename-Item" && p.name == "NewName" {
			a.psNewName(vals, spec, b, d)
			continue
		}
		for _, e := range vals {
			a.psPathWord(e, d, p.wildcard, p.use)
		}
	}
	if canon == "New-Item" {
		a.psNewItem(spec, b, d)
	}
	if piped != nil && spec.pipePaths && !sourceBound && !(canon == "Select-String" && a.psEmitsText(piped)) {
		a.psAdder(spec.use)(FileRef{Display: "paths read from the pipeline"})
	}
	if spec.pipePaths && !sourceBound && piped == nil && implicitPS[canon] {
		a.psAdder(spec.use)(a.pathRef(".", d)) // Get-ChildItem lists the working directory
	}
}

// implicitPS are the cmdlets that use the working directory without a path.
var implicitPS = set("Get-ChildItem")

// psEmitsText reports whether a pipeline element only writes strings, which
// Select-String searches instead of reading them as files.
func (a *psAnalyzer) psEmitsText(el pwsh.CommandBase) bool {
	c, ok := el.(*pwsh.Command)
	if !ok {
		return false
	}
	name, lit := a.psName(c)
	if !lit {
		return false
	}
	canon, isCmdlet := a.psResolve(name, c.Invocation)
	if !isCmdlet {
		return true // a program's output is lines of text
	}
	return canon == "Get-Content" || canon == "Out-String" || canon == "Select-String"
}

// psPathWord records one word given to a path parameter.
func (a *psAnalyzer) psPathWord(e Elem, d dir, wildcard bool, use psUse) {
	add := a.psAdder(use)
	if e.Kind != Lit {
		a.wordRefs(e, d, psGlobs, false, add) // an unquoted wildcard is matched as a quoted one is
		return
	}
	a.fail(a.psEnvWord(e.Text, use))
	w, p, ok, hidden := a.psProviderPath(e.Text, use)
	if hidden != "" {
		a.hidden = append(a.hidden, hidden)
	}
	if !ok {
		return
	}
	if p.Refused != "" || p.Display != "" {
		add(p) // not a FileSystem path, or one the analysis refuses
		return
	}
	if tail, on := psOnDrive(w); on && a.drives {
		add(FileRef{Display: e.Text, Rel: tail}) // a drive New-PSDrive may have made
		return
	}
	if wildcard && psHasWildcard(w) {
		for _, pattern := range a.psTilde(w) { // ~ is the home folder before the wildcard is matched
			if a.windows {
				pattern = strings.ReplaceAll(pattern, `\`, "/")
			}
			a.wordRefs(Elem{Kind: Many, Text: pattern, Glob: true}, d, psGlobs, false, add)
		}
		return
	}
	for _, c := range a.psTilde(w) {
		ref := a.pathRef(c, d)
		ref.Display = e.Text
		add(ref)
	}
}

// psProviderPath reads a path's PowerShell drive or provider and returns
// it without a FileSystem provider's prefix. ok is false for a path on a
// drive that holds no files (env:, variable:); a FileRef with Display set
// is returned for one the analysis doesn't read. hidden is set for a
// function or alias defined through its drive.
func (a *psAnalyzer) psProviderPath(p string, use psUse) (rest string, ref FileRef, ok bool, hidden string) {
	if i := strings.Index(p, "::"); i >= 0 {
		provider := fold.String(p[:i])
		if provider != "filesystem" && provider != `microsoft.powershell.core\filesystem` {
			return "", FileRef{Display: p, Refused: "PowerShell provider paths other than the FileSystem's are not checked"}, true, ""
		}
		p = p[i+2:]
	}
	drive, _, found := strings.Cut(p, ":")
	if !found || len(drive) < 2 || strings.ContainsAny(drive, `/\`) {
		return p, FileRef{}, true, ""
	}
	switch fold.String(drive) {
	case "env", "variable":
		return "", FileRef{}, false, ""
	case "function", "alias":
		if use == psWrite || use == psModify {
			a.sawAnyAlias = true
			return "", FileRef{}, false, "a function or alias defined at run time (" + p + ")"
		}
		return "", FileRef{}, false, ""
	case "temp":
		return "", FileRef{Display: p}, true, "" // the temporary directory, only known at run time
	}
	return "", FileRef{Display: p, Refused: "PowerShell's " + drive + ": drive is not a file system drive the analysis reads"}, true, ""
}

// psOnDrive reports a path on a named drive (C:\x, X:x) and returns the
// rest of it, relative to the drive's root, with "/" separators.
func psOnDrive(p string) (tail string, ok bool) {
	drive, rest, found := strings.Cut(p, ":")
	if !found || drive == "" || strings.ContainsAny(drive, `/\`) {
		return "", false
	}
	return strings.Trim(strings.ReplaceAll(rest, `\`, "/"), "/"), true
}

// psTilde returns the paths a word can be: PowerShell reads a leading ~ as
// the home directory in paths it resolves, and passes it on to programs as written.
func (a *psAnalyzer) psTilde(w string) []string {
	rest, ok := strings.CutPrefix(w, "~")
	if !ok || a.home == "" || rest != "" && rest[0] != '/' && rest[0] != '\\' {
		return []string{w}
	}
	home := a.home
	if a.windows {
		home = a.fs.Show(a.home)
	}
	return []string{home + rest, w}
}

// psNewName records Rename-Item's -NewName, a name in the directory of the item renamed.
func (a *psAnalyzer) psNewName(vals []Elem, spec *psCmdlet, b psBound, d dir) {
	add := a.psAdder(psModify)
	src, ok := a.value(spec, b, "Path")
	if !ok {
		src, _ = a.value(spec, b, "LiteralPath")
	}
	for _, e := range vals {
		if e.Kind != Lit || len(src) != 1 || src[0].Kind != Lit {
			add(FileRef{Display: e.Shown(), Shape: e.Shape})
			continue
		}
		parent := strings.ReplaceAll(src[0].Text, `\`, "/")
		if i := strings.LastIndexByte(parent, '/'); i >= 0 {
			parent = parent[:i+1]
		} else {
			parent = ""
		}
		add(a.pathRef(parent+e.Text, d))
	}
}

// psNewItem records New-Item's -Name, in the directory -Path names, and the
// target of a link it makes (-Value).
func (a *psAnalyzer) psNewItem(spec *psCmdlet, b psBound, d dir) {
	add := a.psAdder(psWrite)
	if names, ok := a.value(spec, b, "Name"); ok {
		dirs, ok := a.value(spec, b, "Path")
		if !ok {
			dirs = []Elem{{Kind: Lit, Text: "."}}
		}
		for _, n := range names {
			for _, p := range dirs {
				if n.Kind != Lit || p.Kind != Lit {
					add(FileRef{Display: n.Shown()})
					continue
				}
				add(a.pathRef(strings.TrimRight(p.Text, `/\`)+"/"+n.Text, d))
			}
		}
	}
	if vals, ok := a.value(spec, b, "Value"); ok {
		kind, _ := a.value(spec, b, "ItemType")
		link := len(kind) != 1 || kind[0].Kind != Lit
		if !link {
			switch fold.String(kind[0].Text) {
			case "symboliclink", "junction", "hardlink":
				link = true
			}
		}
		if link {
			// What the link leads to is reached through it, as ln's target is
			for _, e := range vals {
				a.wordRefs(e, d, globOpts{}, false, a.psAdder(psRead))
			}
		}
	}
}

// psPrintCmdlet checks a print cmdlet for what it calls. ForEach-Object and
// Where-Object run the script blocks they are given, which are read with the
// rest of the line; one held in a variable could run anything. ForEach-Object
// given a name calls that member of every object it is passed.
func (a *psAnalyzer) psPrintCmdlet(id int, canon string, args []pwsh.CommandElement) error {
	switch canon {
	case "ForEach-Object":
		for _, e := range args {
			if p, ok := e.(*pwsh.CommandParameter); ok {
				if p.Argument == nil {
					continue
				}
				e = p.Argument
			}
			switch v := e.(type) {
			case *pwsh.ScriptBlockExpression, *pwsh.Constant:
			case *pwsh.StringConstant:
				if !psSafeMethods[fold.String(v.Value)] {
					a.hidden = append(a.hidden, "ForEach-Object calling the member "+v.Value)
				}
			default:
				a.code = append(a.code, Code{What: "ForEach-Object " + a.psSource(e)})
				return a.markUnknown(id)
			}
		}
	case "Where-Object":
		for _, e := range args {
			if _, ok := e.(*pwsh.CommandParameter); ok {
				continue
			}
			switch e.(type) {
			case *pwsh.ScriptBlockExpression, *pwsh.StringConstant:
				return nil
			}
			a.code = append(a.code, Code{What: "Where-Object " + a.psSource(e)})
			return a.markUnknown(id) // the first positional argument is the filter
		}
	}
	return nil
}

// psRunsBlocks are cmdlets that run a script block they are given. Given a
// script file, or a block only known at run time, they could run anything.
var psRunsBlocks = []string{"Invoke-Command", "Start-Job", "Start-ThreadJob", "Register-ObjectEvent",
	"Register-EngineEvent", "Register-WmiEvent", "New-Module", "Register-ArgumentCompleter", "Trace-Command",
	"Measure-Command"}

// psBlockRunner checks a cmdlet of psRunsBlocks: the script blocks written
// on the line are read with it, and nothing else may be run.
func (a *psAnalyzer) psBlockRunner(id int, canon string, args []pwsh.CommandElement) error {
	block := false
	for _, e := range args {
		switch v := e.(type) {
		case *pwsh.ScriptBlockExpression:
			block = true
		case *pwsh.CommandParameter:
			n := fold.String(v.Name)
			for _, file := range []string{"filepath", "literalpath", "pspath", "initializationscript"} {
				if n != "" && strings.HasPrefix(file, n) {
					a.code = append(a.code, Code{What: canon + " -" + v.Name})
					return a.markUnknown(id)
				}
			}
			if _, ok := v.Argument.(*pwsh.ScriptBlockExpression); ok {
				block = true
			}
		}
	}
	if !block {
		a.code = append(a.code, Code{What: canon})
		return a.markUnknown(id)
	}
	return nil
}

// psAddType checks Add-Type, which compiles the code it is given. Loading
// an assembly by name (-AssemblyName) compiles nothing.
func (a *psAnalyzer) psAddType(id int, args []pwsh.CommandElement) error {
	for i := 0; i < len(args); i++ {
		p, ok := args[i].(*pwsh.CommandParameter)
		n := ""
		if ok {
			n = fold.String(p.Name)
		}
		switch {
		case ok && n != "" && (strings.HasPrefix("assemblyname", n) && len(n) > 1 || n == "an"):
			if p.Argument == nil {
				i++ // its value
			}
		case ok && n != "" && strings.HasPrefix("passthru", n) && len(n) > 1:
		default:
			a.code = append(a.code, Code{What: "Add-Type"})
			return a.markUnknown(id)
		}
	}
	return nil
}

// psInvokeExpression reads the code Invoke-Expression runs, when it is written out.
func (a *psAnalyzer) psInvokeExpression(id int, spec *psCmdlet, b psBound, depth int, d dir) ([]int, error) {
	vals, ok := a.value(spec, b, "Command")
	if !ok || len(vals) != 1 || vals[0].Kind != Lit {
		a.code = append(a.code, Code{What: "Invoke-Expression"})
		return nil, a.markUnknown(id)
	}
	a.code = append(a.code, Code{What: "Invoke-Expression", Analyzed: true})
	return a.psScript(vals[0].Text, depth+1, d)
}

// psStartProcess records the program Start-Process starts. It joins
// -ArgumentList with spaces, and the program splits them again.
func (a *psAnalyzer) psStartProcess(id int, spec *psCmdlet, b psBound, d dir, depth int) error {
	a.psBoundRefs("Start-Process", spec, b, d, nil)
	file, _ := a.value(spec, b, "FilePath")
	if len(file) != 1 || file[0].Kind != Lit {
		return a.markUnknown(id)
	}
	argv := []Elem{file[0]}
	list, _ := a.value(spec, b, "ArgumentList")
	for _, e := range list {
		if e.Kind != Lit || strings.Contains(e.Text, `"`) {
			argv = append(argv, Elem{Kind: Many, Text: "*", Src: e.Src})
			continue
		}
		for w := range strings.FieldsSeq(e.Text) {
			argv = append(argv, Elem{Kind: Lit, Text: w})
		}
	}
	if wd, ok := a.value(spec, b, "WorkingDirectory"); ok {
		d = unknownDir
		if len(wd) == 1 && wd[0].Kind == Lit {
			d = a.psCdPath(wd[0].Text, d)
		}
	}
	if env, ok := b.values[spec.params["environment"]]; ok {
		if err := a.psStartEnv(env); err != nil {
			return err
		}
	}
	return a.psProgram(id, argv, d, depth)
}

// psNewObject checks the .NET or COM object New-Object makes.
func (a *psAnalyzer) psNewObject(spec *psCmdlet, b psBound) error {
	if _, com := b.values[spec.params["comobject"]]; com {
		return a.psForeign("New-Object -ComObject")
	}
	t, _ := a.value(spec, b, "TypeName")
	if len(t) == 1 && t[0].Kind == Lit && psSafeType(t[0].Text, "new") {
		return nil
	}
	words := make([]string, len(t))
	for i, e := range t {
		words[i] = e.Shown()
	}
	return a.psForeign(strings.TrimSpace("New-Object " + strings.Join(words, " ")))
}

// psDefineAlias records an alias Set-Alias or New-Alias defines: commands
// with its name could be anything.
func (a *psAnalyzer) psDefineAlias(spec *psCmdlet, b psBound) {
	names, _ := a.value(spec, b, "Name")
	if len(names) != 1 || names[0].Kind != Lit {
		a.sawAnyAlias = true
		return
	}
	if a.sawAliases == nil {
		a.sawAliases = map[string]bool{}
	}
	a.sawAliases[fold.String(names[0].Text)] = true
	a.hidden = append(a.hidden, "an alias defined at run time ("+names[0].Text+")")
}

// psRedirections records the files a command's redirections write.
func (a *psAnalyzer) psRedirections(rs []pwsh.Redirection, d dir) {
	for _, r := range rs {
		fr, ok := r.(*pwsh.FileRedirection)
		if !ok {
			continue
		}
		if v, ok := fr.Location.(*pwsh.Variable); ok && fold.String(v.Path) == "null" {
			continue
		}
		for _, e := range a.psElems(fr.Location) {
			a.psPathWord(e, d, false, psWrite)
		}
	}
}

// psInvokeMember checks a .NET method call. A static method of a type that
// only computes is allowed, any other runs code the analysis can't read.
// An instance method other than those that compute on strings and
// collections may do anything the object can, and needs confirmation.
func (a *psAnalyzer) psInvokeMember(m *pwsh.InvokeMember) error {
	name, lit := "", false
	if s, ok := m.Member.(*pwsh.StringConstant); ok {
		name, lit = s.Value, true
	}
	if m.Static {
		t, ok := m.Target.(*pwsh.TypeExpression)
		if ok && lit && psSafeType(t.Type.Name, name) {
			return nil
		}
		return a.psForeign("the .NET call " + a.psSource(m))
	}
	f := fold.String(name)
	if lit && psSafeMethods[f] {
		return nil
	}
	if !lit || psCodeMethods[f] {
		// $sb.Invoke(), $ExecutionContext.InvokeCommand.InvokeScript('…'): code run as Invoke-Expression runs it
		return a.psForeign("the method call " + a.psSource(m))
	}
	if lit && f == "foreach" && len(m.Arguments) == 1 {
		if _, ok := m.Arguments[0].(*pwsh.ScriptBlockExpression); ok {
			return nil
		}
	}
	a.hidden = append(a.hidden, "the method call "+a.psSource(m))
	return nil
}

// psAssignment checks what an assignment sets: an environment variable a
// program reads as code, or a file written through its drive (${c:\x} = …).
func (a *psAnalyzer) psAssignment(as *pwsh.Assignment) error {
	v, ok := as.Left.(*pwsh.Variable)
	if !ok {
		return nil
	}
	if fold.String(v.Drive()) != "env" {
		a.psVariable(v, true, unknownDir)
		return nil
	}
	return a.psSetEnv(v.Name(), a.psStatementValue(as.Right))
}

// psStatementValue is the value of the right side of an assignment or a
// hashtable entry: one element, or any.
func (a *psAnalyzer) psStatementValue(st pwsh.Statement) Elem {
	var right pwsh.Node = st
	if p, ok := right.(*pwsh.Pipeline); ok && len(p.Elements) == 1 {
		right = p.Elements[0]
	}
	if ce, ok := right.(*pwsh.CommandExpression); ok {
		if els := a.psElems(ce.Expression); len(els) == 1 {
			return els[0]
		}
	}
	return Elem{Kind: Many, Text: "*"}
}

// psStartEnv checks the variables Start-Process -Environment sets for the
// program it starts, as assignments to $env: are. A map or a name known
// only at run time may set any variable, one a program reads as code too.
func (a *psAnalyzer) psStartEnv(vals []pwsh.CommandElement) error {
	var h *pwsh.Hashtable
	if len(vals) == 1 {
		h, _ = vals[0].(*pwsh.Hashtable)
	}
	if h == nil {
		return a.psForeign("Start-Process -Environment")
	}
	for _, kv := range h.Pairs {
		key := a.psElems(kv.Key)
		if len(key) != 1 || key[0].Kind != Lit {
			return a.psForeign("Start-Process -Environment")
		}
		if err := a.psSetEnv(key[0].Text, a.psStatementValue(kv.Value)); err != nil {
			return err
		}
	}
	return nil
}

// psSetEnv checks an environment variable set to value, for the programs
// that read it as code (envVar).
func (a *psAnalyzer) psSetEnv(name string, value Elem) error {
	if a.windows {
		name = strings.ToUpper(name) // Windows' environment ignores case
	}
	unknown, err := a.envVar(-1, name, value, 0, false, unknownDir)
	if err == nil && unknown {
		err = a.markUnknown(-1)
	}
	return err
}

// psEnvWord checks a word naming an environment variable through the env:
// drive (Set-Item Env:GIT_SSH_COMMAND …), which a cmdlet that writes may
// set to a value the analysis doesn't follow.
func (a *psAnalyzer) psEnvWord(w string, use psUse) error {
	drive, name, ok := strings.Cut(w, ":")
	if !ok || fold.String(drive) != "env" || use == psPrint || use == psNames || use == psRead {
		return nil
	}
	return a.psSetEnv(strings.TrimLeft(name, `/\`), Elem{Kind: Many, Text: "*"})
}

// psVariable checks a variable read or written through a drive: a file on
// a FileSystem drive (${c:\x}), or a function defined through the function: drive.
func (a *psAnalyzer) psVariable(v *pwsh.Variable, written bool, d dir) {
	drive := fold.String(v.Drive())
	switch drive {
	case "", "env", "variable":
		return
	case "function", "alias":
		if written {
			a.sawAnyAlias = true
			a.hidden = append(a.hidden, "a function or alias defined at run time ($"+v.Path+")")
		}
		return
	}
	use := psRead
	if written {
		use = psWrite
	}
	if len(drive) > 1 {
		// A drive PowerShell may not have, or one New-PSDrive made: only
		// known at run time ("$host:x" in a string reads the host: drive)
		a.psAdder(use)(FileRef{Display: "$" + v.Path})
		return
	}
	a.psPathWord(Elem{Kind: Lit, Text: v.Path}, d, false, use)
}

// psWinRef is pathRef for a path PowerShell reads on Windows. PowerShell
// has no mounts: a path starting with one separator is on the working
// directory's drive.
func (a *analyzer) psWinRef(p string, d dir) FileRef {
	s := strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		drive, _, ok := osfs.SplitDrive(d.path)
		if !d.known || !ok {
			return FileRef{Display: p, Rel: strings.TrimLeft(s, "/")}
		}
		s = drive + ":" + s
	}
	ref := a.winPathRef(s, d)
	ref.Display = p
	return ref
}

// psWinGlob is winGlob for PowerShell: a pattern in the engine's form, with
// a leading separator on the working directory's drive.
func (a *analyzer) psWinGlob(pattern string, d dir) (string, bool, string) {
	s := strings.ReplaceAll(pattern, `\`, "/")
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		drive, _, ok := osfs.SplitDrive(d.path)
		if !d.known || !ok {
			return "", false, ""
		}
		s = drive + ":" + s
	}
	if strings.HasPrefix(s, "/") {
		return "", false, "UNC paths (and words starting with two separators) are not supported"
	}
	return a.winGlob(s)
}

// psLink records which commands feed which: each pipeline element feeds
// the next, and the commands in an argument feed the command given it.
func (a *psAnalyzer) psLink(sb *pwsh.ScriptBlock, ids map[*pwsh.Command]int) {
	// in holds the ids of the commands under each node, in walk order
	in := map[pwsh.Node][]int{}
	var collect func(n pwsh.Node) []int
	collect = func(n pwsh.Node) []int {
		var out []int
		if c, ok := n.(*pwsh.Command); ok {
			if id, ok := ids[c]; ok {
				out = append(out, id)
			}
		}
		for _, ch := range pwsh.Children(n) {
			out = append(out, collect(ch)...)
		}
		in[n] = out
		return out
	}
	collect(sb)
	pwsh.Inspect(sb, func(n pwsh.Node) bool {
		switch v := n.(type) {
		case *pwsh.Pipeline:
			for i := 1; i < len(v.Elements); i++ {
				a.link(in[v.Elements[i-1]], in[v.Elements[i]])
			}
		case *pwsh.Command:
			if id, ok := ids[v]; ok {
				for _, e := range v.Elements[1:] {
					a.link(in[e], []int{id})
				}
			}
		}
		return true
	})
}

// psDirs records the directory each command runs in. A literal
// Set-Location or Push-Location moves the statements after it; anything
// that may move elsewhere (a script, a computed command, cd in a block)
// makes the directory unknown from there on.
func (a *psAnalyzer) psDirs(sb *pwsh.ScriptBlock, start dir) map[pwsh.CommandBase]dir {
	p := &psDirPass{a: a, of: map[pwsh.CommandBase]dir{}}
	p.scriptBlock(sb, start)
	return p.of
}

type psDirPass struct {
	a  *psAnalyzer
	of map[pwsh.CommandBase]dir
}

func (p *psDirPass) scriptBlock(sb *pwsh.ScriptBlock, d dir) dir {
	if sb.Param != nil {
		p.all(sb.Param, d)
	}
	for _, b := range []*pwsh.StatementBlock{sb.BeginBlock, sb.ProcessBlock, sb.EndBlock} {
		if b != nil {
			d = p.block(b, d)
		}
	}
	return d
}

func (p *psDirPass) block(b *pwsh.StatementBlock, d dir) dir {
	for _, t := range b.Traps {
		if p.a.psChangesDir(t) {
			p.all(b, unknownDir)
			return unknownDir
		}
	}
	for _, st := range b.Statements {
		d = p.stmt(st, d)
	}
	for _, t := range b.Traps {
		p.all(t, d)
	}
	return d
}

func (p *psDirPass) stmt(st pwsh.Statement, d dir) dir {
	if c := p.simpleCd(st); c != nil {
		p.all(st, d)
		return p.a.psCd(c, d)
	}
	if p.a.psChangesDir(st) {
		// A single command starts in d and may move from there; in anything
		// more, commands may run after the move
		if pl, ok := st.(*pwsh.Pipeline); ok && len(pl.Elements) == 1 && !p.a.psChangesDir(psArgsOf(pl.Elements[0])) {
			p.all(st, d)
		} else {
			p.all(st, unknownDir)
		}
		return unknownDir
	}
	p.all(st, d)
	return d
}

// psArgsOf returns a command's arguments as one node, or the element itself.
func psArgsOf(el pwsh.CommandBase) pwsh.Node {
	c, ok := el.(*pwsh.Command)
	if !ok {
		return el
	}
	return &pwsh.ArrayLiteral{Elements: psExprs(c.Elements[1:])}
}

func psExprs(els []pwsh.CommandElement) []pwsh.Expression {
	var out []pwsh.Expression
	for _, e := range els {
		switch v := e.(type) {
		case pwsh.Expression:
			out = append(out, v)
		case *pwsh.CommandParameter:
			if v.Argument != nil {
				out = append(out, v.Argument)
			}
		}
	}
	return out
}

// all sets the directory of every command under n not yet set.
func (p *psDirPass) all(n pwsh.Node, d dir) {
	pwsh.Inspect(n, func(m pwsh.Node) bool {
		if cb, ok := m.(pwsh.CommandBase); ok {
			if _, done := p.of[cb]; !done {
				p.of[cb] = d
			}
		}
		return true
	})
}

// simpleCd returns a statement that is only Set-Location or Push-Location
// with arguments that run nothing.
func (p *psDirPass) simpleCd(st pwsh.Statement) *pwsh.Command {
	pl, ok := st.(*pwsh.Pipeline)
	if !ok || len(pl.Elements) != 1 || pl.Background {
		return nil
	}
	c, ok := pl.Elements[0].(*pwsh.Command)
	if !ok || c.Invocation != "" {
		return nil
	}
	name, lit := p.a.psName(c)
	if !lit || p.a.anyAlias || p.a.aliases[fold.String(name)] {
		return nil
	}
	if canon, _ := p.a.psResolve(name, ""); canon != "Set-Location" && canon != "Push-Location" {
		return nil
	}
	for _, e := range c.Elements[1:] {
		if p.a.psChangesDir(e) {
			return nil
		}
	}
	return c
}

// psChangesDir reports whether anything under n may change the directory.
func (a *psAnalyzer) psChangesDir(n pwsh.Node) bool {
	found := false
	pwsh.Inspect(n, func(m pwsh.Node) bool {
		if c, ok := m.(*pwsh.Command); ok && a.psMayChangeDir(c) {
			found = true
		}
		return !found
	})
	return found
}

// psMayChangeDir reports a command that may change the location: cd and
// its kin, a script (the location is the session's, not the script's),
// code run as a string, and any command whose name isn't known.
func (a *psAnalyzer) psMayChangeDir(c *pwsh.Command) bool {
	if _, ok := c.Elements[0].(*pwsh.ScriptBlockExpression); ok {
		return false // its commands are inspected themselves
	}
	name, lit := a.psName(c)
	if !lit || c.Invocation == "." || a.anyAlias || a.aliases[fold.String(name)] {
		return true
	}
	canon, isCmdlet := a.psResolve(name, c.Invocation)
	if isCmdlet {
		switch canon {
		case "Set-Location", "Push-Location", "Pop-Location", "Invoke-Expression", "Invoke-Command", "Import-Module":
			return true
		}
		return false
	}
	if !strings.ContainsAny(name, `/\`) {
		return strings.HasSuffix(fold.String(name), ".ps1")
	}
	// A path runs a script unless it names a program: PowerShell finds
	// .\build as build.ps1
	ext := fold.String(path.Ext(strings.ReplaceAll(name, `\`, "/")))
	return !slices.Contains([]string{".exe", ".com", ".bat", ".cmd"}, ext)
}

// psCd returns the directory a literal Set-Location or Push-Location moves to.
func (a *psAnalyzer) psCd(c *pwsh.Command, d dir) dir {
	canon, _ := a.psResolve(c.Elements[0].(*pwsh.StringConstant).Value, "")
	spec := psCmdlets[fold.String(canon)]
	b, ok := psBind(spec, c.Elements[1:])
	if !ok {
		return unknownDir
	}
	wild := true
	vals, ok := a.value(spec, b, "Path")
	if !ok {
		wild = false
		vals, ok = a.value(spec, b, "LiteralPath")
	}
	if !ok || len(vals) != 1 || vals[0].Kind != Lit || wild && psHasWildcard(vals[0].Text) {
		return unknownDir
	}
	return a.psCdPath(vals[0].Text, d)
}

// psCdPath returns the directory Set-Location p moves to from d. PowerShell
// resolves ".." in the path it was given, without following links.
func (a *psAnalyzer) psCdPath(p string, d dir) dir {
	if p == "-" || p == "+" {
		return unknownDir
	}
	p, ref, ok, _ := a.psProviderPath(p, psNames)
	if !ok || ref.Display != "" {
		return unknownDir
	}
	if _, on := psOnDrive(p); on && a.drives {
		return unknownDir
	}
	ref = a.pathRef(a.psTilde(p)[0], d)
	if !ref.Certain || ref.Refused != "" {
		return unknownDir
	}
	if !hasDotDot(ref.Path) {
		return dir{path: ref.Path, known: true}
	}
	c := path.Clean(ref.Path)
	if _, _, onDrive := osfs.SplitDrive(c); a.windows && !onDrive {
		return unknownDir // above the drive's root
	}
	return dir{path: c, known: true}
}
