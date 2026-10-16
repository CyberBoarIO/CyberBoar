package shell

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// FileRef is a path a command line may touch.
type FileRef struct {
	// Path is absolute and not cleaned, so it resolves like the kernel would.
	// Empty when Certain is false.
	Path    string
	Display string // as written, for messages
	// Certain is false for a word only known at run time, or a relative path
	// in a directory only known at run time: it could be any path.
	Certain bool
	// Rel is the relative path when only the directory is unknown: rules
	// anchored anywhere (**/…) can still match its tail.
	Rel string
	// Accessed is false for words a command only prints (echo .env): they are
	// checked against deny and ask rules, but need no allow rule.
	Accessed bool
	// Contents is true when the command may read or change what a directory
	// contains, so a directory path is checked with its contents.
	Contents bool
	// Modifies is true when the command may delete, move, overwrite or change
	// the permissions of the path, and for a directory of what it holds: a
	// directory that holds a guarded file may not be touched this way
	// (builtin.guarded). Repo widens the path to the git work tree holding
	// it (git stash, git reset --hard).
	Modifies bool
	Repo     bool
	// Windows only. Refused says why the path is denied outright (UNC,
	// drive-relative, an unknown mount). Mount is the cleaned Git Bash path
	// of a word outside the drives, for Git Bash's emulated /proc and /dev,
	// which the built-in rules decide first. Alts are the other readings of
	// Path: Git Bash's own, where ".." or a name makes it differ (see
	// gitBashNames). All are checked.
	Refused string
	Mount   string
	Alts    []string
	// Shape is the run-time word's Elem.Shape when Certain is false, so the
	// built-in rules can check what its literal parts pin it to
	Shape string
}

// maxGlobMatches bounds glob expansion; beyond it the word counts as any path.
const maxGlobMatches = 10000

// printOnly commands don't open their arguments: run-time words in them are
// not paths, and literal ones are only checked against deny/ask rules.
var printOnly = set("echo", "printf", "true", "false", ":", "sleep", "kill", "exit", "return",
	"shift", "unset", "seq", "expr", "basename", "dirname", "test", "[", "pwd", "which", "type", "wait")

// namesOnly commands may touch a directory but not what's inside it.
var namesOnly = set("cd", "pushd", "popd", "ls", "dir", "mkdir", "rmdir", "stat", "du", "df",
	"realpath", "readlink", "basename", "dirname", "test", "[", "echo", "printf", "which", "type", "find")

// innerName is the command a wrapper chain finally runs.
func innerName(layers [][]Elem) (string, []Elem) {
	for i := len(layers) - 1; i >= 0; i-- {
		l := layers[i]
		if len(l) > 0 && l[0].Kind == Lit {
			return l[0].Text, l
		}
	}
	return "", nil
}

// fileRefs collects the paths one command may touch, in d unless a wrapper
// moved it elsewhere.
func (a *analyzer) fileRefs(raw []Elem, u unwrapResult, d dir, glob globOpts) []FileRef {
	layers := u.layers
	name, inner := innerName(layers)
	printing := printOnly[name]
	contents := !namesOnly[name]
	// find -exec runs several commands on what it finds, and the last one
	// alone doesn't say what the others do with it: every command that
	// isn't a wrapper counts.
	for _, l := range layers {
		if len(l) > 0 && l[0].Kind == Lit && lookupWrapper(l[0].Text) == nil {
			printing = printing && printOnly[l[0].Text]
			contents = contents || !namesOnly[l[0].Text]
		}
	}
	if name == "find" && hasAny(inner, "-delete", "-fprint", "-fprint0", "-fprintf", "-fls") {
		contents = true
	}
	var refs []FileRef
	add := func(r FileRef) {
		r.Accessed = !printing
		r.Contents = contents && !printing
		refs = append(refs, r)
	}
	for i, e := range raw {
		if i == 0 && (e.Kind != Lit || !strings.Contains(e.Text, "/") && !(a.windows && strings.Contains(e.Text, `\`))) {
			continue // the command name, unless it is a path
		}
		a.wordRefs(e, d, glob, printing, add)
	}
	if u.dirFrom >= 0 {
		// env -C DIR CMD ARGS: the words read in d above are read in DIR
		// as well, which is where CMD opens them.
		d = a.innerDir(u, d)
		for _, l := range layers[u.dirFrom:] {
			for i, e := range l {
				if i > 0 || e.Kind == Lit && strings.Contains(e.Text, "/") {
					a.wordRefs(e, d, glob, printing, add)
				}
			}
		}
	}
	// Words added by wrappers at run time (xargs: arguments from stdin).
	for _, l := range layers[1:] {
		for _, e := range l {
			if e.Kind == Many && e.Text == "*" && !printing {
				add(FileRef{Display: "arguments read at run time"})
			}
		}
	}
	if name == "git" {
		// REF:path names committed content: git show HEAD:.env, cat-file -p :x.
		for _, e := range inner[1:] {
			if e.Kind == Lit && !strings.Contains(e.Text, "://") && !(a.windows && isDriveWord(e.Text)) {
				if _, p, ok := strings.Cut(e.Text, ":"); ok && p != "" {
					add(a.pathRef(p, d))
				}
			}
		}
	}
	if implicitCwd(name, inner) {
		add(a.pathRef(".", d))
	}
	all, extra := a.changes(raw, layers, d)
	if all {
		for i := range refs {
			refs[i].Modifies = true
		}
	}
	return append(refs, extra...)
}

// removes may delete, move or change the permissions of every path they
// name, and of everything a named directory holds.
var removes = set("rm", "rmdir", "unlink", "shred", "srm", "trash", "trash-put", "mv",
	"chmod", "chown", "chgrp", "chattr", "setfacl")

// changes finds what a command may change beyond the paths it opens, for
// builtin.guarded: all says every path it names may be deleted,
// moved or replaced, with what a directory holds; extra are the paths it
// changes without naming them (a copy's destination, the working directory
// an archive is extracted into, the git work tree). Every layer counts, so
// find -exec rm and xargs rm are caught whatever else runs.
func (a *analyzer) changes(raw []Elem, layers [][]Elem, d dir) (all bool, extra []FileRef) {
	implicit := func(repo bool) {
		r := a.pathRef(".", d)
		r.Modifies, r.Repo = true, repo
		extra = append(extra, r)
	}
	for _, l := range layers {
		if len(l) == 0 || l[0].Kind != Lit {
			continue
		}
		name, args := l[0].Text, l[1:]
		switch {
		case removes[name], inPlace(name, args), name == "find" && hasAny(args, "-delete"):
			all = true
		}
		switch name {
		case "cp", "mv", "ln", "install", "rsync", "scp":
			extra = append(extra, a.copyDest(name, args, d)...)
		case "tar", "bsdtar", "gtar":
			if tarExtracts(args) {
				all = true
				if !hasOpt(args, "-C", "--directory") {
					implicit(false)
				}
			}
		case "unzip":
			all = true
			if !hasOpt(args, "-d", "") {
				implicit(false)
			}
		case "patch":
			all = true
			if !hasOpt(args, "-d", "--directory") {
				implicit(false)
			}
		case "git":
			if len(args) == 0 || args[0].Kind != Lit {
				continue
			}
			rest := args[1:]
			switch args[0].Text {
			case "checkout", "restore", "rm", "mv":
				all = true
			case "reset":
				if !hasLong(rest, "hard", "merge", "keep") {
					continue
				}
				fallthrough
			case "clean", "am":
				implicit(true)
				extra = append(extra, a.gitTrees(raw, d)...)
			case "stash":
				if len(rest) > 0 && rest[0].Kind == Lit && (rest[0].Text == "list" || rest[0].Text == "show") {
					continue
				}
				implicit(true)
				extra = append(extra, a.gitTrees(raw, d)...)
			case "apply":
				if hasAny(rest, "--check", "--stat", "--numstat", "--summary") && !hasLong(rest, "apply") {
					continue
				}
				implicit(true)
				extra = append(extra, a.gitTrees(raw, d)...)
			}
		}
	}
	return all, extra
}

// inPlace reports sed, perl or ruby editing the files it names (-i).
func inPlace(name string, args []Elem) bool {
	switch name {
	case "sed", "gsed", "perl", "ruby":
	default:
		return false
	}
	for _, e := range args {
		t := e.Text
		if _, _, long := longOpt(t, "in-place"); e.Kind == Lit && (long ||
			strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'i')) {
			return true
		}
	}
	return false
}

// hasOpt reports a short option (alone or with its value attached) or a long
// one (alone or with "=value").
func hasOpt(args []Elem, short, long string) bool {
	for _, e := range args {
		t := e.Text
		if e.Kind == Lit && (short != "" && strings.HasPrefix(t, short) ||
			long != "" && (t == long || strings.HasPrefix(t, long+"="))) {
			return true
		}
	}
	return false
}

// tarExtracts reports tar in extract mode: x in the first word's bundle
// (tar xzf, tar -xzf), in a later short cluster, or --extract/--get.
func tarExtracts(args []Elem) bool {
	for i, e := range args {
		t := e.Text
		switch {
		case e.Kind != Lit:
		case strings.HasPrefix(t, "--"):
			if _, _, ok := longOpt(t, "extract", "get"); ok {
				return true
			}
		case strings.HasPrefix(t, "-") || i == 0:
			if strings.ContainsRune(t, 'x') {
				return true
			}
		}
	}
	return false
}

// copyDest returns what a copy writes: in a destination directory the
// names of its sources (or the directory itself for a source's contents,
// src/ or src/.), otherwise the destination path.
func (a *analyzer) copyDest(name string, args []Elem, d dir) []FileRef {
	spec := optSpec{short: "St", permute: true, long: set("target-directory", "suffix"), abbrev: true}
	switch name {
	case "install":
		spec = optSpec{short: "gmoSt", permute: true, long: set("group", "mode", "owner", "suffix", "target-directory", "strip-program"),
			flags: set("strip"), abbrev: true}
	case "rsync":
		spec = optSpec{short: "efBTM", permute: true, long: set("rsh", "filter", "exclude", "include", "exclude-from",
			"include-from", "files-from", "temp-dir", "partial-dir", "compare-dest", "copy-dest", "link-dest",
			"backup-dir", "suffix", "chmod", "chown", "usermap", "groupmap", "log-file", "out-format",
			"password-file", "max-size", "min-size", "bwlimit", "timeout", "contimeout", "port", "block-size",
			"rsync-path", "iconv", "remote-option")}
	case "scp":
		spec = optSpec{short: "cDFiJlloPS", permute: true}
	}
	p := parseOpts(args, spec)
	srcs := p.rest
	dest, ok := p.value("t", "target-directory")
	switch {
	case ok && (name == "cp" || name == "mv" || name == "ln" || name == "install"):
	case len(srcs) == 1 && name == "ln":
		dest = Elem{Kind: Lit, Text: "."} // ln TARGET: a link in the working directory
	case len(srcs) < 2:
		return nil
	default:
		dest, srcs = srcs[len(srcs)-1], srcs[:len(srcs)-1]
	}
	if dest.Kind != Lit || name == "scp" && strings.Contains(dest.Text, ":") {
		return nil // a run-time destination is already a path only known at run time
	}
	mark := func(r FileRef) FileRef {
		r.Accessed, r.Contents, r.Modifies = true, true, true
		return r
	}
	target := a.pathRef(dest.Text, d)
	isDir := false
	if target.Certain {
		info, err := a.fs.Stat(target.Path)
		isDir = err == nil && info.IsDir()
	}
	if !isDir {
		return []FileRef{mark(target)}
	}
	var out []FileRef
	for _, s := range srcs {
		base := ""
		if s.Kind == Lit && !s.Glob {
			base = a.baseName(s.Text)
		}
		if base == "" || base == "." || base == ".." {
			out = append(out, mark(target)) // its contents, or names only known at run time
			continue
		}
		out = append(out, mark(a.pathRef(strings.TrimSuffix(dest.Text, "/")+"/"+base, d)))
	}
	return out
}

// baseName is the last name in a path word, "" for a word ending in a
// separator (src/: the directory's contents for rsync and BSD cp).
func (a *analyzer) baseName(w string) string {
	seps := "/"
	if a.windows {
		seps = `/\`
	}
	if w == "" || strings.ContainsRune(seps, rune(w[len(w)-1])) {
		return ""
	}
	if i := strings.LastIndexAny(w, seps); i >= 0 {
		w = w[i+1:]
	}
	return w
}

func hasAny(argv []Elem, words ...string) bool {
	for _, e := range argv {
		for _, w := range words {
			if e.Kind == Lit && e.Text == w {
				return true
			}
		}
	}
	return false
}

// hasLong reports whether argv has any of the long options names, cut short
// or not (git's parse-options takes unambiguous prefixes).
func hasLong(argv []Elem, names ...string) bool {
	for _, e := range argv {
		if _, _, ok := longOpt(e.Text, names...); e.Kind == Lit && ok {
			return true
		}
	}
	return false
}

// wordRefs adds the path candidates of one word.
func (a *analyzer) wordRefs(e Elem, d dir, glob globOpts, printing bool, add func(FileRef)) {
	switch {
	case e.Kind == Lit:
		for _, c := range pathCandidates(e.Text) {
			add(a.pathRef(c, d))
		}
	case e.Glob:
		pattern, ok := e.Text, true
		if a.windows {
			var refused string
			if pattern, ok, refused = a.winGlob(e.Text); refused != "" {
				add(FileRef{Display: e.Text, Refused: refused})
				return
			}
		}
		var matches []string
		if ok {
			matches, ok = a.expandGlob(pattern, d, glob)
		}
		switch {
		case !ok:
			if !printing {
				add(FileRef{Display: e.Text})
			}
		case len(matches) == 0:
			add(a.pathRef(e.Text, d)) // no match: bash passes the pattern on
		default:
			for _, m := range matches {
				add(FileRef{Path: m, Display: a.fs.Show(m), Certain: true})
			}
		}
	case e.Text == "{}": // find -exec placeholder: paths under find's own arguments
	case e.Kind == One && strings.HasPrefix(e.Text, "*/"):
		// A directory only known at run time plus a literal tail (~-/x).
		add(FileRef{Display: e.Text, Rel: e.Text[2:], Shape: e.Shape})
	default:
		if !printing {
			add(FileRef{Display: e.String(), Shape: e.Shape})
		}
	}
}

// pathRef resolves a literal path against the working directory.
func (a *analyzer) pathRef(p string, d dir) FileRef {
	if a.windows {
		return a.winPathRef(p, d)
	}
	switch {
	case path.IsAbs(p):
		return FileRef{Path: p, Display: p, Certain: true}
	case !d.known:
		return FileRef{Display: p, Rel: p} // relative to a directory only known at run time
	default:
		return FileRef{Path: d.path + "/" + p, Display: p, Certain: true}
	}
}

// pathCandidates returns the ways a word can name a file: itself, the value
// after "=" (--file=x, if=x), after a two-letter short option (-fx), after "@"
// or "<" (curl -d @x, curl -F f=<x), after file:// (curl file:///x), and a
// value up to ";" (curl -F 'f=@x;type=text/plain').
func pathCandidates(w string) []string {
	var out []string
	seen := map[string]bool{}
	var addValue func(string)
	addValue = func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
		if strings.HasPrefix(v, "@") || strings.HasPrefix(v, "<") {
			addValue(v[1:])
		}
		if before, _, ok := strings.Cut(v, ";"); ok {
			addValue(before)
		}
		if rest, ok := strings.CutPrefix(v, "file://"); ok {
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				addValue(rest[i:]) // drop the host part
			}
		}
	}
	addValue(w)
	if _, v, ok := strings.Cut(w, "="); ok {
		addValue(v)
	}
	if strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && len(w) > 2 {
		addValue(w[2:])
	}
	return out
}

// redirectRefs collects the files a statement's redirections open.
func (a *analyzer) redirectRefs(st *syntax.Stmt, d dir) []FileRef {
	var refs []FileRef
	for _, r := range st.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrInOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
		case syntax.DplIn, syntax.DplOut:
			if lit := r.Word.Lit(); lit == "-" || isDigits(lit) {
				continue // a file descriptor, not a file
			}
		default:
			continue // heredocs
		}
		for _, e := range a.word(r.Word) {
			if e.Kind == Lit {
				ref := a.pathRef(e.Text, d)
				ref.Accessed = true
				refs = append(refs, ref)
			} else {
				refs = append(refs, FileRef{Display: e.String(), Accessed: true, Shape: e.Shape})
			}
		}
	}
	return refs
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// implicitCwd reports commands that read the working directory's contents when
// given no path: recursive grep, ripgrep and friends, find, git add -A.
func implicitCwd(name string, argv []Elem) bool {
	if len(argv) == 0 {
		return false
	}
	args := argv[1:]
	switch name {
	case "grep", "egrep", "fgrep", "zgrep":
		p := parseOpts(args, optSpec{short: "efABCmdD", permute: true, long: set("regexp", "file",
			"after-context", "before-context", "context", "max-count", "include", "exclude",
			"exclude-dir", "exclude-from", "devices", "directories", "label", "binary-files"),
			flags: set("binary"), abbrev: true})
		recursive := p.has("r", "R", "recursive", "dereference-recursive")
		if v, ok := p.value("d", "directories"); ok && v.Text == "recurse" {
			recursive = true
		}
		return recursive && operands(p) == 0
	case "rg", "ripgrep", "ag", "ack", "ack-grep", "pt", "ugrep":
		p := parseOpts(args, optSpec{short: "efgtTABCmjMEr", permute: true, long: set("regexp", "file",
			"glob", "type", "type-not", "after-context", "before-context", "context", "max-count",
			"threads", "max-columns", "encoding", "replace", "max-depth", "ignore-file")})
		if p.has("files") {
			return len(p.rest) == 0
		}
		return operands(p) == 0
	case "python", "python2", "python3", "pypy", "pypy3":
		// A web server for the working directory, unless told another one
		// (--directory DIR is a literal word and checked as a path).
		for i := 0; i+1 < len(args); i++ {
			if args[i].Kind == Lit && args[i].Text == "-m" && args[i+1].Kind == Lit &&
				(args[i+1].Text == "http.server" || args[i+1].Text == "SimpleHTTPServer") {
				return !hasAny(args, "-d", "--directory")
			}
		}
		return false
	case "find":
		return len(args) == 0 || (args[0].Kind == Lit && (strings.HasPrefix(args[0].Text, "-") ||
			args[0].Text == "(" || args[0].Text == "!"))
	case "php":
		return hasAny(args, "-S") && !hasAny(args, "-t") // serves the working directory
	case "git":
		if len(args) == 0 || args[0].Kind != Lit || args[0].Text != "add" {
			return false
		}
		return hasAny(args[1:], "-A", "-u") || hasLong(args[1:], "all", "update", "no-ignore-removal")
	}
	return false
}

// operands counts the paths after a search command's pattern.
func operands(p parsedOpts) int {
	n := len(p.rest)
	if !p.hasExact("e", "f", "regexp", "file") && n > 0 {
		n-- // the first operand is the pattern
	}
	return n
}

// globOpts are the shell options that change what a glob matches.
type globOpts struct {
	dotglob, globstar, nocaseglob bool
}

// expandGlob expands an unquoted glob relative to d like bash would (without
// nullglob). ok is false when it can't: unknown directory, globstar, too many
// matches or an unreadable directory.
func (a *analyzer) expandGlob(pattern string, d dir, o globOpts) (matches []string, ok bool) {
	if o.globstar && strings.Contains(pattern, "**") {
		return nil, false
	}
	base := "/"
	rel := strings.TrimPrefix(pattern, "/")
	if !path.IsAbs(pattern) {
		if !d.known {
			return nil, false
		}
		base = d.path
	}
	current := []string{base}
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		last := i == len(segs)-1
		var next []string
		for _, dirPath := range current {
			if !hasUnescapedMeta(seg) {
				name := unescapeGlob(seg)
				if a.windows {
					name = gitBashNames(name) // bash expands globs itself
				}
				p := joinDir(dirPath, name)
				if _, err := a.fs.Lstat(p); err == nil || !last {
					next = append(next, p)
				}
				continue
			}
			entries, err := a.fs.ReadDir(dirPath)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, false
			}
			segPat := strings.Replace(seg, "[!", "[^", -1)
			for _, e := range entries {
				n := e.Name()
				shown := n
				if a.windows {
					shown = gitBashView(n)
				}
				if strings.HasPrefix(shown, ".") && !strings.HasPrefix(seg, ".") && !o.dotglob {
					continue
				}
				if o.nocaseglob {
					segPat, shown = strings.ToLower(segPat), strings.ToLower(shown)
				}
				if m, err := path.Match(segPat, shown); err != nil {
					return nil, false
				} else if m {
					next = append(next, joinDir(dirPath, n))
				}
			}
		}
		if len(next) > maxGlobMatches {
			return nil, false
		}
		current = next
	}
	if len(current) == 1 && current[0] == base {
		return nil, true
	}
	sort.Strings(current)
	return current, true
}

// joinDir joins a directory and a name without doubling the root's "/":
// "//x" is a UNC path on Windows.
func joinDir(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func unescapeGlob(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if r == '\\' && !esc {
			esc = true
			continue
		}
		esc = false
		b.WriteRune(r)
	}
	return b.String()
}
