package shell

import (
	"path"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/winpath"
)

// Native Windows, where Git Bash runs the commands. Paths are read into the
// engine's form, /c/... for drive C:, the same form Git Bash itself uses
// Git Bash's other absolute paths (/, /tmp, /usr/bin) go through its mount
// table; without the table they are refused

// winKind is how Git Bash reads a word used as a path.
type winKind int

const (
	winRel      winKind = iota // relative to the working directory
	winDrive                   // on a drive: /c/x, /cygdrive/c/x, C:/x, C:\x
	winDriveRel                // C:x, relative to that drive's current directory
	winMount                   // another absolute path: in Git Bash's mounts (/, /tmp, /usr)
	winUNC                     // //host/share, \\host\share, or anything else starting with two separators
)

// winWord is a word read as a path.
type winWord struct {
	kind winKind
	// path is the engine's form, not cleaned (drive paths, relative paths).
	path string
	// msys is the Git Bash form of a word starting with "/", which Git Bash
	// cleans lexically before it applies its mounts: /c/../etc is Git's /etc, not C:\etc.
	msys string
}

// msysDevices are Git Bash's device files. They aren't files a policy
// protects; /dev/fd and /proc are left to the built-in rules.
var msysDevices = set("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty")

// MSYSDevice reports whether a cleaned Git Bash path is a device file.
func MSYSDevice(p string) bool { return msysDevices[p] }

// readWinWord reads p as Git Bash and the Windows programs it starts do: "\"
// and "/" both separate names, and names reads each name, the way Windows
// programs (winNames) or Git Bash's own programs (gitBashNames) do.
func readWinWord(p string, names func(string) string) winWord {
	s := strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(s, "//") {
		// UNC, or Git Bash's escape for a native program's /switch (cmd //c):
		// either way nothing the engine can check
		return winWord{kind: winUNC}
	}
	if d, rest, ok := driveSpec(s); ok {
		return winWord{kind: winDrive, path: drivePath(d, names(rest))}
	}
	if len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) {
		return winWord{kind: winDriveRel}
	}
	rest, ok := strings.CutPrefix(s, "/")
	if !ok {
		return winWord{kind: winRel, path: names(s)}
	}
	if d, t, ok := driveSpec(rest); ok { // file:///C:/x
		return winWord{kind: winDrive, path: drivePath(d, names(t))}
	}
	msys := "/" + names(rest)
	if d, t, ok := msysDrive(msys); ok {
		return winWord{kind: winDrive, path: drivePath(d, t), msys: msys}
	}
	return winWord{kind: winMount, msys: msys}
}

// msysDrive splits a Git Bash path on a drive, /c/rest or /cygdrive/c/rest.
func msysDrive(p string) (drive, rest string, ok bool) {
	first, tail, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if strings.EqualFold(first, "cygdrive") {
		first, tail, _ = strings.Cut(tail, "/")
	}
	if len(first) != 1 || !isASCIILetter(first[0]) {
		return "", "", false
	}
	return first, tail, true
}

// driveSpec splits "C:" or "C:/rest".
func driveSpec(s string) (drive, rest string, ok bool) {
	if len(s) < 2 || s[1] != ':' || !isASCIILetter(s[0]) || len(s) > 2 && s[2] != '/' {
		return "", "", false
	}
	return s[:1], strings.TrimPrefix(s[2:], "/"), true
}

// drivePath is the engine path of rest, whose names are already read, on a drive.
func drivePath(drive, rest string) string {
	d := "/" + strings.ToLower(drive)
	if rest == "" {
		return d
	}
	return d + "/" + rest
}

// winNames applies Win32's rewriting to each name of a "/"-separated path:
// trailing dots and spaces are stripped, and a name with ":" names a stream
// of the file before the ":".
func winNames(s string) string {
	parts := strings.Split(s, "/")
	for i, n := range parts {
		if n == "" || n == "." || n == ".." {
			continue
		}
		if before, stream, ok := strings.Cut(n, ":"); ok {
			if before != "" {
				n = before
			} else if isIndexStream(stream) {
				n = "." // :$I30:$INDEX_ALLOCATION opens the directory the name is in
			}
		}
		// A name of only dots and spaces (...) trims to nothing, and Win32 then
		// opens the directory it is in. Programs under Git Bash keep the name,
		// which can't exist unless made through \\?\; the directory is the stricter reading
		if n = strings.TrimRight(n, ". "); n == "" {
			n = "."
		}
		parts[i] = n
	}
	return strings.Join(parts, "/")
}

// gitBashNames returns the names Git Bash's own programs (bash, cat, cp, ln)
// open for a "/"-separated path. Like Cygwin, they store each character Win32
// forbids in names, and a name's trailing dots and spaces, as U+F000 plus the
// character, so `ln -s x 'k|y'` makes "k\uF07Cy" and `cat k.` opens
// "k\uF02E", a different file from the k Windows programs open.
func gitBashNames(s string) string {
	parts := strings.Split(s, "/")
	for i, n := range parts {
		if n == "" || n == "." || n == ".." {
			continue
		}
		trail := len(strings.TrimRight(n, ". "))
		var b strings.Builder
		for j, r := range n {
			// #nosec G115 -- r < 0x80, so it fits in a byte
			if r < 0x80 && (winpath.Forbidden(byte(r)) || j >= trail) {
				r += 0xF000
			}
			b.WriteRune(r)
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, "/")
}

// gitBashView is the name Git Bash's programs show for a name on disk, the
// reverse of gitBashNames: what its globs match against.
func gitBashView(name string) string {
	if !strings.ContainsFunc(name, isGitBashRune) {
		return name
	}
	return strings.Map(func(r rune) rune {
		if isGitBashRune(r) {
			return r - 0xF000
		}
		return r
	}, name)
}

func isGitBashRune(r rune) bool {
	c := r - 0xF000
	return 0 <= c && c < 0x80 && (winpath.Forbidden(byte(c)) || c == '.' || c == ' ')
}

// isIndexStream reports whether stream, the part of a name after its first
// ":", names a directory's index rather than a data stream: its attribute
// type (after a second ":") is present and not $DATA.
func isIndexStream(stream string) bool {
	_, typ, ok := strings.Cut(stream, ":")
	return ok && strings.HasPrefix(typ, "$") && !strings.EqualFold(typ, "$DATA")
}

// msysAbs maps a Git Bash absolute path to the engine's form the way Git
// Bash does: ".." applied lexically, then a drive or the longest matching
// mount point. refused says why it can't be mapped.
func (a *analyzer) msysAbs(p string) (mapped, refused string) {
	c := path.Clean(p)
	if d, rest, ok := msysDrive(c); ok {
		return drivePath(d, rest), ""
	}
	if a.mounts == nil {
		return "", "Git Bash's mount table is unknown, so paths outside a drive (" + c + ") can't be checked"
	}
	best, found := "", false
	for pt := range a.mounts {
		if (pt == "/" || strings.EqualFold(c, pt) || len(c) > len(pt) && strings.EqualFold(c[:len(pt)+1], pt+"/")) &&
			(!found || len(pt) > len(best)) {
			best, found = pt, true
		}
	}
	target := a.mounts[best]
	if !found || target == "" {
		return "", "the directory behind Git Bash's mount " + best + " is unknown, so " + c + " can't be checked"
	}
	rest := strings.TrimPrefix(c[len(best):], "/")
	if best == "/" {
		rest = strings.TrimPrefix(c, "/")
	}
	if rest == "" {
		return target, ""
	}
	return target + "/" + rest, ""
}

// alt returns Git Bash's own reading of a path whose Windows reading is
// primary, when ".." makes them differ (it climbs out of a drive or a
// mount), or why that reading can't be checked.
func (a *analyzer) alt(primary, msys string) ([]string, string) {
	if !hasDotDot(msys) {
		return nil, ""
	}
	mapped, refused := a.msysAbs(msys)
	if refused != "" || mapped == path.Clean(primary) {
		return nil, refused
	}
	return []string{mapped}, ""
}

func hasDotDot(p string) bool {
	return slices.Contains(strings.Split(p, "/"), "..")
}

// msys is the directory in Git Bash's form, for its own reading of "..".
func (d dir) msys() string {
	if d.posix != "" {
		return d.posix
	}
	return d.path
}

// winPathRef is pathRef for Windows. Windows programs and Git Bash's own
// programs read some names differently (gitBashNames), and a command may be
// either, so both readings are checked.
func (a *analyzer) winPathRef(p string, d dir) FileRef {
	ref := a.winRef(p, d, winNames)
	if ref.Refused != "" || !ref.Certain {
		return ref
	}
	git := a.winRef(p, d, gitBashNames)
	if git.Refused != "" {
		ref.Refused = git.Refused
		return ref
	}
	for _, q := range append([]string{git.Path}, git.Alts...) {
		if q != ref.Path && !slices.Contains(ref.Alts, q) {
			ref.Alts = append(ref.Alts, q)
		}
	}
	return ref
}

// winRef is one reading of a path word, names being how its names are read.
func (a *analyzer) winRef(p string, d dir, names func(string) string) FileRef {
	w := readWinWord(p, names)
	switch w.kind {
	case winUNC:
		return FileRef{Display: p, Refused: "UNC paths (and words starting with two separators) are not supported"}
	case winDriveRel:
		return FileRef{Display: p, Refused: "a drive-relative path depends on that drive's current directory"}
	case winMount:
		// Mount keeps Git Bash's own path for its emulated /proc and /dev,
		// which the built-in rules and the device list decide first
		ref := FileRef{Display: p, Mount: path.Clean(w.msys)}
		if ref.Path, ref.Refused = a.msysAbs(w.msys); ref.Refused == "" {
			ref.Certain = true
		}
		return ref
	case winDrive:
		ref := FileRef{Path: w.path, Display: p, Certain: true}
		if w.msys != "" {
			ref.Alts, ref.Refused = a.alt(w.path, w.msys)
		}
		return ref
	}
	if !d.known {
		return FileRef{Display: p, Rel: w.path}
	}
	ref := FileRef{Path: d.path + "/" + w.path, Display: p, Certain: true}
	ref.Alts, ref.Refused = a.alt(ref.Path, d.msys()+"/"+w.path)
	return ref
}

// winCd returns the directory `cd p` moves to from d.
// Bash tracks it logically (lexical ".."), in Git Bash's own paths and names.
func (a *analyzer) winCd(p string, d dir) dir {
	w := readWinWord(p, gitBashNames)
	var msys string
	switch w.kind {
	case winDrive:
		if w.msys == "" || !hasDotDot(w.msys) {
			return dir{path: w.path, known: true}
		}
		msys = w.msys
	case winMount:
		msys = w.msys
	case winRel:
		if !d.known {
			return unknownDir
		}
		if d.posix == "" && !hasDotDot(w.path) {
			return dir{path: d.path + "/" + w.path, known: true}
		}
		msys = d.msys() + "/" + w.path
	default:
		return unknownDir
	}
	mapped, refused := a.msysAbs(msys)
	if refused != "" {
		return unknownDir
	}
	c := path.Clean(msys)
	if _, _, onDrive := msysDrive(c); onDrive {
		return dir{path: mapped, known: true}
	}
	return dir{path: mapped, known: true, posix: c}
}

// winGlob returns a glob pattern in the engine's form. ok is false when it
// can't be expanded (a meta character where a mount point could be, or
// ".."), and refused says why it is denied outright.
func (a *analyzer) winGlob(pattern string) (out string, ok bool, refused string) {
	if strings.HasPrefix(pattern, "//") {
		return "", false, "UNC paths (and words starting with two separators) are not supported"
	}
	if d, rest, ok := driveSpec(pattern); ok {
		return "/" + strings.ToLower(d) + "/" + rest, true, ""
	}
	if len(pattern) >= 2 && pattern[1] == ':' && isASCIILetter(pattern[0]) {
		return "", false, "a drive-relative path depends on that drive's current directory"
	}
	if hasDotDot(pattern) {
		return "", false, ""
	}
	if !strings.HasPrefix(pattern, "/") {
		return pattern, true, ""
	}
	if dr, t, ok := msysDrive(pattern); ok && !hasUnescapedMeta(dr) {
		return drivePath(dr, "") + "/" + t, true, ""
	}
	if a.mounts == nil {
		return "", false, "Git Bash's mount table is unknown, so paths outside a drive (" + pattern + ") can't be checked"
	}
	// The literal names before the first meta character must reach past
	// every mount point the pattern could match
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	lit := 0
	for lit < len(segs) && !hasUnescapedMeta(segs[lit]) {
		lit++
	}
	prefix := "/" + strings.Join(segs[:lit], "/")
	for pt := range a.mounts {
		ptSegs := strings.Split(strings.TrimPrefix(pt, "/"), "/")
		if pt != "/" && len(ptSegs) > lit && strings.EqualFold(strings.Join(ptSegs[:lit], "/"), strings.Join(segs[:lit], "/")) {
			return "", false, ""
		}
	}
	mapped, refused := a.msysAbs(prefix)
	if refused != "" {
		return "", false, refused
	}
	if lit == len(segs) {
		return mapped, true, ""
	}
	return mapped + "/" + strings.Join(segs[lit:], "/"), true, ""
}

// winProgram is a program's name as Windows finds it: the last name of a
// path with either separator, without an .exe or .com extension.
func winProgram(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	for _, ext := range []string{".exe", ".com"} {
		if len(name) > len(ext) && strings.EqualFold(name[len(name)-len(ext):], ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

// isDriveWord reports a word starting with a drive, C:/ or C:\, which is not git's REF:path.
func isDriveWord(s string) bool {
	return len(s) >= 3 && s[1] == ':' && isASCIILetter(s[0]) && (s[2] == '/' || s[2] == '\\')
}

func isASCIILetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
