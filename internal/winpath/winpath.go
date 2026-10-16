// Package winpath reads Windows paths into the engine's path space, where
// the drive path C:\Users\dev is /c/Users/dev
//
// It applies what Win32 does to a path before any file is opened: "\" and
// "/" both separate names, and trailing dots and spaces are stripped from
// every name. Forms that name files the engine can't reason about are
// refused: UNC paths (\\host\share, which reach local drives too as
// \\localhost\c$), the \\?\, \\.\ and \??\ namespaces, drive-relative paths
// (C:x), paths rooted without a drive (\x), alternate data streams (a ":"
// in a name) and reserved device names (CON, NUL, COM1, ...)
//
// ".." is kept, so callers can resolve links before or after applying it
package winpath

import (
	"fmt"
	"strings"
)

// Error is a path the engine refuses to read
type Error struct {
	Path string
	Why  string
}

func (e *Error) Error() string { return fmt.Sprintf("%q: %s", e.Path, e.Why) }

func refuse(p, why string) error { return &Error{Path: p, Why: why} }

// Path reads p, absolute (C:\x, C:/x) or relative (x\y), and returns it in
// the engine's form: "/c/x" or "x/y". abs reports which
func Path(p string) (out string, abs bool, err error) {
	s := strings.ReplaceAll(p, `\`, "/")
	switch {
	case strings.HasPrefix(s, "//"):
		return "", false, refuse(p, "UNC paths and the \\\\?\\ and \\\\.\\ namespaces are not supported")
	case strings.HasPrefix(s, "/"):
		return "", false, refuse(p, "a path rooted without a drive letter depends on the current drive")
	}
	drive := ""
	if len(s) >= 2 && s[1] == ':' && isLetter(s[0]) {
		if len(s) == 2 || s[2] != '/' { // "C:" is C's current directory, like "C:x"
			return "", false, refuse(p, "a drive-relative path depends on that drive's current directory")
		}
		drive, s = strings.ToLower(s[:1]), strings.TrimPrefix(s[2:], "/")
		if s == "" {
			return "/" + drive, true, nil
		}
	}
	rest, err := names(p, s)
	if err != nil {
		return "", false, err
	}
	if drive == "" {
		return rest, false, nil
	}
	return "/" + drive + "/" + rest, true, nil
}

// Abs is Path for a path that must be absolute
func Abs(p string) (string, error) {
	out, abs, err := Path(p)
	if err == nil && !abs {
		err = refuse(p, "not an absolute path with a drive letter")
	}
	return out, err
}

// Target reads the target of a symbolic link or junction as Windows stores
// it. Drive and \\?\ (or \??\) drive targets are absolute; a target rooted
// without a drive is on the link's drive; anything else is relative to the
// link's directory. Volume GUID and UNC targets are refused
func Target(t, linkDrive string) (out string, abs bool, err error) {
	s := strings.ReplaceAll(t, `\`, "/")
	for _, prefix := range []string{"//?/", "/??/"} {
		if rest, ok := strings.CutPrefix(s, prefix); ok {
			if len(rest) < 3 || rest[1] != ':' || rest[2] != '/' || !isLetter(rest[0]) {
				return "", false, refuse(t, "a link to a volume or network path can't be checked")
			}
			return Path(rest)
		}
	}
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		rest, err := names(t, strings.TrimLeft(s, "/"))
		if err != nil {
			return "", false, err
		}
		return "/" + linkDrive + "/" + rest, true, nil
	}
	return Path(t)
}

// names checks and rewrites the names of a "/"-separated path
func names(orig, s string) (string, error) {
	parts := strings.Split(s, "/")
	out := parts[:0]
	for _, n := range parts {
		switch n {
		case "", ".", "..":
			if n != "" {
				out = append(out, n)
			}
			continue
		}
		if strings.Contains(n, ":") {
			return "", refuse(orig, "alternate data streams (a \":\" in a name) are not supported")
		}
		// Win32 strips trailing dots and spaces: ".env." opens ".env"
		trimmed := strings.TrimRight(n, ". ")
		if trimmed == "" {
			return "", refuse(orig, fmt.Sprintf("the name %q is only dots and spaces", n))
		}
		if IsDevice(trimmed) {
			return "", refuse(orig, fmt.Sprintf("%q is a reserved device name", n))
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "/"), nil
}

// Forbidden reports whether Win32 forbids c in a file name: the characters
// ", *, :, <, >, ? and |, and the control characters. A name with one can't
// be opened by Windows programs
func Forbidden(c byte) bool {
	return c < 0x20 || strings.IndexByte(`"*:<>?|`, c) >= 0
}

// devices are the reserved names Win32 maps to devices in any directory,
// with or without an extension
var devices = map[string]bool{"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true}

// IsDevice reports whether a name (trailing dots and spaces already removed)
// is a reserved device name: CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM0-9 and
// LPT0-9 (including the superscript digits ¹²³), with any extension
func IsDevice(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToLower(strings.TrimRight(base, " "))
	if devices[base] {
		return true
	}
	for _, p := range []string{"com", "lpt"} {
		if d, ok := strings.CutPrefix(base, p); ok {
			switch d {
			case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
				return true
			}
		}
	}
	return false
}

// FromGitBash turns a directory the harness gives in Git Bash's form, /c/x
// or /cygdrive/c/x, into the Windows path C:\x. Anything else is returned
// unchanged. Only for paths the harness sets (the environment, the hook
// input's cwd): a path the model chose in that form is refused instead
func FromGitBash(p string) string {
	rest, ok := strings.CutPrefix(p, "/")
	if !ok {
		return p
	}
	if r, ok := strings.CutPrefix(rest, "cygdrive/"); ok {
		rest = r
	}
	d, tail, _ := strings.Cut(rest, "/")
	if len(d) != 1 || !isLetter(d[0]) {
		return p
	}
	return strings.ToUpper(d) + `:\` + strings.ReplaceAll(tail, "/", `\`)
}

// SameDir reports whether two absolute Windows paths name the same
// directory as far as their spelling shows: NTFS ignores case
func SameDir(a, b string) bool {
	ca, errA := Abs(a)
	cb, errB := Abs(b)
	return errA == nil && errB == nil && strings.EqualFold(ca, cb)
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
