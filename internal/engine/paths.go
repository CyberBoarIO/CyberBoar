package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/fold"
	"cyberboar.dev/cyberboar/internal/winpath"
)

// maxSymlinks matches Linux's MAXSYMLINKS. More links than this are treated as a loop
const maxSymlinks = 40

// absPath turns an action path into an absolute path WITHOUT cleaning it, so
// resolvePath can apply ".." after symlinks the way the kernel does
func absPath(p, cwd, home string) (string, error) {
	switch {
	case p == "~":
		return home, nil
	case strings.HasPrefix(p, "~/"):
		return home + p[1:], nil
	case strings.HasPrefix(p, "~"):
		return "", fmt.Errorf("path %q: only ~/ (the current user's home) is supported", p)
	case path.IsAbs(p):
		return p, nil
	default:
		return cwd + "/" + p, nil
	}
}

// resolvePath returns the path the kernel would reach for abs. It walks the
// components left to right and replaces a symlink by its target before it
// applies any ".." that follows. Cleaning the path first would be wrong,
// since for "link/../x" path.Clean yields the lexical parent, not the
// parent of the link's target
//
// Once a component does not exist, the rest is appended lexically, so the
// target of a write that creates new files still resolves
//
// On Windows the first component is the drive, ".." stops at the drive's
// root, link targets are Windows paths, junctions are links too, and every
// existing name is replaced by its long form, since it may be an 8.3 short
// name, which need not contain "~" (fsutil file setshortname)
func resolvePath(fsys osfs.FS, abs string) (string, error) {
	dest, _, err := resolveLinks(fsys, abs)
	return dest, err
}

// resolveLinks is resolvePath, and also returns the path the walk goes on
// with after each link it follows, which is the link's target joined with
// the rest. The built-in rules check these paths, since a link to
// /dev/stdin ends where the hook's own standard input is (/proc/self/fd/0,
// then a pipe or /dev/null), not where the agent's is
func resolveLinks(fsys osfs.FS, abs string) (dest string, hops []string, err error) {
	if !path.IsAbs(abs) {
		return "", nil, fmt.Errorf("%q is not absolute", abs)
	}
	pending := strings.Split(abs, "/")
	dest = "/"
	links := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if !fsys.Windows || !isDriveRoot(dest) {
				dest = path.Dir(dest)
			}
			continue
		}
		next := path.Join(dest, c)
		if fsys.Windows && strings.IndexFunc(c, forbidden) >= 0 {
			// No Windows program can open such a name, so the walk stops here.
			// Git Bash's programs open a different name, one the shell analyzer adds itself
			return path.Join(append([]string{next}, pending...)...), hops, nil
		}
		fi, err := fsys.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			return path.Join(append([]string{next}, pending...)...), hops, nil
		}
		if err != nil {
			return "", nil, err
		}
		if fsys.Windows && dest != "/" { // not the drive itself
			long, err := fsys.LongName(next)
			if err != nil {
				return "", nil, fmt.Errorf("the long name of %s: %v", next, err)
			}
			next = path.Join(dest, long)
		}
		if !isLink(fsys, fi) {
			dest = next
			continue
		}
		if links++; links > maxSymlinks {
			return "", nil, fmt.Errorf("more than %d symbolic links (loop?) at %s", maxSymlinks, next)
		}
		target, err := fsys.Readlink(next)
		if err != nil {
			if fi.Mode()&fs.ModeSymlink == 0 {
				// A reparse point that isn't a link (a OneDrive placeholder, an
				// app execution alias) is opened as the file itself
				dest = next
				continue
			}
			return "", nil, err
		}
		if fsys.Windows {
			drive, _, _ := osfs.SplitDrive(next)
			if target, _, err = winpath.Target(target, drive); err != nil {
				return "", nil, fmt.Errorf("the link %s: %v", next, err)
			}
		}
		if path.IsAbs(target) {
			dest = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
		hops = append(hops, path.Join(append([]string{dest}, pending...)...))
	}
	return dest, hops, nil
}

// isLink reports whether fi may be a link to follow. Windows reports
// junctions (mount points) as irregular files, not symlinks
func isLink(fsys osfs.FS, fi fs.FileInfo) bool {
	m := fi.Mode()
	return m&fs.ModeSymlink != 0 || fsys.Windows && m&fs.ModeIrregular != 0
}

// forbidden reports whether r is a character Win32 forbids in a file name.
// #nosec G115 -- r < 0x80, so it fits in a byte
func forbidden(r rune) bool { return r < 0x80 && winpath.Forbidden(byte(r)) }

// isDriveRoot reports whether p is a Windows drive's root, /x
func isDriveRoot(p string) bool {
	_, rest, ok := osfs.SplitDrive(p)
	return ok && rest == ""
}

// cleanPath is path.Clean, except that on Windows ".." stops at the drive's root, as it does at "/"
func cleanPath(p string, windows bool) string {
	if windows {
		if drive, rest, ok := osfs.SplitDrive(p); ok {
			return strings.TrimSuffix("/"+drive+path.Clean("/"+rest), "/")
		}
	}
	return path.Clean(p)
}

// globEscape escapes doublestar metacharacters so a literal path (a home or workspace root) can be joined with a pattern
func globEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`*?[]{}\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isSameOrAncestor reports whether dir is p or one of p's ancestors, folded
// (a case-insensitive filesystem makes /HOME/dev the home directory)
func isSameOrAncestor(dir, p string) bool {
	dir, p = fold.String(dir), fold.String(p)
	return dir == "/" || dir == p || strings.HasPrefix(p, dir+"/")
}

// appendUnique appends the values not already in list
func appendUnique(list []string, vs ...string) []string {
	for _, v := range vs {
		dup := false
		for _, have := range list {
			if have == v {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, v)
		}
	}
	return list
}

// repoRoot returns the git work tree that holds p, which is the nearest
// directory at or above it with a .git entry, or p itself when there is none
func repoRoot(fsys osfs.FS, p string) string {
	d, err := resolvePath(fsys, p)
	if err != nil {
		return p // checkPath denies it as unresolvable
	}
	for {
		if _, err := fsys.Lstat(path.Join(d, ".git")); err == nil {
			return d
		}
		up := path.Dir(d)
		if up == d {
			return p
		}
		d = up
	}
}
