// Package gitbash reads the mount table of Git Bash (Git for Windows' MSYS2
// shell), which Claude Code on Windows runs commands in. The engine maps Git
// Bash's paths outside the drives (/, /tmp, /usr/bin) through it
// Anything it can't read exactly is an error, and the engine then refuses those paths
package gitbash

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

// Env is what Mounts needs from the machine
type Env struct {
	// Getenv returns the value of an environment variable, or ""
	Getenv func(string) string
	// LookPath finds an executable on PATH, as exec.LookPath does
	LookPath func(string) (string, error)
	// ReadFile reads a whole file.
	ReadFile func(string) ([]byte, error)
	// Exists reports whether a file exists
	Exists func(string) bool
	// WindowsDir returns the Windows directory, the last temporary-directory fallback
	WindowsDir func() (string, error)
}

// System returns the Env of the machine the caller runs on, with PATH and
// files as they are. Environment variables are read through getenv, so a
// caller reads the same ones as the hook
func System(getenv func(string) string) Env {
	return Env{
		Getenv:     getenv,
		LookPath:   exec.LookPath,
		ReadFile:   os.ReadFile,
		Exists:     func(p string) bool { _, err := os.Stat(p); return err == nil },
		WindowsDir: windowsDirectory,
	}
}

// Mounts returns Git Bash's mount table, which maps each mount point to a
// Windows directory, or to "" for a mount whose directory is unknown. Git's
// install directory comes from CLAUDE_CODE_GIT_BASH_PATH (the bash.exe Claude
// Code uses) or else from git.exe on PATH, as Claude Code finds it
func Mounts(e Env) (map[string]string, error) {
	root, err := installDir(e)
	if err != nil {
		return nil, err
	}
	// The automatic root is a system mount and requires override to replace it
	table := map[string]mountEntry{"/": {target: root, system: true, immutable: true}}
	temp := tempDirectory(e)
	data, err := e.ReadFile(root + `\etc\fstab`)
	if err != nil {
		return nil, fmt.Errorf("reading %s\\etc\\fstab: %v", root, err)
	}
	if err := parseFstab(data, table, temp, false); err != nil {
		return nil, fmt.Errorf("%s\\etc\\fstab: %v", root, err)
	}
	// MSYS2 adds /bin after reading the system table, unless it was explicit
	if _, present := table["/bin"]; !present {
		table["/bin"] = mountEntry{target: table["/"].target + `\usr\bin`, system: true}
	}
	// Cygwin also reads the user's own table
	if user := e.Getenv("USERNAME"); user != "" {
		name := root + `\etc\fstab.d\` + user
		if e.Exists(name) {
			data, err := e.ReadFile(name)
			if err != nil {
				return nil, err
			}
			if err := parseFstab(data, table, temp, true); err != nil {
				return nil, fmt.Errorf("%s: %v", name, err)
			}
		}
	}
	out := make(map[string]string, len(table)+2)
	for point, entry := range table {
		out[point] = entry.target
	}
	// These paths normally resolve through /, but explicit mounts take precedence
	for _, point := range []string{"/usr/bin", "/usr/lib"} {
		if _, present := out[point]; !present {
			out[point] = out["/"] + strings.ReplaceAll(point, "/", `\`)
		}
	}
	return out, nil
}

// tempDirectory follows GetTempPathW, which MSYS2 uses for usertemp mounts
func tempDirectory(e Env) string {
	for _, name := range []string{"TMP", "TEMP", "USERPROFILE"} {
		if dir := e.Getenv(name); dir != "" {
			return dir
		}
	}
	if e.WindowsDir != nil {
		dir, err := e.WindowsDir()
		if err == nil {
			return dir
		}
	}
	return ""
}

type mountEntry struct {
	target    string
	system    bool
	immutable bool
}

// installDir finds Git's install directory, the one holding usr\bin\bash.exe
func installDir(e Env) (string, error) {
	var candidates []string
	if bash := e.Getenv("CLAUDE_CODE_GIT_BASH_PATH"); bash != "" {
		dir := parent(bash)
		candidates = append(candidates, parent(dir), parent(parent(dir))) // bin\bash.exe, usr\bin\bash.exe
	} else if git, err := e.LookPath("git.exe"); err == nil {
		dir := parent(git)
		candidates = append(candidates, parent(dir), parent(parent(dir))) // cmd\ or bin\git.exe, mingw64\bin\git.exe
	}
	for _, c := range candidates {
		if c != "" && e.Exists(c+`\usr\bin\bash.exe`) {
			return c, nil
		}
	}
	return "", errors.New("the install directory of Git for Windows was not found (set CLAUDE_CODE_GIT_BASH_PATH)")
}

// parent returns a Windows path's directory, or "" at the top
func parent(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`)
	i := strings.LastIndex(p, `\`)
	if i <= 2 { // C:\ or no separator, so nothing is above the drive
		return ""
	}
	return p[:i]
}

// parseFstab applies a Cygwin fstab to table. Lines are "device mountpoint
// type options [dump pass]", with \040 for a space. A # starts a comment
func parseFstab(data []byte, table map[string]mountEntry, temp string, userTable bool) error {
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			return fmt.Errorf("line %d: too few fields", n+1)
		}
		device, point, typ := unescape(f[0]), path.Clean(unescape(f[1])), f[2]
		if !strings.HasPrefix(point, "/") {
			return fmt.Errorf("line %d: mount point %q is not absolute", n+1, point)
		}
		entry := mountEntry{target: device, system: true, immutable: typ == "usertemp"}
		override := false
		for _, option := range strings.Split(f[3], ",") {
			switch option {
			case "user":
				entry.system = false
			case "nouser":
				entry.system = true
			case "override":
				override = true
			case "acl", "auto", "binary", "cygexec", "dos", "exec", "ihash", "noacl", "nosuid", "notexec", "posix=0", "posix=1", "sparse", "text":
				// These options do not change the directory a mount names
			default:
				return fmt.Errorf("line %d: mount option %q is not supported", n+1, option)
			}
		}
		if userTable {
			entry.system = false
		}
		switch typ {
		case "cygdrive":
			// The engine reads /c and /cygdrive/c as drives. Another prefix
			// would make /c a path under Git's root
			if point != "/" && point != "/cygdrive" {
				return fmt.Errorf("line %d: cygdrive prefix %q is not supported", n+1, point)
			}
		case "usertemp":
			entry.target = temp // "" when the temp directory isn't known
		default:
			if len(device) < 3 || device[1] != ':' || (device[2] != '\\' && device[2] != '/') {
				return fmt.Errorf("line %d: %q is not a drive path", n+1, device)
			}
		}
		if typ == "cygdrive" {
			continue
		}
		if old, present := table[point]; present {
			if old.system != entry.system || old.immutable && !override {
				continue // MSYS2 rejects these overrides and retains the existing mount
			}
			entry.immutable = entry.immutable || old.immutable
		}
		table[point] = entry
	}
	return nil
}

// unescape decodes fstab's octal escapes (\040 is a space)
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) && isOctal(s[i+1:i+4]) {
			v := (s[i+1]-'0')*64 + (s[i+2]-'0')*8 + (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isOctal reports whether s is exactly three octal digits
func isOctal(s string) bool {
	if len(s) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return true
}
