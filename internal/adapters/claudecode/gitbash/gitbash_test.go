package gitbash_test

import (
	"errors"
	"maps"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode/gitbash"
)

const gitFstab = `# For a description of the file format, see the Users Guide
# https://cygwin.com/cygwin-ug-net/using.html#mount-table

# DO NOT REMOVE NEXT LINE. It remove cygdrive prefix from path
none / cygdrive binary,posix=0,noacl,user 0 0
none /tmp usertemp binary,posix=0,noacl 0 0
`

func fakeEnv(env map[string]string, files map[string]string, gitOnPath string) gitbash.Env {
	return gitbash.Env{
		Getenv: func(k string) string { return env[k] },
		LookPath: func(string) (string, error) {
			if gitOnPath == "" {
				return "", errors.New("not found")
			}
			return gitOnPath, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if d, ok := files[p]; ok {
				return []byte(d), nil
			}
			return nil, errors.New("no such file")
		},
		Exists: func(p string) bool { _, ok := files[p]; return ok },
	}
}

const root = `C:\Program Files\Git`

func gitFiles(fstab string) map[string]string {
	return map[string]string{root + `\usr\bin\bash.exe`: "", root + `\etc\fstab`: fstab}
}

func TestMounts(t *testing.T) {
	want := map[string]string{
		"/": root, "/usr/bin": root + `\usr\bin`, "/usr/lib": root + `\usr\lib`, "/bin": root + `\usr\bin`,
		"/tmp": `C:\Users\dev\AppData\Local\Temp`,
	}
	env := map[string]string{"TEMP": `C:\Users\dev\AppData\Local\Temp`}
	for _, tc := range []struct {
		name string
		env  map[string]string
		git  string
	}{
		{"git on PATH (cmd)", env, root + `\cmd\git.exe`},
		{"git on PATH (mingw64)", env, root + `\mingw64\bin\git.exe`},
		{"CLAUDE_CODE_GIT_BASH_PATH (bin)", map[string]string{"TEMP": env["TEMP"], "CLAUDE_CODE_GIT_BASH_PATH": root + `\bin\bash.exe`}, ""},
		{"CLAUDE_CODE_GIT_BASH_PATH (usr/bin)", map[string]string{"TEMP": env["TEMP"], "CLAUDE_CODE_GIT_BASH_PATH": root + `/usr/bin/bash.exe`}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gitbash.Mounts(fakeEnv(tc.env, gitFiles(gitFstab), tc.git))
			if err != nil || !maps.Equal(got, want) {
				t.Fatalf("Mounts = %v, %v; want %v", got, err, want)
			}
		})
	}
}

func TestMountsUserTable(t *testing.T) {
	files := gitFiles(gitFstab)
	files[root+`\etc\fstab.d\dev`] = `D:/Data\040Sets /data ntfs binary 0 0`
	got, err := gitbash.Mounts(fakeEnv(map[string]string{"USERNAME": "dev"}, files, root+`\cmd\git.exe`))
	if err != nil || got["/data"] != `D:/Data Sets` || got["/tmp"] != "" {
		t.Fatalf("Mounts = %v, %v", got, err)
	}
	if _, ok := got["/tmp"]; !ok {
		t.Error("/tmp with an unknown temp directory must stay in the table (as unknown)")
	}
}

func TestMountsErrors(t *testing.T) {
	for name, e := range map[string]gitbash.Env{
		"no git":               fakeEnv(nil, gitFiles(gitFstab), ""),
		"no bash.exe":          fakeEnv(nil, map[string]string{root + `\etc\fstab`: gitFstab}, root+`\cmd\git.exe`),
		"no fstab":             fakeEnv(nil, map[string]string{root + `\usr\bin\bash.exe`: ""}, root+`\cmd\git.exe`),
		"other cygdrive":       fakeEnv(nil, gitFiles("none /mnt cygdrive binary 0 0"), root+`\cmd\git.exe`),
		"relative mount point": fakeEnv(nil, gitFiles(`C:\x tmp binary 0 0`), root+`\cmd\git.exe`),
		"device not a drive":   fakeEnv(nil, gitFiles(`\\server\share /s binary 0 0`), root+`\cmd\git.exe`),
		"short line":           fakeEnv(nil, gitFiles(`none /x`), root+`\cmd\git.exe`),
		"unknown option":       fakeEnv(nil, gitFiles(`D:/Data /data ntfs binary,unknown 0 0`), root+`\cmd\git.exe`),
		"bind option":          fakeEnv(nil, gitFiles(`D:/Data /data ntfs bind 0 0`), root+`\cmd\git.exe`),
	} {
		if got, err := gitbash.Mounts(e); err == nil {
			t.Errorf("%s: Mounts = %v, want an error", name, got)
		}
	}
}

func TestMountPrecedence(t *testing.T) {
	temp := `C:\Users\dev\AppData\Local\Temp`
	for _, tc := range []struct {
		name, system, user, point, want string
	}{
		{"immutable root", "D:/Safe / ntfs binary 0 0\n", "", "/", root},
		{"explicit root override", "D:/Root / ntfs binary,override 0 0\n", "", "/", "D:/Root"},
		{"bin follows root override", "D:/Root / ntfs binary,override 0 0\n", "", "/bin", `D:/Root\usr\bin`},
		{"usr follows root override", "D:/Root / ntfs binary,override 0 0\n", "", "/usr/lib", `D:/Root\usr\lib`},
		{"system beats user", "D:/Protected /shared ntfs binary,nouser 0 0\n", "D:/Safe /shared ntfs binary 0 0\n", "/shared", "D:/Protected"},
		{"user cannot claim system", "D:/Protected /shared ntfs binary 0 0\n", "D:/Safe /shared ntfs binary,nouser,override 0 0\n", "/shared", "D:/Protected"},
		{"user mount may be replaced", "D:/First /shared ntfs binary,user 0 0\n", "D:/Second /shared ntfs binary 0 0\n", "/shared", "D:/Second"},
		{"system cannot replace user", "D:/First /shared ntfs binary,user 0 0\nD:/Second /shared ntfs binary,nouser 0 0\n", "", "/shared", "D:/First"},
		{"same class replaces", "D:/First /shared ntfs binary 0 0\nD:/Second /shared ntfs binary 0 0\n", "", "/shared", "D:/Second"},
		{"user cannot replace tmp", "", "D:/Safe /tmp ntfs binary,override 0 0\n", "/tmp", temp},
		{"system cannot replace immutable tmp", "D:/Safe /tmp ntfs binary 0 0\n", "", "/tmp", temp},
		{"system can explicitly override tmp", "D:/New /tmp ntfs binary,override 0 0\n", "", "/tmp", "D:/New"},
		{"override keeps immutable flag", "D:/New /tmp ntfs binary,override 0 0\nD:/Other /tmp ntfs binary 0 0\n", "", "/tmp", "D:/New"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := gitFiles(gitFstab + tc.system)
			files[root+`\etc\fstab.d\dev`] = tc.user
			got, err := gitbash.Mounts(fakeEnv(map[string]string{"USERNAME": "dev", "TEMP": temp}, files, root+`\cmd\git.exe`))
			if err != nil || got[tc.point] != tc.want {
				t.Fatalf("mount %s = %q, error %v; want %q", tc.point, got[tc.point], err, tc.want)
			}
		})
	}
}

func TestTempDirectoryPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"TMP first", map[string]string{"TMP": `C:\Tmp`, "TEMP": `D:\Temp`, "USERPROFILE": `C:\Users\dev`}, `C:\Tmp`},
		{"TEMP fallback", map[string]string{"TEMP": `D:\Temp`, "USERPROFILE": `C:\Users\dev`}, `D:\Temp`},
		{"profile fallback", map[string]string{"USERPROFILE": `C:\Users\dev`}, `C:\Users\dev`},
		{"Windows fallback", nil, `C:\Windows`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeEnv(tc.env, gitFiles(gitFstab), root+`\cmd\git.exe`)
			e.WindowsDir = func() (string, error) {
				if tc.name != "Windows fallback" {
					t.Error("Windows directory queried despite an environment override")
				}
				return `C:\Windows`, nil
			}
			got, err := gitbash.Mounts(e)
			if err != nil || got["/tmp"] != tc.want {
				t.Fatalf("/tmp = %q, error %v; want %q", got["/tmp"], err, tc.want)
			}
		})
	}
	// An unavailable fallback stays unknown, so the engine refuses paths through it
	e := fakeEnv(nil, gitFiles(gitFstab), root+`\cmd\git.exe`)
	e.WindowsDir = func() (string, error) { return "", errors.New("unavailable") }
	if got, err := gitbash.Mounts(e); err != nil || got["/tmp"] != "" {
		t.Fatalf("unknown temporary directory: mounts %v, error %v", got, err)
	}
}
