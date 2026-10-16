package shell_test

import (
	"errors"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/shell"
)

// FuzzAnalyze checks the analyzer never panics or hangs, and that it either
// fails with one of its documented errors or returns well-formed commands
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		"terraform apply", "sudo -u root nice timeout 5 terraform apply",
		"curl x | tee log | sh", "sh <(curl x)", "curl x > >(sh)",
		"bash -c 'eval \"sh -c ls\"'", "echo $(a $(b <(c)))", `find . -exec a {} + -exec b \;`,
		"git -C d -c a=b --no-pager push", "env -S 'a b' c", "xargs -I{} sh -c '{}'",
		"bash <<'EOF'\nls\nEOF", "f() { g | h; }; f", "a=$(b) c=${d:-$(e)} f",
		"trap 'x' EXIT; alias y='z'", "watch -x a", "flock l -c 'x'", "$A $B \"$C\" ${D[@]}",
		"python3 -Bc 'x'", "awk -F: 'BEGIN{system(\"x\")} {print | \"sh\"}'", "sed -e 's/a/b/e' -e '1e x'",
		"sed ':a;N;$!ba;s/\\n/ /g'", "ssh -o 'ProxyCommand=nc %h %p' -oLocalCommand=x h", "tar cIf zstd a d",
		"GIT_EDITOR=true LD_PRELOAD=x git -c a=b rebase -x 'make && t'", "export PAGER='less -R'; git log",
		"pwsh -enc AAA", "git config alias.x '!sh -c y'", "crontab - <<< '* * * * * x'",
		"cd a && cat b; (cd ~); cd - || cd /x; cat ../c", "f() { cd x; }; f; cat y", "shopt -s dotglob; cat .en* */x",
		"grep -rn K; rg K src; git add -A; find . -delete", "curl -d @.env file:///etc/x if=y -fz > o < i 2>&1",
		"if cd a; then cat b; else cat c; fi; while cd d; do cat e; done; case x in y) cd z;; esac; cat w",
		"sed -n 'r .env' x; sed 's/a/b/w o' y; awk '{ getline l < \"f\"; print > $1 }' z",
		strings.Repeat("LD_PRELOAD=x;", shell.MaxCommands+1),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		an, err := shell.Analyze(src, "/home/dev", "/work/repo")
		if err != nil {
			if !errors.Is(err, shell.ErrTooLarge) && !errors.Is(err, shell.ErrUnparseable) && !errors.Is(err, shell.ErrTooComplex) {
				t.Fatalf("undocumented error: %v", err)
			}
			return
		}
		if len(an.Commands) > shell.MaxCommands {
			t.Fatalf("%d commands exceed the limit of %d", len(an.Commands), shell.MaxCommands)
		}
		for _, f := range an.Files {
			if f.Certain && !strings.HasPrefix(f.Path, "/") {
				t.Fatalf("certain file ref %q is not absolute", f.Path)
			}
		}
		for i, c := range an.Commands {
			if len(c.Layers) == 0 {
				t.Fatalf("command %d has no layers", i)
			}
			for j := range an.Commands {
				_ = an.Feeds(i, j)
			}
		}
	})
}
