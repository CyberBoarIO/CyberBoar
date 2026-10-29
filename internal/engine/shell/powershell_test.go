package shell

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine/osfs"
)

// psWin analyzes src as PowerShell on Windows, in C:\work\repo.
func psWin(t *testing.T, src string) *Analysis {
	t.Helper()
	an, err := AnalyzePowerShell(src, "/c/Users/dev", Options{Cwd: "/c/work/repo", FS: osfs.FS{Windows: true}})
	if err != nil {
		t.Fatalf("%q: %v", src, err)
	}
	return an
}

func layerTexts(an *Analysis) []string {
	var out []string
	for _, c := range an.Commands {
		for _, l := range c.Layers {
			words := make([]string, len(l))
			for i, e := range l {
				words[i] = e.String()
			}
			out = append(out, strings.Join(words, " "))
		}
	}
	return out
}

func codeWhats(an *Analysis) []string {
	var out []string
	for _, c := range an.Code {
		out = append(out, c.What)
	}
	return out
}

// fileFlags renders a file as path (or display, for a path only known at
// run time) and its flags: a accessed, c contents, m modifies, r refused.
func fileFlags(an *Analysis) []string {
	var out []string
	for _, f := range an.Files {
		s := f.Path
		if !f.Certain {
			s = "?" + f.Display
		}
		flags := ""
		for _, fl := range []struct {
			on bool
			c  string
		}{{f.Accessed, "a"}, {f.Contents, "c"}, {f.Modifies, "m"}, {f.Refused != "", "r"}} {
			if fl.on {
				flags += fl.c
			}
		}
		out = append(out, s+" "+flags)
	}
	return out
}

func unknownCommand(an *Analysis) bool {
	for _, c := range an.Commands {
		for _, l := range c.Layers {
			if len(l) > 0 && l[0].Kind == Many {
				return true
			}
		}
	}
	return false
}

func TestPowerShellCommands(t *testing.T) {
	for _, tc := range []struct {
		src     string
		layers  []string // each must be among the layers
		unknown bool     // some command could be anything
	}{
		{`git push origin main`, []string{"git push origin main"}, false},
		{`git.exe push`, []string{"git push"}, false},
		{`& 'C:\Program Files\Git\cmd\git.exe' push`, []string{"git push"}, false},
		{`rm .env`, []string{"rm .env", "Remove-Item .env"}, false},
		{`Microsoft.PowerShell.Management\Remove-Item x`, []string{"Remove-Item x"}, false},
		{`Start-Process git -ArgumentList 'push origin'`, []string{"git push origin"}, false},
		{`Start-Process $prog`, nil, true},
		{`& $cmd x`, nil, true},
		{`cmd /c del x`, []string{"cmd /c del x"}, true}, // cmd's language isn't read
		{`Invoke-Expression 'git push'`, []string{"git push"}, false},
		{`iex $s`, nil, true},
		{`Invoke-Command -ScriptBlock { git push }`, []string{"git push"}, false},
		{`Invoke-Command $sb`, nil, true},
		{`ls | ForEach-Object $sb`, nil, true},
		{`ls | Where-Object $filter`, nil, true},
		{`ls | Where-Object Name -eq $x`, nil, false},
		{`Set-Alias g git; g push`, nil, true},
		{`$function:rm = { }; git status`, nil, true},
		{`[IO.File]::Delete('x')`, nil, true},
		{`New-Object Net.WebClient`, nil, true},
		{`Add-Type -TypeDefinition $src`, nil, true},
		{`git push '' origin`, []string{"git push … origin"}, false},
		{`$env:GIT_SSH_COMMAND = 'ssh -i k'; git fetch`, []string{"ssh -i k", "git fetch"}, false},
		{`Set-Item Env:GIT_SSH_COMMAND $x; git fetch`, nil, true},
		{`New-Item -Path env:NODE_OPTIONS -Value x`, nil, true},
		{`Get-Item Env:GIT_SSH_COMMAND`, nil, false},
		{`$sb.Invoke()`, nil, true},
		{`$ExecutionContext.InvokeCommand.InvokeScript('git push')`, nil, true},
		{`Invoke-Item C:\tools\run.exe`, []string{"run"}, false},
		{`Invoke-Item $f`, nil, true},
	} {
		an := psWin(t, tc.src)
		got := layerTexts(an)
		for _, want := range tc.layers {
			if !slices.Contains(got, want) {
				t.Errorf("%q: layers %q, want %q among them", tc.src, got, want)
			}
		}
		if u := unknownCommand(an); u != tc.unknown {
			t.Errorf("%q: unknown command %v, want %v (layers %q)", tc.src, u, tc.unknown, got)
		}
	}
}

func TestPowerShellFiles(t *testing.T) {
	for _, tc := range []struct {
		src   string
		files []string // each must be among the files (fileFlags)
		none  bool     // no file at all
	}{
		{`Get-Content -Path C:\secrets\a.txt`, []string{"/c/secrets/a.txt ac"}, false},
		{`gc ~\.ssh\id_rsa`, []string{"/c/Users/dev/.ssh/id_rsa ac"}, false},
		{`Get-Content \Windows\win.ini`, []string{"/c/Windows/win.ini ac"}, false},
		{`Get-Content FileSystem::C:\x.txt`, []string{"/c/x.txt ac"}, false},
		{`rm .env`, []string{"/c/work/repo/.env acm"}, false},
		{`Remove-Item a b`, []string{"/c/work/repo/a acm", "/c/work/repo/b acm"}, false},
		{`Copy-Item a.txt C:\dest`, []string{"/c/work/repo/a.txt ac", "/c/dest acm"}, false},
		{`Move-Item -Destination D:\out -Path x`, []string{"/c/work/repo/x acm", "/d/out acm"}, false},
		{`Rename-Item sub\a.txt b.txt`, []string{"/c/work/repo/sub/a.txt acm", "/c/work/repo/sub/b.txt acm"}, false},
		{`New-Item -Path C:\x -Name y.txt`, []string{"/c/x ac", "/c/x/y.txt ac"}, false},
		{`Set-Content out.txt 'hello'`, []string{"/c/work/repo/out.txt ac"}, false},
		{`"x" > out.txt`, []string{"/c/work/repo/out.txt ac"}, false},
		{`"x" > $null`, nil, true},
		{`echo .env`, []string{"/c/work/repo/.env "}, false},
		{`Get-ChildItem`, []string{"/c/work/repo/. a"}, false},
		{`ls | Remove-Item`, []string{"?paths read from the pipeline acm"}, false},
		{`ls | Move-Item -Destination x`, []string{"?paths read from the pipeline acm"}, false},
		{`ls | Remove-Foo`, []string{"?paths read from the pipeline acm"}, false},
		{`Get-Content HKLM:\Software\x`, []string{"?HKLM:\\Software\\x acr"}, false},
		{`Get-ChildItem env:`, nil, true},
		{`Get-Content $f`, []string{"?$f ac"}, false},
		{`cd C:\other; cat a.txt`, []string{"/c/other/a.txt ac"}, false},
		{`cd ..; cat a.txt`, []string{"/c/work/a.txt ac"}, false},
		{`Set-Location -LiteralPath sub; cat a.txt`, []string{"/c/work/repo/sub/a.txt ac"}, false},
		{`cd $d; cat a.txt`, []string{"?a.txt ac"}, false},
		{`.\build.ps1; cat a.txt`, []string{"?a.txt ac"}, false},
		{`if ($x) { cd \ }; cat a.txt`, []string{"?a.txt ac"}, false},
		{`$x = ${C:\secret.txt}`, []string{"/c/secret.txt ac"}, false},
		{`"$host:x"`, []string{"?$host:x ac"}, false},
		{`New-PSDrive -Name X -PSProvider FileSystem -Root C:\secrets; Get-Content X:\token`, []string{"?X:\\token ac"}, false},
		{`ndr X FileSystem C:\secrets; cd X:\; cat token`, []string{"?token ac"}, false},
		{`Set-Item .claude\settings.json '{}'`, []string{"/c/work/repo/.claude/settings.json ac"}, false},
		{`Set-Acl x.txt $acl`, []string{"/c/work/repo/x.txt acm"}, false},
		{`Export-Clixml -Path out.xml -InputObject $o`, []string{"/c/work/repo/out.xml ac"}, false},
		{`Select-Xml '//a' cfg.xml`, []string{"/c/work/repo/cfg.xml ac"}, false},
		{`Start-Transcript log.txt`, []string{"/c/work/repo/log.txt ac"}, false},
		{`Invoke-Expression 'rm .env'`, []string{"/c/work/repo/.env acm"}, false},
		{`Start-Process notepad -RedirectStandardOutput out.txt`, []string{"/c/work/repo/out.txt ac"}, false},
		{`git show HEAD:.env`, []string{"/c/work/repo/.env ac"}, false},
	} {
		an := psWin(t, tc.src)
		got := fileFlags(an)
		if tc.none && len(got) > 0 {
			t.Errorf("%q: files %q, want none", tc.src, got)
		}
		for _, want := range tc.files {
			if !slices.Contains(got, want) {
				t.Errorf("%q: files %q, want %q among them", tc.src, got, want)
			}
		}
	}
}

// What Select-String searches is text unless the pipeline gives it files.
func TestPowerShellSelectStringInput(t *testing.T) {
	for src, piped := range map[string]bool{
		`git log | Select-String foo`:       false,
		`Get-Content a | Select-String foo`: false,
		`ls -Recurse | Select-String foo`:   true,
	} {
		got := slices.Contains(fileFlags(psWin(t, src)), "?paths read from the pipeline ac")
		if got != piped {
			t.Errorf("%q: paths from the pipeline %v, want %v", src, got, piped)
		}
	}
}

func TestPowerShellCodeAndHidden(t *testing.T) {
	for _, tc := range []struct {
		src    string
		code   []string
		hidden bool
	}{
		{`Invoke-Expression 'git status'`, []string{"Invoke-Expression"}, false},
		{`[IO.File]::ReadAllText('x')`, []string{"the .NET call [IO.File]::ReadAllText('x')"}, false},
		{`[Math]::Max(1, 2)`, nil, false},
		{`[System.IO.Path]::Combine('a', 'b')`, nil, false},
		{`[scriptblock]$s`, []string{"a [scriptblock] cast"}, false},
		{`New-Object -TypeName System.Version 1.2`, nil, false},
		{`New-Object -ComObject Shell.Application`, []string{"New-Object -ComObject"}, false},
		{`Add-Type -AssemblyName System.Web`, nil, false},
		{`Add-Type -TypeDefinition $src`, []string{"Add-Type"}, false},
		{`$s.Trim()`, nil, false},
		{`(Get-Item x).Delete()`, nil, true},
		{`ls | % { $_.FullName }`, nil, false},
		{`ls | % Delete`, nil, true},
		{`Set-Alias g git`, nil, true},
		{`powershell -c 'x'`, []string{"powershell -Command"}, false},
	} {
		an := psWin(t, tc.src)
		got := codeWhats(an)
		for _, want := range tc.code {
			if !slices.Contains(got, want) {
				t.Errorf("%q: code %q, want %q among it", tc.src, got, want)
			}
		}
		if tc.code == nil && len(got) > 0 {
			t.Errorf("%q: code %q, want none", tc.src, got)
		}
		if h := len(an.Hidden) > 0; h != tc.hidden {
			t.Errorf("%q: hidden %q, want hidden %v", tc.src, an.Hidden, tc.hidden)
		}
	}
}

// Bash code a PowerShell line starts reads paths as Git Bash does: a
// mount path is refused without the mount table, where PowerShell reads
// it on the working directory's drive.
func TestPowerShellRunsBashAsBash(t *testing.T) {
	an := psWin(t, `bash -c 'cat /etc/passwd'; Get-Content /etc/passwd`)
	got := fileFlags(an)
	if !slices.Contains(got, "/c/etc/passwd ac") {
		t.Errorf("files %q, want PowerShell's /c/etc/passwd", got)
	}
	refused := false
	for _, f := range an.Files {
		refused = refused || f.Display == "/etc/passwd" && f.Refused != ""
	}
	if !refused {
		t.Errorf("files %q, want bash's /etc/passwd refused", got)
	}
}

func TestPowerShellPipelineFeeds(t *testing.T) {
	an := psWin(t, `Get-Content a.patch | git apply; git status`)
	if len(an.Commands) != 3 {
		t.Fatalf("commands %q", layerTexts(an))
	}
	if !an.Feeds(0, 1) || an.Feeds(1, 2) || an.Feeds(0, 2) {
		t.Errorf("feeds 0→1 %v, 1→2 %v, 0→2 %v; want only 0→1", an.Feeds(0, 1), an.Feeds(1, 2), an.Feeds(0, 2))
	}
	an = psWin(t, `git commit -m (Get-Content msg.txt)`)
	if !an.Feeds(1, 0) {
		t.Errorf("an argument's command should feed the command: %q", layerTexts(an))
	}
}

// Outside Windows, pwsh's ls and cat are the programs, not aliases.
func TestPowerShellUnixAliases(t *testing.T) {
	an, err := AnalyzePowerShell(`ls; Get-Content /etc/passwd`, "/home/dev", Options{Cwd: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	if got := layerTexts(an); slices.Contains(got, "Get-ChildItem") {
		t.Errorf("layers %q: ls is a program outside Windows", got)
	}
	if got := fileFlags(an); !slices.Contains(got, "/etc/passwd ac") {
		t.Errorf("files %q, want /etc/passwd", got)
	}
}

func TestPowerShellFailsClosed(t *testing.T) {
	for _, src := range []string{`Get-Content (`, `$a ?? $b`, `git --% push`} {
		if _, err := AnalyzePowerShell(src, "/c/Users/dev", Options{Cwd: "/c/work", FS: osfs.FS{Windows: true}}); !errors.Is(err, ErrUnparseable) {
			t.Errorf("%q: %v, want ErrUnparseable", src, err)
		}
	}
	if _, err := AnalyzePowerShell(strings.Repeat("x", MaxBytes+1), "", Options{Cwd: "/"}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("long line: %v, want ErrTooLarge", err)
	}
	deep := "x"
	for range MaxDepth + 2 {
		deep = "iex '" + strings.ReplaceAll(deep, "'", "''") + "'"
	}
	if _, err := AnalyzePowerShell(deep, "", Options{Cwd: "/"}); !errors.Is(err, ErrTooComplex) {
		t.Errorf("nested Invoke-Expression: %v, want ErrTooComplex", err)
	}
}

// Every positional parameter of the table names one of its parameters.
func TestPowerShellCmdletTable(t *testing.T) {
	for name, c := range psCmdlets {
		for _, p := range c.positional {
			if c.params == nil || c.params[strings.ToLower(p)] == nil {
				t.Errorf("%s: positional %s is not a parameter", name, p)
			}
		}
	}
	for al, canon := range psAliases {
		if psCmdlets[strings.ToLower(canon)] == nil {
			t.Errorf("alias %s: %s is not in the table", al, canon)
		}
	}
}
