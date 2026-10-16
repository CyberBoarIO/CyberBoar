package shell

import (
	"slices"
	"testing"

	"cyberboar.dev/cyberboar/internal/fold"
)

// Folded wrapper names must stay distinct, or one program would shadow another.
func TestWrapperNamesFoldUniquely(t *testing.T) {
	seen := map[string]string{}
	for name := range wrappers {
		f := fold.String(name)
		if other, dup := seen[f]; dup {
			t.Errorf("wrappers %q and %q fold to the same name %q", name, other, f)
		}
		seen[f] = name
	}
}

func TestPowerShellOptionValues(t *testing.T) {
	for _, tc := range []struct {
		src  string
		code bool
	}{
		{`pwsh -ExecutionPolicy Bypass -Command 'Write-Output ok'`, true},
		{`pwsh -ep Bypass -enc AAA`, true},
		{`pwsh -ex Bypass -c 'Write-Output ok'`, true},
		{`pwsh -OutputFormat Text -Command 'Write-Output ok'`, true},
		{`pwsh /ExecutionPolicy Bypass /Command 'Write-Output ok'`, true},
		{`pwsh ' -ExecutionPolicy ' Bypass ' -Command ' 'Write-Output ok'`, true},
		{"pwsh \u2013ExecutionPolicy Bypass \u2014Command 'Write-Output ok'", true},
		{"pwsh \u2015Command 'Write-Output ok'", true},
		{`pwsh -of Text -c 'Write-Output ok'`, true},
		{`pwsh -InputFormat Text -Command 'Write-Output ok'`, true},
		{`pwsh -if Text -c 'Write-Output ok'`, true},
		{`pwsh -WorkingDirectory /work -Command 'Write-Output ok'`, true},
		{`pwsh -wd /work -cwa 'Write-Output ok'`, true},
		{`powershell -Version 5.1 -ExecutionPolicy Bypass -Command 'Write-Output ok'`, true},
		{`pwsh -FutureOption value -Command 'Write-Output ok'`, true},
		{`pwsh -ExecutionPolicy "$P" -File ./build.ps1`, true},
		{`pwsh -ExecutionPolicy`, true},
		{`pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ./build.ps1`, false},
		{`pwsh -nop -of Text ./build.ps1`, false},
		{`pwsh /work/build.ps1`, false},
		{`pwsh -File ./build.ps1 -Command script-argument`, false},
		{`powershell -ExecutionPolicy Bypass -File ./build.ps1`, false},
		{`pwsh -Version`, false},
	} {
		t.Run(tc.src, func(t *testing.T) {
			an, err := Analyze(tc.src, "/home/dev", "/work/repo")
			if err != nil {
				t.Fatal(err)
			}
			if (len(an.Code) > 0) != tc.code {
				t.Errorf("inline code=%v, want %v: %+v", len(an.Code) > 0, tc.code, an.Code)
			}
		})
	}
}

func TestAwkEscapedFileNames(t *testing.T) {
	for _, tc := range []struct {
		prog string
		want Elem
	}{
		{`BEGIN {getline line < ".\145nv"}`, Elem{Kind: Lit, Text: ".env"}},
		{`BEGIN {print > "\056env"}`, Elem{Kind: Lit, Text: ".env"}},
		{`BEGIN {print >> "path\\name\"file"}`, Elem{Kind: Lit, Text: "path\\name\"file"}},
		{"BEGIN {getline line < \".\\\nenv\"}", Elem{Kind: Lit, Text: ".env"}},
		{`BEGIN {getline line < ".\x65nv"}`, Elem{Kind: Many, Text: "*"}},
		{`BEGIN {getline line < ".\qenv"}`, Elem{Kind: Many, Text: "*"}},
		{`BEGIN {getline line < ".\000env"}`, Elem{Kind: Many, Text: "*"}},
		{`BEGIN {getline line < ".\777env"}`, Elem{Kind: Many, Text: "*"}},
	} {
		t.Run(tc.prog, func(t *testing.T) {
			if got := awkFiles(tc.prog); !slices.Equal(got, []Elem{tc.want}) {
				t.Errorf("files=%+v, want %+v", got, tc.want)
			}
		})
	}
	if got := awkFiles(`BEGIN {print > "\057dev/stdout"}`); len(got) != 0 {
		t.Errorf("decoded stdout should remain a stream: %+v", got)
	}
}
