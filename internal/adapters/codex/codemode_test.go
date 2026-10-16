package codex

import (
	"testing"
)

// Scripts in the form Codex 0.155 writes them in code mode
func TestCallFromScriptCaptured(t *testing.T) {
	for _, tc := range []struct{ src, cmd, workdir string }{
		{"const r = await tools.exec_command({cmd:\"ls\",max_output_tokens:2000});\ntext(r.output);\n", "ls", ""},
		{"const r = await tools.exec_command({cmd:\"pwd\",workdir:\"src\",max_output_tokens:1000});\ntext(r.output);\n", "pwd", "src"},
		{"const a = await tools.exec_command({\"cmd\": \"cat .env\", \"workdir\": \"/abs\"})\nconst b = await tools.apply_patch(\"*** Begin Patch\\n*** End Patch\")\ntext(JSON.stringify(a))", "cat .env", "/abs"},
		{"await tools.exec_command({cmd:\"ls\",workdir:\"a\"}); await tools.exec_command({cmd:\"ls\",workdir:\"a\"});", "ls", "a"},
		{"const r = await tools.exec_command({cmd:\"cat .env\"});\ntext(r.output);\ntext(`exit_code=${r.exit_code}`);\n", "cat .env", ""},
		{"const r = await tools.exec_command({cmd:\"ls\"}); text(\"out: \" + r.output + `!`)", "ls", ""},
	} {
		call, err := callFromScript(tc.src, tc.cmd)
		if err != nil {
			t.Errorf("%q: %v", tc.src, err)
			continue
		}
		if deref(call.Workdir) != tc.workdir || call.Cmd != tc.cmd {
			t.Errorf("%q: got %+v", tc.src, call)
		}
	}
}

// Anything but straight-line literal calls is untrusted: a script could
// otherwise show a decoy call while running another
func TestCallFromScriptRejects(t *testing.T) {
	for name, src := range map[string]string{
		"aliased tools":          "const t = tools; await t.exec_command({cmd:\"ls\"});",
		"computed workdir":       "const w = \"src\"; await tools.exec_command({cmd:\"ls\",workdir:w});",
		"computed command":       "await tools.exec_command({cmd:\"l\"+\"s\"});",
		"dead-code decoy":        "if (false) { await tools.exec_command({cmd:\"ls\",workdir:\"src\"}); }",
		"loop":                   "for (const d of [\"a\"]) await tools.exec_command({cmd:\"ls\"});",
		"spread":                 "await tools.exec_command({cmd:\"ls\",...{workdir:\"/root\"}});",
		"duplicate key":          "await tools.exec_command({cmd:\"ls\",workdir:\"src\",workdir:\"/root\"});",
		"comment":                "// hi\nawait tools.exec_command({cmd:\"ls\"});",
		"single quotes":          "await tools.exec_command({cmd:'ls'});",
		"template literal":       "await tools.exec_command({cmd:`ls`});",
		"JS-only escape":         "await tools.exec_command({cmd:\"l\\x73\"});",
		"bracket access":         "await tools[\"exec_command\"]({cmd:\"ls\"});",
		"two ways":               "await tools.exec_command({cmd:\"ls\",workdir:\"a\"}); await tools.exec_command({cmd:\"ls\",workdir:\"b\"});",
		"two ways, same text":    "await tools.exec_command({cmd:\"ls\",workdir:\"/w\",shell:\"/bin/sh\"}); await tools.exec_command({cmd:\"ls\",workdir:\"/w/bin/sh\"});",
		"no matching call":       "await tools.exec_command({cmd:\"pwd\"});",
		"non-string workdir":     "await tools.exec_command({cmd:\"ls\",workdir:1});",
		"two arguments":          "await tools.exec_command({cmd:\"ls\"},{workdir:\"a\"});",
		"not awaited":            "tools.exec_command({cmd:\"ls\"});",
		"other statement":        "await tools.exec_command({cmd:\"ls\"}); globalThis.x = 1;",
		"unterminated string":    "await tools.exec_command({cmd:\"ls});",
		"call inside text":       "text(await tools.exec_command({cmd:\"ls\"}));",
		"expression in template": "await tools.exec_command({cmd:\"ls\"}); text(`${tools.exec_command({cmd:\"ls\"})}`);",
		"unterminated template":  "await tools.exec_command({cmd:\"ls\"}); text(`x);",
		"deep nesting":           "await tools.exec_command({cmd:\"ls\",x:[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]});",
		"mis-cased key":          "await tools.exec_command({cmd:\"ls\",workdir:\"/root\",Workdir:null});",
		"key equal when folded":  "await tools.exec_command({cmd:\"ls\",workdir:\"/root\",\"wor\u212adir\":null});",
	} {
		if call, err := callFromScript(src, "ls"); err == nil {
			t.Errorf("%s: trusted, got %+v", name, call)
		}
	}
}

// FuzzCallFromScript: no script panics the parser, and a trusted call always
// has the command asked for
func FuzzCallFromScript(f *testing.F) {
	f.Add("const r = await tools.exec_command({cmd:\"ls\",workdir:\"src\"});\ntext(r.output);\n", "ls")
	f.Add("await tools.apply_patch(\"x\"); text(JSON.stringify(r))", "x")
	f.Add("await tools.exec_command({\"cmd\":\"a\\u0041\",x:[1,{y:null}]})", "aA")
	f.Fuzz(func(t *testing.T, src, cmd string) {
		call, err := callFromScript(src, cmd)
		if err == nil && call.Cmd != cmd {
			t.Fatalf("trusted a call for %q, asked for %q", call.Cmd, cmd)
		}
	})
}

// A terminal requested by any matching call in a script counts
func TestCallFromScriptTty(t *testing.T) {
	for _, c := range []struct {
		src string
		tty bool
	}{
		{`await tools.exec_command({cmd:"more x",tty:true});`, true},
		{`await tools.exec_command({cmd:"more x"});`, false},
		{`await tools.exec_command({cmd:"more x",tty:true}); await tools.exec_command({cmd:"more x"});`, true},
		{`await tools.exec_command({cmd:"more x"}); await tools.exec_command({cmd:"more x",tty:true});`, true},
	} {
		call, err := callFromScript(c.src, "more x")
		if err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got := call.Tty != nil && *call.Tty; got != c.tty {
			t.Errorf("%s: tty %v, want %v", c.src, got, c.tty)
		}
	}
}
