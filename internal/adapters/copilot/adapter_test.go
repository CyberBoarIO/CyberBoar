package copilot

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/engine"
)

var update = flag.Bool("update", false, "rewrite golden files")

const testdata = "testdata"

// Every input captured from a real Copilot CLI run maps cleanly: known tool,
// well-formed input
func TestCapturedInputs(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "captured-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no captured inputs")
	}
	root := filepath.ToSlash(t.TempDir())
	env := Env{ProjectDir: root, Home: "/home/dev"}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.ReplaceAll(line, "{{root}}", root)
			in, err := ParseInput([]byte(line))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(name), i+1, err)
				continue
			}
			if _, err := Actions(in, env); err != nil {
				t.Errorf("%s:%d: %s: %v", filepath.Base(name), i+1, in.ToolName, err)
			}
		}
	}
}

// view lists a directory and reads anything else, so the action depends on
// what the path names on disk. A path that doesn't exist is read
func TestViewListsDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the adapter's path resolution takes POSIX absolute paths")
	}
	root := filepath.ToSlash(t.TempDir())
	if err := os.Mkdir(root+"/proj", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/proj/README.md", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := Env{ProjectDir: root, Home: "/home/dev"}
	for path, want := range map[string]engine.Tool{
		root + "/proj":           engine.ToolList,
		root + "/proj/README.md": engine.ToolRead,
		root + "/proj/missing":   engine.ToolRead,
	} {
		line, err := json.Marshal(map[string]any{"sessionId": "s", "cwd": root, "toolName": "view", "toolArgs": map[string]string{"path": path}})
		if err != nil {
			t.Fatal(err)
		}
		in, err := ParseInput(line)
		if err != nil {
			t.Fatal(err)
		}
		acts, err := Actions(in, env)
		if err != nil || len(acts) != 1 || acts[0].Tool != want {
			t.Errorf("view %s: %+v, %v; want %s", path, acts, err, want)
		}
	}
}

// Every tool a captured Copilot CLI offers the model is classified, so a new
// tool shows up here before it reaches a user
func TestCapturedToolsClassified(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "tools-*.json"))
	if len(files) == 0 {
		t.Fatal("no captured tool lists")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var list struct{ Tools []string }
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		tools, _ := classification()
		for _, tool := range list.Tools {
			if _, ok := tools[tool]; !ok {
				t.Errorf("%s: tool %s is not classified in tools.yaml", filepath.Base(f), tool)
			}
		}
	}
}

func TestSQLFileAccess(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.DateTime + ".000")
	for _, tc := range []struct {
		dialect, q string
		unsafe     bool
	}{
		{"sqlite", "SELECT * FROM todos WHERE status = 'done'", false},
		{"sqlite", "INSERT INTO todos (id, title) VALUES ('a', 'fix config.json')", false}, // SQLite doesn't read file names
		{"sqlite", "CREATE TABLE notes (id TEXT, body TEXT)", false},
		{"sqlite", "attach 'x.db' as x", true},
		{"sqlite", "ATTACH\tDATABASE ':memory:' AS m", true},
		{"sqlite", "VACUUM INTO '/tmp/x'", true},
		{"sqlite", "select load_extension('/tmp/x.so')", true},
		{"sqlite", "select writefile('/tmp/x', 'y')", true},
		{"sqlite", "select edit ('a')", true},
		{"sqlite", "PRAGMA temp_store_directory = '/tmp'", true},
		{"duckdb", "SELECT id FROM sessions WHERE updated_at > '" + timestamp + "'", false},
		{"duckdb", "SELECT * FROM read_csv_auto('x')", true},
		{"duckdb", "SELECT * FROM parquet_scan('x')", true},
		{"duckdb", "SELECT * FROM 'data.csv'", true},
		{"duckdb", `SELECT * FROM "/etc/passwd"`, true},
		{"duckdb", "SELECT * FROM '~/x'", true},
		{"duckdb", "COPY t TO 'x'", true},
		{"duckdb", "INSTALL httpfs", true},
		{"duckdb", "SELECT * FROM glob('*')", true},
		{"duckdb", "EXPORT DATABASE 'dir'", true},
		{"duckdb", "SELECT * FROM query('SELECT 1')", true},
		{"duckdb", `SELECT * FROM "QuErY"/* comment */('SELECT 1')`, true},
		{"duckdb", "SELECT * FROM main.query('SELECT 1')", true},
		{"duckdb", "SELECT * FROM query_table('ses' || 'sions')", true},
		{"duckdb", "SELECT query_text FROM sessions", false},
	} {
		if got := sqlFileAccess(tc.dialect, tc.q) != ""; got != tc.unsafe {
			t.Errorf("%s %q: unsafe %v, want %v", tc.dialect, tc.q, got, tc.unsafe)
		}
	}
}

func TestMCPSplits(t *testing.T) {
	got, err := mcpActions("a-b-c", engine.Action{})
	if err != nil || len(got) != 2 || got[0].MCP != (engine.MCPCall{Server: "a", Tool: "b-c", Names: engine.NamesCopilot}) || got[1].MCP != (engine.MCPCall{Server: "a-b", Tool: "c", Names: engine.NamesCopilot}) {
		t.Errorf("a-b-c: %+v, %v", got, err)
	}
	for _, bad := range []string{"-x", "x-", "-"} {
		if _, err := mcpActions(bad, engine.Action{}); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// Generated configuration is reviewed as diffs of golden files
func TestHooksFileGolden(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    FragmentOptions
	}{
		{"managed-hooks.json", FragmentOptions{Scope: ScopeManaged, Command: "/usr/local/bin/cyberboar", Policy: "/etc/cyberboar/policy.yaml",
			Audit: "/var/log/cyberboar/audit.jsonl", PubKey: "/etc/cyberboar/policy.pub", Deadline: "5s", Briefing: true}},
		{"project-hooks.json", FragmentOptions{Scope: ScopeProject, Command: "cyberboar", Policy: ".cyberboar/policy.yaml", Deadline: "5s"}},
	} {
		out, err := HooksFile(tc.o)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(testdata, "apply", tc.name)
		if *update {
			os.MkdirAll(filepath.Dir(path), 0o755)
			os.WriteFile(path, out, 0o644)
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -update)", err)
		}
		if string(out) != string(want) {
			t.Errorf("output differs from %s (run go test -update and review the diff):\n%s", tc.name, out)
		}
	}
}

func TestSessionStartOutput(t *testing.T) {
	if out := (Adapter{}).SessionStartOutput(""); out != nil {
		t.Errorf("empty text: %q", out)
	}
	var got struct {
		AdditionalContext  string
		HookSpecificOutput map[string]string
	}
	err := json.Unmarshal((Adapter{}).SessionStartOutput("hi"), &got)
	if err != nil || got.AdditionalContext != "hi" ||
		len(got.HookSpecificOutput) != 2 || got.HookSpecificOutput["hookEventName"] != "SessionStart" || got.HookSpecificOutput["additionalContext"] != "hi" {
		t.Errorf("got %+v, %v", got, err)
	}
}

// Every input captured from VS Code's Local agent maps cleanly: known tool,
// well-formed input. The tools denied on purpose (RuleUncheckedTool) count as known
func TestCapturedVSCodeInputs(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "vscode-captured-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no captured inputs")
	}
	root := filepath.ToSlash(t.TempDir())
	env := Env{Home: "/home/dev"}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.ReplaceAll(line, "{{root}}", root)
			in, err := ParseInput([]byte(line))
			if err != nil || !in.Local() {
				t.Errorf("%s:%d: not a Local agent input: %v", filepath.Base(name), i+1, err)
				continue
			}
			if _, err := VSCodeActions(in, env); err != nil {
				if ae, ok := err.(*adapters.Error); !ok || ae.Rule != RuleUncheckedTool {
					t.Errorf("%s:%d: %s: %v", filepath.Base(name), i+1, *in.ToolNameVSCode, err)
				}
			}
		}
	}
}

// Every built-in tool a captured VS Code offers the model is classified, so
// a new tool shows up here before it reaches a user. Extensions' tools are
// denied as unclassified, and MCP tools read as MCP tools
func TestCapturedVSCodeToolsClassified(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(testdata, "vscode-tools-*.json"))
	if len(files) == 0 {
		t.Fatal("no captured tool lists")
	}
	tools, err := vscodeClassification()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var list struct{ Tools, ExtensionTools, MCPTools []string }
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		for _, tool := range list.Tools {
			if _, ok := tools[tool]; !ok {
				t.Errorf("%s: tool %s is not classified in vscode-tools.yaml", filepath.Base(f), tool)
			}
		}
		for _, tool := range list.ExtensionTools {
			if _, ok := tools[tool]; ok || strings.HasPrefix(tool, vscodeMCPPrefix) {
				t.Errorf("%s: extension tool %s is classified or reads as MCP", filepath.Base(f), tool)
			}
		}
		for _, tool := range list.MCPTools {
			acts, err := vscodeMCPActions(tool, engine.Action{})
			if err != nil || len(acts) == 0 {
				t.Errorf("%s: MCP tool %s: %v", filepath.Base(f), tool, err)
			}
		}
	}
}

// VS Code's MCP names split at every "_" inside the longest prefix
func TestVSCodeMCPSplits(t *testing.T) {
	for name, want := range map[string][]string{
		"mcp_e2e_do_thing":              {"e2e/do_thing", "e2e_do/thing"},
		"mcp_azure_bicep_m_build_bicep": {"azure/bicep_m_build_bicep", "azure_bicep/m_build_bicep", "azure_bicep_m/build_bicep"},
		"mcp_github2_create_issue":      {"github2/create_issue"}, // a "_" at 18 would make the prefix too long
		"mcp_abcdefghijklm_x_y":         {"abcdefghijklm/x_y"},
		"mcp_x":                         nil,
		"mcp__tool":                     nil,
	} {
		acts, _ := vscodeMCPActions(name, engine.Action{})
		var got []string
		for _, a := range acts {
			got = append(got, a.MCP.Server+"/"+a.MCP.Tool)
			if a.MCP.Names != engine.NamesVSCode {
				t.Errorf("%s: names %v", name, a.MCP.Names)
			}
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: splits %q, want %q", name, got, want)
		}
	}
}
