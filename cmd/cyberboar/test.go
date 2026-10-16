package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// policyCases are separate from the enforceable policy schema
type policyCases struct {
	Tests []policyCase `json:"tests"`
}

type policyCase struct {
	Name   string           `json:"name"`
	Action policyTestAction `json:"action"`
	Expect string           `json:"expect"`
}

type policyTestAction struct {
	Read      string `json:"read,omitempty"`
	Write     string `json:"write,omitempty"`
	List      string `json:"list,omitempty"`
	Command   string `json:"command,omitempty"`
	MCP       string `json:"mcp,omitempty"`
	Cwd       string `json:"cwd,omitempty"`
	Home      string `json:"home,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

const maxTestCasesBytes = 1 << 20

func runTest(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "validated policy file")
	casesPath := fs.String("cases", "", "YAML test cases file")
	fs.Usage = func() { fmt.Fprintf(stderr, "usage: %s test --policy FILE --cases FILE\n", brand.Name) }
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 0 || *policyPath == "" || *casesPath == "" {
		fs.Usage()
		return 2
	}
	_, compiled, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "test: %v\n", err)
		return 1
	}
	// #nosec G703 -- the operator explicitly chooses the local --cases fixture file
	data, err := os.ReadFile(*casesPath)
	if err != nil {
		fmt.Fprintf(stderr, "test: %v\n", err)
		return 1
	}
	if len(data) > maxTestCasesBytes {
		fmt.Fprintf(stderr, "test: case file exceeds %d bytes\n", maxTestCasesBytes)
		return 1
	}
	j, err := yaml.YAMLToJSON(data)
	if err != nil {
		fmt.Fprintf(stderr, "test: invalid YAML: %v\n", err)
		return 1
	}
	var cases policyCases
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cases); err != nil {
		fmt.Fprintf(stderr, "test: invalid cases: %v\n", err)
		return 1
	}
	if len(cases.Tests) == 0 || len(cases.Tests) > 1000 {
		fmt.Fprintln(stderr, "test: tests must contain 1 to 1000 cases")
		return 1
	}
	for i, c := range cases.Tests {
		if err := checkPolicyCase(c); err != nil {
			fmt.Fprintf(stderr, "test: tests[%d]: %v\n", i, err)
			return 1
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "test: working directory: %v\n", err)
		return 1
	}
	home := h.getenv("HOME")
	if h.goos == "windows" && h.getenv("USERPROFILE") != "" {
		home = h.getenv("USERPROFILE")
	}
	failed := 0
	for _, c := range cases.Tests {
		a := engine.Action{Cwd: wd, Home: home, Workspaces: []string{wd}}
		if c.Action.Cwd != "" {
			a.Cwd = c.Action.Cwd
		}
		if c.Action.Home != "" {
			a.Home = c.Action.Home
		}
		if c.Action.Workspace != "" {
			a.Workspaces[0] = c.Action.Workspace
		}
		if h.goos == "windows" {
			a.Platform = engine.PlatformWindows
		}
		switch {
		case c.Action.Read != "":
			a.Tool, a.Path = engine.ToolRead, c.Action.Read
		case c.Action.Write != "":
			a.Tool, a.Path = engine.ToolWrite, c.Action.Write
		case c.Action.List != "":
			a.Tool, a.Path = engine.ToolList, c.Action.List
		case c.Action.Command != "":
			a.Tool, a.Command = engine.ToolShell, c.Action.Command
		case c.Action.MCP != "":
			a.Tool = engine.ToolMCP
			a.MCP.Server, a.MCP.Tool, _ = strings.Cut(c.Action.MCP, "/")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got := engine.Evaluate(ctx, compiled, a)
		cancel()
		if string(got.Decision) != c.Expect {
			failed++
			fmt.Fprintf(stdout, "FAIL %s: expected %s, got %s (%s)\n", c.Name, c.Expect, got.Decision, got.Rule)
		} else {
			fmt.Fprintf(stdout, "PASS %s: %s\n", c.Name, got.Decision)
		}
	}
	fmt.Fprintf(stdout, "%d passed, %d failed\n", len(cases.Tests)-failed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func checkPolicyCase(c policyCase) error {
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 200 || strings.ContainsAny(c.Name, "\r\n") {
		return fmt.Errorf("name must be nonempty, one line and at most 200 characters")
	}
	switch c.Expect {
	case "allow", "ask", "deny":
	default:
		return fmt.Errorf("expect must be allow, ask or deny")
	}
	n := 0
	for _, v := range []string{c.Action.Read, c.Action.Write, c.Action.List, c.Action.Command, c.Action.MCP} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("action must specify exactly one of read, write, list, command, mcp")
	}
	if c.Action.MCP != "" {
		server, tool, ok := strings.Cut(c.Action.MCP, "/")
		if !ok || server == "" || tool == "" || strings.Contains(tool, "/") {
			return fmt.Errorf("mcp must be server/tool")
		}
	}
	for name, p := range map[string]string{"cwd": c.Action.Cwd, "home": c.Action.Home, "workspace": c.Action.Workspace} {
		if p != "" && !filepath.IsAbs(p) && !looksLikeWindowsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	return nil
}

func looksLikeWindowsAbs(p string) bool {
	return len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}
