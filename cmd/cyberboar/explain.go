package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/engine/osfs"
	"cyberboar.dev/cyberboar/internal/engine/shell"
	"cyberboar.dev/cyberboar/internal/winpath"
)

// runExplain prints the decision the policy gives for one action, and with --verbose
// what the shell analysis found in a command line.
func runExplain(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	wd, _ := os.Getwd()
	policyPath := fs.String("policy", h.getenv(envName("policy")), "policy file (env "+envName("policy")+")")
	shellCmd := fs.String("command", "", "a shell command line")
	shellName := fs.String("shell", "", `the language of --command: "bash" (or "") or "powershell"`)
	read := fs.String("read", "", "a path the agent reads")
	write := fs.String("write", "", "a path the agent writes")
	list := fs.String("list", "", "a path whose names the agent lists")
	mcp := fs.String("mcp", "", "an MCP call as server/tool")
	cwd := fs.String("cwd", wd, "working directory")
	defaultHome, defaultPlatform := h.getenv("HOME"), ""
	if h.goos == "windows" {
		defaultPlatform = engine.PlatformWindows
		if p := h.getenv("USERPROFILE"); p != "" {
			defaultHome = p
		}
	}
	home := fs.String("home", defaultHome, "home directory")
	platform := fs.String("platform", defaultPlatform, `path semantics: "" (POSIX) or "windows"`)
	workspace := fs.String("workspace", "", "workspace root (default: --cwd)")
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	verbose := fs.Bool("verbose", false, "also show what the shell analysis found")
	fs.BoolVar(verbose, "v", false, "alias for --verbose")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 {
		// Flag parsing stops at the first word that isn't a flag
		fmt.Fprintf(stderr, "explain: unexpected argument %q (quote a --command line that has spaces)\n", fs.Arg(0))
		return 2
	}
	if *workspace == "" {
		*workspace = *cwd
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "explain: --policy is required")
		return 2
	}
	a := engine.Action{Cwd: *cwd, Home: *home, Workspaces: []string{*workspace}, Platform: *platform}
	if *platform == "" || runtime.GOOS == "windows" {
		// Elsewhere filepath.Abs would read a Windows path as a relative POSIX one
		// The engine refuses a relative path itself
		a.Cwd, a.Workspaces[0] = absOr(*cwd), absOr(*workspace)
	}
	set := 0
	for _, o := range []struct {
		v    string
		tool engine.Tool
	}{{*shellCmd, engine.ToolShell}, {*read, engine.ToolRead}, {*write, engine.ToolWrite}, {*list, engine.ToolList}, {*mcp, engine.ToolMCP}} {
		if o.v == "" {
			continue
		}
		set++
		a.Tool = o.tool
		switch o.tool {
		case engine.ToolShell:
			a.Command = o.v
		case engine.ToolMCP:
			a.MCP.Server, a.MCP.Tool, _ = strings.Cut(o.v, "/")
		default:
			a.Path = o.v
		}
	}
	if set != 1 {
		fmt.Fprintln(stderr, "explain: give exactly one of --command, --read, --write, --list, --mcp")
		return 2
	}
	if *shellName != "" && a.Tool != engine.ToolShell {
		fmt.Fprintln(stderr, "explain: --shell goes with --command")
		return 2
	}
	shell, err := shellLanguage(*shellName)
	if err != nil {
		fmt.Fprintf(stderr, "explain: --shell: %v\n", err)
		return 2
	}
	a.Shell = shell
	_, c, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "explain: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v := engine.Evaluate(ctx, c, a)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			fmt.Fprintf(stderr, "explain: %v\n", err)
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "%s  (%s)\n%s\n", strings.ToUpper(string(v.Decision)), v.Rule, v.Reason)
	}
	if *verbose && a.Tool == engine.ToolShell {
		out := stdout
		if *asJSON {
			out = stderr // stdout holds only the JSON object
		}
		explainShell(out, a)
	}
	return 0
}

// absOr returns the absolute form of p, or p itself if it has none.
func absOr(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// explainShell prints what the analysis saw, which is the commands, the inline code and the paths.
func explainShell(w io.Writer, a engine.Action) {
	var an *shell.Analysis
	var err error
	if a.Shell == engine.ShellPowerShell {
		// PowerShell reads Windows paths itself, in the engine's form
		o := shell.Options{Cwd: a.Cwd, FS: osfs.FS{Windows: a.Platform == engine.PlatformWindows}}
		home := a.Home
		if o.FS.Windows {
			o.Cwd, _, _ = winpath.Path(a.Cwd)
			home, _, _ = winpath.Path(a.Home)
		}
		an, err = shell.AnalyzePowerShell(a.Command, home, o)
	} else {
		an, err = shell.Analyze(a.Command, a.Home, a.Cwd)
	}
	if err != nil {
		fmt.Fprintf(w, "\nanalysis: %v\n", err)
		return
	}
	fmt.Fprintln(w, "\ncommands:")
	for i, c := range an.Commands {
		for j, layer := range c.Layers {
			parts := make([]string, len(layer))
			for k, e := range layer {
				parts[k] = e.Shown()
			}
			marker := "  "
			if j > 0 {
				marker = "  ↳"
			}
			fmt.Fprintf(w, "%s [%d] %s\n", marker, i, strings.Join(parts, " "))
		}
	}
	if len(an.Code) > 0 {
		fmt.Fprintln(w, "inline code:")
		for _, c := range an.Code {
			fmt.Fprintf(w, "   %s (analyzed: %v)\n", c.What, c.Analyzed)
		}
	}
	if len(an.Files) > 0 {
		fmt.Fprintln(w, "paths:")
		for _, f := range an.Files {
			switch {
			case !f.Certain:
				fmt.Fprintf(w, "   %s (only known at run time)\n", f.Display)
			default:
				fmt.Fprintf(w, "   %s\n", f.Path)
			}
		}
	}
}
