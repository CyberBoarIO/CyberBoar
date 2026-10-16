package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// applyClaudeCode installs the hook into Claude Code's settings for the
// user, the project, the local project or the machine
func applyClaudeCode(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int {
	if a.lock && claudecode.Scope(a.scope) != claudecode.ScopeManaged {
		return usage("--lock needs --scope managed")
	}
	if err := checkDeadline(a.deadline, claudecode.HookTimeout, "Claude Code hook timeout", ": a timed-out hook fails open"); err != nil {
		return usage("%v", err)
	}
	o := claudecode.FragmentOptions{Scope: claudecode.Scope(a.scope), Policy: a.policy, Audit: a.audit, State: a.state,
		Deadline: a.deadline.String(), Command: a.command, Lock: a.lock, PubKey: a.pubkey}

	var target string
	switch o.Scope {
	case claudecode.ScopeUser:
		home := getenv("HOME")
		if a.goos == "windows" && getenv("USERPROFILE") != "" {
			home = getenv("USERPROFILE") // where Claude Code looks for ~/.claude
		}
		if home == "" {
			return fail("HOME is not set")
		}
		target = filepath.Join(home, ".claude", "settings.json")
	case claudecode.ScopeProject:
		target = filepath.Join(a.dir, ".claude", "settings.json")
		rel, err := projectPolicy(a.dir, a.policy)
		if err != nil {
			return fail("%v", err)
		}
		o.Policy = "${CLAUDE_PROJECT_DIR}/" + rel
		if o.Command == "" {
			o.Command = brand.Name
		}
	case claudecode.ScopeLocal:
		target = filepath.Join(a.dir, ".claude", "settings.local.json")
	case claudecode.ScopeManaged:
		target = filepath.Join(a.managedDir, "managed-settings.d", "50-"+brand.Name+".json")
	default:
		return usage("unknown --scope %q (user, project, local, managed)", a.scope)
	}
	p, _, err := loadPolicy(a.policy)
	if err != nil {
		return fail("%v", err)
	}
	if o.Command, err = hookCommand(o.Command); err != nil {
		return fail("%v", err)
	}

	frag := claudecode.BuildFragment(p, o)
	var out []byte
	if o.Scope == claudecode.ScopeManaged {
		out, err = claudecode.Marshal(frag.Settings) // a drop-in file CyberBoar owns entirely
	} else {
		existing, rerr := os.ReadFile(target)
		if rerr != nil && !os.IsNotExist(rerr) {
			return fail("%v", rerr)
		}
		out, err = claudecode.Merge(existing, frag.Settings)
	}
	if err != nil {
		return fail("%s: %v", target, err)
	}
	if err := emit(stdout, a, target, "#", out, getenv); err != nil {
		return fail("%v", err)
	}
	if o.Scope != claudecode.ScopeManaged || !o.Lock {
		fmt.Fprintln(stdout, "NOTE: Claude Code runs no hook while any of its settings files sets disableAllHooks, and users can set it "+
			"in their own settings at any time. Only --scope managed --lock stops that.")
	}
	if a.goos == "windows" {
		fmt.Fprintf(stdout, "NOTE: Claude Code's PowerShell tool is blocked: %s can't check PowerShell yet. The settings deny the tool, "+
			"so Claude uses its Bash tool (Git Bash, from Git for Windows) instead; without Git Bash, use WSL.\n", brand.DisplayName)
	}
	if len(frag.Notes) > 0 {
		printNotes(stdout, "Native permission rules are a fallback for when the hook can't run. Enforced only by the hook:", frag.Notes)
	}
	return 0
}
