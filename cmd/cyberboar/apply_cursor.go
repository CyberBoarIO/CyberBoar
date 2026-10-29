package main

import (
	"io"
	"os"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/adapters/cursor"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// applyCursor installs the hook into Cursor's hooks.json for the user, the
// project or the machine. Cursor reads one hooks.json per scope, so the file is merged.
func applyCursor(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int {
	if err := checkDeadline(a.deadline, cursor.HookTimeout, "Cursor hook timeout", ""); err != nil {
		return usage("%v", err)
	}
	if a.lock {
		// Cursor's team hooks (dashboard) are the lockable form, which
		// this command can't write
		return usage("--lock is not supported for cursor; --scope managed hooks run before users' own, but users can add their own")
	}
	o := cursor.FragmentOptions{Policy: a.policy, Audit: a.audit, State: a.state, Deadline: a.deadline.String(),
		Command: a.command, PubKey: a.pubkey}

	var target string
	switch cursor.Scope(a.scope) {
	case cursor.ScopeUser:
		home, err := userHome(getenv)
		if err != nil {
			return fail("%v", err)
		}
		target = filepath.Join(home, ".cursor", "hooks.json")
	case cursor.ScopeProject:
		// Cursor runs project hooks in the project root
		target = filepath.Join(a.dir, ".cursor", "hooks.json")
		rel, err := projectPolicy(a.dir, a.policy)
		if err != nil {
			return fail("%v", err)
		}
		o.Policy = rel
		if o.Command == "" {
			o.Command = brand.Name
		}
	case cursor.ScopeManaged:
		target = filepath.Join(a.managedDir, "hooks.json")
	default:
		return usage("unknown --scope %q for cursor (user, project, managed)", a.scope)
	}
	p, _, err := loadPolicy(a.policy)
	if err != nil {
		return fail("%v", err)
	}
	o.Briefing = p.Spec.Session.Briefing.On()
	if o.Command, err = hookCommand(o.Command); err != nil {
		return fail("%v", err)
	}
	existing, err := os.ReadFile(target)
	if err != nil && !os.IsNotExist(err) {
		return fail("%v", err)
	}
	out, err := cursor.MergeHooks(existing, o)
	if err != nil {
		return fail("%s: %v", target, err)
	}
	if err := emit(stdout, a, target, "#", out, getenv); err != nil {
		return fail("%v", err)
	}
	notes := []string{
		"the hooks are failClosed: a crashed or timed-out hook blocks the tool",
		"Cursor ignores ask from preToolUse, so ask rules deny",
		"Cursor runs every matching hook: a later preToolUse hook can replace a tool's input after the check, " +
			"and a sessionStart hook can set the environment later hooks run in; install only hooks you trust",
		"command, file and MCP rules are enforced only by the hook",
	}
	if cursor.Scope(a.scope) != cursor.ScopeManaged {
		notes = append(notes, "users can edit or remove user and project hooks outside Cursor; --scope managed must be owned by root")
	}
	printNotes(stdout, "Notes:", notes)
	return 0
}

// cursorManagedDir is the directory of Cursor's machine-wide hooks.json, in
// the host's path syntax.
func cursorManagedDir(goos string) string {
	return filepath.FromSlash(cursor.ManagedDir(goos))
}
