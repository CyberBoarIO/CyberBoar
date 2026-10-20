package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/adapters/copilot"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// applyCopilot installs the hook into GitHub Copilot CLI. It writes a hooks
// file of its own in the user's or the repository's hooks directory, or in
// the machine-wide policy directory for the managed scope.
func applyCopilot(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int {
	if err := checkDeadline(a.deadline, copilot.HookTimeout, "Copilot hook timeout", ": a timed-out hook fails open"); err != nil {
		return usage("%v", err)
	}
	if a.lock {
		// Copilot's allowManagedHooksOnly lives in its managed settings
		return usage("--lock is not supported for copilot-cli yet; --scope managed hooks can't be switched off by users, but users can add their own")
	}
	o := copilot.FragmentOptions{Scope: copilot.Scope(a.scope), Policy: a.policy, Audit: a.audit, State: a.state, Deadline: a.deadline.String(),
		Command: a.command, PubKey: a.pubkey}

	var target string
	// settings are the files of the scope that can switch its hooks off
	var settings []string
	// local says whether VS Code's Local agent reads the target: it reads the
	// repository's .github/hooks and ~/.copilot/hooks
	local := true
	switch o.Scope {
	case copilot.ScopeUser:
		dir := getenv("COPILOT_HOME")
		if dir == "" {
			home, err := userHome(getenv)
			if err != nil {
				return fail("%v", err)
			}
			dir = filepath.Join(home, ".copilot")
		} else if home, err := userHome(getenv); err != nil || filepath.Clean(dir) != filepath.Join(home, ".copilot") {
			local = false
		}
		target = filepath.Join(dir, "hooks", copilot.FileName)
		settings = []string{filepath.Join(dir, "config.json"), filepath.Join(dir, "settings.json")}
	case copilot.ScopeProject:
		// Copilot runs hooks in the repository root
		target = filepath.Join(a.dir, ".github", "hooks", copilot.FileName)
		settings = []string{filepath.Join(a.dir, ".github", "copilot", "settings.json"),
			filepath.Join(a.dir, ".github", "copilot", "settings.local.json")}
		rel, err := projectPolicy(a.dir, a.policy)
		if err != nil {
			return fail("%v", err)
		}
		o.Policy = rel
		if o.Command == "" {
			o.Command = brand.Name
		}
	case copilot.ScopeManaged:
		target = filepath.Join(a.managedDir, copilot.FileName)
		local = false
	default:
		return usage("unknown --scope %q for copilot-cli (user, project, managed)", a.scope)
	}
	p, _, err := loadPolicy(a.policy)
	if err != nil {
		return fail("%v", err)
	}
	o.Briefing = p.Spec.Session.Briefing.On()
	for _, f := range settings {
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fail("%v", err)
		}
		off, err := copilot.HooksOff(data)
		if err != nil {
			return fail("%s: %v", f, err)
		}
		if off {
			return fail("%s sets disableAllHooks, so Copilot would run no %s hook; remove the key and apply again", f, o.Scope)
		}
	}
	if o.Command, err = hookCommand(o.Command); err != nil {
		return fail("%v", err)
	}
	out, err := copilot.HooksFile(o)
	if err != nil {
		return fail("%v", err)
	}
	if err := emit(stdout, a, target, "#", out, getenv); err != nil {
		return fail("%v", err)
	}
	notes := []string{
		"Copilot lets a tool call through when the hook times out or answers with invalid JSON; the hook answers within --deadline to stay clear of that",
		"command, file and MCP rules are enforced only by the hook",
	}
	if local {
		notes = append(notes, "VS Code's Copilot session target and Local agent run this hook too, in a trusted workspace while chat.useHooks is on; start a new chat to load it")
	} else {
		notes = append(notes, "VS Code's Local agent doesn't read "+filepath.Dir(target)+", so it runs without this hook; to cover it, also apply --scope project, or --scope user with COPILOT_HOME unset")
	}
	if o.Scope != copilot.ScopeManaged {
		notes = append(notes, "users can switch user and repository hooks off (disableAllHooks); --scope managed can't be switched off and must be owned by root")
	}
	printNotes(stdout, "Notes:", notes)
	return 0
}
