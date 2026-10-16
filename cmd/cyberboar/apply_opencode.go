package main

import (
	"io"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/adapters/opencode"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// applyOpencode installs the hook into opencode as a plugin file of its own
// in the user's or the project's plugin directory;
// the plugin runs the hook before every tool call
func applyOpencode(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int {
	if err := checkDeadline(a.deadline, opencode.HookTimeout, "plugin's hook timeout", ", after which every call is blocked"); err != nil {
		return usage("%v", err)
	}
	if a.lock || a.scope == "managed" {
		// opencode reads managed configuration (/etc/opencode), but
		// `opencode --pure` and OPENCODE_PURE=1 skip every plugin, managed
		// ones included, so nothing CyberBoar writes can be locked.
		return usage("--scope managed and --lock are not supported for opencode: anyone who starts opencode with --pure (or OPENCODE_PURE=1) runs it without plugins; only the OpenCode Console's policies can lock its configuration")
	}
	o := opencode.ShimOptions{Scope: opencode.Scope(a.scope), Policy: a.policy, Audit: a.audit, State: a.state, Deadline: a.deadline.String(),
		Command: a.command, PubKey: a.pubkey}

	var target string
	switch o.Scope {
	case opencode.ScopeUser:
		config := getenv("XDG_CONFIG_HOME")
		if config == "" {
			home, err := userHome(getenv)
			if err != nil {
				return fail("%v", err)
			}
			config = filepath.Join(home, ".config")
		}
		target = filepath.Join(config, "opencode", "plugin", opencode.FileName)
	case opencode.ScopeProject:
		// The plugin runs the hook in the project root
		target = filepath.Join(a.dir, ".opencode", "plugin", opencode.FileName)
		rel, err := projectPolicy(a.dir, a.policy)
		if err != nil {
			return fail("%v", err)
		}
		o.Policy = rel
		if o.Command == "" {
			o.Command = brand.Name
		}
	default:
		return usage("unknown --scope %q for opencode (user, project)", a.scope)
	}
	p, _, err := loadPolicy(a.policy)
	if err != nil {
		return fail("%v", err)
	}
	o.Briefing = p.Spec.Session.Briefing.On()
	if o.Command, err = hookCommand(o.Command); err != nil {
		return fail("%v", err)
	}
	out, err := opencode.Shim(o)
	if err != nil {
		return fail("%v", err)
	}
	if err := emit(stdout, a, target, "//", out, getenv); err != nil {
		return fail("%v", err)
	}
	printNotes(stdout, "Notes:", []string{
		"the plugin blocks every tool call the hook doesn't answer in time or answers with anything but no objection; opencode's own permissions still apply after it",
		"opencode can't ask the user from a plugin, so ask rules block the call",
		"opencode runs commands in a login shell that reads ~/.bashrc or ~/.zshrc first, aliases included; the hook can't see what those change",
		"opencode skips a plugin that fails to load without a word, and starting it with --pure (or OPENCODE_PURE=1) skips every plugin; the project scope is also skipped with OPENCODE_DISABLE_PROJECT_CONFIG=1",
		"other opencode plugins run in the same process and can change a tool call after the check; install only plugins you trust",
		"command, file and MCP rules are enforced only by the hook",
	})
	return 0
}
