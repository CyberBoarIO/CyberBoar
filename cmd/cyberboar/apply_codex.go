package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/adapters"
	"cyberboar.dev/cyberboar/internal/adapters/codex"
	"cyberboar.dev/cyberboar/internal/winpath"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// applyCodex installs the hook into Codex. It writes hooks.json for the user
// and project scopes and requirements.toml for the managed scope.
func applyCodex(a applyArgs, stdout io.Writer, getenv func(string) string, fail, usage func(string, ...any) int) int {
	if err := checkDeadline(a.deadline, codex.HookTimeout, "Codex hook timeout", ": a timed-out hook fails open"); err != nil {
		return usage("%v", err)
	}
	if a.lock && codex.Scope(a.scope) != codex.ScopeManaged {
		return usage("--lock needs --scope managed")
	}
	windows := a.goos == "windows"
	o := codex.FragmentOptions{Scope: codex.Scope(a.scope), Policy: a.policy, Audit: a.audit, State: a.state, Deadline: a.deadline.String(),
		Command: a.command, Lock: a.lock, PubKey: a.pubkey, Windows: windows}
	if windows && o.Scope == codex.ScopeProject {
		return usage("%v", codex.CheckWindows(o))
	}

	var target string
	switch o.Scope {
	case codex.ScopeUser:
		// Codex reads the user's hooks.json from CODEX_HOME when it is set,
		// and on Windows finds the home through Windows (USERPROFILE)
		dir := getenv("CODEX_HOME")
		switch {
		case dir != "" && windows:
			if _, err := winpath.Abs(dir); err != nil {
				return fail("CODEX_HOME: %v", err)
			}
		case dir != "":
			if !filepath.IsAbs(dir) {
				return fail("CODEX_HOME %q is not an absolute path", dir)
			}
		case windows:
			if dir = getenv("USERPROFILE"); dir == "" {
				return fail("USERPROFILE is not set")
			}
			dir = adapters.Under(true, dir, ".codex")
		default:
			home, err := userHome(getenv)
			if err != nil {
				return fail("%v", err)
			}
			dir = filepath.Join(home, ".codex")
		}
		target = adapters.Under(windows, dir, "hooks.json")
	case codex.ScopeProject:
		target = filepath.Join(a.dir, ".codex", "hooks.json")
		rel, err := projectPolicy(a.dir, a.policy)
		if err != nil {
			return fail("%v", err)
		}
		o.Policy = rel
		if o.Command == "" {
			o.Command = brand.Name
		}
	case codex.ScopeManaged:
		target = adapters.Under(windows, a.managedDir, "requirements.toml")
	default:
		return usage("unknown --scope %q for codex (user, project, managed)", a.scope)
	}
	p, _, err := loadPolicy(a.policy)
	if err != nil {
		return fail("%v", err)
	}
	o.Briefing = p.Spec.Session.Briefing.On()
	if o.Command, err = hookCommand(o.Command); err != nil {
		return fail("%v", err)
	}
	if windows {
		// The hook's command line needs the program without spaces, which a
		// path such as C:\Program Files\… has in its 8.3 short name
		if !codex.BareWindowsProgram(o.Command) {
			if short, err := shortPathName(o.Command); err == nil && codex.BareWindowsProgram(short) {
				o.Command = short
			}
		}
		if err := codex.CheckWindows(o); err != nil {
			return fail("%v", err)
		}
	}

	existing, rerr := os.ReadFile(target)
	if rerr != nil && !os.IsNotExist(rerr) {
		return fail("%v", rerr)
	}
	var out []byte
	var notes []string
	if o.Scope == codex.ScopeManaged {
		if rerr == nil && !bytes.HasPrefix(existing, []byte(codex.RequirementsHeader)) {
			return fail("%s exists and was not written by %s apply; merge the output of a dry run into it by hand", target, brand.Name)
		}
		out, notes = codex.Requirements(p, o)
	} else {
		if out, err = codex.MergeHooksJSON(existing, o); err != nil {
			return fail("%s: %v", target, err)
		}
		notes = []string{"Codex runs user and project hooks only after you trust them in /hooks; until then the policy is NOT enforced",
			"command, file and MCP rules are enforced only by the hook; --scope managed also installs native command rules"}
	}
	if err := emit(stdout, a, target, "#", out, getenv); err != nil {
		return fail("%v", err)
	}
	printNotes(stdout, "Notes:", notes)
	return 0
}
