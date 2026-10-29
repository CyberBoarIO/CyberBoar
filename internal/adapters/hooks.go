package adapters

// RemoveHandlers removes the handlers that ours matches from hooks, a hooks
// object in the shape Claude Code and Codex share,
// {"Event": [{"matcher": ..., "hooks": [handler, ...]}, ...]}. A group left
// with no handlers is removed, and so is an event left with no groups.
// Anything that isn't in that shape is kept as it is.
func RemoveHandlers(hooks map[string]any, ours func(handler map[string]any) bool) {
	for event, v := range hooks {
		existing, ok := v.([]any)
		if !ok {
			continue
		}
		var groups []any
		for _, g := range existing {
			gm, ok := g.(map[string]any)
			if !ok {
				groups = append(groups, g)
				continue
			}
			handlers, ok := gm["hooks"].([]any)
			if !ok {
				groups = append(groups, g)
				continue
			}
			kept := []any{}
			for _, h := range handlers {
				if hm, ok := h.(map[string]any); ok && ours(hm) {
					continue
				}
				kept = append(kept, h)
			}
			if len(kept) == 0 && len(handlers) > 0 {
				continue
			}
			gm["hooks"] = kept
			groups = append(groups, gm)
		}
		switch {
		case len(groups) > 0:
			hooks[event] = groups
		case len(existing) > 0:
			delete(hooks, event)
		}
	}
}

// HookArgs returns the arguments of the hook command for agent, which is its
// --agent name. Empty audit, state and pubkey are left out.
func HookArgs(agent, policy, audit, state, pubkey, deadline string) []string {
	args := []string{"hook", "--agent", agent, "--policy", policy}
	if audit != "" {
		args = append(args, "--audit", audit)
	}
	if state != "" {
		args = append(args, "--state", state)
	}
	if pubkey != "" {
		args = append(args, "--pubkey", pubkey)
	}
	return append(args, "--deadline", deadline)
}

// BriefArgs returns the arguments of the briefing command for agent.
// An empty pubkey is left out.
func BriefArgs(agent, policy, pubkey string) []string {
	args := []string{"brief", "--agent", agent, "--policy", policy}
	if pubkey != "" {
		args = append(args, "--pubkey", pubkey)
	}
	return args
}
