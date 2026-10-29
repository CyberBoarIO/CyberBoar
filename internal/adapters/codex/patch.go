package codex

import "cyberboar.dev/cyberboar/internal/adapters"

const beginPatch = adapters.BeginPatch

// checkPatchEnvironment refuses an apply_patch document that names another
// environment, because its files are on a machine the hook can't see.
func checkPatchEnvironment(patch string) error {
	if _, env := adapters.PatchPaths(patch); env {
		return &adapters.Error{Rule: RuleRemoteEnvironment, Msg: "the patch targets another environment, whose files the policy can't check, so it is blocked"}
	}
	return nil
}
