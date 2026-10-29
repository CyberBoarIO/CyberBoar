package adapters

import (
	"errors"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
)

// apply_patch markers. The file header markers are given without the space
// that follows them, because the agents read the path after them in two
// ways. Codex (codex-rs/apply-patch) takes the text after the marker and one
// space, as it is. opencode takes the text after the marker with surrounding
// spaces trimmed, so for it "*** Add File:a" and "*** Add File:  a" both add
// the file a. Copilot CLI's apply_patch tool is said to take Codex's grammar,
// but its parser can't be read, so both readings are used for every agent.
const (
	BeginPatch      = "*** Begin Patch"
	addFile         = "*** Add File:"
	deleteFile      = "*** Delete File:"
	updateFile      = "*** Update File:"
	moveTo          = "*** Move to:"
	environmentLine = "*** Environment ID:"
)

// PatchPaths returns every file an apply_patch document may touch, and
// whether the patch names an environment (a machine other than the hook's).
//
// It over-approximates on purpose. Codex trims lines before matching headers
// in most states, and instead of following its parser state by state,
// PatchPaths takes every line that could be read as a file header in any
// state, so a header hidden in hunk content still counts. For each header it
// returns both Codex's and opencode's reading of the path. Extra paths can
// only make the verdict stricter.
func PatchPaths(patch string) (paths []string, environment bool) {
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	for line := range strings.SplitSeq(patch, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, environmentLine) {
			environment = true
		}
		for _, m := range []string{addFile, deleteFile, updateFile, moveTo} {
			rest, ok := strings.CutPrefix(t, m)
			if !ok {
				continue
			}
			if p, ok := strings.CutPrefix(rest, " "); ok {
				add(p)
			}
			add(strings.TrimSpace(rest))
		}
	}
	return paths, environment
}

// PatchText returns what an apply_patch document may add to files, for the
// secrets check. That is every line that could be an added line, without its
// "+". Like PatchPaths, it over-approximates, so a line indented before its
// "+" counts.
func PatchText(patch string) string {
	var add []string
	for line := range strings.SplitSeq(patch, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if t := strings.TrimLeft(line, " \t"); strings.HasPrefix(t, "+") {
			add = append(add, t[1:])
		}
	}
	return strings.Join(add, "\n")
}

// PatchWrites returns the write actions of an apply_patch document, one for
// each path it may touch (PatchPaths). Each holds what the document may add
// (PatchText) and, for a file it updates, the Rewrite that works out the file
// after it (package edits), so the secrets check sees what the file will hold.
// A moved file's complete rewritten contents are checked as a new write.
// A document Codex couldn't read gives each write a Rewrite that fails. Codex
// would refuse the patch too, and what a looser reader such as opencode's
// makes of it can't be worked out.
func PatchWrites(patch string, base engine.Action) []engine.Action {
	paths, _ := PatchPaths(patch)
	rewrites, moves, err := edits.PatchWithMoves(patch)
	// opencode updates the file at the trimmed path, so that path gets the
	// Rewrite of the header that names it. When two headers trim to the same
	// path, opencode changes that file twice, which neither Rewrite follows
	headers := map[string]int{}
	for k := range rewrites {
		headers[strings.TrimSpace(k)]++
	}
	trimmed := map[string]engine.Rewrite{}
	trimmedMoves := map[string]bool{}
	for k, r := range rewrites {
		p := strings.TrimSpace(k)
		trimmedMoves[p] = trimmedMoves[p] || moves[k]
		if headers[p] > 1 {
			r = func(string, bool) ([]string, error) {
				return nil, errors.New("the patch changes the file more than once; send one change per file")
			}
		}
		trimmed[p] = r
	}
	added := PatchText(patch)
	var out []engine.Action
	for _, p := range paths {
		a := base
		a.Tool, a.Path, a.Content = engine.ToolWrite, p, added
		switch {
		case err != nil:
			a.Rewrite = func(string, bool) ([]string, error) { return nil, err }
		case trimmed[p] != nil:
			a.Rewrite = trimmed[p]
		case rewrites[p] != nil:
			a.Rewrite = rewrites[p]
		}
		a.RewriteMoves = a.Rewrite != nil && (moves[p] || trimmedMoves[p])
		out = append(out, a)
	}
	return out
}
