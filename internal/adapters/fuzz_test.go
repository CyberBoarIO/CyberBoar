package adapters

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/engine"
)

// FuzzPatchPaths reads any document: no panic, every file header's path as
// Codex reads it is among the paths, and each path gets one write action
func FuzzPatchPaths(f *testing.F) {
	f.Add("*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\n")
	f.Add("*** Begin Patch\n*** Update File: b\n*** Move to:  c\n@@\n-x\n+y\n*** End Patch\n")
	f.Add("  *** Delete File: d\r\n*** Environment ID: e\n")
	f.Fuzz(func(t *testing.T, patch string) {
		paths, _ := PatchPaths(patch)
		for _, line := range strings.Split(patch, "\n") {
			tl := strings.TrimSpace(line)
			for _, m := range []string{addFile, deleteFile, updateFile, moveTo} {
				if p, ok := strings.CutPrefix(tl, m+" "); ok && !slices.Contains(paths, p) {
					t.Fatalf("header %q: path %q missing from %q", line, p, paths)
				}
			}
		}
		writes := PatchWrites(patch, engine.Action{Cwd: "/w"})
		if len(writes) != len(paths) {
			t.Fatalf("%d writes for %d paths", len(writes), len(paths))
		}
		for i, w := range writes {
			if w.Tool != engine.ToolWrite || w.Path != paths[i] {
				t.Fatalf("write %d: %+v, want a write of %q", i, w, paths[i])
			}
		}
	})
}

// FuzzSplitMCP splits any name: each reading puts the name back together,
// with neither part empty, and there is one for each "__" between them
func FuzzSplitMCP(f *testing.F) {
	f.Add("github__create_issue")
	f.Add("a___b__c")
	f.Add("__x__")
	f.Fuzz(func(t *testing.T, rest string) {
		splits := SplitMCP(rest)
		want := 0
		for i := 1; i+2 < len(rest); i++ {
			if rest[i:i+2] == "__" {
				want++
			}
		}
		if len(splits) != want {
			t.Fatalf("%q: %d splits, want %d", rest, len(splits), want)
		}
		for _, c := range splits {
			if c.Server == "" || c.Tool == "" || c.Server+"__"+c.Tool != rest {
				t.Fatalf("%q: split %+v", rest, c)
			}
		}
	})
}

// FuzzToolInputObject decodes any tool input: when it is accepted, every
// path field holds a string (or nothing), so Extract can't skip a path
func FuzzToolInputObject(f *testing.F) {
	f.Add(`{"path": "a", "paths": ["b"], "files": {"x": {"from": "c"}}}`)
	f.Add(`{"path": 7}`)
	f.Add(`{"paths": [1, "b"], "files": {"x": "c"}}`)
	f.Fuzz(func(t *testing.T, data string) {
		fields := []string{"path", "paths[]", "files.*.from"}
		input, err := ToolInputObject("T", json.RawMessage(data), nil, fields)
		if err != nil {
			return
		}
		pathOK := func(v any) bool { _, s := v.(string); return v == nil || s }
		if !pathOK(input["path"]) {
			t.Fatalf("path %v accepted", input["path"])
		}
		if v, ok := input["paths"]; ok && v != nil {
			arr, isArr := v.([]any)
			if !isArr {
				t.Fatalf("paths %v accepted", v)
			}
			for _, el := range arr {
				if !pathOK(el) {
					t.Fatalf("paths element %v accepted", el)
				}
			}
		}
		if v, ok := input["files"]; ok && v != nil {
			obj, isObj := v.(map[string]any)
			if !isObj {
				t.Fatalf("files %v accepted", v)
			}
			for _, el := range obj {
				if el == nil {
					continue
				}
				m, isObj := el.(map[string]any)
				if !isObj || !pathOK(m["from"]) {
					t.Fatalf("files value %v accepted", el)
				}
			}
		}
	})
}
