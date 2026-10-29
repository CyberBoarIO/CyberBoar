package adapters

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cyberboar.dev/cyberboar/internal/adapters/edits"
	"cyberboar.dev/cyberboar/internal/engine"
)

// EditSpec says where a tool's input holds its text edits (package edits).
// If List is set, it is the field holding an array of edit objects, as in
// Claude Code's MultiEdit.
// Otherwise the input is the one edit.
// Old, New and All name the fields of an edit, and All, a boolean, may be left out.
// Match is "opencode" for opencode's matching (edits.Opencode), or "" for edits.Loose.
type EditSpec struct {
	List  string `yaml:"list"`
	Old   string `yaml:"old"`
	New   string `yaml:"new"`
	All   string `yaml:"all"`
	Match string `yaml:"match"`
}

// Valid returns an error if the spec doesn't name the fields an edit needs.
func (s *EditSpec) Valid() error {
	if s.Old == "" || s.New == "" {
		return errors.New("edit without old and new fields")
	}
	if s.Match != "" && s.Match != "opencode" {
		return fmt.Errorf("unknown edit match %q", s.Match)
	}
	return nil
}

// Read returns the edits in a tool's input. Anything not of the expected
// types is an error, because the engine must not guess what the tool will do.
func (s *EditSpec) Read(input map[string]any) ([]edits.Replace, error) {
	objs := []any{input}
	if s.List != "" {
		list, ok := input[s.List].([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("field %q is not a list of edits", s.List)
		}
		objs = list
	}
	var out []edits.Replace
	for _, o := range objs {
		obj, ok := o.(map[string]any)
		if !ok {
			return nil, errors.New("an edit is not an object")
		}
		old, ok1 := obj[s.Old].(string)
		with, ok2 := obj[s.New].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("an edit's %q or %q is not a string", s.Old, s.New)
		}
		all := false
		if s.All != "" {
			switch v := obj[s.All].(type) {
			case nil:
			case bool:
				all = v
			default:
				return nil, fmt.Errorf("an edit's %q is not a boolean", s.All)
			}
		}
		out = append(out, edits.Replace{Old: old, New: with, All: all})
	}
	return out, nil
}

// WriteText returns what a write tool puts in its file, for the secrets check.
// That is the text at its content fields and its edits' new text.
// If edit is set, WriteText also returns the Rewrite that applies the edits (edits.StringsMatching).
func WriteText(input map[string]any, content []string, edit *EditSpec) (string, engine.Rewrite, error) {
	text := Text(input, content)
	if edit == nil {
		return text, nil, nil
	}
	es, err := edit.Read(input)
	if err != nil {
		return "", nil, err
	}
	if t := EditText(es); text == "" {
		text = t
	} else {
		text += "\n" + t
	}
	m := edits.Loose
	if edit.Match == "opencode" {
		m = edits.Opencode
	}
	return text, edits.StringsMatching(es, m), nil
}

// EditText joins the new texts of edits with newlines.
// That is what the edits add, for the secrets check.
func EditText(es []edits.Replace) string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.New
	}
	return strings.Join(parts, "\n")
}

// Text joins the strings at the input's field paths, as Extract reads them, with newlines.
// It gives the secrets check the text a tool writes.
func Text(input any, fields []string) string {
	var parts []string
	for _, f := range fields {
		parts = append(parts, Extract(input, f)...)
	}
	return strings.Join(parts, "\n")
}

// JSONText returns every object key and string value in JSON, such as an MCP
// call's arguments, with object keys in order and joined with newlines.
// It gives the secrets check what the call sends out.
// Text that isn't JSON is returned as it is.
func JSONText(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return ValuesText(v)
}

// ValuesText returns every object key and string value in a decoded JSON value,
// at any depth, with object keys in order and joined with newlines.
func ValuesText(v any) string {
	return strings.Join(stringValues(v), "\n")
}

func stringValues(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var out []string
		for _, k := range keys {
			out = append(out, k)
			out = append(out, stringValues(v[k])...)
		}
		return out
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, stringValues(e)...)
		}
		return out
	}
	return nil
}
