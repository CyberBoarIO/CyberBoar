// Package audit writes one JSON line per decision and defines
// the events and batches an endpoint sends to a console (docs/protocol).
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// maxField bounds free text (commands, paths) in an event.
const maxField = 4096

// Event is one hook decision.
// Fields may be added but never renamed.
type Event struct {
	Time       string   `json:"time"` // RFC 3339, UTC
	Agent      string   `json:"agent"`
	Version    string   `json:"version"`
	Session    string   `json:"session,omitempty"`
	ToolUseID  string   `json:"toolUseId,omitempty"`
	AgentID    string   `json:"agentId,omitempty"`
	AgentType  string   `json:"agentType,omitempty"`
	Mode       string   `json:"permissionMode,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Project    string   `json:"project,omitempty"`
	Tool       string   `json:"tool,omitempty"`
	Actions    []Action `json:"actions,omitempty"`
	Decision   string   `json:"decision"` // allow | ask | deny
	Rule       string   `json:"rule"`
	Reason     string   `json:"reason"`
	PolicyName string   `json:"policyName,omitempty"`
	PolicyHash string   `json:"policySha256,omitempty"`
	DurationMs float64  `json:"durationMs"`
	// ActionsOmitted counts actions left out of Actions to keep the line within MaxLineBytes.
	ActionsOmitted int `json:"actionsOmitted,omitempty"`
}

// Action is one engine action the tool call became.
type Action struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Server  string `json:"mcpServer,omitempty"`
	MCPTool string `json:"mcpTool,omitempty"`
}

// Endpoint identifies the machine that sends events to the console.
// Add fields, never rename them.
type Endpoint struct {
	ID       string `json:"id"` // random UUID, lowercase, kept in a local state file
	Hostname string `json:"hostname,omitempty"`
	Version  string `json:"version"` // cyberboar version
}

// Batch is the body of the console's POST /api/v1/events.
// Fields a newer endpoint adds are kept.
type Batch struct {
	Endpoint Endpoint          `json:"endpoint"`
	Events   []json.RawMessage `json:"events"`
}

// MaxLineBytes bounds one audit line the console accepts.
// Truncate keeps the hook's lines well below it.
const MaxLineBytes = 64 << 10

// ParseLine parses one audit line and checks what the console relies on: a
// known decision, an RFC 3339 time and keys as CheckKeys requires.
// Unknown fields are ignored, so lines from newer versions still parse.
func ParseLine(line []byte) (Event, error) {
	var ev Event
	if len(line) > MaxLineBytes {
		return ev, fmt.Errorf("larger than %d bytes", MaxLineBytes)
	}
	if err := CheckKeys(line, ev); err != nil {
		return ev, err
	}
	if err := json.Unmarshal(line, &ev); err != nil {
		return ev, err
	}
	switch ev.Decision {
	case "allow", "ask", "deny":
	default:
		return ev, fmt.Errorf("decision %q is not allow, ask or deny", ev.Decision)
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.Time); err != nil {
		return ev, fmt.Errorf("time: %w", err)
	}
	return ev, nil
}

// MaxDepth bounds how deeply objects and arrays nest in a line, and in a
// batch around its events.
const MaxDepth = 32

// CheckKeys returns an error if data, at any depth, holds an object with two
// keys that are equal when case is ignored, or a key that matches a field of
// v's type only when case is ignored. v is an Event, a Batch or a pointer to
// one, and the events of a batch are checked as Events. CheckKeys also
// returns an error for nesting deeper than MaxDepth.
//
// encoding/json accepts such keys, keeps the last value and matches keys to
// fields without regard to case. Other JSON parsers keep the first value or
// match exactly. A line holding "decision":"deny" and "Decision":"allow"
// would mean deny to one SIEM and allow to another.
func CheckKeys(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(dec, reflect.TypeOf(v), 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}

var rawMessage = reflect.TypeFor[json.RawMessage]()

// checkValue reads one value from dec
// t is the Go type it decodes into, or nil when it has none.
func checkValue(dec *json.Decoder, t reflect.Type, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessage {
		// An event in a batch is held to the same bound as the line on its own
		t, depth = reflect.TypeFor[Event](), 0
	}
	if depth >= MaxDepth {
		return fmt.Errorf("nested more than %d levels deep", MaxDepth)
	}
	switch d {
	case '[':
		var elem reflect.Type
		if t != nil && t.Kind() == reflect.Slice {
			elem = t.Elem()
		}
		for dec.More() {
			if err := checkValue(dec, elem, depth+1); err != nil {
				return err
			}
		}
	case '{':
		fields := map[string]reflect.StructField{}
		if t != nil && t.Kind() == reflect.Struct {
			for f := range t.Fields() {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				fields[foldKey(name)] = f
			}
		}
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key := tok.(string)
			k := foldKey(key)
			if seen[k] {
				return fmt.Errorf("key %q appears twice in an object (case ignored)", key)
			}
			seen[k] = true
			var ft reflect.Type
			if f, ok := fields[k]; ok {
				if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != key {
					return fmt.Errorf("key %q must be spelled %q", key, name)
				}
				ft = f.Type
			}
			if err := checkValue(dec, ft, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// foldKey folds case at least as far as encoding/json does when it matches
// keys to fields, so two keys it could confuse fold to the same string.
func foldKey(s string) string { return strings.ToLower(strings.ToUpper(s)) }

// Truncate shortens a free-text field to about maxField bytes.
// The cut is at a rune boundary and the result says how long the original was.
func Truncate(s string) string { return truncate(s, maxField) }

// truncate cuts s to at most n bytes at a rune boundary and appends its original length.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("...(%d bytes)", len(s))
}

// maxWrite keeps a written line below MaxLineBytes with room to spare.
const maxWrite = MaxLineBytes - 1024

// Marshal returns ev as one JSON line, newline included, within MaxLineBytes.
// An event too large for one line first loses actions from the end, counted
// in ActionsOmitted, and then has its free text cut short.
// It returns an error if the shortened line still exceeds MaxLineBytes.
// The console drops a line over MaxLineBytes.
// An agent controls how many actions a call has (an apply_patch naming thousands of files).
// The size limit must not keep its denials out of the audit trail.
func Marshal(ev Event) ([]byte, error) {
	line, err := json.Marshal(ev)
	for err == nil && len(line) > maxWrite && len(ev.Actions) > 0 {
		keep := len(ev.Actions) / 2
		ev.ActionsOmitted += len(ev.Actions) - keep
		ev.Actions = ev.Actions[:keep:keep]
		line, err = json.Marshal(ev)
	}
	if err == nil && len(line) > maxWrite {
		// JSON escaping can make a field up to six times its size.
		// Shorten free-text fields before checking the final line size.
		const n = 256
		for _, f := range []*string{&ev.Agent, &ev.Version, &ev.Session, &ev.ToolUseID, &ev.AgentID, &ev.AgentType,
			&ev.Mode, &ev.Cwd, &ev.Project, &ev.Tool, &ev.Rule, &ev.Reason, &ev.PolicyName, &ev.PolicyHash} {
			*f = truncate(*f, n)
		}
		line, err = json.Marshal(ev)
	}
	if err != nil {
		return nil, err
	}
	if len(line)+1 > MaxLineBytes {
		return nil, fmt.Errorf("audit line larger than %d bytes", MaxLineBytes)
	}
	return append(line, '\n'), nil
}

// AppendFile appends ev as one line to path. A file and directory it creates are readable only by the owner.
// The line is written with a single call to Write on a file opened for append.
func AppendFile(path string, ev Event) error {
	line, err := Marshal(ev)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
