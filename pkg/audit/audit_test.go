package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestMarshalBoundsLine(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	ctl := strings.Repeat("\x01", maxField) // six bytes each once escaped
	many := make([]Action, 5000)
	for i := range many {
		many[i] = Action{Tool: "write", Path: "/w/" + strings.Repeat("x", 100)}
	}
	for _, tc := range []struct {
		name string
		ev   Event
	}{
		{"many actions", Event{Actions: many}},
		{"escaped text", Event{Cwd: ctl, Project: ctl, Session: ctl, Reason: ctl, Rule: ctl, AgentID: ctl,
			Actions: []Action{{Tool: "shell", Command: ctl}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.ev.Time, tc.ev.Decision = timestamp, "deny"
			line, err := Marshal(tc.ev)
			if err != nil {
				t.Fatal(err)
			}
			if len(line) > MaxLineBytes {
				t.Fatalf("line is %d bytes, above %d", len(line), MaxLineBytes)
			}
			ev, err := ParseLine(line[:len(line)-1])
			if err != nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if got := len(ev.Actions) + ev.ActionsOmitted; got != len(tc.ev.Actions) {
				t.Errorf("%d actions kept plus omitted, want %d", got, len(tc.ev.Actions))
			}
		})
	}
}

func TestMarshalKeepsSmallEvent(t *testing.T) {
	ev := Event{Time: time.Now().UTC().Format(time.RFC3339Nano), Decision: "allow", Actions: []Action{{Tool: "read", Path: "/w/a"}}}
	line, err := Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), "actionsOmitted") {
		t.Errorf("small event lost actions: %s", line)
	}
}

func TestMarshalRejectsOversizedFields(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, tc := range []struct {
		name string
		ev   Event
	}{
		{"time", Event{Time: strings.Repeat("x", MaxLineBytes), Decision: "deny"}},
		{"decision", Event{Time: timestamp, Decision: strings.Repeat("x", MaxLineBytes)}},
		{"escaped time", Event{Time: strings.Repeat("\x01", MaxLineBytes/6+1), Decision: "deny"}},
		{"escaped decision", Event{Time: timestamp, Decision: strings.Repeat("\x01", MaxLineBytes/6+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := Marshal(tc.ev)
			if err == nil || len(line) != 0 {
				t.Fatalf("Marshal returned %d bytes and error %v, want no bytes and an error", len(line), err)
			}
		})
	}
}

func TestMarshalLineLimitIncludesNewline(t *testing.T) {
	ev := Event{Decision: "deny"}
	base, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.Time = strings.Repeat("x", MaxLineBytes-len(base)-1)
	line, err := Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(line) != MaxLineBytes || line[len(line)-1] != '\n' {
		t.Fatalf("expected a newline-terminated line of %d bytes, got %d bytes", MaxLineBytes, len(line))
	}
	ev.Time += "x"
	line, err = Marshal(ev)
	if err == nil || len(line) != 0 {
		t.Fatalf("Marshal returned %d bytes and error %v for a line one byte over the limit", len(line), err)
	}
}

func TestAppendFileRejectsOversizedEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ev := Event{Time: time.Now().UTC().Format(time.RFC3339Nano), Decision: "deny"}
	if err := AppendFile(path, ev); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ev.Decision = strings.Repeat("x", MaxLineBytes)
	if err := AppendFile(path, ev); err == nil {
		t.Fatal("AppendFile accepted an oversized event")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected event changed the existing audit log")
	}
	missingDir := filepath.Join(dir, "missing")
	if err := AppendFile(filepath.Join(missingDir, "audit.jsonl"), ev); err == nil {
		t.Fatal("AppendFile accepted an oversized event at a new path")
	}
	if _, err := os.Stat(missingDir); !os.IsNotExist(err) {
		t.Fatalf("rejected event created its log directory: %v", err)
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("a", maxField-1) + "é" // é straddles the cut
	if got := Truncate(s); !utf8.ValidString(got) {
		t.Errorf("Truncate split a rune: %q", got[len(got)-20:])
	}
}

// The field name is part of the protocol: the golden batch in
// testdata/protocol carries it as consoles will receive it
func TestActionsOmittedIsTheProtocolName(t *testing.T) {
	data, err := os.ReadFile("../../testdata/protocol/events/accept-actions-omitted.json")
	if err != nil {
		t.Fatal(err)
	}
	var b Batch
	if err := json.Unmarshal(data, &b); err != nil || len(b.Events) != 1 {
		t.Fatalf("golden batch: %v", err)
	}
	ev, err := ParseLine(b.Events[0])
	if err != nil || ev.ActionsOmitted != 4998 || len(ev.Actions) != 2 {
		t.Fatalf("ParseLine = %+v, %v", ev, err)
	}
	line, _ := Marshal(Event{Time: ev.Time, Decision: "deny", ActionsOmitted: 1})
	if !strings.Contains(string(line), `"actionsOmitted":1`) {
		t.Errorf("Marshal writes %s", line)
	}
}

func TestCheckKeys(t *testing.T) {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	event := func(fields string) string {
		return `{"time":"` + timestamp + `",` + fields + `}`
	}
	deep := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	for _, tc := range []struct {
		line string
		ok   bool
	}{
		{event(`"decision":"deny","actions":[{"tool":"read"},{"tool":"write"}]`), true},
		{event(`"decision":"deny","newer":{"Decision":1,"decision":2}`), false},
		{event(`"decision":"deny","newer":{"x":1,"y":{"x":2}}`), true},
		{event(`"decision":"deny","decision":"allow"`), false},
		{event(`"decision":"deny","Decision":"allow"`), false},
		{event(`"DECISION":"deny"`), false},
		{event(`"deciſion":"deny"`), false}, // encoding/json folds ſ to s
		{event(`"decision":"deny","actions":[{"tool":"read","Tool":"write"}]`), false},
		{event(`"decision":"deny","actions":[{"tool":"read","Path":"/x"}]`), false},
		{event(`"decision":"deny","newer":` + deep(MaxDepth-1)), true},
		{event(`"decision":"deny","newer":` + deep(MaxDepth)), false},
		{event(`"decision":"deny"`) + ` {}`, false},
	} {
		_, err := ParseLine([]byte(tc.line))
		if (err == nil) != tc.ok {
			t.Errorf("%.120s: ParseLine says %v", tc.line, err)
		}
		// A line ParseLine accepts must not fail the batch it is sent in.
		batch := `{"endpoint":{"id":"3f1c6a52-8d4e-4b7a-9c21-5e0f7d9a1b24","version":"v1"},"events":[` + tc.line + `]}`
		if err == nil {
			if err := CheckKeys([]byte(batch), Batch{}); err != nil {
				t.Errorf("%.120s: accepted alone but not in a batch: %v", tc.line, err)
			}
		}
	}
	for _, body := range []string{
		`{"endpoint":{"id":"x","version":"v1"},"Events":[]}`,
		`{"endpoint":{"id":"x","version":"v1","Version":"v2"},"events":[]}`,
		`{"endpoint":{"id":"x","version":"v1"},"events":[],"events":[]}`,
	} {
		if err := CheckKeys([]byte(body), Batch{}); err == nil {
			t.Errorf("%s: accepted", body)
		}
	}
}
