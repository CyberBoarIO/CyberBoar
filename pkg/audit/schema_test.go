package audit_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// The JSON Schemas in schema/ are the published contract for SIEM pipelines
// and protocol implementations
// These tests hold them to the code and to the golden files in testdata/protocol

const (
	eventSchema = "schema/event.v1.json"
	batchSchema = "schema/batch.v1.json"
)

func readSchema(t *testing.T, file string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return doc.(map[string]any)
}

// compile compiles the schema in file, with every schema in schema/ added
// under its $id so references resolve without a network.
func compile(t *testing.T, file string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	var id string
	for _, f := range []string{eventSchema, batchSchema} {
		doc := readSchema(t, f)
		if err := c.AddResource(doc["$id"].(string), doc); err != nil {
			t.Fatal(err)
		}
		if f == file {
			id = doc["$id"].(string)
		}
	}
	sch, err := c.Compile(id)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return sch
}

func validate(sch *jsonschema.Schema, data []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return sch.Validate(v)
}

// A product rename moves the schemas' $id with the API group.
func TestSchemaIDs(t *testing.T) {
	for _, f := range []string{eventSchema, batchSchema} {
		id, _ := readSchema(t, f)["$id"].(string)
		if !strings.HasPrefix(id, "https://"+brand.APIGroup+"/schemas/audit/") {
			t.Errorf("%s: $id %q is not under https://%s/schemas/audit/", f, id, brand.APIGroup)
		}
	}
}

// The schemas must name exactly the fields of Event, Action, Endpoint and Batch.
func TestSchemaFieldsMatchTypes(t *testing.T) {
	event := readSchema(t, eventSchema)
	batch := readSchema(t, batchSchema)
	props := func(obj map[string]any, path ...string) []string {
		for _, p := range path {
			obj = obj[p].(map[string]any)
		}
		var names []string
		for name := range obj["properties"].(map[string]any) {
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		got  []string
	}{
		{"Event", reflect.TypeFor[audit.Event](), props(event)},
		{"Action", reflect.TypeFor[audit.Action](), props(event, "$defs", "action")},
		{"Endpoint", reflect.TypeFor[audit.Endpoint](), props(batch, "properties", "endpoint")},
		{"Batch", reflect.TypeFor[audit.Batch](), props(batch)},
	} {
		var want []string
		for f := range tc.typ.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			want = append(want, name)
		}
		slices.Sort(want)
		if !slices.Equal(tc.got, want) {
			t.Errorf("%s: schema has %v, type has %v", tc.name, tc.got, want)
		}
	}
}

// beyondSchema are golden batches rejected for rules JSON Schema can't express.
var beyondSchema = map[string]bool{
	"reject-duplicate-key.json":     true, // a parser keeps one of the two
	"reject-key-case-in-event.json": true, // "Decision" is an unknown field to a schema
	"reject-nested-too-deep.json":   true,
}

// Every golden batch a console must accept validates.
// Every one it must reject doesn't, unless the rule it breaks is beyond the schema.
func TestSchemaGoldenBatches(t *testing.T) {
	sch := compile(t, batchSchema)
	files, err := filepath.Glob("../../testdata/protocol/events/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden batches: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		err = validate(sch, data)
		switch name := filepath.Base(f); {
		case strings.HasPrefix(name, "accept-") && err != nil:
			t.Errorf("%s is invalid: %v", name, err)
		case strings.HasPrefix(name, "reject-") && err == nil && !beyondSchema[name]:
			t.Errorf("%s is valid", name)
		}
	}
}

// Marshal output must match the event schema and retain all required fields,
// even when an event is shortened to fit the size limit.
func TestSchemaMarshalledLines(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sch := compile(t, eventSchema)
	many := make([]audit.Action, 5000)
	for i := range many {
		many[i] = audit.Action{Tool: "write", Path: "/w/" + strings.Repeat("x", 100)}
	}
	for _, ev := range []audit.Event{
		{Time: now.Format(time.RFC3339), Decision: "deny"},
		{Time: now.Add(123 * time.Millisecond).Format(time.RFC3339Nano), Agent: "codex", Version: "v1.0.0", Tool: "Bash", Decision: "ask",
			Rule: "commands.ask", Reason: "r", PolicyName: "baseline", PolicyHash: strings.Repeat("0", 64), DurationMs: 0.5,
			Actions: []audit.Action{{Tool: "shell", Command: "git push"}, {Tool: "shell", Command: "Get-ChildItem", Shell: "powershell"},
				{Tool: "mcp", Server: "github", MCPTool: "x"}}},
		{Time: now.Format(time.RFC3339), Decision: "deny", Actions: many},
	} {
		line, err := audit.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(sch, line); err != nil {
			t.Errorf("%.200s: %v", line, err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(line, &keys); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"time", "agent", "version", "decision", "rule", "reason", "durationMs"} {
			if _, ok := keys[k]; !ok {
				t.Errorf("%.200s: no %s", line, k)
			}
		}
	}
}

// The event schema rejects what ParseLine rejects.
func TestSchemaAgreesWithParseLine(t *testing.T) {
	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339Nano)
	offset := now.In(time.FixedZone("UTC+2", 2*60*60)).Format(time.RFC3339Nano)
	invalid := now.Format(time.DateTime)
	sch := compile(t, eventSchema)
	for _, line := range []string{
		`{"time":"` + timestamp + `","decision":"deny"}`,
		`{"time":"` + offset + `","decision":"allow","newerField":{"x":1}}`,
		`{"time":"` + timestamp + `","decision":"maybe"}`,
		`{"time":"` + invalid + `","decision":"deny"}`,
		`{"decision":"deny"}`,
		`{"time":"` + timestamp + `"}`,
		`{"time":"` + timestamp + `","decision":"deny","durationMs":"1"}`,
		`{"time":"` + timestamp + `","decision":"deny","actions":{"tool":"read"}}`,
		`{"time":"` + timestamp + `","decision":"deny","actionsOmitted":2.5}`,
		`[]`,
	} {
		_, perr := audit.ParseLine([]byte(line))
		serr := validate(sch, []byte(line))
		if (perr == nil) != (serr == nil) {
			t.Errorf("%s: ParseLine says %v, the schema %v", line, perr, serr)
		}
	}
}
