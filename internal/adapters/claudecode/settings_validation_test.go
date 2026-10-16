package claudecode_test

import (
	"encoding/json"
	"testing"

	"cyberboar.dev/cyberboar/internal/adapters/claudecode"
)

func TestSettingsRequireOneObject(t *testing.T) {
	merge := func(existing []byte) ([]byte, error) {
		return claudecode.Merge(existing, map[string]any{"hooks": map[string]any{}})
	}
	for _, existing := range []string{
		"null", "[]", "1", `"settings"`, "{", "{} {}", "{} null", "{} garbage", "{} {",
	} {
		t.Run(existing, func(t *testing.T) {
			if out, err := merge([]byte(existing)); err == nil || out != nil {
				t.Fatalf("accepted invalid settings %q: output %s, error %v", existing, out, err)
			}
		})
	}
	for _, existing := range []string{"", " \n\t", `{}`, "{} \n\t"} {
		if _, err := merge([]byte(existing)); err != nil {
			t.Errorf("valid settings %q: %v", existing, err)
		}
	}
	out, err := merge([]byte(`{"unknown":{"number":9007199254740993,"fraction":1e3}}`))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Unknown map[string]json.RawMessage `json:"unknown"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc.Unknown["number"]) != "9007199254740993" || string(doc.Unknown["fraction"]) != "1e3" {
		t.Fatalf("unknown settings or number representations changed: %s", out)
	}
}
