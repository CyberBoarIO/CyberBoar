package copilot

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHooksOff(t *testing.T) {
	firstLaunch := time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
	for _, c := range []struct {
		name, settings string
		off, err       bool
	}{
		{"empty", "", false, false},
		{"the config.json Copilot 1.0.97 writes", "// User settings belong in settings.json.\n// This file is managed automatically.\n{\n  \"firstLaunchAt\": \"" + firstLaunch + "\"\n}\n", false, false},
		{"set after a comment", "// c\n{\"disableAllHooks\": true}", true, false},
		{"false", `{"disableAllHooks": false}`, false, false},
		{"null", `{"disableAllHooks": null}`, false, false},
		{"block comment and trailing comma", "{/* x */ \"disableAllHooks\": true, }", true, false},
		{"trailing comma in a list", `{"a": [1, 2,], "disableAllHooks": true}`, true, false},
		{"comment markers in strings", `{"url": "http://x/*y*/", "note": "// no", "disableAllHooks": true}`, true, false},
		{"escaped quote in a string", `{"a": "x\" // y", "disableAllHooks": true}`, true, false},
		{"a list", `[1]`, false, true},
		{"null document", `null`, false, true},
		{"unterminated object", `{`, false, true},
		{"unterminated comment", `{"disableAllHooks": true} /* x`, false, true},
	} {
		off, err := HooksOff([]byte(c.settings))
		if off != c.off || (err != nil) != c.err {
			t.Errorf("%s: off %v, err %v; want off %v, error %v", c.name, off, err, c.off, c.err)
		}
	}
}

// Text inside strings is kept as it is.
func TestJSONCKeepsStrings(t *testing.T) {
	var v map[string]string
	if err := json.Unmarshal(jsonc([]byte(`{"u": "http://x/*y*/ // z", "q": "a\",}"} // end`)), &v); err != nil {
		t.Fatal(err)
	}
	if v["u"] != "http://x/*y*/ // z" || v["q"] != `a",}` {
		t.Errorf("got %q", v)
	}
}
