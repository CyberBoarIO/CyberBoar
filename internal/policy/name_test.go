package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNameMatchesSchema(t *testing.T) {
	var schema struct {
		Properties struct {
			Metadata struct {
				Properties struct {
					Name struct {
						Pattern   string `json:"pattern"`
						MaxLength int    `json:"maxLength"`
					} `json:"name"`
				} `json:"properties"`
			} `json:"metadata"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	n := schema.Properties.Metadata.Properties.Name
	if n.Pattern != namePattern.String() || n.MaxLength != maxName {
		t.Fatalf("schema says %q (max %d), IsName uses %q (max %d)", n.Pattern, n.MaxLength, namePattern, maxName)
	}
	for s, want := range map[string]bool{"baseline": true, "a": true, "team-1": true, "-x": false, "x-": false, "Upper": false,
		"a.b": false, "": false, strings.Repeat("a", 63): true, strings.Repeat("a", 64): false} {
		if IsName(s) != want {
			t.Errorf("IsName(%q) = %v", s, !want)
		}
	}
}
