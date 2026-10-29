package policy

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/brand"
)

func TestTooLarge(t *testing.T) {
	data := []byte("# " + strings.Repeat("x", MaxSize))
	_, err := Load(data)
	var perr *Error
	if !errors.As(err, &perr) || perr.Code != CodeTooLarge {
		t.Fatalf("want %s, got %v", CodeTooLarge, err)
	}
}

func TestSchemaCompiles(t *testing.T) {
	if _, err := compiledSchema(); err != nil {
		t.Fatal(err)
	}
}

// The schema is a static file, so it can drift from pkg/brand on rename.
func TestSchemaMatchesBrand(t *testing.T) {
	var s struct {
		ID         string `json:"$id"`
		Properties struct {
			APIVersion struct {
				Const string `json:"const"`
			} `json:"apiVersion"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaJSON, &s); err != nil {
		t.Fatal(err)
	}
	if s.Properties.APIVersion.Const != brand.APIVersion {
		t.Errorf("schema apiVersion const is %q, brand.APIVersion is %q", s.Properties.APIVersion.Const, brand.APIVersion)
	}
	if !strings.Contains(s.ID, "//"+brand.APIGroup+"/") {
		t.Errorf("schema $id %q does not use brand.APIGroup %q", s.ID, brand.APIGroup)
	}
}

func TestLoadFillsDefaults(t *testing.T) {
	p, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\nspec: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.Defaults.Posture != DenyListed {
		t.Errorf("default posture = %q, want %q", p.Spec.Defaults.Posture, DenyListed)
	}
	if p.Spec.Files.Containing != ContainingDeny {
		t.Errorf("default containing = %q, want %q", p.Spec.Files.Containing, ContainingDeny)
	}
	if !p.Spec.Commands.InterpretersDenied() {
		t.Error("denyInterpreters must default to true")
	}
	if p.Spec.Session.Tripwire.On() {
		t.Error("the tripwire must be off unless the policy configures it")
	}
	if !p.Spec.Session.Briefing.On() {
		t.Error("briefing must default to on")
	}
}

// A tripwire block turns the tripwire on, with the defaults for what it leaves out.
func TestTripwireBlockTurnsItOn(t *testing.T) {
	p, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n" +
		"spec: {session: {tripwire: {}}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	tw := p.Spec.Session.Tripwire
	if !tw.On() || tw.Limit() != DefaultMaxDenials || tw.WindowDuration() != 0 {
		t.Errorf("tripwire: {} = on %v, limit %d, window %s; want on, %d, whole session", tw.On(), tw.Limit(), tw.WindowDuration(), DefaultMaxDenials)
	}
	if (Tripwire{}).On() {
		t.Error("a Tripwire not built by Load must count as off")
	}
}

func TestSessionSettings(t *testing.T) {
	p, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n" +
		"spec: {session: {tripwire: {enabled: false, maxDenials: 7, window: 2h}, briefing: {enabled: false}}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	tw := p.Spec.Session.Tripwire
	if tw.On() || tw.Limit() != 7 || tw.WindowDuration().Hours() != 2 {
		t.Errorf("tripwire = on %v, limit %d, window %s; want off, 7, 2h", tw.On(), tw.Limit(), tw.WindowDuration())
	}
	if p.Spec.Session.Briefing.On() {
		t.Error("briefing: enabled: false must turn it off")
	}
}

// An unsupported API version error names the supported version.
func TestUnsupportedAPIVersionNamesSupportedVersion(t *testing.T) {
	_, err := Load([]byte("apiVersion: " + brand.APIGroup + "/v2\nkind: Policy\nmetadata: {name: x}\nspec: {}\n"))
	var perr *Error
	if !errors.As(err, &perr) || perr.Code != CodeAPIVersion || !strings.Contains(err.Error(), brand.APIVersion) {
		t.Fatalf("want an apiVersion error naming %s, got %v", brand.APIVersion, err)
	}
}

// Deep nesting is refused before the parser sees it, since parsing it takes
// time and memory quadratic in the depth.
func TestTooDeep(t *testing.T) {
	const n = 100000
	head := "apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n"
	for name, body := range map[string]string{
		"flow sequences": "spec: {audit: {sink: " + strings.Repeat("[", n) + strings.Repeat("]", n) + "}}\n",
		"flow mappings":  "spec: {audit: {sink: " + strings.Repeat("{a: ", n) + "1" + strings.Repeat("}", n) + "}}\n",
		"block entries":  "spec:\n  audit:\n    sink:\n      " + strings.Repeat("- ", n) + "x\n",
		"complex keys":   "spec:\n  audit:\n    sink:\n      " + strings.Repeat("? ", n) + "x\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(head + body))
			var perr *Error
			if !errors.As(err, &perr) || perr.Code != CodeTooDeep {
				t.Fatalf("want %s, got %.200v", CodeTooDeep, err)
			}
		})
	}
}

// Nesting under the limit reaches the schema, and comments don't count as levels.
func TestNotTooDeep(t *testing.T) {
	var comments strings.Builder
	for i := range 2 * MaxDepth {
		comments.WriteString(strings.Repeat(" ", i) + "# note\n")
	}
	head := "apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n"
	n := MaxDepth - 4
	_, err := Load([]byte(head + comments.String() + "spec: {audit: {sink: " + strings.Repeat("[", n) + strings.Repeat("]", n) + "}}\n"))
	var perr *Error
	if !errors.As(err, &perr) || perr.Code != CodeSchema {
		t.Fatalf("want %s, got %v", CodeSchema, err)
	}
}

// Of several schema errors, the first in index order is reported.
func TestSchemaErrorOrder(t *testing.T) {
	deny := make([]string, 11)
	for i := range deny {
		deny[i] = `"x"`
	}
	deny[2], deny[10] = `""`, `""`
	_, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n" +
		"spec: {files: {deny: [" + strings.Join(deny, ", ") + "]}}\n"))
	var perr *Error
	if !errors.As(err, &perr) || perr.Path != "spec.files.deny[2]" {
		t.Fatalf("want an error at spec.files.deny[2], got %v", err)
	}
}

// A pattern error quotes the pattern as written, not its translated form.
func TestPatternErrorQuotesWrittenPattern(t *testing.T) {
	_, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n" +
		"spec: {files: {deny: ['C:\\']}}\n"))
	if err == nil || !strings.Contains(err.Error(), `"C:\\"`) {
		t.Fatalf(`want an error quoting "C:\\", got %v`, err)
	}
}

// Drive patterns still reach the engine in its /c/x form.
func TestDrivePatternsTranslated(t *testing.T) {
	p, err := Load([]byte("apiVersion: " + brand.APIVersion + "\nkind: Policy\nmetadata: {name: x}\n" +
		"spec: {files: {deny: ['C:\\Users\\*\\.ssh\\**', 'D:/data/**']}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/c/Users/*/.ssh/**", "/d/data/**"}
	if !slices.Equal(p.Spec.Files.Deny, want) {
		t.Fatalf("deny = %q, want %q", p.Spec.Files.Deny, want)
	}
}
