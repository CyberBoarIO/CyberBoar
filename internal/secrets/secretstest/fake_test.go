package secretstest_test

import (
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

func TestExpand(t *testing.T) {
	a, _ := secretstest.Fake("github-pat")
	b, _ := secretstest.FakeN("github-pat", 1)
	if a == b || a != secretstest.Expand("{{fake:github-pat}}") || b != secretstest.Expand("{{fake:github-pat:1}}") {
		t.Fatal("Fake and FakeN don't match Expand")
	}
	if got := secretstest.Expand("x={{fake:github-pat}} y={{fake:nope}} z={{fake:github-pat:x}} {{fake:"); got !=
		"x="+a+" y={{fake:nope}} z={{fake:github-pat:x}} {{fake:" {
		t.Fatalf("Expand = %q", got)
	}
	for _, id := range secretstest.Rules() {
		if s, ok := secretstest.Fake(id); !ok || len(s) < 16 || strings.Contains(s, "{{") {
			t.Errorf("%s: %q", id, s)
		}
	}
}

func TestHide(t *testing.T) {
	a, _ := secretstest.Fake("github-pat")
	if got := secretstest.Expand("{{fake:github-pat:0:sq}}"); got != a[:2]+"''"+a[2:] {
		t.Errorf("sq = %q", got)
	}
	if got := secretstest.Expand("{{fake:github-pat:0:nope}}"); got != "{{fake:github-pat:0:nope}}" {
		t.Errorf("unknown how = %q", got)
	}
	for _, how := range []string{"sq", "dq", "bs", "base64", "base64x2", "base64url", "hex", "percent", "punct", "head", "tail", "ansic"} {
		if h, ok := secretstest.Hide(a, how); !ok || h == a || strings.Contains(h, a) {
			t.Errorf("%s: %q", how, h)
		}
	}
	if secretstest.Expand("{{fake:github-pat:0:head}}{{fake:github-pat:0:tail}}") != a {
		t.Error("head and tail don't make the credential")
	}
	if got, _ := secretstest.Hide(a, "punct"); got != a[:3]+"%5F"+a[4:] {
		t.Errorf("punct = %q", got)
	}
	w, _ := secretstest.Fake("slack-webhook-url")
	if h, ok := secretstest.Hide(w, "queryescape"); !ok || !strings.HasPrefix(h, "https%3A%2F%2Fhooks.") || strings.Contains(h, "/") {
		t.Errorf("queryescape: %q", h)
	}
	g, _ := secretstest.Fake("gitlab-pat")
	if h, ok := secretstest.Hide(g, "lookalike"); !ok || strings.Contains(h, "-") || len(h) != len(g)+2 {
		t.Errorf("lookalike: %q", h)
	}
}
