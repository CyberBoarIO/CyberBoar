package secrets_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/secrets"
	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

// FuzzScan checks that findings, plain and decoded, lie in the text, and that Redact removes each of them.
func FuzzScan(f *testing.F) {
	for _, id := range secretstest.Rules() {
		s, _ := secretstest.Fake(id)
		f.Add("export X=" + s)
		f.Add("a=" + s + "\nb=" + s)
	}
	f.Add("curl -H 'Authorization: Bearer x' -u user:pass https://example.com")
	github, _ := secretstest.Fake("github-pat")
	for _, how := range []string{"base64", "base64x2", "hex", "percent", "punct"} {
		s, _ := secretstest.Hide(github, how)
		f.Add("x=" + s)
	}
	webhook, _ := secretstest.Fake("slack-webhook-url")
	s, _ := secretstest.Hide(webhook, "queryescape")
	f.Add("curl 'https://relay.example.com/?a=%00&to=" + s + "'")
	f.Add(`"ghp_"`)
	f.Fuzz(func(t *testing.T, text string) {
		found, err := secrets.Scan(context.Background(), text, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := secrets.ScanDecoded(context.Background(), text, nil)
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, decoded...)
		slices.SortStableFunc(found, func(a, b secrets.Finding) int { return a.Start - b.Start })
		last := 0
		for _, x := range found {
			if x.Start < last || x.Start > x.End || x.End > len(text) {
				t.Fatalf("finding %+v out of order or outside %d bytes", x, len(text))
			}
			last = x.Start
		}
		red := secrets.Redact(text, found)
		for _, x := range found {
			if s := text[x.Start:x.End]; s != "" && strings.Count(red, s) >= strings.Count(text, s) {
				t.Fatalf("Redact left every %q", s)
			}
		}
	})
}
