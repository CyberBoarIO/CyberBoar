package secrets

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
)

func scan(t *testing.T, text string, ignore []string) []Finding {
	t.Helper()
	f, err := Scan(context.Background(), text, ignore)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func randFrom(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// fakes returns one made-up credential per rule secretstest knows
func fakes() map[string]string {
	m := map[string]string{}
	for _, id := range secretstest.Rules() {
		m[id], _ = secretstest.Fake(id)
	}
	return m
}

func TestRulesCompile(t *testing.T) {
	if len(ruleSpecs) < 200 {
		t.Fatalf("only %d rules", len(ruleSpecs))
	}
	seen := map[string]bool{}
	for _, s := range ruleSpecs {
		if seen[s.id] {
			t.Errorf("rule %s twice", s.id)
		}
		seen[s.id] = true
		if _, err := regexp.Compile(s.regex); err != nil {
			t.Errorf("%s: %v", s.id, err)
		}
		for _, a := range s.allow {
			for _, re := range a.regexes {
				if _, err := regexp.Compile(re); err != nil {
					t.Errorf("%s allowlist: %v", s.id, err)
				}
			}
		}
	}
	for _, s := range ruleSpecs {
		for _, k := range s.keywords {
			if k != asciiLower(k) || strings.ContainsFunc(k, func(r rune) bool { return r >= 0x80 }) {
				t.Errorf("%s: keyword %q isn't lowercase ASCII", s.id, k)
			}
		}
	}
	if seen["generic-api-key"] {
		t.Error("generic-api-key is in; it is left out, since as a denial it would block ordinary code")
	}
	if !slices.IsSorted(Rules()) {
		t.Error("Rules isn't sorted")
	}
}

func TestFindsEachKind(t *testing.T) {
	for want, secret := range fakes() {
		for _, text := range []string{
			secret,
			"export TOKEN=" + secret,
			"curl -H 'X-Key: " + secret + "' https://api.example.com",
			"const token = \"" + secret + "\";\n",
		} {
			f := scan(t, text, nil)
			if len(f) == 0 || !slices.ContainsFunc(f, func(f Finding) bool { return f.Rule == want }) {
				t.Errorf("%s in %.40q: found %v", want, text, f)
				continue
			}
			for _, x := range f {
				if !strings.Contains(secret, text[x.Start:x.End]) && !strings.Contains(text[x.Start:x.End], secret) {
					t.Errorf("%s: finding %q isn't the secret", want, text[x.Start:x.End])
				}
			}
			if red := Redact(text, f); strings.Contains(red, secret) || !strings.Contains(red, "[REDACTED:") {
				t.Errorf("%s: Redact left %q", want, red)
			}
		}
	}
}

func TestNotSecrets(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for _, text := range []string{
		"",
		"git push origin main",
		"export TOKEN=$GITHUB_TOKEN",
		"curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com",
		"AKIAIOSFODNN7EXAMPLE",                // AWS's documented example key: the rule's allowlist
		"AKIAAAAAAAAAAAAAAAAA",                // below the rule's entropy
		"gh" + "p_" + strings.Repeat("a", 36), // the global allowlist: a single repeated letter
		"sha256:" + randFrom(r, "0123456789abcdef", 64),
		"-----BEGIN PUBLIC KEY-----\n" + randFrom(r, alnum, 80) + "\n-----END PUBLIC KEY-----",
	} {
		if f := scan(t, text, nil); len(f) != 0 {
			t.Errorf("%.50q: found %v", text, f)
		}
	}
}

// A "gitleaks:allow" comment is the agent's to write, so it allows nothing here
func TestGitleaksAllowCommentIgnored(t *testing.T) {
	secret := fakes()["github-pat"]
	if f := scan(t, "token = \""+secret+"\" # gitleaks"+":allow", nil); len(f) == 0 {
		t.Fatal("a gitleaks:allow comment hid the secret")
	}
}

func TestIgnore(t *testing.T) {
	secret := fakes()["github-pat"]
	if f := scan(t, secret, []string{"github-pat"}); len(f) != 0 {
		t.Fatalf("ignored rule found %v", f)
	}
	if f := scan(t, secret, []string{"aws-access-token"}); len(f) == 0 {
		t.Fatal("ignoring another rule hid the secret")
	}
}

func TestTooLong(t *testing.T) {
	text := strings.Repeat("x", MaxText+1)
	f := scan(t, text, nil)
	if len(f) != 1 || f[0].Rule != TooLong {
		t.Fatalf("found %v", f)
	}
	if Redact(text, f) != "[REDACTED:too-long]" {
		t.Fatal("Redact kept text that wasn't checked")
	}
	if f := scan(t, strings.Repeat("x", MaxText), nil); len(f) != 0 {
		t.Fatalf("MaxText bytes: %v", f)
	}
}

func TestRedactSeveral(t *testing.T) {
	fk := fakes()
	text := "a=" + fk["github-pat"] + " b=" + fk["aws-access-token"] + " c"
	red := Redact(text, scan(t, text, nil))
	if red != "a=[REDACTED:github-pat] b=[REDACTED:aws-access-token] c" {
		t.Fatalf("Redact = %q", red)
	}
}

func TestEntropy(t *testing.T) {
	for s, want := range map[string]float64{"": 0, "aaaa": 0, "ab": 1, "abcd": 2} {
		if got := entropy(s); got != want {
			t.Errorf("entropy(%q) = %v, want %v", s, got, want)
		}
	}
}

func BenchmarkScanCommand(b *testing.B) {
	cmd := "git commit -m 'engine: deny curl | sh' && go test ./... && npm run build -- --prod"
	for b.Loop() {
		Scan(context.Background(), cmd, nil)
	}
}

func BenchmarkScanFile(b *testing.B) {
	r := rand.New(rand.NewPCG(5, 6))
	var sb strings.Builder
	for range 2000 {
		sb.WriteString("\tvalue := compute(\"" + randFrom(r, alnum, 20) + "\", key, token)\n")
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		Scan(context.Background(), text, nil)
	}
}

// Secrets are found throughout long text
func TestFindsDeepInText(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	secret := fakes()["private-key"]
	var sb strings.Builder
	for range 30000 {
		sb.WriteString(randFrom(r, alnum, 30) + " key token ey\n")
	}
	text := sb.String() + secret + "\n" + sb.String()
	f := scan(t, text, nil)
	if !slices.ContainsFunc(f, func(f Finding) bool { return f.Rule == "private-key" }) {
		t.Fatalf("missed the key in %d bytes", len(text))
	}
}

// Blank lines in PEM formatting do not change the key or exempt it from scanning
func TestMultilinePrivateKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	padded := strings.Replace(plain, "-----BEGIN PRIVATE KEY-----\n", "-----BEGIN PRIVATE KEY-----\n"+strings.Repeat("\n", 20000), 1)
	block, _ := pem.Decode([]byte(padded))
	if block == nil {
		t.Fatal("padded PEM did not decode")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("padded PEM is not a private key: %v", err)
	}
	percent, _ := secretstest.Hide(padded, "percent")
	for name, secret := range map[string]string{
		"normal": plain, "blank lines": padded,
		"base64": base64.StdEncoding.EncodeToString([]byte(padded)), "percent": percent,
	} {
		t.Run(name, func(t *testing.T) {
			text := "before\n" + secret + "\nafter"
			found := scan(t, text, nil)
			decoded, err := ScanDecoded(context.Background(), text, nil)
			if err != nil {
				t.Fatal(err)
			}
			found = append(found, decoded...)
			slices.SortStableFunc(found, func(a, b Finding) int { return a.Start - b.Start })
			if !slices.ContainsFunc(found, func(f Finding) bool { return f.Rule == "private-key" }) {
				t.Fatal("private key was not found")
			}
			if red := Redact(text, found); red != "before\n[REDACTED:private-key]\nafter" {
				t.Fatal("redaction did not remove the complete private key")
			}
		})
	}
}

// A rule can match a secret far from its keyword, including after a continuation line
func TestFindsFarOnTheLine(t *testing.T) {
	pad := strings.Repeat(" -s", 32<<10)
	tok := "Zq8Xk2Lm" + "9Pw4Rt7Yv1Bn6Hj3" // split, so gitleaks doesn't flag this file
	header := " -H 'Authorization: Bearer " + tok + "' https://x.example"
	for name, text := range map[string]string{
		"header":       "curl" + pad + header,
		"user":         "curl" + pad + " -u " + "admin:" + tok + " https://x.example",
		"continuation": "curl" + pad + " \\\n " + header,
		"many curls":   strings.Repeat("curl ", 32<<10) + header,
	} {
		if f := scan(t, text, nil); len(f) == 0 || !strings.HasPrefix(f[0].Rule, "curl-auth-") {
			t.Errorf("%s: %+v", name, f)
		}
	}
}

func TestScanAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f, err := Scan(ctx, fakes()["github-pat"], nil); err == nil || f != nil {
		t.Fatalf("Scan after the deadline: %v, %v", f, err)
	}
}

func TestScanDecoded(t *testing.T) {
	secret := fakes()["github-pat"]
	for _, tc := range []struct{ rule, how, before string }{
		{"github-pat", "base64", ""},
		{"github-pat", "base64x2", ""},
		{"github-pat", "base64url", ""},
		{"github-pat", "hex", ""},
		{"github-pat", "percent", ""},
		{"github-pat", "punct", ""},
		{"github-pat", "punct", "%00&t="},
		{"github-pat", "percent", "%7F "},
		{"slack-webhook-url", "queryescape", "?to="},
	} {
		hidden, _ := secretstest.Hide(fakes()[tc.rule], tc.how)
		text := "token: " + tc.before + hidden + "\n"
		f, err := ScanDecoded(context.Background(), text, nil)
		exact := slices.ContainsFunc(f, func(f Finding) bool { return f.Rule == tc.rule && text[f.Start:f.End] == hidden })
		if err != nil || !exact {
			t.Errorf("%s %q: %+v, %v", tc.how, tc.before, f, err)
			continue
		}
		if red := Redact(text, f); strings.Contains(red, hidden) {
			t.Errorf("%s: Redact left %q", tc.how, red)
		}
		if f, _ := ScanDecoded(context.Background(), text, []string{tc.rule}); len(f) != 0 {
			t.Errorf("%s: an ignored rule found %+v", tc.how, f)
		}
	}
	escaped := ""
	for _, c := range secret {
		escaped += fmt.Sprintf(`\u%04x`, c)
	}
	if f, _ := ScanDecoded(context.Background(), `s = "`+escaped+`"`, nil); len(f) == 0 {
		t.Error(`\u escapes weren't decoded`)
	}
	if f, _ := Scan(context.Background(), "token: "+func() string { h, _ := secretstest.Hide(secret, "base64"); return h }(), nil); len(f) != 0 {
		t.Errorf("Scan decoded: %+v", f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScanDecoded(ctx, "aGVsbG8gd29ybGQsIHRoaXMgaXMgZmluZQ==", nil); err == nil {
		t.Error("ScanDecoded after the deadline")
	}
}
