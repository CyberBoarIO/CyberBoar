// Package secretstest makes up credentials for tests: each one has the shape
// a rule of package secrets looks for, but none was ever issued. They are
// built at run time from a fixed seed, so no file in the repository holds
// one that a secret scanner (ours, gitleaks, push protection) would report.
package secretstest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lower   = "abcdefghijklmnopqrstuvwxyz0123456789"
	upper32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	upnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits  = "0123456789"
)

// randFrom returns n bytes drawn from alphabet.
func randFrom(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

// The literals are split so that the source itself matches no rule.
var makers = map[string]func(r *rand.Rand) string{
	"aws-access-token": func(r *rand.Rand) string { return "AK" + "IA" + randFrom(r, upper32, 16) },
	"github-pat":       func(r *rand.Rand) string { return "gh" + "p_" + randFrom(r, alnum, 36) },
	"gitlab-pat":       func(r *rand.Rand) string { return "gl" + "pat-" + randFrom(r, alnum, 20) },
	"slack-bot-token": func(r *rand.Rand) string {
		return "xo" + "xb-" + randFrom(r, digits, 12) + "-" + randFrom(r, digits, 12) + "-" + randFrom(r, alnum, 24)
	},
	"slack-webhook-url": func(r *rand.Rand) string {
		return "https://hooks." + "slack.com/services/T" + randFrom(r, upnum, 8) + "/B" + randFrom(r, upnum, 8) + "/" + randFrom(r, alnum, 24)
	},
	"stripe-access-token": func(r *rand.Rand) string { return "sk" + "_live_" + randFrom(r, alnum, 24) },
	"npm-access-token":    func(r *rand.Rand) string { return "np" + "m_" + randFrom(r, lower, 36) },
	"private-key": func(r *rand.Rand) string {
		return "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + randFrom(r, alnum, 70) + "\n" +
			randFrom(r, alnum, 70) + "\n-----END " + "OPENSSH PRIVATE KEY-----"
	},
}

// Rules returns the rule ids Fake can make a credential for, sorted.
func Rules() []string {
	ids := make([]string, 0, len(makers))
	for id := range makers {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Fake returns a made-up credential that the rule id finds, the same one on
// every call. ok is false for a rule it has none for.
func Fake(id string) (secret string, ok bool) {
	return FakeN(id, 0)
}

// FakeN is Fake's n-th credential for the rule: different n, different credential.
func FakeN(id string, n uint64) (secret string, ok bool) {
	mk, ok := makers[id]
	if !ok {
		return "", false
	}
	var seed uint64
	for i := range len(id) {
		seed = seed*31 + uint64(id[i])
	}
	// #nosec G404 -- fake credentials for tests: the same ones on every run
	return mk(rand.New(rand.NewPCG(seed, n))), true
}

// Expand replaces every {{fake:RULE}} in s with Fake(RULE), and
// {{fake:RULE:N}} with FakeN(RULE, N). {{fake:RULE:N:HOW}} also hides the
// credential the way HOW names (Hide). Anything it can't read is left as written.
func Expand(s string) string {
	const open = "{{fake:"
	var b strings.Builder
	for {
		i := strings.Index(s, open)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		parts := strings.Split(s[i+len(open):i+j], ":")
		var n uint64
		var err error
		if len(parts) > 1 {
			n, err = strconv.ParseUint(parts[1], 10, 64)
		}
		f, ok := FakeN(parts[0], n)
		if ok && len(parts) > 2 {
			f, ok = Hide(f, parts[2])
		}
		b.WriteString(s[:i])
		if ok && err == nil && len(parts) <= 3 {
			b.WriteString(f)
		} else {
			b.WriteString(s[i : i+j+2])
		}
		s = s[i+j+2:]
	}
}

// Hide returns secret as an agent might hide it: "sq", "dq" and "bs" split
// it after its second byte with an empty pair of single quotes, an empty pair
// of double quotes, or a backslash (shell quoting);
// "base64", "base64url", "hex" and "percent" encode it whole; "base64x2"
// encodes it twice. "queryescape" encodes it as url.QueryEscape does, which
// leaves letters, digits and "-_.~" as they are, and "punct" percent-encodes
// only the bytes that aren't letters or digits
// "head" and "tail" are its first 8 bytes and the rest,
// to be put together later; "ansic" writes its first 4 bytes as \x escapes
// (for $'…' and printf); "lookalike" has its first '-' replaced by U+2010,
// a hyphen that looks the same. ok is false for another how.
func Hide(secret, how string) (string, bool) {
	split := func(sep string) string { return secret[:2] + sep + secret[2:] }
	switch how {
	case "head":
		return secret[:8], true
	case "tail":
		return secret[8:], true
	case "ansic":
		var b strings.Builder
		for i := range 4 {
			fmt.Fprintf(&b, `\x%02x`, secret[i])
		}
		return b.String() + secret[4:], true
	case "lookalike":
		i := strings.IndexByte(secret, '-')
		if i < 0 {
			return "", false
		}
		return secret[:i] + "\u2010" + secret[i+1:], true
	case "sq":
		return split("''"), true
	case "dq":
		return split(`""`), true
	case "bs":
		return split(`\`), true
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(secret)), true
	case "base64x2":
		return base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret)))), true
	case "base64url":
		return base64.RawURLEncoding.EncodeToString([]byte(secret)), true
	case "hex":
		return hex.EncodeToString([]byte(secret)), true
	case "percent":
		var b strings.Builder
		for i := range len(secret) {
			fmt.Fprintf(&b, "%%%02X", secret[i])
		}
		return b.String(), true
	case "queryescape":
		return url.QueryEscape(secret), true
	case "punct":
		var b strings.Builder
		for i := range len(secret) {
			if c := secret[i]; strings.IndexByte(alnum, c) >= 0 {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		return b.String(), true
	}
	return "", false
}
