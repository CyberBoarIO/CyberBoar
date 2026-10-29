package secrets

import (
	"context"
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxDecodeDepth is how many layers of encoding ScanDecoded unwraps, as gitleaks' --max-decode-depth default.
const MaxDecodeDepth = 5

// encodedRe finds what may be encoded text, as gitleaks' decoder does
// (detect/codec): percent escapes, \u escapes, hex, and base64 or base64url,
// in that precedence. The base64 pattern also matches long identifiers;
// decoding rejects them (they hold none of the characters base64 output
// usually has, or don't decode to printable ASCII.
var encodedRe = regexp.MustCompile(`(%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?)|((?i:(?:\\{1,2}u[a-fA-F0-9]{4})+))|([0-9A-Fa-f]{32,})|([\w/+-]{16,}={0,2})`)

var escapeRe = regexp.MustCompile(`(?i)\\{1,2}u([a-fA-F0-9]{4})`)

// ScanDecoded returns the secrets hidden in text by encoding, MaxDecodeDepth layers deep.
// It decodes in two ways and reports what either finds.
// Each encoded run is scanned on its own, and again for what it in turn encodes.
// The text is also scanned with every run replaced by what it decodes to, and
// each %XX escape replaced on its own, so that a secret only partly encoded
// (url.QueryEscape leaves letters, digits and "-_.~" alone) is found with the
// text around it, as gitleaks finds it. A finding's Start and End cover the
// encoded text that holds the secret, widened to whole encoded runs, so Redact removes it
// Secrets in the plain text are Scan's to find, so a caller runs both.
func ScanDecoded(ctx context.Context, text string, ignore []string) ([]Finding, error) {
	if len(text) > MaxText {
		return nil, nil // Scan reports it
	}
	var found []Finding
	report := func(f Finding, start, end int) {
		f.Start, f.End = start, end
		found = append(found, f)
	}
	runs, err := findRuns(ctx, text)
	if err != nil {
		return nil, err
	}
	if err := scanRuns(ctx, runs, ignore, 1, report); err != nil {
		return nil, err
	}
	if err := scanInPlace(ctx, text, runs, ignore, report); err != nil {
		return nil, err
	}
	return found, nil
}

// run is an encoded run of a text: text[start:end] decodes to decoded.
type run struct {
	start, end int
	decoded    string
	percent    bool // %XX escapes, decoded one by one in place
}

// findRuns returns the encoded runs of text that decode to something a credential could be.
func findRuns(ctx context.Context, text string) ([]run, error) {
	var runs []run
	for _, m := range encodedRe.FindAllStringSubmatchIndex(text, -1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := run{start: m[0], end: m[1], percent: m[2] >= 0}
		enc := text[r.start:r.end]
		switch {
		case r.percent:
			if r.decoded = decodePercent(enc); r.decoded == enc {
				r.decoded = "" // every escape stands for a control byte
			}
		case m[4] >= 0:
			r.decoded = decodeEscapes(enc)
		case m[6] >= 0:
			r.decoded = decodeHex(enc)
		default:
			r.decoded = decodeBase64(enc)
		}
		if r.decoded != "" {
			runs = append(runs, r)
		}
	}
	return runs, nil
}

// scanRuns reports the secrets in each run decoded on its own, and in what it in turn encodes.
func scanRuns(ctx context.Context, runs []run, ignore []string, depth int, report func(f Finding, start, end int)) error {
	for _, r := range runs {
		found, err := Scan(ctx, r.decoded, ignore)
		if err != nil {
			return err
		}
		for _, f := range found {
			report(f, r.start, r.end)
		}
		if depth == MaxDecodeDepth {
			continue
		}
		inner, err := findRuns(ctx, r.decoded)
		if err != nil {
			return err
		}
		err = scanRuns(ctx, inner, ignore, depth+1, func(f Finding, _, _ int) { report(f, r.start, r.end) })
		if err != nil {
			return err
		}
	}
	return nil
}

// segment is a part of a text that decoding in place replaced:
// text[start:end] became the decoded text's [dstart:dend].
type segment struct{ start, end, dstart, dend int }

// scanInPlace decodes text in place, layer by layer, and reports each secret
// in a layer that a replacement made for that layer touches, with its offsets
// mapped back to text
// runs are text's encoded runs.
func scanInPlace(ctx context.Context, text string, runs []run, ignore []string, report func(f Finding, start, end int)) error {
	var layers [][]segment
	for depth := 1; len(runs) > 0; depth++ {
		next, segs := decodeInPlace(text, runs)
		layers = append(layers, segs)
		found, err := Scan(ctx, next, ignore)
		if err != nil {
			return err
		}
		for _, f := range found {
			// A secret no replacement touches was in the layer before, for Scan or the layer before that to find
			if !touches(segs, f.Start, f.End) {
				continue
			}
			start, end := f.Start, f.End
			for _, layer := range slices.Backward(layers) {
				start, end = encodedOffset(layer, start, false), encodedOffset(layer, end, true)
			}
			report(f, start, end)
		}
		if depth == MaxDecodeDepth {
			return nil
		}
		text = next
		if runs, err = findRuns(ctx, text); err != nil {
			return err
		}
	}
	return nil
}

// decodeInPlace returns text with each run replaced by what it decodes to,
// and the replacements in order. In a percent run each escape that decodes
// is a replacement of its own, so the rest of the run maps back exactly.
func decodeInPlace(text string, runs []run) (string, []segment) {
	var b strings.Builder
	var segs []segment
	last := 0
	replace := func(start, end int, with string) {
		b.WriteString(text[last:start])
		segs = append(segs, segment{start: start, end: end, dstart: b.Len(), dend: b.Len() + len(with)})
		b.WriteString(with)
		last = end
	}
	for _, r := range runs {
		if !r.percent {
			replace(r.start, r.end, r.decoded)
			continue
		}
		for i := r.start; i < r.end; i++ {
			if c, ok := percentByte(text[:r.end], i); ok {
				replace(i, i+3, string(c))
				i += 2
			}
		}
	}
	b.WriteString(text[last:])
	return b.String(), segs
}

// touches reports whether the span [start, end) of a decoded text overlaps a replacement.
func touches(segs []segment, start, end int) bool {
	for _, g := range segs {
		if start < g.dend && end > g.dstart {
			return true
		}
	}
	return false
}

// encodedOffset maps an offset in a decoded text to the text it was decoded from
// an offset inside a replacement moves to the replacement's start, or
// with end to its end, so a span maps to one that covers every replacement it touches.
func encodedOffset(segs []segment, off int, end bool) int {
	delta := 0
	for _, g := range segs {
		if off < g.dstart || off == g.dstart && end {
			break
		}
		if off < g.dend || off == g.dend && end {
			if end {
				return g.end
			}
			return g.start
		}
		delta = g.end - g.dend
	}
	return off + delta
}

// printableASCII reports whether s holds only printable ASCII, tab and newline
// included, the bytes a decoded credential can have.
func printableASCII(s string) bool {
	for i := range len(s) {
		if c := s[i]; c <= '\x08' || c >= '\x7f' {
			return false
		}
	}
	return true
}

// decodeBase64 decodes s as standard or URL-safe base64, and returns "" unless
// the result is printable ASCII.
func decodeBase64(s string) string {
	if !strings.ContainsAny(s, "0123456789+/-_") {
		return ""
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && printableASCII(string(b)) {
			return string(b)
		}
	}
	return ""
}

// decodeHex decodes s as pairs of hex digits, and returns "" unless the result is printable ASCII.
func decodeHex(s string) string {
	if len(s)%2 != 0 || !strings.ContainsAny(s, "0123456789") {
		return ""
	}
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return ""
		}
		b[i] = byte(v)
	}
	if !printableASCII(string(b)) {
		return ""
	}
	return string(b)
}

// decodePercent decodes the %XX escapes in s that percentByte accepts and
// keeps the rest as written. An escape of a control byte stays an escape
// rather than spoiling the whole run, which would let one %00 on a line hide
// every escape after it.
func decodePercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c, ok := percentByte(s, i); ok {
			b.WriteByte(c)
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// percentByte reports whether s[i:] starts with a %XX escape of a byte a
// credential can hold (printable ASCII, tab or newline), and returns the byte.
func percentByte(s string, i int) (byte, bool) {
	if i+3 > len(s) || s[i] != '%' {
		return 0, false
	}
	v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
	if err != nil || v <= 0x08 || v >= 0x7f {
		return 0, false
	}
	return byte(v), true
}

// decodeEscapes decodes a run of \uXXXX escapes.
func decodeEscapes(s string) string {
	var b strings.Builder
	for _, m := range escapeRe.FindAllStringSubmatch(s, -1) {
		v, _ := strconv.ParseUint(m[1], 16, 16) // four hex digits
		if r := rune(uint16(v)); utf8.ValidRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
