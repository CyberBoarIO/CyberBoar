package policy

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Code classifies load failures. Codes are stable strings, not Go identifiers,
// because Error.Error prints them and users and tools read them in load errors.
type Code string

// The error codes Load reports.
const (
	CodeTooLarge          Code = "tooLarge"
	CodeTooDeep           Code = "tooDeep"
	CodeSyntax            Code = "syntax"
	CodeEmpty             Code = "empty"
	CodeMultipleDocuments Code = "multipleDocuments"
	CodeYAMLFeature       Code = "yamlFeature"
	CodeAPIVersion        Code = "apiVersion"
	CodeKind              Code = "kind"
	CodeSchema            Code = "schema"
	CodePattern           Code = "pattern"
	// CodeInternal means a bug in this program, not in the policy.
	CodeInternal Code = "internal"
)

// Error is the only error type Load returns.
type Error struct {
	Code Code
	// Path is the document path of the offending node, e.g. "spec.files.deny[1]".
	// Empty means the document root or no specific node.
	Path string
	Msg  string
}

// Error returns the message with the code and, when set, the path.
func (e *Error) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("policy: %s: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("policy: %s at %s: %s", e.Code, e.Path, e.Msg)
}

func newError(code Code, path, format string, args ...any) *Error {
	return &Error{Code: code, Path: path, Msg: fmt.Sprintf(format, args...)}
}

// englishPrinter formats validator messages in English, whatever the locale.
var englishPrinter = message.NewPrinter(language.English)

// schemaError reduces a validation error tree to its first leaf, deterministically.
func schemaError(err error) *Error {
	ve, ok := errors.AsType[*jsonschema.ValidationError](err)
	if !ok {
		return newError(CodeSchema, "", "%v", err)
	}
	var leaves []*jsonschema.ValidationError
	var collect func(*jsonschema.ValidationError)
	collect = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			leaves = append(leaves, e)
			return
		}
		for _, c := range e.Causes {
			collect(c)
		}
	}
	collect(ve)

	type located struct {
		path []string
		msg  string
	}
	var all []located
	for _, l := range leaves {
		path := slices.Clone(l.InstanceLocation)
		// Point at the offending property itself, not its parent object
		switch k := l.ErrorKind.(type) {
		case *kind.AdditionalProperties:
			path = append(path, slices.Min(k.Properties))
		case *kind.Required:
			path = append(path, slices.Min(k.Missing))
		}
		all = append(all, located{path, l.ErrorKind.LocalizedString(englishPrinter)})
	}
	first := slices.MinFunc(all, func(a, b located) int {
		if c := comparePath(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(a.msg, b.msg)
	})
	return newError(CodeSchema, formatPath(first.path), "%s", first.msg)
}

// comparePath orders document locations segment by segment, indexes by
// number and keys as text, so that deny[2] comes before deny[10].
func comparePath(a, b []string) int {
	for i := range min(len(a), len(b)) {
		x, xerr := strconv.Atoi(a[i])
		y, yerr := strconv.Atoi(b[i])
		c := strings.Compare(a[i], b[i])
		if xerr == nil && yerr == nil {
			c = cmp.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// formatPath joins the segments of a document location into a path such as "spec.files.deny[1]".
// Numeric segments are indexes, and the rest are keys.
func formatPath(segs []string) string {
	var b strings.Builder
	for _, s := range segs {
		if _, err := strconv.Atoi(s); err == nil {
			fmt.Fprintf(&b, "[%s]", s)
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s)
	}
	return b.String()
}
