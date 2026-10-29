package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"cyberboar.dev/cyberboar/pkg/brand"
)

// MaxSize is the largest policy document Load accepts, in bytes.
const MaxSize = 1 << 20

// MaxDepth is the deepest nesting of collections Load accepts.
// A valid policy nests about five levels deep.
const MaxDepth = 64

//go:embed schema/policy.v1.json
var schemaJSON []byte

const schemaURL = "policy.v1.json"

// compiledSchema compiles the embedded schema once.
var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(schemaURL)
})

// Load parses and fully validates a policy document. Every failure is an *Error.
func Load(data []byte) (p *Policy, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, newError(CodeInternal, "", "panic while loading policy: %v", r)
		}
	}()

	if len(data) > MaxSize {
		return nil, newError(CodeTooLarge, "", "policy is %d bytes; the limit is %d", len(data), MaxSize)
	}
	// The parser takes time and memory quadratic in the nesting depth, so
	// a small document nested thousands of levels deep could exhaust memory
	// before it failed. The lexer is linear, so measure the depth first
	if tooDeep(lexer.Tokenize(string(data))) {
		return nil, newError(CodeTooDeep, "", "collections are nested more than %d levels deep", MaxDepth)
	}

	file, perr := parser.ParseBytes(data, 0)
	if perr != nil {
		return nil, newError(CodeSyntax, "", "%s", yaml.FormatError(perr, false, false))
	}
	var docs []*ast.DocumentNode
	for _, d := range file.Docs {
		if d != nil && d.Body != nil {
			docs = append(docs, d)
		}
	}
	switch len(docs) {
	case 0:
		return nil, newError(CodeEmpty, "", "policy document is empty")
	case 1:
	default:
		return nil, newError(CodeMultipleDocuments, "", "found %d YAML documents; a policy file holds exactly one", len(docs))
	}
	if err := rejectYAMLFeatures(docs[0]); err != nil {
		return nil, err
	}
	if err := rejectNonFinite(docs[0]); err != nil {
		return nil, err
	}

	raw, jerr := yaml.YAMLToJSON(data)
	if jerr != nil {
		return nil, newError(CodeSyntax, "", "%s", yaml.FormatError(jerr, false, false))
	}
	generic, jerr := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if jerr != nil {
		return nil, newError(CodeSyntax, "", "%v", jerr)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return nil, newError(CodeSchema, "", "policy must be a mapping")
	}
	if err := checkHeader(obj); err != nil {
		return nil, err
	}

	sch, serr := compiledSchema()
	if serr != nil {
		return nil, newError(CodeInternal, "", "embedded schema does not compile: %v", serr)
	}
	if verr := sch.Validate(generic); verr != nil {
		return nil, schemaError(verr)
	}
	if err := checkIntegers(generic, nil); err != nil {
		return nil, err
	}

	var pol Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&pol); derr != nil {
		// The schema should have caught this, so a mismatch between the schema and the types is a bug
		return nil, newError(CodeInternal, "", "schema accepted a document the types reject: %v", derr)
	}
	if pol.Spec.Defaults.Posture == "" {
		pol.Spec.Defaults.Posture = DenyListed
	}
	if pol.Spec.Files.Containing == "" {
		pol.Spec.Files.Containing = ContainingDeny
	}
	if pol.Spec.Commands.DenyInterpreters == nil {
		deny := true
		pol.Spec.Commands.DenyInterpreters = &deny
	}
	// The tripwire is on only when the policy has a tripwire block, because locking an agent out is the organization's call
	configured := hasTripwire(obj)
	if pol.Spec.Session.Tripwire.Enabled == nil {
		pol.Spec.Session.Tripwire.Enabled = &configured
	}
	if pol.Spec.Session.Tripwire.MaxDenials == 0 {
		pol.Spec.Session.Tripwire.MaxDenials = DefaultMaxDenials
	}
	if pol.Spec.Session.Briefing.Enabled == nil {
		on := true
		pol.Spec.Session.Briefing.Enabled = &on
	}
	if pol.Spec.Secrets.Action == "" {
		pol.Spec.Secrets.Action = SecretsDeny
	}
	if err := validateSession(&pol); err != nil {
		return nil, err
	}
	if err := validateSync(&pol); err != nil {
		return nil, err
	}
	if err := validatePatterns(&pol); err != nil {
		return nil, err
	}
	translateDrivePatterns(&pol.Spec.Files.Rules)
	return &pol, nil
}

// tooDeep reports whether a token stream nests collections more than
// MaxDepth levels deep.
// A flow collection is a level per bracket.
// A block collection is a level per indentation step, so the open block levels are a
// stack of columns. Each sequence entry or "?" key opens a level of its own,
// since "- - x" nests two sequences on one line.
func tooDeep(tokens token.Tokens) bool {
	var cols []int
	flow, line := 0, 0
	for _, tk := range tokens {
		switch tk.Type {
		case token.CommentType:
			continue
		case token.SequenceStartType, token.MappingStartType:
			flow++
		case token.SequenceEndType, token.MappingEndType:
			flow = max(flow-1, 0)
		}
		pos := tk.Position
		if flow == 0 && (pos.Line != line || tk.Type == token.SequenceEntryType || tk.Type == token.MappingKeyType) {
			for len(cols) > 0 && cols[len(cols)-1] >= pos.Column {
				cols = cols[:len(cols)-1]
			}
			cols = append(cols, pos.Column)
		}
		line = pos.Line
		if flow+len(cols) > MaxDepth {
			return true
		}
	}
	return false
}

// checkHeader dispatches on apiVersion and kind before schema validation, so a
// policy for another version gets a precise error instead of schema noise.
func checkHeader(obj map[string]any) error {
	v, ok := obj["apiVersion"].(string)
	switch {
	case obj["apiVersion"] == nil:
		return newError(CodeAPIVersion, "apiVersion", "apiVersion is required; this build supports %q", brand.APIVersion)
	case !ok:
		return newError(CodeAPIVersion, "apiVersion", "apiVersion must be a string")
	case v != brand.APIVersion:
		return newError(CodeAPIVersion, "apiVersion", "unsupported apiVersion %q; this build supports %q", v, brand.APIVersion)
	}
	if k, _ := obj["kind"].(string); k != "Policy" {
		if obj["kind"] == nil {
			return newError(CodeKind, "kind", "kind is required and must be \"Policy\"")
		}
		return newError(CodeKind, "kind", "unsupported kind %v; expected \"Policy\"", obj["kind"])
	}
	return nil
}

// rejectYAMLFeatures refuses YAML constructs that have no use in policy data:
// anchors, aliases and merge keys (expansion bombs, hidden indirection) and tags.
func rejectYAMLFeatures(doc *ast.DocumentNode) error {
	var found *Error
	ast.Walk(visitorFunc(func(n ast.Node) bool {
		if found != nil {
			return false
		}
		var what string
		switch n.(type) {
		case *ast.AnchorNode:
			what = "anchors (&)"
		case *ast.AliasNode:
			what = "aliases (*)"
		case *ast.MergeKeyNode:
			what = "merge keys (<<)"
		case *ast.TagNode:
			what = "tags (!)"
		default:
			return true
		}
		pos := n.GetToken().Position
		found = newError(CodeYAMLFeature, "", "line %d: YAML %s are not supported in policies", pos.Line, what)
		return false
	}), doc)
	if found == nil {
		return nil // not `return found`, since a nil *Error in an error interface is non-nil
	}
	return found
}

// rejectNonFinite refuses YAML's .inf and .nan. They are numbers in YAML,
// but JSON has no way to write them, so the policy can't be read as JSON with them in it.
func rejectNonFinite(doc *ast.DocumentNode) error {
	var found *Error
	ast.Walk(visitorFunc(func(n ast.Node) bool {
		if found != nil {
			return false
		}
		switch n.(type) {
		case *ast.InfinityNode, *ast.NanNode:
			path := strings.TrimPrefix(strings.TrimPrefix(n.GetPath(), "$"), ".")
			found = newError(CodeSchema, path, "got %s, want an integer, or text in quotes", n.GetToken().Value)
			return false
		}
		return true
	}), doc)
	if found == nil {
		return nil
	}
	return found
}

// checkIntegers refuses a number written with a decimal point or an
// exponent, such as 1.0. JSON Schema counts 1.0 as an integer, so the schema
// lets it through, but the field it fills is a Go int.
// The schema has already allowed numbers only where it wants integers.
func checkIntegers(v any, path []string) error {
	switch v := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if err := checkIntegers(v[k], append(path, k)); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range v {
			if err := checkIntegers(e, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return newError(CodeSchema, formatPath(path), "got %s, want an integer written without a decimal point", v)
		}
	}
	return nil
}

// visitorFunc adapts a function to ast.Visitor.
// The function returns false to stop the walk below a node.
type visitorFunc func(ast.Node) bool

// Visit calls f on n and returns f to walk n's children, or nil to stop.
func (f visitorFunc) Visit(n ast.Node) ast.Visitor {
	if n == nil || !f(n) {
		return nil
	}
	return f
}

// hasTripwire reports whether the document has a spec.session.tripwire block.
func hasTripwire(doc map[string]any) bool {
	spec, _ := doc["spec"].(map[string]any)
	session, _ := spec["session"].(map[string]any)
	_, ok := session["tripwire"]
	return ok
}
