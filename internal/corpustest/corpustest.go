// Package corpustest loads and runs the YAML corpus in testdata/corpus for
// the engine's tests
//
// The corpus is the specification. It states, independently of the Go
// implementation, which verdict each policy and action pair must produce
// Only tests import this package; the binary never links it
package corpustest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"

	"cyberboar.dev/cyberboar/internal/secrets/secretstest"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// File is one corpus file
type File struct {
	Path     string                  `yaml:"-"`
	FS       []FSEntry               `yaml:"fs"`
	Defaults Defaults                `yaml:"defaults"`
	Policies map[string]PolicySource `yaml:"policies"`
	Cases    []Case                  `yaml:"cases"`
}

// FSEntry is one fixture entry: exactly one of File, Dir, Symlink, Files
type FSEntry struct {
	Path    string  `yaml:"path"`
	File    *string `yaml:"file"`
	Dir     bool    `yaml:"dir"`
	Symlink string  `yaml:"symlink"`
	// Files creates a directory of numbered empty files for resource boundaries
	Files int `yaml:"files"`
}

// Defaults holds what every case in a file starts from
type Defaults struct {
	// Action fields are merged into every case's action; the case wins
	Action map[string]any `yaml:"action"`
}

// PolicySource names exactly one of: a file relative to the corpus file, an
// inline mapping, or raw bytes
type PolicySource struct {
	File   string         `yaml:"file"`
	Inline map[string]any `yaml:"inline"`
	Raw    *string        `yaml:"raw"`
}

// Case is one action evaluated against one policy, with the verdict or load
// error it must produce
type Case struct {
	Name   string `yaml:"name"`
	Policy string `yaml:"policy"`
	// Action stays untyped until File.Action merges it with Defaults.Action
	Action map[string]any `yaml:"action"`
	Expect Expect         `yaml:"expect"`
}

// Expect is what a case must produce.
type Expect struct {
	// LoadError is the policy.Code the load must fail with; empty means it must load
	LoadError string `yaml:"loadError"`
	// ErrorPath, when set, is the expected policy.Error.Path ("" is the root)
	ErrorPath *string `yaml:"errorPath"`

	// Decision, Rule and ReasonContains check the verdict of a case with an action
	Decision       string `yaml:"decision"`
	Rule           string `yaml:"rule"`
	ReasonContains string `yaml:"reasonContains"`
}

// Action is the corpus form of engine.Action
type Action struct {
	Tool    string `yaml:"tool"`
	Command string `yaml:"command"`
	Path    string `yaml:"path"`
	// Content is what a write adds; Edits, Insert or Patch say how it
	// changes its file instead of replacing it (package edits; Patch is an
	// apply_patch document whose header names Path). They may hold
	// {{fake:RULE}}, a made-up credential (internal/secrets/secretstest); so
	// may Command and fs files
	Content string  `yaml:"content"`
	Edits   []Edit  `yaml:"edits"`
	Insert  *Insert `yaml:"insert"`
	Patch   string  `yaml:"patch"`
	MCP     struct {
		Server string `yaml:"server"`
		Tool   string `yaml:"tool"`
		Names  string `yaml:"names"` // engine.MCPCall.Names: "", "opencode", "copilot", "codex" or "claude-code"
	} `yaml:"mcp"`
	Cwd        string `yaml:"cwd"`
	CwdUnknown bool   `yaml:"cwdUnknown"`
	// ShellPersists is engine.Action.ShellPersists
	ShellPersists bool              `yaml:"shellPersists"`
	Shell         string            `yaml:"shell"` // engine.Action.Shell
	CDPath        bool              `yaml:"cdpath"`
	Home          string            `yaml:"home"`
	Workspaces    []string          `yaml:"workspaces"`
	Protected     []string          `yaml:"protected"`
	Guarded       []string          `yaml:"guarded"`
	Platform      string            `yaml:"platform"`
	Drives        map[string]string `yaml:"drives"`
	Mounts        map[string]string `yaml:"mounts"`
}

// Edit is the corpus form of edits.Replace
type Edit struct {
	Old string `yaml:"old"`
	New string `yaml:"new"`
	All bool   `yaml:"all"`
}

// Insert is the corpus form of edits.Insert
type Insert struct {
	Line int    `yaml:"line"`
	Text string `yaml:"text"`
}

// Action merges the file defaults into the case action, substitutes {{root}}
// and {{fake:RULE}}, and decodes it strictly
func (f *File) Action(c Case, root string) (*Action, error) {
	merged := map[string]any{}
	for k, v := range f.Defaults.Action {
		merged[k] = v
	}
	for k, v := range c.Action {
		merged[k] = v
	}
	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, err
	}
	data = substituteRoot(data, root)
	var a Action
	if err := yaml.UnmarshalWithOptions(data, &a, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("action: %s", yaml.FormatError(err, false, false))
	}
	// After decoding: a credential can span lines, which YAML text can't take in place
	a.Command, a.Content, a.Patch = secretstest.Expand(a.Command), secretstest.Expand(a.Content), secretstest.Expand(a.Patch)
	for i := range a.Edits {
		a.Edits[i].Old, a.Edits[i].New = secretstest.Expand(a.Edits[i].Old), secretstest.Expand(a.Edits[i].New)
	}
	if a.Insert != nil {
		a.Insert.Text = secretstest.Expand(a.Insert.Text)
	}
	if n := len(a.Edits); n > 0 && a.Insert != nil || n > 0 && a.Patch != "" || a.Insert != nil && a.Patch != "" {
		return nil, errors.New("action: set at most one of edits, insert and patch")
	}
	return &a, nil
}

// LoadFile reads and checks a corpus file. Unknown fields are errors, so a typo
// in the corpus can't silently weaken a case
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.UnmarshalWithOptions(data, &f, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %s", path, yaml.FormatError(err, false, true))
	}
	f.Path = path
	if err := f.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// check reports every problem in the file's policies, cases and fixture
// entries at once, so one run shows them all
func (f *File) check() error {
	var errs []error
	for name, src := range f.Policies {
		n := 0
		if src.File != "" {
			n++
		}
		if src.Inline != nil {
			n++
		}
		if src.Raw != nil {
			n++
		}
		if n != 1 {
			errs = append(errs, fmt.Errorf("policy %q: set exactly one of file, inline, raw", name))
		}
	}
	seen := map[string]bool{}
	used := map[string]bool{}
	for i, c := range f.Cases {
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("case %d has no name", i))
		}
		if seen[c.Name] {
			errs = append(errs, fmt.Errorf("duplicate case name %q", c.Name))
		}
		seen[c.Name] = true
		switch {
		case c.Action != nil && c.Expect.Decision == "":
			errs = append(errs, fmt.Errorf("case %q: has an action but no expected decision", c.Name))
		case c.Action == nil && (c.Expect.Decision != "" || c.Expect.Rule != "" || c.Expect.ReasonContains != ""):
			errs = append(errs, fmt.Errorf("case %q: expects a verdict but has no action", c.Name))
		case c.Action != nil:
			if _, err := f.Action(c, "/root-placeholder"); err != nil {
				errs = append(errs, fmt.Errorf("case %q: %w", c.Name, err))
			}
		}
		if _, ok := f.Policies[c.Policy]; !ok {
			errs = append(errs, fmt.Errorf("case %q: unknown policy %q", c.Name, c.Policy))
		}
		used[c.Policy] = true
	}
	for i, e := range f.FS {
		n := 0
		if e.File != nil {
			n++
		}
		if e.Dir {
			n++
		}
		if e.Symlink != "" {
			n++
		}
		if e.Files > 0 {
			n++
		}
		if e.Files < 0 || e.Files > 100000 {
			errs = append(errs, fmt.Errorf("fs[%d]: files must be between 1 and 100000", i))
		}
		if n != 1 {
			errs = append(errs, fmt.Errorf("fs[%d] %q: set exactly one of file, dir, symlink, files", i, e.Path))
		}
		if !filepath.IsLocal(e.Path) {
			errs = append(errs, fmt.Errorf("fs[%d] %q: path must be relative and stay inside the fixture", i, e.Path))
		}
	}
	for name := range f.Policies {
		if !used[name] {
			errs = append(errs, fmt.Errorf("policy %q is not used by any case", name))
		}
	}
	return errors.Join(errs...)
}

// PolicyBytes returns the document bytes of the named policy, with {{root}} replaced by root
func (f *File) PolicyBytes(name, root string) ([]byte, error) {
	src, ok := f.Policies[name]
	var data []byte
	var err error
	switch {
	case !ok:
		return nil, fmt.Errorf("unknown policy %q", name)
	case src.File != "":
		data, err = os.ReadFile(filepath.Join(filepath.Dir(f.Path), src.File))
	case src.Raw != nil:
		data = []byte(*src.Raw)
	default:
		data, err = yaml.Marshal(src.Inline)
	}
	return substituteRoot(data, root), err
}

func substituteRoot(data []byte, root string) []byte {
	return bytes.ReplaceAll(data, []byte("{{root}}"), []byte(root))
}

// BuildFixture creates the file's fs entries under a new temporary directory
// and returns its symlink-free absolute path, with "/" separators so it can
// be substituted into YAML on Windows too
// The caller removes it
func (f *File) BuildFixture() (string, error) {
	dir, err := os.MkdirTemp("", brand.Name+"-corpus-")
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return dir, err
	}
	root = filepath.ToSlash(root)
	for _, e := range f.FS {
		p := filepath.Join(root, e.Path)
		// #nosec G301 -- test fixtures in a temporary directory
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return root, err
		}
		switch {
		case e.File != nil:
			// #nosec G306 -- test fixtures in a temporary directory
			err = os.WriteFile(p, substituteRoot([]byte(secretstest.Expand(*e.File)), root), 0o644)
		case e.Dir:
			// #nosec G301 -- test fixtures in a temporary directory
			err = os.MkdirAll(p, 0o755)
		case e.Files > 0:
			// #nosec G301 -- resource-boundary fixtures in a temporary directory
			err = os.MkdirAll(p, 0o755)
			for i := 0; err == nil && i < e.Files; i++ {
				// #nosec G306 -- empty test fixtures in a temporary directory
				err = os.WriteFile(filepath.Join(p, fmt.Sprintf("entry-%05d", i)), nil, 0o644)
			}
		default:
			err = os.Symlink(string(substituteRoot([]byte(e.Symlink), root)), p)
		}
		if err != nil {
			return root, err
		}
	}
	return root, nil
}
