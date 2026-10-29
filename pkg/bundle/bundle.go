// Package bundle reads a directory of policy files and turns each valid one
// into a policy bundle, the document the console serves to endpoints.
//
// The bundle format is a client contract. It is a JSON envelope, versioned by
// apiVersion and kind, holding the policy file byte for byte, so the
// SHA-256 an endpoint reports in its audit events (policySha256) can be
// compared with the bundle's to detect drift. The format is specified in
// docs/protocol, and this package is its reference implementation.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// Kind is the bundle envelope's kind.
const Kind = "PolicyBundle"

// MaxFiles bounds the number of policy files LoadDir reads from one directory.
const MaxFiles = 1000

// MaxSize bounds an encoded bundle. JSON can expand each policy byte to a
// six-byte escape; the remaining space holds the envelope and signature.
const MaxSize = 6*policy.MaxSize + (4 << 10)

// Envelope is the bundle document. Add fields only with a new apiVersion.
type Envelope struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	PolicySHA256 string `json:"policySha256"` // lowercase hex SHA-256 of Policy
	Policy       string `json:"policy"`       // the policy file, byte for byte
	// Signature is the contents of the POLICY.sig file (sign package).
	// Endpoints verify it with their pinned public key and ignore a bundle that fails.
	Signature string `json:"signature,omitempty"`
}

// Bundle is a servable bundle. Its name is a policy's metadata.name, which the
// policy schema limits to a DNS label, so it is safe as a URL path segment.
type Bundle struct {
	Name         string // metadata.name of the policy
	PolicySHA256 string // lowercase hex SHA-256 of the policy file
	ETag         string // quoted strong ETag made from the SHA-256 of Body
	Body         []byte // the encoded Envelope, newline included
}

// Source is one policy file in the directory.
type Source struct {
	File         string // base name
	Name         string // metadata.name, when the policy loaded
	PolicySHA256 string // of the file's bytes
	Data         []byte
	Policy       *policy.Policy // nil when Err is set
	Sig          string         // POLICY.sig contents, if any
	// Header is the signature's serial and expiry. It is verified when
	// LoadDir had a key and read unchecked otherwise. It is zero when Sig
	// isn't a signature file.
	Header sign.Header
	Err    error
}

// Set is everything found in a policy directory.
type Set struct {
	Sources []Source // by file name
	bundles map[string]*Bundle
}

// Bundle returns the bundle for a policy name.
func (s *Set) Bundle(name string) (*Bundle, bool) {
	if s == nil {
		return nil, false
	}
	b, ok := s.bundles[name]
	return b, ok
}

// Bundles returns every servable bundle, by name.
func (s *Set) Bundles() []*Bundle {
	if s == nil {
		return nil
	}
	out := make([]*Bundle, 0, len(s.bundles))
	for _, b := range s.bundles {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b *Bundle) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// LoadDir reads the *.yaml and *.yml files directly in dir. Hidden files and
// directories are skipped. A symlink is followed only if it resolves to a
// regular file inside dir, since Kubernetes ConfigMap volumes are built from
// such links. A link pointing elsewhere, for a policy or its POLICY.sig, is
// listed as not served and is never read, so that a console cannot show a file
// from outside the directory.
// A file that fails to load, or shares its metadata.name with another file, is
// kept as a Source with Err set and is not served, so an endpoint keeps its
// last good policy rather than getting a broken or ambiguous one. An error
// is returned if the directory cannot be read or contains too many policy files.
//
// With pub set, a policy is served only with a valid POLICY.sig from that
// key. Without it, a signature file is passed on unchecked (endpoints verify
// it anyway).
func LoadDir(dir string, pub ed25519.PublicKey) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	set := &Set{bundles: map[string]*Bundle{}}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !(e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0) ||
			!(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		if len(set.Sources) == MaxFiles {
			return nil, fmt.Errorf("more than %d policy files in %s", MaxFiles, dir)
		}
		path := filepath.Join(realDir, n)
		if e.Type()&fs.ModeSymlink != 0 {
			target, ok := inside(realDir, path)
			if !ok {
				set.Sources = append(set.Sources, Source{File: n, Err: errors.New("a symlink that doesn't resolve to a file inside the policy directory")})
				continue
			}
			path = target
		}
		src := loadFile(path)
		src.File = n
		if src.Err == nil {
			// The signature may be a link too (a ConfigMap's are), held to the
			// same rule, and checked before anything is read through it.
			var sig []byte
			err := fs.ErrNotExist
			if _, lerr := os.Lstat(path + sign.SigSuffix); lerr == nil {
				if _, ok := inside(realDir, path+sign.SigSuffix); !ok {
					src.Err = errors.New(n + sign.SigSuffix + " is a symlink that doesn't resolve to a file inside the policy directory")
				} else {
					sig, err = sign.ReadSig(path)
				}
			}
			switch {
			case src.Err != nil:
			case err == nil:
				src.Sig = string(sig)
				src.Header, _, _ = sign.Parse(sig)
			case pub != nil:
				src.Err = errors.New("unsigned: no " + n + sign.SigSuffix)
			}
			if pub != nil && src.Err == nil {
				if src.Header, err = sign.Verify(pub, src.Name, src.Data, sig); err != nil {
					src.Err = fmt.Errorf("%s: %w", n+sign.SigSuffix, err)
				}
			}
		}
		set.Sources = append(set.Sources, src)
	}

	count := map[string]int{}
	for _, s := range set.Sources {
		if s.Err == nil {
			count[s.Name]++
		}
	}
	for i := range set.Sources {
		s := &set.Sources[i]
		if s.Err != nil {
			continue
		}
		if count[s.Name] > 1 {
			s.Err = fmt.Errorf("another file also defines policy %q; neither is served", s.Name)
			continue
		}
		b, err := build(s)
		if err != nil {
			s.Err = err
			continue
		}
		set.bundles[s.Name] = b
	}
	return set, nil
}

// inside resolves the links of path, a file in realDir, and reports whether
// it ends at a file inside realDir. A path without links is inside.
func inside(realDir, path string) (string, bool) {
	target, err := filepath.EvalSymlinks(path)
	return target, err == nil && strings.HasPrefix(target, realDir+string(filepath.Separator))
}

func loadFile(path string) Source {
	s := Source{File: filepath.Base(path)}
	f, err := os.Open(path)
	if err != nil {
		s.Err = err
		return s
	}
	defer f.Close()
	// path has no symlinks left, so if it has one now, it was swapped in
	// since it was resolved
	lst, err1 := os.Lstat(path)
	fst, err2 := f.Stat()
	if err1 != nil || err2 != nil || !lst.Mode().IsRegular() || !os.SameFile(lst, fst) {
		s.Err = errors.New("the file changed while it was read, or is not a regular file")
		return s
	}
	data, err := io.ReadAll(io.LimitReader(f, policy.MaxSize+1))
	if err != nil {
		s.Err = err
		return s
	}
	s.Data = data
	sum := sha256.Sum256(data)
	s.PolicySHA256 = hex.EncodeToString(sum[:])
	if !utf8.Valid(data) {
		s.Err = errors.New("the file is not valid UTF-8")
		return s
	}
	p, err := policy.Load(data)
	if err != nil {
		s.Err = err
		return s
	}
	if _, err := engine.Compile(p); err != nil {
		s.Err = err
		return s
	}
	s.Name, s.Policy = p.Metadata.Name, p
	return s
}

func build(s *Source) (*Bundle, error) {
	body, err := json.Marshal(Envelope{APIVersion: brand.APIVersion, Kind: Kind, Name: s.Name,
		PolicySHA256: s.PolicySHA256, Policy: string(s.Data), Signature: s.Sig})
	if err != nil {
		return nil, err
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	return &Bundle{Name: s.Name, PolicySHA256: s.PolicySHA256, ETag: `"sha256-` + hex.EncodeToString(sum[:]) + `"`, Body: body}, nil
}
