package enroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// These are the files an enrolled endpoint keeps in its state directory.
// Where the console is, which policy the endpoint gets, the key that proves
// who it is and the console key it trusts all decide what the endpoint
// enforces, so they must be out of an agent's reach. A machine-wide install
// keeps them in a directory only root or SYSTEM can read (docs/deploy-mdm.md).
const (
	KeyFile         = "endpoint.key"
	CertificateFile = "endpoint.crt"
	EnrollmentFile  = "enrollment.json"
	IDFile          = "endpoint-id" // written by EndpointID
)

// maxStateFile bounds a key file, which is one PEM block, and the small JSON
// record. maxCertFile bounds a certificate chain.
const (
	maxStateFile = 4096
	maxCertFile  = endpointauth.MaxCertificatePEM
)

// readPrivate reads a file that must be private to the current user
// (checkPrivate), at most limit bytes.
func readPrivate(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkPrivate(path, fi); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// SecureDir creates the state directory if needed and makes it private to
// the current user. On Unix its mode becomes 0700. On Windows it gets a DACL
// that grants access only to SYSTEM and the current user and inherits
// nothing. It refuses a directory another user owns and a symbolic link.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return securePath(dir, fi)
}

// writeNew creates path (it must not exist), private to the current user,
// and writes data to disk before returning.
func writeNew(path string, data []byte) error {
	if err := atomicfile.WriteNew(path, data, 0o600); err != nil {
		return err
	}
	if err := securePath(path, nil); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// writeReplace replaces path atomically with a file private to the current
// user. A reader sees the old contents or the new, never part of either.
func writeReplace(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+rand.Text()[:12])
	if err := writeNew(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// CreateKey makes a new P-256 key in the store storage asks for
// (keystore.Create) and writes its key file to path. It never replaces an
// existing file. The key file is private to the current user. If it can't
// be written, a key in the TPM or the OS key store is removed again.
func CreateKey(path string, storage keystore.Storage) (*keystore.Key, error) {
	k, err := keystore.Create(storage)
	if err != nil {
		return nil, fmt.Errorf("creating the endpoint key (%s): %w", storage, err)
	}
	if err := writeNew(path, k.KeyFile); err != nil {
		if derr := k.Discard(); derr != nil {
			err = fmt.Errorf("%w; and removing the new key again: %v", err, derr)
		}
		return nil, err
	}
	return k, nil
}

// LoadKey returns the key the key file at path names (keystore.Load). It
// refuses a key file that anyone but the current user (and, on Windows,
// SYSTEM and Administrators) may read or change, as ssh does.
func LoadKey(path string) (*keystore.Key, error) {
	data, err := readPrivate(path, maxStateFile)
	if err != nil {
		return nil, err
	}
	k, err := keystore.Load(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return k, nil
}

// Enrollment is what an endpoint keeps about its enrollment besides its key
// and certificate. The rest of its configuration comes from here, so a
// machine needs only its state directory and the policy signing key.
type Enrollment struct {
	Console    string `json:"console"` // the console's base URL
	EndpointID string `json:"endpointId"`
	Policy     string `json:"policy"`     // the policy the console assigned
	ConsoleKey string `json:"consoleKey"` // the pinned key the console's answers are signed with
}

// checkBaseURL returns an error unless raw is a console base URL, which is
// an https URL with no credentials, query, fragment or trailing slash.
func checkBaseURL(raw string) error {
	if err := httpsclient.CheckURL(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(raw, "/") {
		return fmt.Errorf("%q is not a console base URL such as https://console.example", raw)
	}
	return nil
}

// check validates a record's fields and returns the console key it pins.
func (e Enrollment) check() (*ecdsa.PublicKey, error) {
	if err := checkBaseURL(e.Console); err != nil {
		return nil, err
	}
	if !endpointauth.ValidEndpointID(e.EndpointID) {
		return nil, errors.New("endpointId is not a valid endpoint ID")
	}
	if !endpointauth.ValidPolicyName(e.Policy) {
		return nil, fmt.Errorf("policy %q is not a policy name", e.Policy)
	}
	k, err := endpointauth.DecodePublicKey(e.ConsoleKey)
	if err != nil {
		return nil, fmt.Errorf("consoleKey: %v", err)
	}
	return k, nil
}

// saveEnrollment writes the enrollment record.
func saveEnrollment(stateDir string, e Enrollment) error {
	if _, err := e.check(); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(e, "", "  ")
	return writeReplace(filepath.Join(stateDir, EnrollmentFile), append(data, '\n'))
}

// LoadEnrollment reads the enrollment record. It returns ErrNotEnrolled when
// there is none.
func LoadEnrollment(stateDir string) (Enrollment, error) {
	path := filepath.Join(stateDir, EnrollmentFile)
	data, err := readPrivate(path, maxStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return Enrollment{}, ErrNotEnrolled
	}
	if err != nil {
		return Enrollment{}, err
	}
	var e Enrollment
	if err := strictjson.Decode(data, &e); err != nil {
		return Enrollment{}, fmt.Errorf("%s: %v", path, err)
	}
	if _, err := e.check(); err != nil {
		return Enrollment{}, fmt.Errorf("%s: %v", path, err)
	}
	return e, nil
}

// ErrNotEnrolled is returned when the state directory holds no enrollment.
var ErrNotEnrolled = errors.New("this endpoint is not enrolled")

// ErrUnfinished is wrapped in Load's error for a state directory with a key
// but no enrollment record or certificate. That is an enrollment whose answer
// was lost, and enrolling again with the same key completes it.
var ErrUnfinished = errors.New("enrollment didn't finish")

// parseChain reads a PEM certificate chain the endpoint saved, and checks
// that it is the endpoint's (endpointauth.MatchCertificate). Its validity
// period is checked where it is used.
func parseChain(data []byte, id string, pub *ecdsa.PublicKey) (*tls.Certificate, error) {
	cert := &tls.Certificate{}
	for rest := data; len(bytes.TrimSpace(rest)) > 0; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return nil, errors.New("not a series of PEM CERTIFICATE blocks")
		}
		cert.Certificate = append(cert.Certificate, b.Bytes)
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := endpointauth.MatchCertificate(leaf, id, pub); err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return cert, nil
}

// Load returns the enrolled endpoint in stateDir. Without a key it returns
// ErrNotEnrolled. Anything else wrong, such as a key without its record or
// certificate (ErrUnfinished), a record for another endpoint ID, or files
// others could read or change, is an error of its own, so a client never
// falls back to unauthenticated requests. An expired certificate is not an
// error here, because the endpoint can still enroll again with its key. now
// is the clock the endpoint checks its certificate against. If nil,
// time.Now is used.
func Load(stateDir string, now func() time.Time) (*Endpoint, error) {
	dir, err := os.Lstat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", stateDir)
	}
	if err := checkPrivate(stateDir, dir); err != nil {
		return nil, err
	}
	key, err := LoadKey(filepath.Join(stateDir, KeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	e, err := LoadEnrollment(stateDir)
	if errors.Is(err, ErrNotEnrolled) {
		return nil, fmt.Errorf("%s has an endpoint key but no %s: %w; enroll again", stateDir, EnrollmentFile, ErrUnfinished)
	}
	if err != nil {
		return nil, err
	}
	consoleKey, _ := e.check()
	data, err := os.ReadFile(filepath.Join(stateDir, IDFile))
	if err != nil || strings.TrimSpace(string(data)) != e.EndpointID {
		return nil, fmt.Errorf("%s: the enrollment is for endpoint %s, but %s doesn't hold that ID", stateDir, e.EndpointID, IDFile)
	}
	certPath := filepath.Join(stateDir, CertificateFile)
	data, err = readPrivate(certPath, maxCertFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s has no %s: %w; enroll again", stateDir, CertificateFile, ErrUnfinished)
	}
	if err != nil {
		return nil, err
	}
	cert, err := parseChain(data, e.EndpointID, key.Public().(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", certPath, err)
	}
	cert.PrivateKey = key
	ep := &Endpoint{Enrollment: e, StateDir: stateDir, key: key, consoleKey: consoleKey, now: now}
	ep.cert.Store(cert)
	return ep, nil
}
