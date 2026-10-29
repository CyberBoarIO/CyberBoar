// Package httpsclient makes the HTTP client an endpoint uses to reach the
// console or a static policy host. The client speaks only TLS 1.3, verifies
// the server and follows no redirects.
package httpsclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// TLS says how an endpoint verifies the console it talks to
// Traffic is always TLS 1.3, and plain http is never used.
type TLS struct {
	// CAFile is a PEM file of CA certificates. When set, only certificates
	// issued by these CAs are trusted, instead of the system's roots. That
	// is the way to use a private CA or a self-signed certificate and still
	// verify the server.
	CAFile string
	// SkipVerify accepts any server certificate. The traffic stays encrypted,
	// but nothing proves which server it reaches. It exists for self-signed
	// setups, though CAFile is the safer way to the same end.
	SkipVerify bool
}

// maxCAFile bounds the CA bundle read from disk.
const maxCAFile = 1 << 20

// timeout bounds one request, response included.
const timeout = 30 * time.Second

// New returns the client endpoints use. It speaks only TLS 1.3, verifies
// the server as t says, and follows no redirects, which could send audit
// events to another host.
func New(t TLS) (*http.Client, error) {
	if t.CAFile != "" && t.SkipVerify {
		return nil, errors.New("a CA file and skipping verification contradict each other; choose one")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	switch {
	case t.SkipVerify:
		cfg.InsecureSkipVerify = true
	case t.CAFile != "":
		pool, err := loadCAs(t.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.Proxy = http.ProxyFromEnvironment
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// loadCAs returns a pool with the PEM certificates in the file at path.
func loadCAs(path string) (*x509.CertPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// One Read may return less than the whole file, which would drop the
	// CAs after it without an error.
	data, err := io.ReadAll(io.LimitReader(f, maxCAFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCAFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxCAFile)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: no PEM certificates", path)
	}
	return pool, nil
}

// CheckURL accepts only an absolute https URL without credentials. Audit
// events name files and commands, so they must not cross the network in clear
// text, loopback included.
// Credentials in a URL end up in logs.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Parse errors can include the original URL, including credentials
		return errors.New("not a valid URL")
	}
	if u.User != nil {
		return errors.New("credentials in the URL are not allowed")
	}
	if u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%q: not an absolute URL", raw)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q: the scheme must be https; plain http is never used, not even to loopback", raw)
	}
	return nil
}
