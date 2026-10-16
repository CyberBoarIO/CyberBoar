// Package pull fetches a policy bundle from the console and installs it only
// if its signature verifies with the endpoint's pinned public key, it hasn't
// expired and its serial doesn't roll the endpoint back. Any failure leaves
// the installed policy as it was. An endpoint keeps its last good signed
// policy, and with none the hook denies everything.
package pull

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/boundedfile"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
	"cyberboar.dev/cyberboar/internal/engine"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// Options configure one pull.
type Options struct {
	Server    string // console base URL, e.g. https://console.example
	Name      string // policy name (metadata.name)
	Out       string // where the policy is installed, with its signature at Out + ".sig"
	PublicKey ed25519.PublicKey
	TLS       httpsclient.TLS // how the console or static host is verified
	Client    *http.Client    // httpsclient.New(TLS) if nil
	Now       func() time.Time
}

// Once fetches the bundle and installs it if it changed. changed reports
// whether a new policy was installed.
func Once(ctx context.Context, o Options) (changed bool, err error) {
	if o.PublicKey == nil {
		return false, errors.New("no public key: bundles are only installed when their signature verifies")
	}
	if err := httpsclient.CheckURL(o.Server); err != nil {
		return false, err
	}
	u := strings.TrimSuffix(o.Server, "/") + "/api/v1/bundles/" + url.PathEscape(o.Name)
	client := o.Client
	if client == nil {
		if client, err = httpsclient.New(o.TLS); err != nil {
			return false, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("fetching %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return false, fmt.Errorf("the console answered %s: %q", resp.Status, strings.TrimSpace(string(msg)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxSize+1))
	if err != nil {
		return false, err
	}
	if len(body) > bundle.MaxSize {
		return false, fmt.Errorf("bundle is larger than %d bytes", bundle.MaxSize)
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	data, sig, h, err := Check(body, o.Name, o.PublicKey, now())
	if err != nil {
		return false, err
	}
	return install(o.Out, data, sig, h)
}

// Check validates a bundle body completely at the time now and returns the
// policy, its signature file contents and the signature's header. An
// expired bundle is refused, because the hook would deny everything with it.
func Check(body []byte, name string, pub ed25519.PublicKey, now time.Time) (policyData, sig []byte, h sign.Header, err error) {
	var env bundle.Envelope
	if err := strictjson.Decode(body, &env); err != nil {
		return nil, nil, h, fmt.Errorf("bundle is not valid JSON: %v", err)
	}
	switch {
	case env.APIVersion != brand.APIVersion || env.Kind != bundle.Kind:
		return nil, nil, h, fmt.Errorf("bundle is %s %s, want %s %s", env.APIVersion, env.Kind, brand.APIVersion, bundle.Kind)
	case env.Name != name:
		return nil, nil, h, fmt.Errorf("bundle is for policy %q, not %q", env.Name, name)
	case env.Signature == "":
		return nil, nil, h, errors.New("bundle is not signed")
	}
	data := []byte(env.Policy)
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != env.PolicySHA256 {
		return nil, nil, h, errors.New("bundle's policySha256 doesn't match its policy")
	}
	if h, err = sign.Verify(pub, name, data, []byte(env.Signature)); err != nil {
		return nil, nil, h, err
	}
	if h.Expired(now) {
		return nil, nil, h, fmt.Errorf("bundle %s (serial %d) expired at %s", name, h.Serial, h.Expires.Format(sign.TimeFormat))
	}
	p, err := policy.Load(data)
	if err != nil {
		return nil, nil, h, err
	}
	if p.Metadata.Name != name {
		return nil, nil, h, fmt.Errorf("policy is named %q, not %q", p.Metadata.Name, name)
	}
	// As bundle.LoadDir does: a policy the hook can't compile would make it
	// deny everything, so the last good one stays
	if _, err := engine.Compile(p); err != nil {
		return nil, nil, h, err
	}
	return data, []byte(env.Signature), h, nil
}

// install writes a checked policy and its signature to out, unless that
// would roll the endpoint back. The serial must be above the installed
// signature's. An equal serial must come with the installed signature byte
// for byte, and then at most an interrupted install is completed, since the
// same serial with another signature means one release was signed twice
// with different contents. changed reports whether anything was written.
func install(out string, data, sig []byte, h sign.Header) (changed bool, err error) {
	out, unlock, err := lockInstall(out)
	if err != nil {
		return false, err
	}
	defer unlock()
	installed, err := installedSerial(out)
	if err != nil {
		return false, err
	}
	oldSig, _ := sign.ReadSig(out)
	switch {
	case h.Serial < installed:
		return false, fmt.Errorf("the bundle's serial %d is below the installed policy's %d, so it would roll this endpoint back; "+
			"to go back on purpose, sign the older policy again with a serial above %d", h.Serial, installed, installed)
	case h.Serial == installed && !bytes.Equal(oldSig, sig):
		return false, fmt.Errorf("the bundle has the installed policy's serial %d but another signature; a new policy needs a higher serial", installed)
	case h.Serial == installed:
		if old, err := boundedfile.Read(out, policy.MaxSize); err == nil && bytes.Equal(old, data) {
			return false, nil
		}
		// The signature is in place, so only the policy's rename was lost.
		return true, writeAtomic(out, data)
	}
	// The signature goes first. Between the two renames the hook sees a new
	// signature with the old policy and denies, never the reverse, and the
	// new serial is already recorded.
	if err := writeAtomic(out+sign.SigSuffix, sig); err != nil {
		return false, err
	}
	if err := writeAtomic(out, data); err != nil {
		return false, err
	}
	return true, nil
}

// installedSerial returns the serial of the policy installed at out, which
// is the rollback floor. It is 0 when no signature is installed
// An invalid signature file blocks installation because its serial is unknown
func installedSerial(out string) (uint64, error) {
	sig, err := sign.ReadSig(out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, nil
	case err != nil:
		return 0, err
	}
	h, _, err := sign.Parse(sig)
	if err != nil {
		return 0, fmt.Errorf("the installed %s is not a signature file, so its serial is unknown and nothing is installed over it; "+
			"remove the installed policy and its signature to accept any validly signed bundle", out+sign.SigSuffix)
	}
	return h.Serial, nil
}

// writeAtomic replaces path with data. The directory and the file are
// readable by all, because the hook reads the policy, possibly as another
// user than pull.
func writeAtomic(path string, data []byte) error {
	// #nosec G301 -- the hook reads the policy, possibly as another user than pull.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o644)
}
