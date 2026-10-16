package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// runKeygen creates the key pair that signs policies
// The private key belongs in CI's secret store, and the public key goes to endpoints
func runKeygen(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	priv := fs.String("private", "policy-signing.key", "private key file to create (never overwritten)")
	pub := fs.String("public", "policy-signing.pub", "public key file to create (never overwritten)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "usage: %s keygen [--private FILE] [--public FILE]\n", brand.Name)
		return 2
	}
	if err := sign.Keygen(*priv, *pub); err != nil {
		fmt.Fprintf(stderr, "keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (secret: store it in CI, nowhere else) and %s\n", *priv, *pub)
	return 0
}

// maxLifetime bounds how far ahead sign puts an expiry
// It is the longest an endpoint can be kept on an old policy by a console that stops serving new ones
const maxLifetime = 366 * 24 * time.Hour

// runSign writes POLICY.sig for each policy, with a serial and an expiry
// Endpoints refuse an older policy than the one they have, and stop trusting one nobody signs again
func runSign(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	keyPath := fs.String("key", h.getenv(envName("signing-key")), "private key file (env "+envName("signing-key")+")")
	serialFlag := fs.String("serial", "", "the signature's serial, 1 to 2^63-1: endpoints never install a lower serial than the one they have, "+
		"so use one rising counter for every policy, e.g. $(date +%s)")
	expiresFlag := fs.String("expires", "", "when endpoints stop trusting the policy and deny every call: an RFC 3339 time, "+
		"or a duration from now (2160h is 90 days); at most 366 days ahead. 0 or never: the policy doesn't expire")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s sign --key KEY --serial N --expires WHEN POLICY...\n", brand.Name)
		printFlagDefaults(fs)
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 || *keyPath == "" || *serialFlag == "" || *expiresFlag == "" {
		fs.Usage()
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "sign: %v\n", err)
		return 1
	}
	t := h.now()
	hdr, err := signHeader(*serialFlag, *expiresFlag, t)
	if err != nil {
		return fail(err)
	}
	if hdr.Expires.IsZero() {
		fmt.Fprintf(stderr, "sign: WARNING: no expiry: a server that keeps serving these signatures can keep endpoints on them forever\n")
	}
	priv, err := sign.LoadPrivate(*keyPath)
	if err != nil {
		return fail(err)
	}
	for _, path := range fs.Args() {
		// #nosec G703 -- a policy file the operator named
		data, err := os.ReadFile(path)
		if err != nil {
			return fail(err)
		}
		p, err := policy.Load(data) // never sign a policy that doesn't load
		if err != nil {
			return fail(fmt.Errorf("%s: %v", path, err))
		}
		sig, err := sign.Sign(priv, p.Metadata.Name, data, hdr)
		if err != nil {
			return fail(err)
		}
		// Endpoints that installed the old signature would refuse the new one
		if old, err := sign.ReadSig(path); err == nil && string(old) != sig {
			if oh, _, err := sign.Parse(old); err == nil && oh.Serial >= hdr.Serial {
				return fail(fmt.Errorf("%s is already signed with serial %d: endpoints refuse a new signature unless its serial is higher", path, oh.Serial))
			}
		}
		// Replace the signature as one complete file
		// Readers never see a truncated signature, and an existing symlink cannot redirect the write
		if err := atomicfile.Write(path+sign.SigSuffix, []byte(sig), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "signed  %s (%s, serial %d, expires %s)\n", path, p.Metadata.Name, hdr.Serial, hdr.Expiry())
	}
	return 0
}

// signHeader parses sign's --serial and --expires
// A duration in --expires counts from t
func signHeader(serial, expires string, t time.Time) (sign.Header, error) {
	var h sign.Header
	n, err := strconv.ParseUint(serial, 10, 64)
	if err != nil || n < 1 || n > sign.MaxSerial || strconv.FormatUint(n, 10) != serial {
		return h, fmt.Errorf("--serial %q is not a whole number from 1 to %d", serial, uint64(sign.MaxSerial))
	}
	h.Serial = n
	if expires == "0" || expires == "never" {
		return h, nil // allowed with a warning, since serials alone give no freeze protection
	}
	if at, err := time.Parse(time.RFC3339, expires); err == nil {
		if !at.Equal(at.Truncate(time.Second)) {
			return h, fmt.Errorf("--expires %s has fractions of a second", expires)
		}
		h.Expires = at.UTC()
	} else if d, err := time.ParseDuration(expires); err == nil {
		h.Expires = t.Add(d).UTC().Truncate(time.Second)
	} else {
		return h, fmt.Errorf("--expires %q is neither an RFC 3339 time nor a duration", expires)
	}
	switch {
	case !h.Expires.After(t):
		return h, fmt.Errorf("--expires %s is not in the future", h.Expires.Format(sign.TimeFormat))
	case h.Expires.Sub(t) > maxLifetime:
		return h, fmt.Errorf("--expires %s is more than 366 days ahead: sign again regularly instead", h.Expires.Format(sign.TimeFormat))
	}
	return h, nil
}

// runVerify checks POLICY.sig for each policy
func runVerify(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	pubPath := fs.String("pubkey", h.getenv(envName("pubkey")), "public key file (env "+envName("pubkey")+")")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 || *pubPath == "" {
		fmt.Fprintf(stderr, "usage: %s verify --pubkey KEY POLICY...\n", brand.Name)
		return 2
	}
	pub, err := sign.LoadPublic(*pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	failed := false
	t := h.now()
	for _, path := range fs.Args() {
		hdr, err := verifyFile(pub, path)
		switch {
		case err != nil:
			failed = true
			fmt.Fprintf(stdout, "invalid %s: %v\n", path, err)
		case hdr.Expired(t):
			failed = true
			fmt.Fprintf(stdout, "expired %s (serial %d, expired %s)\n", path, hdr.Serial, hdr.Expires.Format(sign.TimeFormat))
		default:
			fmt.Fprintf(stdout, "ok      %s (serial %d, expires %s)\n", path, hdr.Serial, hdr.Expiry())
		}
	}
	if failed {
		return 1
	}
	return 0
}

// verifyFile checks the signature in path's POLICY.sig file against the policy in path and returns its header
func verifyFile(pub []byte, path string) (sign.Header, error) {
	// #nosec G703 -- a policy file the operator named
	data, err := os.ReadFile(path)
	if err != nil {
		return sign.Header{}, err
	}
	p, err := policy.Load(data)
	if err != nil {
		return sign.Header{}, err
	}
	sig, err := sign.ReadSig(path)
	if err != nil {
		return sign.Header{}, err
	}
	return sign.Verify(pub, p.Metadata.Name, data, sig)
}
