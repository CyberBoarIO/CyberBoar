package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// bundlePath is where a bundle lives under a static site's root, the path
// `cyberboar pull` fetches (docs/protocol).
func bundlePath(root, name string) string {
	return filepath.Join(root, "api", "v1", "bundles", name)
}

// runBundle writes the signed bundles for a policy directory as a static
// site, so any web server can serve them without a console.
//
// If one policy doesn't load or isn't signed with the key, nothing is
// written, and an expired signature counts as not signed. Every bundle is
// written and synced to a temporary file before any is published, so a
// failed write leaves the site as it was. Only the renames that publish
// them, one per bundle in the same directory, could stop halfway. Bundles of
// policies no longer in the directory are then removed, so the generated
// bundles match the policy directory.
func runBundle(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	pubPath := fs.String("pubkey", h.getenv(envName("pubkey")), "public key the policies must be signed with (env "+envName("pubkey")+")")
	out := fs.String("out", "", "site root to write api/v1/bundles/NAME under")
	fs.Usage = func() { fmt.Fprintf(stderr, "usage: %s bundle --pubkey KEY --out SITE POLICYDIR\n", brand.Name) }
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 || *pubPath == "" || *out == "" {
		fs.Usage()
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "bundle: %v\n", err)
		return 1
	}
	pub, err := sign.LoadPublic(*pubPath)
	if err != nil {
		return fail(err)
	}
	set, err := bundle.LoadDir(fs.Arg(0), pub)
	if err != nil {
		return fail(err)
	}
	failed := false
	t := h.now()
	for _, s := range set.Sources {
		switch {
		case s.Err != nil:
			fmt.Fprintf(stderr, "bundle: %s: %v\n", s.File, s.Err)
			failed = true
		case s.Header.Expired(t):
			// Endpoints would refuse it, so it must be signed again
			fmt.Fprintf(stderr, "bundle: %s: the signature expired at %s\n", s.File, s.Header.Expires.Format(sign.TimeFormat))
			failed = true
		}
	}
	bundles := set.Bundles()
	switch {
	case failed:
		fmt.Fprintln(stderr, "bundle: nothing written")
		return 1
	case len(bundles) == 0:
		// An empty site would remove every bundle below, so none is written
		fmt.Fprintf(stderr, "bundle: no policies in %s\n", fs.Arg(0))
		return 1
	}
	if err := publish(*out, bundles, stage, stdout); err != nil {
		return fail(err)
	}
	return 0
}

// publish writes bundles under site and removes the bundles of policies that
// no longer exist. Every bundle is staged before any replaces the
// one published, so after a failed write nothing is published.
func publish(site string, bundles []*bundle.Bundle, stage func(dir, name string, data []byte) (string, error), stdout io.Writer) error {
	dir := bundlePath(site, "")
	// #nosec G301 -- bundles are served to every endpoint, so they are public
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temps := make([]string, len(bundles))
	defer func() {
		for _, tmp := range temps {
			if tmp != "" {
				os.Remove(tmp)
			}
		}
	}()
	for i, b := range bundles {
		var err error
		if temps[i], err = stage(dir, b.Name, b.Body); err != nil {
			return fmt.Errorf("%v; nothing published", err)
		}
	}
	current := map[string]bool{}
	for i, b := range bundles {
		if err := os.Rename(temps[i], bundlePath(site, b.Name)); err != nil {
			return err
		}
		temps[i], current[b.Name] = "", true
		fmt.Fprintf(stdout, "wrote   %s (policy %s, ETag %s)\n", bundlePath(site, b.Name), b.PolicySHA256, b.ETag)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		// Remove only what this command writes, which is files named like a
		// policy. Anything else an operator put there stays
		if n := e.Name(); e.Type().IsRegular() && policy.IsName(n) && !current[n] {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "removed %s (no such policy any more)\n", filepath.Join(dir, n))
		}
	}
	return nil
}

// stage writes a bundle to a synced temporary file in dir and returns its
// name. The file is readable by all, because bundles are served to every
// endpoint and so are public.
func stage(dir, name string, data []byte) (string, error) {
	return atomicfile.Stage(dir, name, data, 0o644)
}
