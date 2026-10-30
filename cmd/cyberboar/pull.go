package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/pull"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// runPull installs the signed bundle for a policy, once or every --every.
// An enrolled endpoint pulls the policy its console assigned it, with authentication,
// and one that isn't enrolled pulls from a static site (docs/protocol).
func runPull(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	server := fs.String("server", h.getenv(envName("server")), "static site base URL, https; for an enrolled endpoint only checked against its console's (env "+envName("server")+")")
	name := fs.String("name", "", "policy name (metadata.name) to install; for an enrolled endpoint only checked against the one its console assigned")
	out := fs.String("out", h.getenv(envName("policy")), "where the hook reads its policy (env "+envName("policy")+")")
	pubkey := fs.String("pubkey", h.getenv(envName("pubkey")), "public key bundles must be signed with (env "+envName("pubkey")+")")
	stateDir := fs.String("state", h.getenv(envName("state")), "state directory holding the enrollment, if any (env "+envName("state")+"; default: $XDG_STATE_HOME/"+brand.Name+")")
	tlsOpts := tlsFlags(fs, h.getenv)
	every := fs.Duration("every", 0, "keep running and pull at this interval (at least 10s); overrides the installed policy's spec.sync.pullEvery; 0 pulls once")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 || *out == "" || *pubkey == "" || *every != 0 && *every < policy.MinPullInterval {
		fmt.Fprintf(stderr, "usage: %s pull --out FILE --pubkey KEY [--state DIR | --server URL --name POLICY] [--ca FILE | --insecure-skip-verify] [--every DURATION]\n", brand.Name)
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "pull: %v (the installed policy is unchanged)\n", err)
		return 1
	}
	pub, err := sign.LoadPublic(*pubkey)
	if err != nil {
		return fail(err)
	}
	if *stateDir == "" {
		if *stateDir, err = h.defaultStateDir(); err != nil {
			return fail(err)
		}
	}
	ep, client, err := enrolledClient(*stateDir, tlsOpts, h.now)
	if err != nil {
		return fail(err)
	}
	if ep != nil {
		switch {
		case *server != "" && strings.TrimSuffix(*server, "/") != ep.Console:
			return fail(fmt.Errorf("--server %s is not the console this endpoint is enrolled with (%s)", *server, ep.Console))
		case *name != "" && *name != ep.Policy:
			return fail(fmt.Errorf("--name %s is not the policy the console assigned this endpoint (%s)", *name, ep.Policy))
		}
		*server, *name = ep.Console, ep.Policy
	} else if *server == "" || *name == "" {
		fmt.Fprintf(stderr, "pull: this endpoint is not enrolled (state %s): give the static site's --server and the policy's --name, or run `%s enroll`\n", *stateDir, brand.Name)
		return 2
	}
	o := pull.Options{Server: *server, Name: *name, Out: *out, PublicKey: pub, TLS: *tlsOpts, Client: client, Now: h.now}
	warnSkipVerify(stderr, "pull", tlsOpts)
	everySet := flagWasSet(fs, "every")
	loadInterval := func() {
		if !everySet {
			if d, err := installedPullInterval(*out, *name, pub, h.now()); err == nil {
				*every = d
			}
		}
	}
	// An existing signed policy supplies the retry interval even if the first request fails
	// No local policy is required for the first pull
	loadInterval()
	once := func(ctx context.Context) bool {
		if ep != nil {
			if err := renewIfDue(ctx, ep, client, stderr, "pull"); err != nil {
				fail(err)
				return false
			}
		}
		changed, err := pull.Once(ctx, o)
		switch {
		case err != nil:
			fail(err)
			return false
		case changed:
			fmt.Fprintf(stdout, "installed policy %s at %s\n", *name, *out)
		}
		loadInterval()
		return true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var tick *time.Ticker
	interval := *every
	if interval > 0 {
		tick = time.NewTicker(interval)
	}
	defer func() {
		if tick != nil {
			tick.Stop()
		}
	}()
	for {
		ok := once(ctx)
		if ctx.Err() != nil {
			return 0
		}
		if *every == 0 {
			if !ok {
				return 1
			}
			return 0
		}
		if tick == nil {
			tick = time.NewTicker(*every)
		} else if *every != interval {
			tick.Reset(*every)
		}
		interval = *every
		select {
		case <-ctx.Done():
			return 0
		case <-tick.C:
		}
	}
}
