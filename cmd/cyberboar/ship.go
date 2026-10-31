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

	"cyberboar.dev/cyberboar/internal/endpoint/ship"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// runShip sends the audit log to the console the endpoint is enrolled
// with, once or every --every. Every request is authenticated and every
// acceptance checked (docs/protocol).
func runShip(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	auditPath := fs.String("audit", h.getenv(envName("audit")), "the hook's audit log (env "+envName("audit")+")")
	sink := fs.String("sink", h.getenv(envName("sink")), "the console's events URL; only checked: it must be the enrolled console's (env "+envName("sink")+")")
	policyPath := fs.String("policy", h.getenv(envName("policy")),
		"policy file with spec.sync.shipEvery and spec.audit.sink, if set, matching the enrolled console's events URL (env "+envName("policy")+")")
	stateDir := fs.String("state", h.getenv(envName("state")), "state directory: the enrollment, endpoint ID and shipping offsets (env "+envName("state")+"; default: $XDG_STATE_HOME/"+brand.Name+")")
	every := fs.Duration("every", 0, "keep running and ship at this interval (at least 1s); overrides spec.sync.shipEvery; 0 ships once")
	tlsOpts := tlsFlags(fs, h.getenv)
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 || *auditPath == "" || *every != 0 && *every < policy.MinShipInterval {
		fmt.Fprintf(stderr, "usage: %s ship --audit FILE [--state DIR] [--ca FILE | --insecure-skip-verify] [--every DURATION]\n", brand.Name)
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "ship: %v\n", err)
		return 1
	}
	if *stateDir == "" {
		dir, err := h.defaultStateDir()
		if err != nil {
			return fail(err)
		}
		*stateDir = dir
	}
	ep, client, err := enrolledClient(*stateDir, tlsOpts, h.now)
	if err != nil {
		return fail(err)
	}
	if ep == nil {
		return fail(fmt.Errorf("this endpoint is not enrolled (state %s): run `%s enroll --server URL` first; events are only sent as an enrolled endpoint", *stateDir, brand.Name))
	}
	events := ep.Console + "/api/v1/events"
	notConsole := func(what, s string) int {
		return fail(fmt.Errorf("%s %s is not the events URL of the console this endpoint is enrolled with (%s)", what, s, events))
	}
	if *sink != "" && *sink != events {
		return notConsole("the sink", *sink)
	}
	everySet := flagWasSet(fs, "every")
	loadPolicy := func() error {
		if *policyPath == "" {
			return nil
		}
		// The policy is checked even with --sink, since both can come from
		// the environment. One that names another sink, or can't be read,
		// is a configuration to fix
		p, err := endpointPolicy(*policyPath)
		if err != nil {
			return err
		}
		if s := p.Spec.Audit.Sink; s != "" && s != events {
			return fmt.Errorf("the policy's sink %s is not the events URL of the console this endpoint is enrolled with (%s)", s, events)
		}
		if !everySet {
			*every = p.Spec.Sync.ShipInterval()
		}
		return nil
	}
	if err := loadPolicy(); err != nil {
		return fail(err)
	}
	host, _ := os.Hostname()
	o := ship.Options{AuditPath: *auditPath, Sink: events, StateDir: *stateDir, Hostname: host, Version: version, Client: client, Now: h.now}
	warnSkipVerify(stderr, "ship", tlsOpts)

	once := func(ctx context.Context) error {
		// Reload before sending: a changed destination is never sent past,
		// and an updated interval takes effect without restarting the service
		if err := loadPolicy(); err != nil {
			fmt.Fprintf(stderr, "ship: %v (events stay in the audit log)\n", err)
			return err
		}
		if err := renewIfDue(ctx, ep, client, stderr, "ship"); err != nil {
			fmt.Fprintf(stderr, "ship: %v (events stay in the audit log)\n", err)
			return err
		}
		res, err := ship.Once(ctx, o)
		if res.Restarted && res.OldLog != "" {
			fmt.Fprintf(stderr, "ship: %s was rotated since the last run; the rest of the old log, %s, was shipped first.\n", *auditPath, res.OldLog)
		}
		if len(res.Between) > 0 {
			fmt.Fprintf(stderr, "ship: %s was rotated more than once since the last run; %s was shipped too.\n", *auditPath, strings.Join(res.Between, ", "))
		}
		switch {
		case res.Lost > 0 && res.OldLog != "":
			fmt.Fprintf(stderr, "ship: %d of the logs rotated since the last run are compressed, so the lines they got after it were not sent; "+
				"the console is told. Keep rotated logs uncompressed until ship has run.\n", res.Lost)
		case res.Lost > 0:
			fmt.Fprintf(stderr, "ship: %s was truncated or replaced since the last run, and the old log isn't next to it, so any lines it got "+
				"after the last run were not sent; the console is told a log was lost. Rotate the audit log by renaming it, not by "+
				"copying and truncating it, and keep rotated logs uncompressed until ship has run.\n", *auditPath)
		}
		if res.Sent > 0 || res.Skipped > 0 || err == nil && *every == 0 {
			fmt.Fprintf(stdout, "shipped %d events in %d batches, skipped %d invalid lines\n", res.Sent, res.Batches, res.Skipped)
		}
		if err != nil {
			fmt.Fprintf(stderr, "ship: %v\n", err)
		}
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		err := once(ctx)
		if ctx.Err() != nil {
			return 0
		}
		if *every == 0 {
			if err != nil {
				return 1
			}
			return 0
		}
		wait := nextShip(*every, err) // a failure is retried after the wait
		if wait > *every {
			fmt.Fprintf(stderr, "ship: the console asked to wait %s before the next batch\n", wait)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0
		case <-t.C:
		}
	}
}

// nextShip returns how long --every waits after a run. That is the interval,
// or longer if the console answered with a Retry-After (docs/protocol).
func nextShip(every time.Duration, err error) time.Duration {
	return max(every, ship.RetryAfter(err))
}
