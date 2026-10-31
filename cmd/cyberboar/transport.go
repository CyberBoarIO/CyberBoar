package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/enroll"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
)

// tlsFlags adds the flags that say how enroll, ship and pull verify the
// console. Traffic to a console is always encrypted.
func tlsFlags(fs *flag.FlagSet, getenv func(string) string) *httpsclient.TLS {
	t := &httpsclient.TLS{}
	fs.StringVar(&t.CAFile, "ca", getenv(envName("ca")), "trust only certificates from the CAs in this PEM file, e.g. a private CA or a self-signed certificate (env "+envName("ca")+")")
	fs.BoolVar(&t.SkipVerify, "insecure-skip-verify", false, "don't verify the server's certificate: still encrypted, but the server is not authenticated; prefer --ca")
	return t
}

// warnSkipVerify says on every run that the server is not being verified.
func warnSkipVerify(stderr io.Writer, cmd string, t *httpsclient.TLS) {
	if t.SkipVerify {
		fmt.Fprintf(stderr, "%s: WARNING: --insecure-skip-verify: the server's certificate is not checked; anyone on the network path can pose as it\n", cmd)
	}
}

// enrolledClient returns the endpoint enrolled in stateDir and the client
// that talks to its console. Without an enrollment both are nil.
// Nothing falls back to unauthenticated requests.
func enrolledClient(stateDir string, t *httpsclient.TLS, now func() time.Time) (*enroll.Endpoint, *http.Client, error) {
	ep, err := enroll.Load(stateDir, now)
	if errors.Is(err, enroll.ErrNotEnrolled) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	client, err := ep.Client(*t)
	if err != nil {
		return nil, nil, err
	}
	return ep, client, nil
}

// renewIfDue renews the client certificate when half its lifetime has
// passed. Only an expired certificate is an error. A renewal that fails
// while the certificate still works is retried on the next run.
func renewIfDue(ctx context.Context, ep *enroll.Endpoint, client *http.Client, stderr io.Writer, cmd string) error {
	_, err := ep.RenewIfDue(ctx, client)
	if errors.Is(err, enroll.ErrExpired) {
		return err
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v (the current certificate is valid until %s; retrying next run)\n", cmd, err,
			ep.Certificate().Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
