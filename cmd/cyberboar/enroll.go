package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/enroll"
	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// maxTokenFile bounds a token file.
// A token is under 64 bytes.
const maxTokenFile = 4096

// runEnroll enrolls this machine with a console, or, when it is already
// enrolled, renews its client certificate if that is due.
// It is safe to run on every MDM check-in. The token comes from a file or the environment,
// never from a flag value, which any user on the machine can read in the process list.
func runEnroll(h host, fs *flag.FlagSet, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	server := fs.String("server", h.getenv(envName("server")), "console base URL, e.g. https://console.example (env "+envName("server")+")")
	tokenFile := fs.String("token-file", "", "file holding the enrollment token, - for stdin; default: env "+envName("enroll-token"))
	stateDir := fs.String("state", h.getenv(envName("state")), "state directory for the endpoint's key and enrollment (env "+envName("state")+
		"; default: $XDG_STATE_HOME/"+brand.Name+"; machine-wide installs use one only root or SYSTEM can read, see docs/deploy-mdm.md)")
	consoleKey := fs.String("console-key", h.getenv(envName("console-key")),
		"PEM public key the console's answers must be signed with; required with --insecure-skip-verify (env "+envName("console-key")+")")
	defaultStorage := h.getenv(envName("key-storage"))
	if defaultStorage == "" {
		defaultStorage = string(keystore.Auto)
	}
	keyStorage := fs.String("key-storage", defaultStorage,
		"where a new endpoint key is made: auto (the TPM, else the OS key store, else a file), tpm, os or file (env "+envName("key-storage")+")")
	tlsOpts := tlsFlags(fs, h.getenv)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s enroll --server URL [flags]\n\n"+
			"Enroll requires a compatible console and its enrollment token.\n"+
			"Local hooks and static-site pull do not need enrollment.\n\n", brand.Name)
		printFlagDefaults(fs)
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	storage, err := keystore.ParseStorage(*keyStorage)
	if fs.NArg() > 0 || *server == "" || err != nil {
		if err != nil {
			fmt.Fprintf(stderr, "enroll: --key-storage: %v\n", err)
		}
		fmt.Fprintf(stderr, "usage: %s enroll --server URL [--token-file FILE] [--state DIR] [--console-key FILE] [--key-storage auto|tpm|os|file] [--ca FILE | --insecure-skip-verify]\n", brand.Name)
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	warnSkipVerify(stderr, "enroll", tlsOpts)
	token, err := readToken(*tokenFile, stdin, h.getenv)
	if err != nil {
		return fail(err)
	}
	if *stateDir == "" {
		if *stateDir, err = h.defaultStateDir(); err != nil {
			return fail(err)
		}
	}
	var pinned *ecdsa.PublicKey
	if *consoleKey != "" {
		if pinned, err = loadConsoleKey(*consoleKey); err != nil {
			return fail(err)
		}
	}
	host, _ := os.Hostname()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ep, how, err := enroll.Once(ctx, enroll.Options{Server: *server, Token: token, StateDir: *stateDir, Hostname: host,
		Version: version, TLS: *tlsOpts, ConsoleKey: pinned, KeyStorage: storage, Now: h.now})
	if errors.Is(err, enroll.ErrNoToken) {
		err = fmt.Errorf("no enrollment token: give --token-file, or set %s", envName("enroll-token"))
	}
	if err != nil {
		return fail(err)
	}
	what := outcomeText[how]
	if how == enroll.Already {
		client, err := ep.Client(*tlsOpts)
		if err != nil {
			return fail(err)
		}
		// Renewing is what enroll is run for on an enrolled machine, so a
		// renewal that fails fails the command (ship and pull go on with the
		// current certificate instead)
		renewed, err := ep.RenewIfDue(ctx, client)
		if err != nil {
			return fail(fmt.Errorf("the certificate could not be renewed (%w); it is valid until %s", err,
				ep.Certificate().Leaf.NotAfter.UTC().Format(time.RFC3339)))
		}
		if renewed {
			what += ", certificate renewed"
		}
	}
	if why := ep.KeySkipped(); why != "" {
		fmt.Fprintf(stderr, "enroll: the endpoint key is in %s (%s); --key-storage tpm makes that an error\n", keyPlace[ep.KeyStorage()], why)
	}
	fmt.Fprintf(stdout, "%s: endpoint %s with %s, policy %s; certificate valid until %s; key in %s (state in %s)\n", what, ep.EndpointID,
		ep.Console, ep.Policy, ep.Certificate().Leaf.NotAfter.UTC().Format(time.RFC3339), keyPlace[ep.KeyStorage()], *stateDir)
	return 0
}

// outcomeText says what enroll.Once did, for the summary line.
var outcomeText = map[enroll.Outcome]string{
	enroll.Enrolled:   "enrolled",
	enroll.Reenrolled: "enrolled again",
	enroll.Already:    "already enrolled",
}

// keyPlace names where an endpoint key is, for messages.
var keyPlace = map[keystore.Storage]string{keystore.TPM: "the TPM", keystore.OS: "the OS key store", keystore.File: "a file"}

// readToken reads the enrollment token from path, from stdin if path is
// "-", or from the environment if there is no path. The token may be empty,
// because an enrolled endpoint needs none.
func readToken(path string, stdin io.Reader, getenv func(string) string) (string, error) {
	if path == "" {
		return strings.TrimSpace(getenv(envName("enroll-token"))), nil
	}
	var r io.Reader = stdin
	if path != "-" {
		// #nosec G703 -- the operator's own --token-file argument
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxTokenFile+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxTokenFile {
		return "", errors.New("the token file is too large to hold an enrollment token")
	}
	return strings.TrimSpace(string(data)), nil
}

// loadConsoleKey reads a PEM "PUBLIC KEY" file holding a P-256 key.
func loadConsoleKey(path string) (*ecdsa.PublicKey, error) {
	// #nosec G703 -- the operator's own --console-key argument
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, rest := pem.Decode(data)
	if b == nil || b.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("%s: not a single PEM \"PUBLIC KEY\" block", path)
	}
	k, err := endpointauth.DecodePublicKey(base64.StdEncoding.EncodeToString(b.Bytes))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return k, nil
}
