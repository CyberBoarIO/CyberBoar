package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"time"

	"cyberboar.dev/cyberboar/internal/boundedfile"
	"cyberboar.dev/cyberboar/internal/policy"
	"cyberboar.dev/cyberboar/pkg/sign"
)

// flagWasSet distinguishes an explicit --every 0s from an omitted flag
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func endpointPolicy(path string) (*policy.Policy, error) {
	data, err := boundedfile.Read(path, policy.MaxSize)
	if err != nil {
		return nil, err
	}
	return policy.Load(data)
}

// installedPullInterval uses only a valid signed policy for scheduling. A
// missing, expired or damaged local policy must not prevent pull repairing it
func installedPullInterval(path, name string, pub ed25519.PublicKey, now time.Time) (time.Duration, error) {
	data, err := boundedfile.Read(path, policy.MaxSize)
	if err != nil {
		return 0, err
	}
	sig, err := sign.ReadSig(path)
	if err != nil {
		return 0, err
	}
	header, err := sign.Verify(pub, name, data, sig)
	if err != nil {
		return 0, err
	}
	if header.Expired(now) {
		return 0, fmt.Errorf("installed policy %s has expired", name)
	}
	p, err := policy.Load(data)
	if err != nil {
		return 0, err
	}
	if p.Metadata.Name != name {
		return 0, fmt.Errorf("installed policy is named %q, not %q", p.Metadata.Name, name)
	}
	return p.Spec.Sync.PullInterval(), nil
}
