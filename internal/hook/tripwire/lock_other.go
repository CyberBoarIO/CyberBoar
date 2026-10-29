//go:build !unix && !windows

package tripwire

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("the tripwire is not supported on this platform yet; turn it off in the policy (spec.session.tripwire.enabled: false)")

// openFile always fails, because without file locks concurrent calls could
// lose denials. Failing the open, not only the lock, makes Check fail on the
// first call of a session too, so the hook denies every call from the start.
func openFile(string, int, os.FileMode) (*os.File, error) { return nil, errUnsupported }

func lockShared(*os.File) error    { return errUnsupported }
func lockExclusive(*os.File) error { return errUnsupported }
