//go:build !unix && !windows

package ship

import "errors"

// lock is not implemented on this platform, so shipping refuses to run
// rather than risk two runs sending the same events.
func lock(string) (func(), error) {
	return nil, errors.New("shipping is not supported on this platform yet")
}
