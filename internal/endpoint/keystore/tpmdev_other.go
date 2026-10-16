//go:build !linux

package keystore

import (
	"fmt"
	"runtime"

	"github.com/google/go-tpm/tpm2/transport"
)

// openPlatformTPM reaches no TPM. On Windows the TPM is used through CNG
// (cng_windows.go), and other systems have no TPM 2.0 device this package knows
func openPlatformTPM() (transport.TPMCloser, error) {
	return nil, fmt.Errorf("TPM 2.0 key files are for Linux, not %s: %w", runtime.GOOS, ErrUnavailable)
}
