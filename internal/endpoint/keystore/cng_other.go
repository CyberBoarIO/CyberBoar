//go:build !windows

package keystore

import (
	"fmt"
	"runtime"
)

// createOS always fails. Linux has no persistent key store apart from the
// TPM, and the macOS keychain is not supported yet
func createOS() (*Key, error) {
	return nil, fmt.Errorf("no OS key store is supported on %s: %w", runtime.GOOS, ErrUnavailable)
}

// loadCNG always fails, because the key is in a Windows key store
func loadCNG([]byte) (*Key, error) {
	return nil, fmt.Errorf("the key is in a Windows key store, and this is %s", runtime.GOOS)
}
