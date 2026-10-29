package keystore

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// tpmDevice is the kernel's TPM resource manager.
// The raw /dev/tpm0 is not used, because it serves one process at a time and
// whatever else uses the TPM (tpm2-abrmd, systemd) would race with us on its handles.
const tpmDevice = "/dev/tpmrm0"

func openPlatformTPM() (transport.TPMCloser, error) {
	t, err := linuxtpm.Open(tpmDevice)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s doesn't exist: %w", tpmDevice, ErrUnavailable)
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", tpmDevice, err)
	}
	return t, nil
}
