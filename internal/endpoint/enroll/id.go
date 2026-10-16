package enroll

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cyberboar.dev/cyberboar/internal/atomicfile"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// EndpointID returns this machine's endpoint ID, creating it on first use.
// A file that exists but doesn't hold a valid ID is an error rather than
// being replaced, so the endpoint doesn't silently become a new fleet entry.
func EndpointID(stateDir string) (string, error) {
	path := filepath.Join(stateDir, IDFile)
	for range 2 {
		data, err := os.ReadFile(path)
		if err == nil {
			id := strings.TrimSpace(string(data))
			if !endpointauth.ValidEndpointID(id) {
				return "", fmt.Errorf("%s does not hold a valid endpoint ID; remove it to create a new one", path)
			}
			return id, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return "", err
		}
		id := newUUID()
		err = atomicfile.WriteNew(path, []byte(id+"\n"), 0o600)
		if errors.Is(err, os.ErrExist) {
			continue // another run created it first, so read theirs
		}
		if err != nil {
			return "", err
		}
		return id, nil
	}
	return "", fmt.Errorf("%s: could not create or read the endpoint ID", path)
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:]) // never fails (crypto/rand)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
