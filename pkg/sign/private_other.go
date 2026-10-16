//go:build !windows

package sign

import "cyberboar.dev/cyberboar/internal/atomicfile"

func writePrivate(path string, data []byte) error {
	return atomicfile.WriteNew(path, data, 0o600)
}
