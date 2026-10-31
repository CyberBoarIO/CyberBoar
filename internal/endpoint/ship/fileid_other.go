//go:build !unix && !windows

package ship

import "os"

// fileID has no file IDs to read on this platform, so logs are recognized by
// how they start alone.
func fileID(*os.File) (string, error) { return "", nil }
