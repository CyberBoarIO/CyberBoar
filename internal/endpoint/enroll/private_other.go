//go:build !unix && !windows

package enroll

import (
	"fmt"
	"os"
	"runtime"
)

// On other systems nothing can show that the key is private, so no key is
// written or read.

func securePath(path string, _ os.FileInfo) error {
	return fmt.Errorf("%s: endpoint keys are not supported on %s", path, runtime.GOOS)
}

func checkPrivate(path string, _ os.FileInfo) error { return securePath(path, nil) }
