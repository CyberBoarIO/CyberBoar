// Package boundedfile reads regular files without allocating beyond a byte limit
package boundedfile

import (
	"fmt"
	"io"
	"math"
	"os"
)

// Read follows symlinks to a regular file and reads at most limit bytes
// Both the path and the opened file are checked: a FIFO or device is refused,
// and growth or replacement cannot defeat the allocation bound
// Filesystem operations may still block, so callers with a deadline must bound the call
func Read(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, limit)
	}
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++ // One extra byte detects a file that grew past the limit
	}
	data, err := io.ReadAll(io.LimitReader(f, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}
