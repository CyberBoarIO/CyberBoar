package boundedfile_test

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/internal/boundedfile"
)

func TestReadBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := boundedfile.Read(path, 4); err != nil || string(data) != "1234" {
		t.Fatalf("boundary: %q, %v", data, err)
	}
	for _, p := range []string{path, dir, filepath.Join(dir, "missing")} {
		if data, err := boundedfile.Read(p, 3); err == nil || data != nil {
			t.Errorf("%s: %q, %v", p, data, err)
		}
	}
}

func TestReadLimitRange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int64
		content   string
		wantError bool
	}{
		{"maximum", math.MaxInt64, "payload", false},
		{"below maximum", math.MaxInt64 - 1, "payload", false},
		{"zero with empty file", 0, "", false},
		{"zero with nonempty file", 0, "payload", true},
		{"negative", -1, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			data, err := boundedfile.Read(path, tc.limit)
			if tc.wantError {
				if err == nil || data != nil {
					t.Fatalf("Read(%d) = %q, %v; want an error and no data", tc.limit, data, err)
				}
				return
			}
			if err != nil || string(data) != tc.content {
				t.Fatalf("Read(%d) = %q, %v; want %q", tc.limit, data, err, tc.content)
			}
		})
	}
}
