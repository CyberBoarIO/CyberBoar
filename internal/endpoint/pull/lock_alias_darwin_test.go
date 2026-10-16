package pull

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"cyberboar.dev/cyberboar/pkg/sign"
)

func TestInstallLockDarwinAliases(t *testing.T) {
	for _, tc := range []struct{ name, original, alias string }{
		{"case", "policy.yaml", "POLICY.yaml"},
		{"unicode", "polic\u00fd.yaml", "policy\u0301.yaml"},
	} {
		for _, existing := range []bool{false, true} {
			name := tc.name + "/new"
			if existing {
				name = tc.name + "/existing"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				out := filepath.Join(dir, tc.original)
				alias := filepath.Join(dir, tc.alias)
				if existing {
					if err := os.WriteFile(out, nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				_, unlock, err := lockInstall(out)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
				originalInfo, err := os.Stat(out + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				aliasInfo, err := os.Stat(alias + ".lock")
				if errors.Is(err, fs.ErrNotExist) {
					t.Skip("filesystem preserves distinct spellings")
				}
				if err != nil {
					t.Fatal(err)
				}
				if !os.SameFile(originalInfo, aliasInfo) {
					t.Fatal("alias does not refer to the original lock")
				}
				if changed, err := install(alias, nil, nil, sign.Header{Serial: 1}); !errors.Is(err, ErrBusy) || changed {
					t.Fatalf("concurrent install through alias: %v, %v", changed, err)
				}
			})
		}
	}
}
