package enroll

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/endpoint/keystore"
	"cyberboar.dev/cyberboar/internal/protocoltest"
)

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, KeyFile)
	priv, err := CreateKey(path, keystore.File)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateKey(path, keystore.File); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second CreateKey: %v, want it to refuse", err)
	}
	got, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Storage != keystore.File || !got.Public().(*ecdsa.PublicKey).Equal(priv.Public()) {
		t.Fatal("loaded another key")
	}

	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pemKey, _ := os.ReadFile(path)
	for name, data := range map[string]string{
		"empty":      "",
		"garbage":    "not a key",
		"two blocks": string(pemKey) + string(pemKey),
		"public":     strings.ReplaceAll(string(pemKey), "PRIVATE KEY", "PUBLIC KEY"),
		"headers":    strings.Replace(string(pemKey), "-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1),
		"huge":       strings.Repeat("A", maxStateFile+1),
		"ed25519":    ed25519PEM(t),
		"P-384":      p384PEM(t),
	} {
		if _, err := LoadKey(write(name, data)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadKey(dir); err == nil {
		t.Error("loaded a directory")
	}
}

func ed25519PEM(t *testing.T) string {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func p384PEM(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestWriteReplace(t *testing.T) {
	dir := t.TempDir()
	SecureDir(dir)
	path := filepath.Join(dir, "f")
	for _, s := range []string{"one", "two"} {
		if err := writeReplace(path, []byte(s)); err != nil {
			t.Fatal(err)
		}
		if got, err := readPrivate(path, 10); err != nil || string(got) != s {
			t.Fatalf("%q, %v", got, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left temporary files: %v", entries)
	}
}

// enrolledState returns a state directory enrolled with a test console.
func enrolledState(t *testing.T) string {
	t.Helper()
	_, o := enrolled(t, protocoltest.New(t, "", nil))
	return o.StateDir
}

// TestUnixPermissions checks that a key, record, certificate or state
// directory that other users may read or change is refused, as ssh refuses
// such keys.
func TestUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := enrolledState(t)
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(dir, KeyFile), 0o640},
		{filepath.Join(dir, KeyFile), 0o604},
		{filepath.Join(dir, EnrollmentFile), 0o644},
		{filepath.Join(dir, EnrollmentFile), 0o620},
		{filepath.Join(dir, CertificateFile), 0o664},
		{dir, 0o770},
		{dir, 0o702},
	} {
		fi, _ := os.Stat(tc.path)
		os.Chmod(tc.path, tc.mode)
		if _, err := Load(dir, nil); err == nil || err == ErrNotEnrolled {
			t.Errorf("%s with mode %04o: %v", filepath.Base(tc.path), tc.mode, err)
		}
		os.Chmod(tc.path, fi.Mode().Perm())
	}
	if _, err := Load(dir, nil); err != nil {
		t.Fatalf("restored: %v", err)
	}
	// The directory may be listed by others, not written.
	os.Chmod(dir, 0o755)
	if _, err := Load(dir, nil); err != nil {
		t.Errorf("0755 directory: %v", err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("SecureDir left mode %04o", fi.Mode().Perm())
	}
	for _, f := range []string{KeyFile, EnrollmentFile, CertificateFile} {
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %04o", f, fi.Mode().Perm())
		}
	}
}

// TestWindowsACL checks that the key gets a DACL for SYSTEM and this user
// only, and that a file granting access to Users is refused.
func TestWindowsACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows DACLs")
	}
	dir := enrolledState(t)
	for _, f := range []string{KeyFile, EnrollmentFile, CertificateFile} {
		if err := checkPrivate(filepath.Join(dir, f), nil); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if err := checkPrivate(dir, nil); err != nil {
		t.Fatalf("state directory: %v", err)
	}
	open := filepath.Join(t.TempDir(), "open")
	os.WriteFile(open, []byte("x"), 0o600)
	if err := grantUsers(open); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(open, nil); err == nil {
		t.Error("a file Users can read passed")
	}
}

func TestLoadStateDirectory(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing"), nil); err != ErrNotEnrolled {
		t.Fatalf("no state directory: %v, want ErrNotEnrolled", err)
	}
	empty := t.TempDir()
	SecureDir(empty)
	if _, err := Load(empty, nil); err != ErrNotEnrolled {
		t.Fatalf("empty state: %v, want ErrNotEnrolled", err)
	}
	dir := enrolledState(t)
	if _, err := Load(dir, nil); err != nil {
		t.Fatal(err)
	}

	broken := func(name string, edit func(dir string)) {
		t.Helper()
		d := enrolledState(t)
		edit(d)
		if _, err := Load(d, nil); err == nil || err == ErrNotEnrolled || errors.Is(err, ErrUnfinished) {
			t.Errorf("%s: %v, want an error of its own", name, err)
		}
	}
	rewrite := func(name, data string) func(string) {
		return func(d string) {
			p := filepath.Join(d, name)
			os.Remove(p)
			if err := writeNew(p, []byte(data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	edit := func(old, new string) func(string) {
		return func(d string) {
			data, _ := os.ReadFile(filepath.Join(d, EnrollmentFile))
			rewrite(EnrollmentFile, strings.Replace(string(data), old, new, 1))(d)
		}
	}
	// Only a key without its record or certificate is an enrollment enroll
	// may finish.
	for _, f := range []string{EnrollmentFile, CertificateFile} {
		d := enrolledState(t)
		os.Remove(filepath.Join(d, f))
		if _, err := Load(d, nil); !errors.Is(err, ErrUnfinished) {
			t.Errorf("key without %s: %v, want ErrUnfinished", f, err)
		}
	}
	other := enrolledState(t)
	otherCert, _ := os.ReadFile(filepath.Join(other, CertificateFile))
	otherKey, _ := os.ReadFile(filepath.Join(other, KeyFile))
	broken("key without ID", func(d string) { os.Remove(filepath.Join(d, IDFile)) })
	broken("other ID", rewrite(IDFile, "1b6a3f4e-2c1d-4e5f-8a9b-0c1d2e3f4a5b\n"))
	broken("broken key", rewrite(KeyFile, "broken"))
	broken("another endpoint's key", rewrite(KeyFile, string(otherKey)))
	broken("another endpoint's certificate", rewrite(CertificateFile, string(otherCert)))
	broken("broken certificate", rewrite(CertificateFile, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	broken("broken record", rewrite(EnrollmentFile, "{"))
	broken("unknown field", edit(`"policy"`, `"x": 1, "policy"`))
	broken("http console", edit(`"https:`, `"http:`))
	broken("console with user", edit(`"https://`, `"https://u@`))
	broken("console with slash", edit(`",
  "endpointId"`, `/",
  "endpointId"`))
	broken("bad policy", edit(`"baseline"`, `"../x"`))
	broken("bad console key", edit(`"MFkw`, `"MFkx`))
	broken("state is a file", func(d string) {
		os.RemoveAll(d)
		os.WriteFile(d, nil, 0o600)
	})
	if runtime.GOOS != "windows" {
		broken("state is a symlink", func(d string) {
			real := d + ".real"
			os.Rename(d, real)
			os.Symlink(real, d)
		})
	}
}
