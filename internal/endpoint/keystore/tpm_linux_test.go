package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// swtpm is a software TPM in a child process, reached over a Unix socket
// that carries raw TPM commands
type swtpm struct{ sock string }

// startSWTPM starts a fresh software TPM
// Without swtpm the test is skipped, except in CI, which installs it
func startSWTPM(t *testing.T) *swtpm {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("swtpm is not installed; CI installs it so the TPM key store is tested")
		}
		t.Skip("swtpm is not installed")
	}
	dir := t.TempDir()
	s := &swtpm{sock: filepath.Join(dir, "tpm.sock")}
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+s.sock, "--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--flags", "not-need-init,startup-clear")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; ; i++ {
		if _, err := os.Stat(s.sock); err == nil {
			break
		}
		if i == 100 {
			t.Fatalf("swtpm didn't start: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s
}

func (s *swtpm) open() (transport.TPMCloser, error) {
	c, err := net.Dial("unix", s.sock)
	if err != nil {
		return nil, err
	}
	return &rawTPM{c}, nil
}

type rawTPM struct{ net.Conn }

func (r *rawTPM) Send(cmd []byte) ([]byte, error) {
	if _, err := r.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[2:6])
	if n < 10 || n > 1<<16 {
		return nil, fmt.Errorf("response size %d", n)
	}
	rsp := make([]byte, n)
	copy(rsp, hdr)
	_, err := io.ReadFull(r, rsp[10:])
	return rsp, err
}

func TestTPMKey(t *testing.T) {
	tpm := startSWTPM(t)
	k, err := createWith(TPM, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	if k.Storage != TPM || !bytes.HasPrefix(k.KeyFile, []byte("-----BEGIN "+pemTPM+"-----")) {
		t.Fatalf("Storage %q, key file %q", k.Storage, k.KeyFile)
	}
	checkSigns(t, k)
	l, err := load(k.KeyFile, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	if l.Storage != TPM || !l.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("Load returned another key")
	}
	checkSigns(t, l)
	if err := k.Discard(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoPrefersTPM(t *testing.T) {
	k, err := createWith(Auto, startSWTPM(t).open)
	if err != nil {
		t.Fatal(err)
	}
	if k.Storage != TPM || k.Skipped != "" {
		t.Fatalf("Storage %q, Skipped %q", k.Storage, k.Skipped)
	}
}

// A TPM key works only in the TPM that made it, and only while that TPM
// can be reached; neither failure falls back to anything
func TestTPMKeyStaysWithItsTPM(t *testing.T) {
	a, b := startSWTPM(t), startSWTPM(t)
	k, err := createWith(TPM, a.open)
	if err != nil {
		t.Fatal(err)
	}
	l, err := load(k.KeyFile, b.open)
	if err != nil {
		t.Fatal(err) // the key file is well formed; only the TPM can tell
	}
	if _, err := l.Sign(rand.Reader, digest("x"), crypto.SHA256); err == nil || !strings.Contains(err.Error(), "loading the key") {
		t.Fatalf("another TPM signed: %v", err)
	}
	if l, err = load(k.KeyFile, noTPM); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(rand.Reader, digest("x"), crypto.SHA256); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("signed without a TPM: %v", err)
	}
}

// tamper rewrites a TPM key file's ASN.1
func tamper(t *testing.T, keyFile []byte, f func(*tssKey)) []byte {
	t.Helper()
	b, _ := pem.Decode(keyFile)
	var tk tssKey
	if _, err := asn1.Unmarshal(b.Bytes, &tk); err != nil {
		t.Fatal(err)
	}
	f(&tk)
	der, err := asn1.Marshal(tk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTPM, Bytes: der})
}

// public rewrites the key's public area
func public(t *testing.T, f func(*tpm2.TPMTPublic)) func(*tssKey) {
	return func(tk *tssKey) {
		b, err := tpm2.Unmarshal[tpm2.TPM2BPublic](tk.PubKey)
		if err != nil {
			t.Fatal(err)
		}
		p, err := b.Contents()
		if err != nil {
			t.Fatal(err)
		}
		f(p)
		tk.PubKey = tpm2.Marshal(tpm2.New2B(*p))
	}
}

func TestTPMKeyFileRefused(t *testing.T) {
	tpm := startSWTPM(t)
	k, err := createWith(TPM, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*tssKey){
		"importable key OID": func(tk *tssKey) { tk.Type = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 4} },
		"with a password":    func(tk *tssKey) { tk.EmptyAuth = false },
		"other parent":       func(tk *tssKey) { tk.Parent = int64(tpm2.TPMRHEndorsement) },
		"persistent parent":  func(tk *tssKey) { tk.Parent = 0x81000001 },
		"trailing public":    func(tk *tssKey) { tk.PubKey = append(tk.PubKey, 0) },
		"trailing private":   func(tk *tssKey) { tk.PrivKey = append(tk.PrivKey, 0) },
		"short private":      func(tk *tssKey) { tk.PrivKey = tk.PrivKey[:len(tk.PrivKey)-1] },
		"duplicable":         public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false }),
		"re-parentable":      public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false }),
		"imported":           public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = false }),
		"decrypts":           public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true }),
		"restricted":         public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true }),
		"policy only":        public(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false }),
		"SHA-1 name":         public(t, func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA1 }),
		"P-384": public(t, func(p *tpm2.TPMTPublic) {
			e, _ := p.Parameters.ECCDetail()
			e.CurveID = tpm2.TPMECCNistP384
		}),
		"no scheme": public(t, func(p *tpm2.TPMTPublic) {
			e, _ := p.Parameters.ECCDetail()
			e.Scheme = tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull}
		}),
		"SHA-384 scheme": public(t, func(p *tpm2.TPMTPublic) {
			e, _ := p.Parameters.ECCDetail()
			e.Scheme.Details = tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA384})
		}),
		"point off the curve": public(t, func(p *tpm2.TPMTPublic) {
			pt, _ := p.Unique.ECC()
			pt.Y.Buffer[31] ^= 1
		}),
	} {
		_, err := load(tamper(t, k.KeyFile, f), tpm.open)
		t.Logf("%s: %v", name, err)
		if err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}

// A public area that passes every check but isn't the one the private area
// was made with is caught by the TPM when it loads the key
func TestTPMChecksPrivateAgainstPublic(t *testing.T) {
	tpm := startSWTPM(t)
	k1, err := createWith(TPM, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := createWith(TPM, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := pem.Decode(k2.KeyFile)
	var tk2 tssKey
	if _, err := asn1.Unmarshal(b2.Bytes, &tk2); err != nil {
		t.Fatal(err)
	}
	swapped := tamper(t, k1.KeyFile, func(tk *tssKey) { tk.PubKey = tk2.PubKey })
	l, err := load(swapped, tpm.open)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(rand.Reader, digest("x"), crypto.SHA256); err == nil {
		t.Fatal("signed with a public area from another key")
	}
}
