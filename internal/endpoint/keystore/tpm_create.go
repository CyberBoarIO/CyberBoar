//go:build !windows

package keystore

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// This file makes TPM keys through a TPM 2.0 device. On Windows the TPM is
// reached through CNG instead (cng_windows.go)

// keyTemplate is the template of the endpoint key. The key is generated in
// the TPM (sensitiveDataOrigin), can never be duplicated (fixedTPM,
// fixedParent), signs with ECDSA and SHA-256 only, is used with its empty
// password (userWithAuth), and is exempt from dictionary-attack lockout,
// which an empty password can't trigger anyway
var keyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
		KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
}

// createTPM makes a key in the TPM (Linux) or fails with ErrUnavailable
func createTPM(openTPM tpmOpener) (*Key, error) { return createTSS(openTPM) }

// createTSS makes a key in the TPM openTPM reaches
func createTSS(openTPM tpmOpener) (*Key, error) {
	t, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate
	err = withSRK(t, func(srk tpm2.AuthHandle) error {
		rsp, err := tpm2.Create{ParentHandle: srk, InPublic: tpm2.New2B(keyTemplate)}.Execute(t)
		if err != nil {
			return fmt.Errorf("creating the key in the TPM: %w", err)
		}
		pub, priv = rsp.OutPublic, rsp.OutPrivate
		return nil
	})
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(tssKey{
		Type:      oidLoadableKey,
		EmptyAuth: true,
		Parent:    int64(tpm2.TPMRHOwner),
		PubKey:    tpm2.Marshal(pub),
		PrivKey:   tpm2.Marshal(priv),
	})
	if err != nil {
		return nil, err
	}
	k, err := loadTPM(der, openTPM)
	if err != nil {
		return nil, err
	}
	k.KeyFile = pem.EncodeToMemory(&pem.Block{Type: pemTPM, Bytes: der})
	return k, nil
}
