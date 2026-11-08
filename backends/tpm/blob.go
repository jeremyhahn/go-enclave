package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/go-tpm/tpm2"
)

// tpmBlobVersion is the first byte of every blob Protect returns.
const tpmBlobVersion = 1

// maxKeyBytes is MAX_SYM_DATA, the bound of a TPM2B_SENSITIVE_DATA.
const maxKeyBytes = 128

// label is bound into the parent's unique field, so only go-enclave's parent
// loads a blob this provider sealed.
const label = "go-enclave v1 TPM KeyProtector"

// parentTemplate is the ECC P-256 storage primary of the TCG "EK and SRK"
// profile, with unique.x carrying SHA-256 of the label.
func parentTemplate() tpm2.TPMTPublic {
	x := sha256.Sum256([]byte(label))
	return storageTemplate(x[:])
}

// storageTemplate is the ECC P-256 storage template with unique.x set to x.
// The standard SRK template is storageTemplate of 32 zero bytes.
func storageTemplate(x []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

// sealedTemplate is the public area of the sealed-data object, with unique
// set to the given digest: empty in TPM2_Create, 32 bytes as the TPM returns
// it.
func sealedTemplate(unique []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: unique}),
	}
}

// encodeBlob frames a sealed object: the version byte, then the TPMT_PUBLIC
// and the TPM2B_PRIVATE buffer, each behind its TPM2B size field.
func encodeBlob(public, private []byte) []byte {
	blob := make([]byte, 0, 1+2+len(public)+2+len(private))
	blob = append(blob, tpmBlobVersion)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(public))) //nolint:gosec // a TPMT_PUBLIC fits a TPM2B
	blob = append(blob, public...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(private))) //nolint:gosec // a TPM2B_PRIVATE fits a TPM2B
	return append(blob, private...)
}

// parseBlob splits a blob into its public and private areas without the
// device, and refuses, with an error matching ErrSealedAuthentication, any
// blob whose framing or public area is not one Protect produced. The results
// alias blob; nothing is copied or written.
func parseBlob(blob []byte) (public, private []byte, err error) {
	if len(blob) < 1 || blob[0] != tpmBlobVersion {
		return nil, nil, &authError{reason: "the blob has no version 1 header"}
	}
	rest := blob[1:]
	public, rest, ok := sized(rest)
	if !ok {
		return nil, nil, &authError{reason: "the public area's size runs past the blob"}
	}
	private, rest, ok = sized(rest)
	if !ok {
		return nil, nil, &authError{reason: "the private area's size runs past the blob"}
	}
	if len(rest) != 0 {
		return nil, nil, &authError{reason: "bytes follow the private area"}
	}
	if err := checkPublic(public); err != nil {
		return nil, nil, err
	}
	return public, private, nil
}

// sized reads a TPM2B size field and the bytes it covers.
func sized(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b)-2 < n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// checkPublic refuses a public area that does not unmarshal or differs from
// the sealed-object template in anything but a 32-byte unique.
func checkPublic(public []byte) error {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return &authError{reason: "the public area does not unmarshal", err: err}
	}
	if pub.Type != tpm2.TPMAlgKeyedHash {
		return &authError{reason: "the public area is not a sealed-data object"}
	}
	unique, err := pub.Unique.KeyedHash()
	if err != nil || len(unique.Buffer) != sha256.Size {
		return &authError{reason: "the public area's unique is not a SHA-256 digest"}
	}
	if !bytes.Equal(tpm2.Marshal(sealedTemplate(unique.Buffer)), public) {
		return &authError{reason: "the public area is not the sealed-object template"}
	}
	return nil
}
