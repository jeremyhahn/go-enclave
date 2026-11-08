package tpm

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
)

// sealedPublicBytes is the marshaled TPMT_PUBLIC the TPM returns for a
// sealed object: 46 bytes, with a 32-byte unique.
const sealedPublicBytes = 46

// sealedPrivateBytes is the TPM2B_PRIVATE buffer of a 32-byte key under a
// SHA-256, AES-128 parent: the integrity digest (2+32) and the encrypted
// TPM2B_SENSITIVE (2 + type 2 + authValue 2 + seedValue 2+32 + data 2+32).
const sealedPrivateBytes = 108

func testPublic(t *testing.T, mutate func(*tpm2.TPMTPublic)) []byte {
	t.Helper()
	pub := sealedTemplate(bytes.Repeat([]byte{0xa5}, 32))
	if mutate != nil {
		mutate(&pub)
	}
	return tpm2.Marshal(pub)
}

func testBlob(t *testing.T) []byte {
	t.Helper()
	return encodeBlob(testPublic(t, nil), bytes.Repeat([]byte{0x5a}, sealedPrivateBytes))
}

func requireAuth(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("got %v, want an error matching ErrSealedAuthentication", err)
	}
}

func TestBlob_RoundTrip(t *testing.T) {
	public := testPublic(t, nil)
	if len(public) != sealedPublicBytes {
		t.Fatalf("sealed public area is %d bytes, want %d", len(public), sealedPublicBytes)
	}
	private := bytes.Repeat([]byte{0x5a}, sealedPrivateBytes)
	blob := encodeBlob(public, private)
	if want := 1 + 2 + sealedPublicBytes + 2 + sealedPrivateBytes; len(blob) != want {
		t.Fatalf("blob is %d bytes, want %d", len(blob), want)
	}
	if blob[0] != tpmBlobVersion {
		t.Fatalf("version byte %d, want %d", blob[0], tpmBlobVersion)
	}
	gotPub, gotPriv, err := parseBlob(blob)
	if err != nil {
		t.Fatalf("parseBlob: %v", err)
	}
	if !bytes.Equal(gotPub, public) || !bytes.Equal(gotPriv, private) {
		t.Fatal("parseBlob did not return the areas encodeBlob framed")
	}
}

func TestBlob_ParseDoesNotWriteTheBlob(t *testing.T) {
	blob := testBlob(t)
	before := bytes.Clone(blob)
	if _, _, err := parseBlob(blob); err != nil {
		t.Fatalf("parseBlob: %v", err)
	}
	if !bytes.Equal(blob, before) {
		t.Fatal("parseBlob modified the blob")
	}
}

func TestBlob_Truncation(t *testing.T) {
	blob := testBlob(t)
	for n := 0; n < len(blob); n++ {
		t.Run(fmt.Sprintf("len_%d", n), func(t *testing.T) {
			_, _, err := parseBlob(blob[:n])
			requireAuth(t, err)
		})
	}
}

func TestBlob_Refused(t *testing.T) {
	good := testBlob(t)
	cases := map[string][]byte{
		"wrong_version":        append([]byte{2}, good[1:]...),
		"version_zero":         append([]byte{0}, good[1:]...),
		"trailing_byte":        append(bytes.Clone(good), 0),
		"public_size_past_end": append([]byte{tpmBlobVersion, 0xff, 0xff}, good[3:]...),
		"private_size_past_end": func() []byte {
			b := bytes.Clone(good)
			b[3+sealedPublicBytes] = 0xff
			return b
		}(),
		"public_does_not_unmarshal": encodeBlob([]byte{0x00, 0x08, 0x00}, []byte{1}),
		"public_has_trailing_bytes": encodeBlob(append(testPublic(t, nil), 0), []byte{1}),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseBlob(blob)
			requireAuth(t, err)
		})
	}
}

func TestBlob_TemplateFieldChanged(t *testing.T) {
	cases := map[string]func(*tpm2.TPMTPublic){
		"type_ecc": func(p *tpm2.TPMTPublic) {
			*p = storageTemplate(make([]byte, 32))
		},
		"name_alg_sha1":         func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA1 },
		"name_alg_sha384":       func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA384 },
		"fixed_tpm_clear":       func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		"fixed_parent_clear":    func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedParent = false },
		"user_with_auth_clear":  func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false },
		"no_da_clear":           func(p *tpm2.TPMTPublic) { p.ObjectAttributes.NoDA = false },
		"sensitive_origin_set":  func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SensitiveDataOrigin = true },
		"sign_set":              func(p *tpm2.TPMTPublic) { p.ObjectAttributes.SignEncrypt = true },
		"decrypt_set":           func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		"admin_with_policy_set": func(p *tpm2.TPMTPublic) { p.ObjectAttributes.AdminWithPolicy = true },
		"st_clear_set":          func(p *tpm2.TPMTPublic) { p.ObjectAttributes.STClear = true },
		"auth_policy_non_empty": func(p *tpm2.TPMTPublic) { p.AuthPolicy = tpm2.TPM2BDigest{Buffer: make([]byte, 32)} },
		"unique_short":          func(p *tpm2.TPMTPublic) { p.Unique = sealedTemplate(make([]byte, 20)).Unique },
		"unique_empty":          func(p *tpm2.TPMTPublic) { p.Unique = sealedTemplate(nil).Unique },
		"scheme_hmac": func(p *tpm2.TPMTPublic) {
			p.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme:  tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
				},
			})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			blob := encodeBlob(testPublic(t, mutate), []byte{1})
			_, _, err := parseBlob(blob)
			requireAuth(t, err)
		})
	}
}

func TestBlob_ParentTemplateBindsTheLabel(t *testing.T) {
	parent, srk := parentTemplate(), storageTemplate(make([]byte, 32))
	bound, err := parent.Unique.ECC()
	if err != nil {
		t.Fatalf("parent unique: %v", err)
	}
	standard, err := srk.Unique.ECC()
	if err != nil {
		t.Fatalf("standard unique: %v", err)
	}
	if bytes.Equal(bound.X.Buffer, standard.X.Buffer) {
		t.Fatal("the parent template does not carry the label")
	}
	if len(bound.X.Buffer) != 32 || !bytes.Equal(bound.Y.Buffer, make([]byte, 32)) {
		t.Fatal("the parent's unique is not SHA-256 of the label and 32 zero bytes")
	}
}
