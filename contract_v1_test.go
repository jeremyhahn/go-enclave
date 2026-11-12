package enclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// The known-answer vectors in testdata/contract-v1 pin blob contract v1
// (docs/sealing/engineering.md, "Blob contract v1" and "Envelope version").
// They are checked twice: rebuilt byte for byte by contractRef, an encoder
// written from the document with the standard library only, and opened
// through the package's own unwrap and open paths. Regenerate them with
//
//	go test -run ContractV1 -update-vectors ./
//
// which is a format change: the document says so for any changed byte.
var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/contract-v1 from the reference encoder")

// The documented constants, copied from the document, not from the package.
const (
	refBlobVersion      = 1
	refKindDEK          = 1
	refKindKEK          = 2
	refKindProvider     = 3
	refHeaderLen        = 6
	refNonceLen         = 12
	refTagLen           = 16
	refKeyLen           = 32
	refWrappingInfo     = "go-enclave v1 ModeRootKey KEK-wrapping key"
	refProtectInfo      = "go-enclave v1 SoftwareProvider Protect key"
	refEnvelopeV1       = 0
	refEnvelopeV2       = 2
	refSoftwareBlobSize = refHeaderLen + refNonceLen + refKeyLen + refTagLen // 66
)

const contractV1Dir = "testdata/contract-v1"

// hexBytes is a byte string written as lowercase hex in the vector files.
type hexBytes []byte

func (b hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(b)) }

func (b *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*b = d
	return err
}

// contractVector is one sealed value: inputs first, then the derived key and
// the expected bytes. KEK fields are empty for a SoftwareProvider vector.
type contractVector struct {
	Name            string   `json:"name"`
	RootKey         hexBytes `json:"root_key"`
	WrappingSalt    hexBytes `json:"wrapping_salt,omitempty"`
	KEK             hexBytes `json:"kek,omitempty"`
	KEKGeneration   uint32   `json:"kek_generation,omitempty"`
	KEKNonce        hexBytes `json:"kek_nonce,omitempty"`
	DEK             hexBytes `json:"dek"`
	BlobNonce       hexBytes `json:"blob_nonce"`
	EnvelopeVersion uint8    `json:"envelope_version"`
	Plaintext       hexBytes `json:"plaintext"`
	SealedNonce     hexBytes `json:"sealed_nonce"`

	// DerivedKey is the HKDF output: the wrapping key for ModeRootKey, the
	// Protect key for a SoftwareProvider.
	DerivedKey hexBytes `json:"derived_key"`
	KEKBlob    hexBytes `json:"kek_blob,omitempty"`
	Blob       hexBytes `json:"blob"`
	AAD        hexBytes `json:"aad"`
	Sealed     hexBytes `json:"sealed"`
}

// contractRefusal is a blob a reader must refuse with ErrSealedAuthentication:
// Base's blob changed by Mutation.
type contractRefusal struct {
	Name     string   `json:"name"`
	File     string   `json:"file"`
	Base     string   `json:"base"`
	Mutation string   `json:"mutation"`
	Blob     hexBytes `json:"blob"`
	Expect   string   `json:"expect"`
}

type contractFile struct {
	Comment string           `json:"comment"`
	Vectors []contractVector `json:"vectors"`
}

type refusalFile struct {
	Comment  string            `json:"comment"`
	Refusals []contractRefusal `json:"refusals"`
}

const (
	softwareFile = "software-provider.json"
	rootKeyFile  = "root-key.json"
	refusalsFile = "refusals.json"
)

// Mutations a refusal vector applies to its base blob. Header changes are
// re-wrapped, so the AEAD tag is valid and only the header check refuses.
const (
	mutHeaderVersion2 = "header-version-2"
	mutKind           = "kind-"
	mutGeneration     = "generation-not-held"
	mutFlipTag        = "flip-last-tag-byte"
	mutShort          = "truncate-to-5-bytes"
)

// contractRef is the reference encoder: the documented layout, standard
// library only.
type contractRef struct{}

func (contractRef) gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// wrap is a wrapped-key blob: version || kind || generation (big-endian) ||
// nonce || ciphertext || tag, with the 6-byte header as the AAD.
func (r contractRef) wrap(wrapping []byte, version, kind byte, gen uint32, nonce, key []byte) []byte {
	header := []byte{version, kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[2:refHeaderLen], gen)
	out := append(append([]byte(nil), header...), nonce...)
	return r.gcm(wrapping).Seal(out, nonce, key, header)
}

// seal is the sealed string: nonce || ciphertext || tag under the DEK.
func (r contractRef) seal(dek, nonce, plaintext, aad []byte) []byte {
	return r.gcm(dek).Seal(append([]byte(nil), nonce...), nonce, plaintext, aad)
}

// aad is the blob for envelope version 1 (zero), 0x02 || blob for version 2.
func (contractRef) aad(version uint8, blob []byte) []byte {
	if version == refEnvelopeV2 {
		return append([]byte{refEnvelopeV2}, blob...)
	}
	return append([]byte(nil), blob...)
}

func (contractRef) hkdf(secret, salt []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, salt, info, refKeyLen)
	if err != nil {
		panic(err)
	}
	return k
}

// build fills every derived field of v from its inputs.
func (r contractRef) build(v contractVector) contractVector {
	if v.KEK == nil {
		v.DerivedKey = r.hkdf(v.RootKey, nil, refProtectInfo)
		v.Blob = r.wrap(v.DerivedKey, refBlobVersion, refKindProvider, 0, v.BlobNonce, v.DEK)
	} else {
		v.DerivedKey = r.hkdf(v.RootKey, v.WrappingSalt, refWrappingInfo)
		v.KEKBlob = r.wrap(v.DerivedKey, refBlobVersion, refKindKEK, v.KEKGeneration, v.KEKNonce, v.KEK)
		v.Blob = r.wrap(v.KEK, refBlobVersion, refKindDEK, v.KEKGeneration, v.BlobNonce, v.DEK)
	}
	v.AAD = r.aad(v.EnvelopeVersion, v.Blob)
	v.Sealed = r.seal(v.DEK, v.SealedNonce, v.Plaintext, v.AAD)
	return v
}

// mutate is base's blob changed as m says.
func (r contractRef) mutate(base contractVector, m string) []byte {
	wrapping, kind, gen := base.DerivedKey, byte(refKindProvider), uint32(0)
	if base.KEK != nil {
		wrapping, kind, gen = base.KEK, refKindDEK, base.KEKGeneration
	}
	switch {
	case m == mutHeaderVersion2:
		return r.wrap(wrapping, 2, kind, gen, base.BlobNonce, base.DEK)
	case len(m) == len(mutKind)+1 && m[:len(mutKind)] == mutKind:
		return r.wrap(wrapping, refBlobVersion, m[len(mutKind)]-'0', gen, base.BlobNonce, base.DEK)
	case m == mutGeneration:
		return r.wrap(wrapping, refBlobVersion, kind, gen+5, base.BlobNonce, base.DEK)
	case m == mutFlipTag:
		b := bytes.Clone(base.Blob)
		b[len(b)-1] ^= 0x01
		return b
	case m == mutShort:
		return bytes.Clone(base.Blob[:5])
	}
	panic("unknown mutation " + m)
}

// pattern is n bytes counting up from start: fixed, recognizable inputs.
func pattern(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

var contractPlaintext = []byte("go-enclave contract v1 known-answer plaintext")

// contractInputs are the inputs every vector file is generated from.
func contractInputs() (software, rootKey []contractVector, refusals []contractRefusal) {
	for _, version := range []uint8{refEnvelopeV1, refEnvelopeV2} {
		suffix := map[uint8]string{refEnvelopeV1: "envelope-v1", refEnvelopeV2: "envelope-v2"}[version]
		software = append(software, contractVector{
			Name:            "software-provider-" + suffix,
			RootKey:         pattern(0x00, refKeyLen),
			DEK:             pattern(0x60, refKeyLen),
			BlobNonce:       pattern(0xa0, refNonceLen),
			EnvelopeVersion: version,
			Plaintext:       contractPlaintext,
			SealedNonce:     pattern(0xc0, refNonceLen),
		})
		rootKey = append(rootKey, contractVector{
			Name:            "root-key-" + suffix,
			RootKey:         pattern(0x00, refKeyLen),
			WrappingSalt:    pattern(0x20, refKeyLen),
			KEK:             pattern(0x40, refKeyLen),
			KEKGeneration:   0x0102, // two non-zero bytes pin the byte order
			KEKNonce:        pattern(0xb0, refNonceLen),
			DEK:             pattern(0x60, refKeyLen),
			BlobNonce:       pattern(0xa0, refNonceLen),
			EnvelopeVersion: version,
			Plaintext:       contractPlaintext,
			SealedNonce:     pattern(0xc0, refNonceLen),
		})
	}
	refuse := func(file, base string, mutations ...string) {
		for _, m := range mutations {
			refusals = append(refusals, contractRefusal{
				Name: base + "-" + m, File: file, Base: base, Mutation: m,
				Expect: "ErrSealedAuthentication",
			})
		}
	}
	refuse(softwareFile, "software-provider-envelope-v2",
		mutHeaderVersion2, mutKind+"1", mutGeneration, mutFlipTag, mutShort)
	refuse(rootKeyFile, "root-key-envelope-v2",
		mutHeaderVersion2, mutKind+"2", mutKind+"3", mutGeneration, mutFlipTag, mutShort)
	return software, rootKey, refusals
}

// contractExpected is every vector file as the reference encoder builds it.
func contractExpected() (files map[string]contractFile, refusals refusalFile) {
	software, rootKey, refs := contractInputs()
	var r contractRef
	byName := map[string]contractVector{}
	for i := range software {
		software[i] = r.build(software[i])
		byName[software[i].Name] = software[i]
	}
	for i := range rootKey {
		rootKey[i] = r.build(rootKey[i])
		byName[rootKey[i].Name] = rootKey[i]
	}
	for i := range refs {
		refs[i].Blob = r.mutate(byName[refs[i].Base], refs[i].Mutation)
	}
	files = map[string]contractFile{
		softwareFile: {
			Comment: "Blob contract v1, SoftwareProvider blob (kind 3, generation 0) and a sealed value under it. docs/sealing/engineering.md.",
			Vectors: software,
		},
		rootKeyFile: {
			Comment: "Blob contract v1, ModeRootKey: KEK blob (kind 2) under the HKDF wrapping key, DEK blob (kind 1) under that KEK generation, sealed value. docs/sealing/engineering.md.",
			Vectors: rootKey,
		},
	}
	refusals = refusalFile{
		Comment:  "Blobs a contract v1 reader refuses with ErrSealedAuthentication: base vector's blob changed by mutation; header changes carry a valid tag.",
		Refusals: refs,
	}
	return files, refusals
}

func readContractFile(t *testing.T, name string, v any) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(contractV1Dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return data
}

func marshalContract(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(data, '\n')
}

func TestContractV1_ReferenceEncoder(t *testing.T) {
	files, refusals := contractExpected()
	want := map[string][]byte{refusalsFile: marshalContract(t, refusals)}
	for name, f := range files {
		want[name] = marshalContract(t, f)
	}

	if *updateVectors {
		if err := os.MkdirAll(contractV1Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range want {
			if err := os.WriteFile(filepath.Join(contractV1Dir, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	for name, data := range want {
		var parsed any
		got := readContractFile(t, name, &parsed)
		if !bytes.Equal(got, data) {
			t.Errorf("%s differs from the reference encoder's bytes: a contract v1 format change", name)
		}
	}

	for _, v := range files[softwareFile].Vectors {
		if len(v.Blob) != refSoftwareBlobSize {
			t.Errorf("%s: blob is %d bytes, want %d", v.Name, len(v.Blob), refSoftwareBlobSize)
		}
	}
	for _, f := range files {
		for _, v := range f.Vectors {
			if len(v.Sealed) != refNonceLen+len(v.Plaintext)+refTagLen {
				t.Errorf("%s: sealed is %d bytes, want nonce + plaintext + tag", v.Name, len(v.Sealed))
			}
		}
	}
}

// TestContractV1_PackageConstants checks the package's constants against the
// document's.
func TestContractV1_PackageConstants(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"blobVersion", int(blobVersion), refBlobVersion},
		{"blobKindDEK", int(blobKindDEK), refKindDEK},
		{"blobKindKEK", int(blobKindKEK), refKindKEK},
		{"blobKindProvider", int(blobKindProvider), refKindProvider},
		{"blobHeaderLen", int(blobHeaderLen), refHeaderLen},
		{"sealedOverhead", int(sealedOverhead), refNonceLen + refTagLen},
		{"dekBytes", int(dekBytes), refKeyLen},
		{"kekBytes", int(kekBytes), refKeyLen},
		{"RootKeyBytes", int(RootKeyBytes), refKeyLen},
		{"wrappingKeyInfo", wrappingKeyInfo, refWrappingInfo},
		{"softwareProtectKeyInfo", softwareProtectKeyInfo, refProtectInfo},
		{"sealedVersionV1", int(sealedVersionV1), refEnvelopeV1},
		{"sealedVersionV2", int(sealedVersionV2), refEnvelopeV2},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, the document says %v", c.name, c.got, c.want)
		}
	}
}

func loadContractVectors(t *testing.T) (map[string]contractVector, refusalFile) {
	t.Helper()
	byName := map[string]contractVector{}
	for _, name := range []string{softwareFile, rootKeyFile} {
		var f contractFile
		readContractFile(t, name, &f)
		if len(f.Vectors) == 0 {
			t.Fatalf("%s holds no vectors", name)
		}
		for _, v := range f.Vectors {
			byName[v.Name] = v
		}
	}
	var r refusalFile
	readContractFile(t, refusalsFile, &r)
	return byName, r
}

func mustRegion(t *testing.T, b []byte) *lockedRegion {
	t.Helper()
	r, err := newMemory(bytes.Clone(b))
	if err != nil {
		t.Fatalf("newMemory: %v", err)
	}
	t.Cleanup(func() { _ = r.Destroy() })
	return r
}

// softwareProviderFor is a SoftwareProvider over v's root that has derived
// its Protect key, as its first Protect would.
func softwareProviderFor(t *testing.T, v contractVector) *softwareProvider {
	t.Helper()
	p := &softwareProvider{s: &softwareState{root: mustRegion(t, v.RootKey)}}
	t.Cleanup(func() { _ = p.Destroy() })
	p.s.mu.Lock()
	pk, err := p.s.protectKeyLocked()
	p.s.mu.Unlock()
	if err != nil {
		t.Fatalf("protectKeyLocked: %v", err)
	}
	if !holds(pk, v.DerivedKey) {
		t.Fatalf("%s: the package's Protect key differs from derived_key", v.Name)
	}
	return p
}

// rootKeyStateFor is a ModeRootKey hierarchy over v's root and salt holding
// v's KEK generation: current, or retired so its KEK blob is unwrapped under
// the wrapping key.
func rootKeyStateFor(t *testing.T, v contractVector, retired bool) *sealerState {
	t.Helper()
	wrapping := bytes.Clone(v.RootKey)
	if err := deriveWrappingKey(wrapping, bytes.Clone(v.WrappingSalt)); err != nil {
		t.Fatalf("deriveWrappingKey: %v", err)
	}
	if !bytes.Equal(wrapping, v.DerivedKey) {
		t.Fatalf("%s: the package's wrapping key differs from derived_key", v.Name)
	}
	gen := v.KEKGeneration
	s := &sealerState{
		mode:     ModeRootKey,
		root:     mustRegion(t, wrapping),
		kek:      mustRegion(t, v.KEK),
		kekGen:   gen,
		kekBlobs: map[uint32][]byte{gen: bytes.Clone(v.KEKBlob)},
		kekRefs:  map[uint32]*atomic.Int64{gen: new(atomic.Int64)},
	}
	if retired {
		s.kek, s.kekGen = mustRegion(t, pattern(0xe0, refKeyLen)), gen+1
		s.kekRefs[gen+1] = new(atomic.Int64)
	}
	return s
}

// openSealed opens v's sealed string under dek with the package's AAD.
func openSealed(t *testing.T, v contractVector, dek *lockedRegion) {
	t.Helper()
	aad, err := sealedAAD(v.EnvelopeVersion, v.Blob)
	if err != nil {
		t.Fatalf("sealedAAD: %v", err)
	}
	if !bytes.Equal(aad, v.AAD) {
		t.Errorf("%s: the package's AAD differs from aad", v.Name)
	}
	out := make([]byte, len(v.Plaintext))
	if err := openWithKeyInto(dek, bytes.Clone(v.Sealed), aad, out); err != nil {
		t.Fatalf("%s: openWithKeyInto: %v", v.Name, err)
	}
	if !bytes.Equal(out, v.Plaintext) {
		t.Errorf("%s: opened to %x, want the plaintext", v.Name, out)
	}
}

func TestContractV1_PackageOpens(t *testing.T) {
	vectors, refusals := loadContractVectors(t)

	for _, v := range vectors {
		if v.KEK != nil {
			for name, retired := range map[string]bool{"current generation": false, "retired generation": true} {
				t.Run(v.Name+"/"+name, func(t *testing.T) {
					s := rootKeyStateFor(t, v, retired)
					dek, err := newMemorySized(refKeyLen)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = dek.Destroy() })
					if err := s.unprotectRootKey(t.Context(), bytes.Clone(v.Blob), dek); err != nil {
						t.Fatalf("unprotectRootKey: %v", err)
					}
					if !holds(dek, v.DEK) {
						t.Fatal("unprotectRootKey recovered another DEK")
					}
					openSealed(t, v, dek)
				})
			}
			continue
		}

		t.Run(v.Name, func(t *testing.T) {
			p := softwareProviderFor(t, v)
			dek := make([]byte, refKeyLen)
			if err := p.Unprotect(t.Context(), bytes.Clone(v.Blob), dek); err != nil {
				t.Fatalf("Unprotect: %v", err)
			}
			if !bytes.Equal(dek, v.DEK) {
				t.Fatal("Unprotect recovered another DEK")
			}
			openSealed(t, v, mustRegion(t, dek))

			// The whole envelope, through a Sealer's Open.
			sealer, err := NewSealer(WithKeyProtector(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			t.Cleanup(func() { _ = sealer.Destroy() })
			e, err := envelopeOf(sealer)
			if err != nil {
				t.Fatalf("envelopeOf: %v", err)
			}
			sv := &sealedValue{sealedState: &sealedState{
				sealer: e, sealed: bytes.Clone(v.Sealed), blob: bytes.Clone(v.Blob),
				size: len(v.Plaintext), version: v.EnvelopeVersion, sealedAtGen: sweepGeneration(),
			}}
			opened, err := sv.Open(t.Context())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer opened.Destroy()
			if !holds(opened, v.Plaintext) {
				t.Error("Open did not return the plaintext")
			}
		})
	}

	for _, r := range refusals.Refusals {
		t.Run("refuses/"+r.Name, func(t *testing.T) {
			if r.Expect != "ErrSealedAuthentication" {
				t.Fatalf("expect = %q", r.Expect)
			}
			base, ok := vectors[r.Base]
			if !ok {
				t.Fatalf("no base vector %q", r.Base)
			}
			var err error
			if base.KEK != nil {
				s := rootKeyStateFor(t, base, false)
				dek, merr := newMemorySized(refKeyLen)
				if merr != nil {
					t.Fatal(merr)
				}
				t.Cleanup(func() { _ = dek.Destroy() })
				err = s.unprotectRootKey(t.Context(), bytes.Clone(r.Blob), dek)
			} else {
				err = softwareProviderFor(t, base).Unprotect(t.Context(), bytes.Clone(r.Blob), make([]byte, refKeyLen))
			}
			if !errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("unwrap of %s = %v, want ErrSealedAuthentication", r.Name, err)
			}
		})
	}
}
