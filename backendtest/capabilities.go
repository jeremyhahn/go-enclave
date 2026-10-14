package backendtest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"
)

func checkByteAccess(r *report, cfg Config) {
	const property = "ByteAccess"
	eachCase(r, cfg, property, enclave.CapabilityBytes, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, material []byte) {
		ba, ok := h.(enclave.ByteAccess)
		if !ok {
			return
		}
		var got []byte
		if err := ba.WithBytes(func(b []byte) error {
			got = append(got, b...)
			if len(b) != h.Size() {
				r.fail(property, "%s: WithBytes view length is %d, want Size %d", hc.Name, len(b), h.Size())
			}
			return nil
		}); err != nil {
			r.fail(property, "%s: WithBytes returned %v", hc.Name, err)
		}
		if material != nil && !bytes.Equal(got, material) {
			r.fail(property, "%s: WithBytes view does not hold the imported material", hc.Name)
		}
		if err := ba.WithBytes(func([]byte) error { return errBorrowProbe }); !errors.Is(err, errBorrowProbe) {
			r.fail(property, "%s: WithBytes returned %v when fn returned an error; it returns fn's error", hc.Name, err)
		}
		eq, err := ba.EqualTo(got)
		if err != nil || !eq {
			r.fail(property, "%s: EqualTo(exact material) = %v, %v; want true, nil", hc.Name, eq, err)
		}
		other := append([]byte(nil), got...)
		if len(other) > 0 {
			other[0] ^= 0xff
			eq, err = ba.EqualTo(other)
			if err != nil || eq {
				r.fail(property, "%s: EqualTo(altered material) = %v, %v; want false, nil", hc.Name, eq, err)
			}
		}
		eq, err = ba.EqualTo(append(got, 0))
		if err != nil || eq {
			r.fail(property, "%s: EqualTo(wrong length) = %v, %v; want false, nil", hc.Name, eq, err)
		}
	})
}

// checkFreezer freezes a fresh handle twice and requires the material intact,
// readable and no longer writable. validateConfig has refused a Freezer
// without ByteAccess, the only way to observe read-only material.
func checkFreezer(r *report, cfg Config) {
	const property = "Freezer"
	eachCase(r, cfg, property, enclave.CapabilityFreeze, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		f, ok := h.(enclave.Freezer)
		ba, hasBytes := h.(enclave.ByteAccess)
		if !ok || !hasBytes {
			return
		}
		before := snapshot(ba)
		if err := f.Freeze(); err != nil {
			r.fail(property, "%s: Freeze of a fresh live handle returned %v", hc.Name, err)
			if !h.IsAlive() {
				r.fail(property, "%s: a refused Freeze left the handle dead; a refusal leaves it alive and writable", hc.Name)
			}
			return
		}
		if err := f.Freeze(); err != nil {
			r.fail(property, "%s: a second Freeze returned %v; Freeze is idempotent", hc.Name, err)
		}
		if !h.IsAlive() {
			r.fail(property, "%s: the handle is not alive after Freeze", hc.Name)
			return
		}
		if eq, err := ba.EqualTo(before); err != nil || !eq {
			r.fail(property, "%s: EqualTo(material before Freeze) = %v, %v after Freeze; want true, nil", hc.Name, eq, err)
		}
		writable := false
		if err := ba.WithBytes(func(b []byte) error {
			writable = canWrite(b)
			return nil
		}); err != nil {
			r.fail(property, "%s: WithBytes after Freeze returned %v", hc.Name, err)
			return
		}
		if writable {
			r.fail(property, "%s: a page of the WithBytes view is still writable after Freeze returned nil; Freeze makes all the material read-only", hc.Name)
		}
	})
}

// canWrite reports whether any byte of p can be written. It probes one byte of
// every page p spans, its first and last byte among them, so a view frozen
// only in part answers true. A read-only page answers false instead of killing
// the process, and the fault's panic never leaves the probe, so it never
// unwinds through the backend's WithBytes.
func canWrite(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	// A step of one page from the first byte lands in every page p spans but
	// a partial last one, which the last byte covers.
	page := os.Getpagesize()
	for off := 0; off < len(p); off += page {
		if storable(&p[off]) {
			return true
		}
	}
	return storable(&p[len(p)-1])
}

// storable reports whether *b can be written, by writing it back unchanged
// with a fault turned into a recoverable panic. Each probe recovers its own
// fault, so one read-only page does not stand for the pages after it.
func storable(b *byte) (ok bool) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if _, isFault := rec.(runtime.Error); !isFault {
			panic(rec)
		}
		ok = false
	}()
	rewrite(b, *b)
	return true
}

// rewrite stores v into b. Not inlined, so the compiler cannot see that v
// was loaded from b and drop the store as a no-op.
//
//go:noinline
func rewrite(b *byte, v byte) {
	*b = v
}

// checkDeriver requires Derive to refuse an ended context, and to be a
// function of the material and info: the same info gives the same material, a
// different info a different one. The derived material is compared through
// ByteAccess or AEAD; a derived handle with neither cannot be compared, and the
// capability is refused as unchecked.
func checkDeriver(r *report, cfg Config) {
	const property = "Deriver"
	eachCase(r, cfg, property, enclave.CapabilityDerive, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		d, ok := h.(enclave.Deriver)
		if !ok {
			return
		}
		infoA, infoB := []byte("backendtest derive A"), []byte("backendtest derive B")
		child, err := d.Derive(canceledContext(r.ctx), infoA, deriveBytes)
		if !errors.Is(err, context.Canceled) {
			r.fail(property, "%s: Derive with an already-canceled context returned %v, want an error matching context.Canceled", hc.Name, err)
		}
		if !isNilInterface(child) {
			r.fail(property, "%s: Derive with an already-canceled context returned a handle", hc.Name)
			_ = destroy(child)
		}
		var children []enclave.Handle
		defer func() {
			for _, c := range children {
				if err := destroy(c); err != nil || c.IsAlive() {
					r.fail(property, "%s: Destroy of a derived handle returned %v, alive %v", hc.Name, err, c.IsAlive())
				}
			}
		}()
		for _, info := range [][]byte{infoA, infoA, infoB} {
			c := deriveChild(r, property, hc.Name, h, d, info)
			if c == nil {
				return
			}
			children = append(children, c)
		}
		same, observable, err := sameMaterial(children[0], children[1])
		if !observable {
			r.unchecked(hc.Name, enclave.CapabilityDerive, "derived handles are %T, with neither ByteAccess nor AEAD, "+
				"so the suite cannot compare derived material", children[0])
			return
		}
		if err != nil || !same {
			r.fail(property, "%s: two Derive calls with the same info gave different material (%v); Derive is a function of the material and info", hc.Name, err)
		}
		same, observable, err = sameMaterial(children[0], children[2])
		if !observable {
			r.unchecked(hc.Name, enclave.CapabilityDerive, "the handle derived with different info is %T, which shares "+
				"neither ByteAccess nor AEAD with %T, so the suite cannot tell its material from the first", children[2], children[0])
			return
		}
		if err != nil || same {
			r.fail(property, "%s: Derive with different info gave the same material (%v); the output is bound to info", hc.Name, err)
		}
	})
}

// deriveChild derives deriveBytes bytes bound to info and checks the new
// handle's core, or reports why there is none and returns nil.
func deriveChild(r *report, property, name string, parent enclave.Handle, d enclave.Deriver, info []byte) enclave.Handle {
	c, err := d.Derive(r.ctx, info, deriveBytes)
	if err != nil {
		r.fail(property, "%s: Derive returned %v", name, err)
		return nil
	}
	if isNilInterface(c) {
		r.fail(property, "%s: Derive returned a nil handle and a nil error", name)
		return nil
	}
	if !c.IsAlive() {
		r.fail(property, "%s: the derived handle is not alive", name)
	}
	if c.Size() != deriveBytes {
		r.fail(property, "%s: the derived handle's Size is %d, want the %d bytes asked for", name, c.Size(), deriveBytes)
	}
	if !sameBackend(c.Backend(), parent.Backend()) {
		r.fail(property, "%s: the derived handle's Backend is not its parent's; Derive returns a handle from the same backend", name)
	}
	return c
}

// sameMaterial reports whether x and y hold the same material, through
// ByteAccess or, failing that, by opening with y what x sealed. observable is
// false when neither way is open.
func sameMaterial(x, y enclave.Handle) (same, observable bool, err error) {
	bx, okX := x.(enclave.ByteAccess)
	by, okY := y.(enclave.ByteAccess)
	if okX && okY {
		var eqErr error
		err = bx.WithBytes(func(b []byte) error {
			same, eqErr = by.EqualTo(b)
			return eqErr
		})
		return same, true, err
	}
	ax, okX := x.(enclave.AEAD)
	ay, okY := y.(enclave.AEAD)
	if !okX || !okY {
		return false, false, nil
	}
	nonce := nonceFor(ax)
	plaintext := []byte("backendtest derive probe")
	sealed, err := ax.Seal(nil, nonce, plaintext, nil)
	if err != nil {
		return false, true, err
	}
	opened, err := ay.Open(nil, nonce, sealed, nil)
	if errors.Is(err, enclave.ErrAEADAuthentication) {
		return false, true, nil
	}
	return err == nil && bytes.Equal(opened, plaintext), true, err
}

// signScheme is one signature scheme the suite verifies a Signer under.
type signScheme struct {
	name   string
	opts   crypto.SignerOpts
	verify func(digest, sig []byte) bool
}

// signSchemes returns the schemes a crypto.Signer with pub must serve, so its
// handle plugs into tls.Certificate and x509.CreateCertificate: ECDSA over
// SHA-256, RSA PKCS #1 v1.5 and PSS over SHA-256, and Ed25519. It returns nil
// for a public key of any other type.
func signSchemes(pub crypto.PublicKey) []signScheme {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return []signScheme{{name: "ECDSA SHA-256", opts: crypto.SHA256, verify: func(digest, sig []byte) bool {
			return ecdsa.VerifyASN1(k, digest, sig)
		}}}
	case *rsa.PublicKey:
		pss := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
		return []signScheme{
			{name: "RSA PKCS #1 v1.5 SHA-256", opts: crypto.SHA256, verify: func(digest, sig []byte) bool {
				return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) == nil
			}},
			{name: "RSA PSS SHA-256", opts: pss, verify: func(digest, sig []byte) bool {
				return rsa.VerifyPSS(k, crypto.SHA256, digest, sig, pss) == nil
			}},
		}
	case ed25519.PublicKey:
		return []signScheme{{name: "Ed25519", opts: crypto.Hash(0), verify: func(msg, sig []byte) bool {
			return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
		}}}
	default:
		return nil
	}
}

// checkSigner requires every signature to verify against Public under each
// scheme its key type serves. A key of a type the suite cannot verify is
// refused as unchecked.
func checkSigner(r *report, cfg Config) {
	const property = "crypto.Signer"
	eachCase(r, cfg, property, enclave.CapabilitySign, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		s, ok := h.(crypto.Signer)
		if !ok {
			return
		}
		pub := s.Public()
		schemes := signSchemes(pub)
		if schemes == nil {
			r.unchecked(hc.Name, enclave.CapabilitySign, "Public returned %T; the suite verifies ECDSA, RSA and Ed25519 signatures only", pub)
			return
		}
		for _, scheme := range schemes {
			digest, _ := signArgs(pub, randomBytes(materialBytes))
			sig, err := s.Sign(rand.Reader, digest, scheme.opts)
			if err != nil {
				r.fail(property, "%s: Sign (%s) returned %v", hc.Name, scheme.name, err)
				continue
			}
			if !scheme.verify(digest, sig) {
				r.fail(property, "%s: a %s signature from Sign does not verify against Public", hc.Name, scheme.name)
			}
		}
	})
}

// checkDecrypter requires Decrypt to reverse RSA-OAEP encryption to Public and
// to refuse a tampered ciphertext. A key that is not RSA is refused as
// unchecked: the seam names no other encryption to Public the suite can make.
func checkDecrypter(r *report, cfg Config) {
	const property = "crypto.Decrypter"
	eachCase(r, cfg, property, enclave.CapabilityDecrypt, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		d, ok := h.(crypto.Decrypter)
		if !ok {
			return
		}
		pub, ok := d.Public().(*rsa.PublicKey)
		if !ok {
			r.unchecked(hc.Name, enclave.CapabilityDecrypt, "Public returned %T; the suite exercises RSA-OAEP decryption only", d.Public())
			return
		}
		msg := randomBytes(materialBytes)
		opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
		if err != nil {
			r.fail(property, "%s: RSA-OAEP SHA-256 encryption to Public failed: %v", hc.Name, err)
			return
		}
		plaintext, err := d.Decrypt(rand.Reader, ciphertext, opts)
		if err != nil || !bytes.Equal(plaintext, msg) {
			r.fail(property, "%s: Decrypt of an RSA-OAEP SHA-256 ciphertext to Public did not return the message (%v)", hc.Name, err)
		}
		tampered := append([]byte(nil), ciphertext...)
		tampered[len(tampered)/2] ^= 0x01
		if plaintext, err := d.Decrypt(rand.Reader, tampered, opts); err == nil {
			r.fail(property, "%s: Decrypt accepted a tampered ciphertext and returned %d bytes", hc.Name, len(plaintext))
		}
	})
}

func checkAEAD(r *report, cfg Config) {
	const property = "AEAD"
	eachCase(r, cfg, property, enclave.CapabilityAEAD, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		aead, ok := h.(enclave.AEAD)
		if !ok {
			return
		}
		nonce := nonceFor(aead)
		plaintext := []byte("backendtest plaintext")
		aad := []byte("backendtest aad")
		prefix := []byte("dst")
		sealed, err := aead.Seal(append([]byte(nil), prefix...), nonce, plaintext, aad)
		if err != nil {
			r.fail(property, "%s: Seal returned %v", hc.Name, err)
			return
		}
		if !bytes.HasPrefix(sealed, prefix) {
			r.fail(property, "%s: Seal did not append to dst", hc.Name)
			return
		}
		sealed = sealed[len(prefix):]
		if extra := len(sealed) - len(plaintext); extra < 0 || extra > aead.Overhead() {
			r.fail(property, "%s: Seal added %d bytes to the plaintext, more than Overhead %d", hc.Name, extra, aead.Overhead())
		}
		opened, err := aead.Open(append([]byte(nil), prefix...), nonce, sealed, aad)
		if err != nil || !bytes.Equal(opened, append(append([]byte(nil), prefix...), plaintext...)) {
			r.fail(property, "%s: Open round trip appended to dst = %q, %v; want dst then the plaintext, nil", hc.Name, opened, err)
		}
		badNonce := wrongNonceFor(aead)
		if _, err := aead.Seal(nil, badNonce, plaintext, aad); !errors.Is(err, enclave.ErrInvalidNonce) {
			r.fail(property, "%s: Seal with wrong nonce length returned %v, want ErrInvalidNonce", hc.Name, err)
		}
		if _, err := aead.Open(nil, badNonce, sealed, aad); !errors.Is(err, enclave.ErrInvalidNonce) {
			r.fail(property, "%s: Open with wrong nonce length returned %v, want ErrInvalidNonce", hc.Name, err)
		}
		tampered := append([]byte(nil), sealed...)
		tampered[len(tampered)/2] ^= 0x80
		if opened, err := aead.Open(nil, nonce, tampered, aad); !errors.Is(err, enclave.ErrAEADAuthentication) || len(opened) != 0 {
			r.fail(property, "%s: Open of tampered ciphertext returned %q, %v; want no plaintext and ErrAEADAuthentication", hc.Name, opened, err)
		}
		if opened, err := aead.Open(nil, nonce, sealed, []byte("other aad")); !errors.Is(err, enclave.ErrAEADAuthentication) || len(opened) != 0 {
			r.fail(property, "%s: Open with different additional data returned %q, %v; want no plaintext and ErrAEADAuthentication", hc.Name, opened, err)
		}
	})
}

// checkAttester holds the backend's Attester and every case's to the nonce
// contract. Evidence is never parsed, so binding is checked as evidence that
// differs when the nonce does.
func checkAttester(r *report, cfg Config) {
	const property = "Attester"
	if hasCap(cfg.BackendCapabilities, enclave.CapabilityAttest) {
		b, err := newBackend(cfg)
		if err != nil {
			r.fail(property, "%v", err)
		} else if a, ok := b.(enclave.Attester); ok {
			checkAttestation(r, cfg, property, "", a)
		}
	}
	eachCase(r, cfg, property, enclave.CapabilityAttest, func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		if a, ok := h.(enclave.Attester); ok {
			checkAttestation(r, cfg, property, hc.Name, a)
		}
	})
}

// checkAttestation checks a, the backend's own Attester for an empty caseName
// or a handle of that case otherwise.
func checkAttestation(r *report, cfg Config, property, caseName string, a enclave.Attester) {
	who := caseName
	if who == "" {
		who = "backend"
	}
	nonce := randomBytes(materialBytes)
	e1, err := a.Attest(r.ctx, bytes.Clone(nonce))
	if err != nil {
		r.fail(property, "%s: Attest returned %v", who, err)
		return
	}
	if e1.Format == "" || len(e1.Data) == 0 {
		r.fail(property, "%s: Attest returned evidence with Format %q and %d bytes of Data; both are required", who, e1.Format, len(e1.Data))
	}
	if e2, err := a.Attest(r.ctx, randomBytes(materialBytes)); err != nil {
		r.fail(property, "%s: a second Attest returned %v", who, err)
	} else if bytes.Equal(e1.Data, e2.Data) {
		r.fail(property, "%s: evidence for two different nonces is identical, so it does not bind the nonce", who)
	}
	checkBinding(r, cfg, property, caseName, who, nonce, e1)
	for _, n := range []int{1, maxNonce} {
		if _, err := a.Attest(r.ctx, randomBytes(n)); err != nil {
			r.fail(property, "%s: Attest refused a %d-byte nonce (%v); 1 to %d bytes are valid", who, n, err, maxNonce)
		}
	}
	for _, nonce := range [][]byte{nil, randomBytes(maxNonce + 1)} {
		if _, err := a.Attest(r.ctx, nonce); err == nil {
			r.fail(property, "%s: Attest accepted a %d-byte nonce; the nonce is 1 to %d bytes and is never truncated", who, len(nonce), maxNonce)
		}
	}
	if _, err := a.Attest(canceledContext(r.ctx), randomBytes(materialBytes)); !errors.Is(err, context.Canceled) {
		r.fail(property, "%s: Attest with an already-canceled context returned %v, want an error matching context.Canceled", who, err)
	}
}

// checkBinding checks that evidence, which Attest returned for nonce, binds
// it: it verifies against nonce and not against a nonce one bit away. Without
// [Config.VerifyEvidence] evidence that differs between calls is all the suite
// can see, and an Attester that ignores the nonce but randomizes its evidence
// shows the same, so the capability is reported unchecked, not certified.
func checkBinding(r *report, cfg Config, property, caseName, who string, nonce []byte, evidence enclave.Evidence) {
	if cfg.VerifyEvidence == nil {
		r.unchecked(caseName, enclave.CapabilityAttest, "Config.VerifyEvidence is nil, so the suite cannot tell evidence "+
			"that binds the nonce from evidence that merely differs between calls")
		return
	}
	if err := cfg.VerifyEvidence(bytes.Clone(nonce), evidence); err != nil {
		r.fail(property, "%s: evidence for a nonce does not verify against that nonce: %v", who, err)
	}
	other := bytes.Clone(nonce)
	other[0] ^= 1
	if err := cfg.VerifyEvidence(other, evidence); err == nil {
		r.fail(property, "%s: evidence for one nonce also verifies against another, so it does not bind the nonce", who)
	}
}

func checkImporter(r *report, cfg Config) {
	const property = "Importer"
	if !hasCap(cfg.BackendCapabilities, enclave.CapabilityImport) {
		return
	}
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	imp, ok := b.(enclave.Importer)
	if !ok {
		return
	}
	for _, hc := range cfg.Handles {
		if hc.Import == nil {
			continue
		}
		src := randomBytes(hc.ImportSize)
		orig := append([]byte(nil), src...)
		h, ierr := imp.Import(r.ctx, src, hc.Import...)
		if !allZero(src) {
			r.fail(property, "%s: Import did not wipe the caller's source on success", hc.Name)
		}
		if ierr != nil {
			r.fail(property, "%s: Import returned %v", hc.Name, ierr)
			if !isNilInterface(h) {
				_ = destroy(h)
			}
			continue
		}
		if isNilInterface(h) {
			r.fail(property, "%s: Import returned a nil handle and a nil error", hc.Name)
			continue
		}
		checkImportedPurpose(r, property, hc, h, orig)
		checkDestroy(r, property, hc.Name+": Destroy of the imported handle", h)
	}
	src := randomBytes(materialBytes)
	refused, err := imp.Import(r.ctx, src, nil)
	if !errors.Is(err, enclave.ErrInvalidImport) {
		r.fail(property, "Import with a nil option returned %v, want ErrInvalidImport", err)
	}
	if !allZero(src) {
		r.fail(property, "Import did not wipe the caller's source after invalid options")
	}
	checkRefusedImport(r, property, "with a nil option", refused, err)
	src = randomBytes(materialBytes - 1)
	refused, err = imp.Import(r.ctx, src, enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM))
	if !errors.Is(err, enclave.ErrInvalidImport) {
		r.fail(property, "Import with an invalid AES-256-GCM key length returned %v, want ErrInvalidImport", err)
	}
	if !allZero(src) {
		r.fail(property, "Import did not wipe the caller's source after invalid material length")
	}
	checkRefusedImport(r, property, "with an invalid AES-256-GCM key length", refused, err)
	src = randomBytes(materialBytes)
	refused, err = imp.Import(canceledContext(r.ctx), src, enclave.WithPurpose(enclave.PurposeMaterial))
	if !errors.Is(err, context.Canceled) {
		r.fail(property, "Import with an already-canceled context returned %v, want context.Canceled", err)
	}
	if !allZero(src) {
		r.fail(property, "Import did not wipe the caller's source after context cancellation")
	}
	checkRefusedImport(r, property, "with an already-canceled context", refused, err)
}

// checkRefusedImport fails property if an Import, which probe describes,
// returned an error and a live handle: the Importer contract refuses before
// any device work, so a refusal holds no material. Whatever the error, it
// destroys any handle returned, so the probe leaks nothing.
func checkRefusedImport(r *report, property, probe string, h enclave.Handle, err error) {
	if isNilInterface(h) {
		return
	}
	if err != nil && h.IsAlive() {
		r.fail(property, "Import %s returned %v and a live handle; a refused import holds no material", probe, err)
	}
	_ = destroy(h)
}

// checkImportedPurpose holds an imported handle to its purpose's contract: the
// material for PurposeMaterial, and for a key the imported key, through the
// view or, for an AES-256-GCM AEAD with a 12-byte nonce, by opening what this
// process sealed with the imported key.
func checkImportedPurpose(r *report, property string, hc HandleCase, h enclave.Handle, material []byte) {
	spec, err := enclave.NewImportSpec(hc.Import...)
	if err != nil {
		r.fail(property, "%s: NewImportSpec refused the case's options: %v", hc.Name, err)
		return
	}
	if h.Size() != len(material) {
		r.fail(property, "%s: Size is %d, want imported material size %d", hc.Name, h.Size(), len(material))
	}
	ba, hasBytes := h.(enclave.ByteAccess)
	aead, hasAEAD := h.(enclave.AEAD)
	switch {
	case spec.Purpose == enclave.PurposeMaterial && !hasBytes:
		r.fail(property, "%s: a PurposeMaterial handle is %T, without ByteAccess", hc.Name, h)
		return
	case !hasBytes && !hasAEAD:
		r.fail(property, "%s: a %s handle is %T, with neither AEAD nor ByteAccess", hc.Name, spec.Purpose, h)
		return
	}
	if hasBytes {
		if eq, err := ba.EqualTo(material); err != nil || !eq {
			r.fail(property, "%s: the %s handle does not hold the imported material (EqualTo = %v, %v)", hc.Name, spec.Purpose, eq, err)
		}
	}
	isAES := spec.Algorithm == enclave.AlgorithmAES256GCM
	if hasAEAD && isAES {
		checkImportedAESKey(r, property, hc.Name, aead, material)
	}
	// Without ByteAccess, only checkImportedAESKey's in-process GCM can see
	// the material, and only when the handle takes the caller's nonce.
	if !hasBytes && (!isAES || aead.NonceSize() == 0) {
		r.unchecked(hc.Name, enclave.CapabilityImport, "the %s handle is %T, an AEAD without ByteAccess, and the suite "+
			"can tell it holds the imported material only for an AES-256-GCM key with a 12-byte nonce", spec.Purpose, h)
	}
}

// checkImportedAESKey requires an AES-256-GCM handle to be that algorithm, and
// to open what the imported key sealed in this process. A handle that draws
// its own nonce carries it in a format the seam leaves to the backend, so only
// its constants are checked. FIPS 140-only mode refuses this process a GCM
// under a caller-chosen nonce, so there only the ciphertext body is checked.
func checkImportedAESKey(r *report, property, name string, aead enclave.AEAD, key []byte) {
	const nonceSize, overhead = 12, 16
	if aead.Overhead() != overhead || aead.NonceSize() != nonceSize && aead.NonceSize() != 0 {
		r.fail(property, "%s: an AES-256-GCM handle reports NonceSize %d and Overhead %d, want %d (or 0) and %d",
			name, aead.NonceSize(), aead.Overhead(), nonceSize, overhead)
		return
	}
	if aead.NonceSize() == 0 {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		r.fail(property, "%s: the imported key is not an AES key: %v", name, err)
		return
	}
	nonce := randomBytes(nonceSize)
	plaintext := []byte("backendtest imported key")
	if fips140.Enforced() {
		checkImportedGCMBody(r, property, name, aead, block, nonce, plaintext)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		r.fail(property, "%s: %v", name, err)
		return
	}
	opened, err := aead.Open(nil, nonce, gcm.Seal(nil, nonce, plaintext, nil), nil)
	if err != nil || !bytes.Equal(opened, plaintext) {
		r.fail(property, "%s: the handle cannot open what the imported key sealed (%v); it does not hold the imported key", name, err)
	}
}

// checkImportedGCMBody is checkImportedAESKey under FIPS 140-only mode: it
// requires the handle's ciphertext body under nonce to be GCM's, the plaintext
// under AES-CTR from the nonce's second counter block, using the approved
// AES-CTR the mode leaves this process. The tag is the handle's own.
func checkImportedGCMBody(r *report, property, name string, aead enclave.AEAD, block cipher.Block, nonce, plaintext []byte) {
	sealed, err := aead.Seal(nil, nonce, plaintext, nil)
	if err != nil || len(sealed) != len(plaintext)+aead.Overhead() {
		r.fail(property, "%s: the handle cannot seal under the imported key (%d bytes, %v)", name, len(sealed), err)
		return
	}
	// GCM's J0+1 for a 12-byte nonce: the nonce, then a 32-bit counter of 2.
	counter := binary.BigEndian.AppendUint32(bytes.Clone(nonce), 2)
	want := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter).XORKeyStream(want, plaintext)
	if !bytes.Equal(sealed[:len(plaintext)], want) {
		r.fail(property, "%s: the handle's ciphertext is not the imported key's AES-GCM; it does not hold the imported key", name)
	}
}

func checkSweeper(r *report, cfg Config) {
	const property = "Sweeper"
	if !hasCap(cfg.BackendCapabilities, enclave.CapabilitySweep) {
		return
	}
	for _, ctx := range []context.Context{nil, canceledContext(r.ctx)} {
		b, err := newBackend(cfg)
		if err != nil {
			r.fail(property, "%v", err)
			return
		}
		sw, ok := b.(enclave.Sweeper)
		if !ok {
			return
		}
		var names []string
		var handles []enclave.Handle
		var consts []constants
		for _, hc := range cfg.Handles {
			h, _, err := newHandleFromBackend(r.ctx, b, hc)
			if err != nil {
				r.fail(property, "%s: %v", hc.Name, err)
				continue
			}
			names = append(names, hc.Name)
			handles = append(handles, h)
			consts = append(consts, constantsOf(h))
		}
		held, err := sw.Sweep(ctx)
		if held != 0 || err != nil {
			r.fail(property, "Sweep(%s) = %d, %v; want 0, nil", contextName(ctx), held, err)
		}
		// A swept handle is destroyed: it must behave as one in every way,
		// not just report itself dead.
		for i, h := range handles {
			if h.IsAlive() {
				r.fail(property, "%s: handle is alive after Sweep(%s)", names[i], contextName(ctx))
			} else {
				checkDestroyed(r, property, names[i]+": after Sweep("+contextName(ctx)+")", h, b, consts[i])
			}
			_ = destroy(h)
		}
		if held, err := sw.Sweep(ctx); held != 0 || err != nil {
			r.fail(property, "a repeated Sweep(%s) = %d, %v; want 0, nil", contextName(ctx), held, err)
		}
	}
}

func checkConfiner(r *report, cfg Config) {
	const property = "Confiner"
	if !hasCap(cfg.BackendCapabilities, enclave.CapabilityConfine) {
		return
	}
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	confiner, ok := b.(enclave.Confiner)
	if !ok {
		return
	}
	first := confiner.ConfinesProcess()
	for i := 0; i < 8; i++ {
		if got := confiner.ConfinesProcess(); got != first {
			r.fail(property, "ConfinesProcess changed from %v to %v", first, got)
			return
		}
	}
}

// checkProber checks what enclave.Detect relies on: Rank is fixed, and Probe
// gives one verdict, nil or an error, under a live and a nil context, called
// again and called concurrently. It cannot check that the verdict matches the
// host; the backend's own tests do that.
func checkProber(r *report, cfg Config) {
	const property = "Prober"
	if !hasCap(cfg.BackendCapabilities, enclave.CapabilityProbe) {
		return
	}
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	prober, ok := b.(enclave.Prober)
	if !ok {
		return
	}
	rank := prober.Rank()
	for i := 0; i < 8; i++ {
		if got := prober.Rank(); got != rank {
			r.fail(property, "Rank changed from %d to %d", rank, got)
			return
		}
	}
	first := prober.Probe(r.ctx)
	for _, ctx := range []context.Context{r.ctx, nil} {
		if err := prober.Probe(ctx); (err == nil) != (first == nil) {
			r.fail(property, "Probe(%s) = %v after Probe returned %v", contextName(ctx), err, first)
			return
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, concurrencyRuns)
	for i := range errs {
		wg.Go(func() {
			defer func() {
				if p := recover(); p != nil {
					r.panicked(p)
					errs[i] = first
				}
			}()
			errs[i] = prober.Probe(r.ctx)
		})
	}
	wg.Wait()
	for _, err := range errs {
		if (err == nil) != (first == nil) {
			r.fail(property, "a concurrent Probe = %v after Probe returned %v", err, first)
			return
		}
	}
}
