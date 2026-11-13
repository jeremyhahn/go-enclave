// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package tpm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
)

// FuzzParseBlob hands parseBlob arbitrary bytes, as storage may return them.
// It never panics and never writes the blob. A refusal matches
// ErrSealedAuthentication. An accepted blob is exactly the framing encodeBlob
// makes of its two areas: the public area is the sealed-object template with a
// SHA-256 unique, the private area is no larger than Protect makes, and both
// areas are the blob's own bytes at their framed offsets, not copies.
func FuzzParseBlob(f *testing.F) {
	// testPublic and testBlob take a *testing.T; f is a *testing.F, so the
	// seeds are built from the same template here.
	seedPublic := func(mutate func(*tpm2.TPMTPublic)) []byte {
		pub := sealedTemplate(bytes.Repeat([]byte{0xa5}, sha256.Size))
		if mutate != nil {
			mutate(&pub)
		}
		return tpm2.Marshal(pub)
	}
	public := seedPublic(nil)
	good := encodeBlob(public, bytes.Repeat([]byte{0x5a}, sealedPrivateBytes))

	f.Add([]byte(nil))
	f.Add(good)
	for n := range len(good) {
		f.Add(bytes.Clone(good[:n]))
	}
	f.Add(append([]byte{tpmBlobVersion + 1}, good[1:]...))
	f.Add(append([]byte{0}, good[1:]...))
	f.Add(append(bytes.Clone(good), 0))
	f.Add(encodeBlob(public, nil))
	f.Add(encodeBlob(public, bytes.Repeat([]byte{0x5a}, maxPrivateBytes)))
	f.Add(encodeBlob(public, bytes.Repeat([]byte{0x5a}, maxPrivateBytes+1)))
	f.Add(encodeBlob(append(bytes.Clone(public), 0), []byte{1}))
	for _, mutate := range []func(*tpm2.TPMTPublic){
		func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA384 },
		func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false },
		func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true },
		func(p *tpm2.TPMTPublic) { p.AuthPolicy = tpm2.TPM2BDigest{Buffer: make([]byte, 32)} },
		func(p *tpm2.TPMTPublic) { p.Unique = sealedTemplate(make([]byte, 20)).Unique },
		func(p *tpm2.TPMTPublic) { *p = storageTemplate(make([]byte, 32)) },
	} {
		f.Add(encodeBlob(seedPublic(mutate), []byte{1}))
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		before := bytes.Clone(in)
		pub, priv, err := parseBlob(in)
		if !bytes.Equal(in, before) {
			t.Fatal("parseBlob modified the blob")
		}
		if err != nil {
			if !errors.Is(err, enclave.ErrSealedAuthentication) {
				t.Fatalf("parseBlob = %v, want an error matching ErrSealedAuthentication", err)
			}
			if pub != nil || priv != nil {
				t.Fatal("a refused parseBlob returned an area")
			}
			return
		}
		if !bytes.Equal(encodeBlob(pub, priv), in) {
			t.Fatal("the accepted blob is not the framing of its two areas")
		}
		if len(priv) > maxPrivateBytes {
			t.Fatalf("accepted a %d-byte private area, bound %d", len(priv), maxPrivateBytes)
		}
		decoded, err := tpm2.Unmarshal[tpm2.TPMTPublic](pub)
		if err != nil {
			t.Fatalf("the accepted public area does not unmarshal: %v", err)
		}
		unique, err := decoded.Unique.KeyedHash()
		if err != nil || len(unique.Buffer) != sha256.Size {
			t.Fatal("the accepted public area's unique is not a SHA-256 digest")
		}
		if !bytes.Equal(pub, tpm2.Marshal(sealedTemplate(unique.Buffer))) {
			t.Fatal("the accepted public area is not the sealed-object template")
		}
		// The framing is version (1), size (2), public, size (2), private:
		// each area must be the blob's own bytes at its offset.
		if &pub[0] != &in[3] {
			t.Fatal("the public area does not alias the blob")
		}
		if len(priv) > 0 && &priv[0] != &in[3+len(pub)+2] {
			t.Fatal("the private area does not alias the blob")
		}
	})
}
