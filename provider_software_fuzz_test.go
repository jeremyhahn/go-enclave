// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// FuzzSoftwareProviderUnprotect hands Unprotect blobs from storage it did not
// write, with a live, canceled or expired context. It never panics. An ended
// context is refused with ctx.Err() before the blob is read, leaving key
// untouched. A live context opens only the one blob Protect produced, into the
// key Protect was given; every other blob is refused with
// ErrSealedAuthentication, leaving key untouched or wiped.
func FuzzSoftwareProviderUnprotect(f *testing.F) {
	p := NewSoftwareProvider()
	f.Cleanup(func() { _ = p.Destroy() })
	key := make([]byte, RootKeyBytes)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	blob, err := p.Protect(f.Context(), bytes.Clone(key))
	if err != nil {
		f.Fatalf("Protect: %v", err)
	}
	other := NewSoftwareProvider()
	foreign, err := other.Protect(f.Context(), bytes.Clone(key))
	if err != nil {
		f.Fatalf("Protect (foreign): %v", err)
	}
	if err := other.Destroy(); err != nil {
		f.Fatalf("Destroy (foreign): %v", err)
	}

	canceled, cancel := context.WithCancel(f.Context())
	cancel()
	expired, release := context.WithDeadline(f.Context(), time.Unix(0, 0))
	f.Cleanup(release)
	ended := []context.Context{canceled, expired}

	const live, n = uint8(0), uint8(RootKeyBytes)
	f.Add([]byte(nil), n, live)
	f.Add(blob, n, live)
	f.Add(foreign, n, live)
	f.Add(blob, n-1, live)
	f.Add(blob, n+1, live)
	f.Add(blob, n, uint8(1))
	f.Add(blob, n, uint8(2))
	for _, c := range fuzzSeedMutations(blob) {
		f.Add(c, n, live)
	}

	f.Fuzz(func(t *testing.T, in []byte, keyLen, ctxCase uint8) {
		ctx := t.Context()
		if c := int(ctxCase) % (len(ended) + 1); c > 0 {
			ctx = ended[c-1]
		}
		dst := fuzzDestination(int(keyLen))
		err := p.Unprotect(ctx, in, dst)
		switch {
		case ctx.Err() != nil:
			if !errors.Is(err, ctx.Err()) {
				t.Fatalf("Unprotect(ended context) = %v, want %v", err, ctx.Err())
			}
			if !bytes.Equal(dst, fuzzDestination(len(dst))) {
				t.Fatal("Unprotect wrote into the key under an ended context")
			}
		case err == nil:
			if !bytes.Equal(dst, key) {
				t.Fatal("Unprotect opened a blob Protect did not produce")
			}
		case !errors.Is(err, ErrSealedAuthentication):
			t.Fatalf("Unprotect = %v, want ErrSealedAuthentication", err)
		case !refusedCleanly(dst):
			t.Fatal("a refused Unprotect left the key partly written")
		}
	})
}

// FuzzSoftwareProviderRoundTrip checks that Unprotect of a Protect blob returns
// the protected key exactly, for any 32-byte key.
func FuzzSoftwareProviderRoundTrip(f *testing.F) {
	p := NewSoftwareProvider()
	f.Cleanup(func() { _ = p.Destroy() })
	seed := make([]byte, RootKeyBytes)
	if _, err := rand.Read(seed); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	f.Add(seed)
	f.Add(make([]byte, RootKeyBytes))
	f.Add(fuzzDestination(RootKeyBytes))

	f.Fuzz(func(t *testing.T, in []byte) {
		key := make([]byte, RootKeyBytes)
		copy(key, in)
		blob, err := p.Protect(t.Context(), bytes.Clone(key))
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		got := make([]byte, RootKeyBytes)
		if err := p.Unprotect(t.Context(), blob, got); err != nil {
			t.Fatalf("Unprotect: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("Unprotect returned another key than Protect was given")
		}
	})
}
