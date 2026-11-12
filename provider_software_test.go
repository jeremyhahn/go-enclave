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
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"hash"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// TestSoftwareProvider_ProtectUnprotect covers the software provider as a
// bare KeyProtector: round trip, the authenticated-by-contract refusals with
// their controls, and the framing checks.
func TestSoftwareProvider_ProtectUnprotect(t *testing.T) {
	p := newSoftwareProvider()

	key := bytes.Repeat([]byte{0x3C}, RootKeyBytes)
	blob, err := p.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	got := make([]byte, len(key))
	if err := p.Unprotect(t.Context(), blob, got); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("Unprotect recovered the wrong key")
	}

	// Foreign: a blob from a different provider instance must be refused.
	other := newSoftwareProvider()
	otherBlob, err := other.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect (other): %v", err)
	}
	if err := p.Unprotect(t.Context(), otherBlob, got); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect(foreign blob) = %v, want ErrSealedAuthentication", err)
	}

	// A provider that has protected nothing owns no blobs at all.
	if err := newSoftwareProvider().Unprotect(t.Context(), blob, got); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect on a fresh provider = %v, want ErrSealedAuthentication", err)
	}

	// Tampering and truncation across the blob, with the frame cases spelled
	// out: wrong version, wrong kind, nonzero generation.
	for name, corrupt := range map[string]func([]byte) []byte{
		"flipped body byte": func(b []byte) []byte { c := append([]byte(nil), b...); c[blobHeaderLen] ^= 0xFF; return c },
		"flipped last byte": func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-1] ^= 0xFF; return c },
		"truncated":         func(b []byte) []byte { return b[:len(b)-1] },
		"frame only":        func(b []byte) []byte { return b[:blobHeaderLen] },
		"empty":             func([]byte) []byte { return nil },
		"wrong version":     func(b []byte) []byte { c := append([]byte(nil), b...); c[0] = 99; return c },
		"wrong kind":        func(b []byte) []byte { c := append([]byte(nil), b...); c[1] = blobKindDEK; return c },
		"nonzero gen":       func(b []byte) []byte { c := append([]byte(nil), b...); c[5] = 1; return c },
	} {
		if err := p.Unprotect(t.Context(), corrupt(blob), got); !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("Unprotect(%s) = %v, want ErrSealedAuthentication", name, err)
		}
	}

	// Wrong destination length is an authentication failure, decided before
	// anything is decrypted — the same no-reallocation rule as everywhere.
	if err := p.Unprotect(t.Context(), blob, make([]byte, 16)); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect into a short destination = %v, want ErrSealedAuthentication", err)
	}

	// Control after all the refusals: the original still unprotects.
	if err := p.Unprotect(t.Context(), blob, got); err != nil {
		t.Fatalf("control Unprotect: %v", err)
	}
}

// TestSoftwareProvider_MessageLimit pins the provider's refusal at its
// per-key encryption budget, driving the counter directly.
func TestSoftwareProvider_MessageLimit(t *testing.T) {
	p := newSoftwareProvider()
	key := make([]byte, RootKeyBytes)

	blob, err := p.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	p.s.mu.Lock()
	p.s.protects = softwareProtectLimit
	p.s.mu.Unlock()

	if _, err := p.Protect(t.Context(), append([]byte(nil), key...)); !errors.Is(err, ErrProviderMessageLimit) {
		t.Errorf("Protect at the limit = %v, want ErrProviderMessageLimit", err)
	}

	// The refusal is on ENCRYPTION only: existing blobs still unprotect,
	// because the bound protects nonce uniqueness, not decryption.
	got := make([]byte, len(key))
	if err := p.Unprotect(t.Context(), blob, got); err != nil {
		t.Errorf("Unprotect past the Protect limit = %v; the bound must not strand existing blobs", err)
	}
}

// TestSoftwareProvider_UnsealRoot covers the RootUnsealer half: the size
// contract, and determinism across calls — two sealers over one provider
// must receive the same root, or "the provider's root" would not be a
// meaningful phrase.
func TestSoftwareProvider_UnsealRoot(t *testing.T) {
	p := newSoftwareProvider()

	if err := p.UnsealRoot(t.Context(), make([]byte, RootKeyBytes-1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(short dst) = %v, want ErrInvalidSize", err)
	}
	if err := p.UnsealRoot(t.Context(), make([]byte, RootKeyBytes+1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(long dst) = %v, want ErrInvalidSize", err)
	}

	// Generated key material: unsealed into locked destinations and compared
	// inside their borrows, never copied onto the heap.
	a, err := newMemorySized(RootKeyBytes)
	if err != nil {
		t.Fatalf("allocating a: %v", err)
	}
	defer func() { _ = a.Destroy() }()
	b, err := newMemorySized(RootKeyBytes)
	if err != nil {
		t.Fatalf("allocating b: %v", err)
	}
	defer func() { _ = b.Destroy() }()
	var same, zero bool
	if err := a.WithBytes(func(ra []byte) error {
		if err := p.UnsealRoot(t.Context(), ra); err != nil {
			return err
		}
		zero = memscan.AllZero(ra)
		return b.WithBytes(func(rb []byte) error {
			if err := p.UnsealRoot(t.Context(), rb); err != nil {
				return err
			}
			same = bytes.Equal(ra, rb)
			return nil
		})
	}); err != nil {
		t.Fatalf("UnsealRoot: %v", err)
	}
	if !same {
		t.Error("two UnsealRoot calls yielded different roots")
	}
	if zero {
		t.Error("UnsealRoot yielded an all-zero root; the CSPRNG was not consulted")
	}
}

// TestSoftwareProvider_RefusesAnEndedContext pins the shipped provider's half
// of the contract directly: every method refuses an ended context with its
// error, a refused first call generates no root, and a refused Protect is not
// charged to the message budget.
func TestSoftwareProvider_RefusesAnEndedContext(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			p := newSoftwareProvider()
			key := bytes.Repeat([]byte{0x3C}, RootKeyBytes)

			if _, err := p.Protect(ec.ctx, key); !errors.Is(err, ec.want) {
				t.Errorf("Protect = %v, want %v", err, ec.want)
			}
			dst := make([]byte, RootKeyBytes)
			if err := p.UnsealRoot(ec.ctx, dst); !errors.Is(err, ec.want) {
				t.Errorf("UnsealRoot = %v, want %v", err, ec.want)
			}
			p.s.mu.Lock()
			root, protects := p.s.root, p.s.protects
			p.s.mu.Unlock()
			if root != nil {
				t.Error("a refused call generated the provider root")
			}
			if protects != 0 {
				t.Errorf("a refused Protect was charged to the budget (%d)", protects)
			}

			blob, err := p.Protect(t.Context(), key)
			if err != nil {
				t.Fatalf("Protect: %v", err)
			}
			got := make([]byte, RootKeyBytes)
			if err := p.Unprotect(ec.ctx, blob, got); !errors.Is(err, ec.want) {
				t.Errorf("Unprotect = %v, want %v", err, ec.want)
			}
			if !bytes.Equal(got, make([]byte, RootKeyBytes)) {
				t.Error("a refused Unprotect wrote into the destination")
			}
			// The size contract is a programming mistake and is reported as
			// such whatever the context says.
			if err := p.UnsealRoot(ec.ctx, make([]byte, 1)); !errors.Is(err, ErrInvalidSize) {
				t.Errorf("UnsealRoot(short dst, ended ctx) = %v, want ErrInvalidSize", err)
			}
		})
	}
}

func TestSoftwareProvider_Destroy(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()

	p := newSoftwareProvider()
	blob, err := p.Protect(ctx, make([]byte, RootKeyBytes))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if err := p.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d: the root outlived Destroy", got, base)
	}
	if _, err := p.Protect(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("Protect after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if err := p.Unprotect(ctx, blob, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("Unprotect after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if err := p.UnsealRoot(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("UnsealRoot after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if err := p.Health(); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("Health after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if err := p.Destroy(); err != nil {
		t.Errorf("second Destroy = %v, want nil", err)
	}

	// A provider destroyed before first use never generates a root.
	fresh := newSoftwareProvider()
	if err := fresh.Destroy(); err != nil {
		t.Fatalf("Destroy of an unused provider: %v", err)
	}
	if err := fresh.UnsealRoot(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("UnsealRoot on a provider destroyed unused = %v, want ErrSealerDestroyed", err)
	}
	if fresh.s.root != nil {
		t.Error("a destroyed provider generated a root")
	}

	var nilProvider *softwareProvider
	if err := nilProvider.Destroy(); err != nil {
		t.Errorf("nil provider Destroy = %v, want nil", err)
	}
}

// TestSoftwareProvider_OpenableDoesNotGenerateARoot pins that Openable has no
// side effects: it does not generate a root for a provider that sealed
// nothing.
func TestSoftwareProvider_OpenableDoesNotGenerateARoot(t *testing.T) {
	p := newSoftwareProvider()

	if err := p.Health(); err != nil {
		t.Errorf("Health on a fresh provider = %v, want nil: nothing was sealed through it, "+
			"so nothing it holds is unopenable", err)
	}

	p.s.mu.Lock()
	root := p.s.root
	p.s.mu.Unlock()
	if root != nil {
		t.Error("asking whether a provider can open generated its root; a diagnostic must not " +
			"allocate locked memory or draw from the CSPRNG")
	}
}

// TestSoftwareProvider_ProtectKeyIsNotTheRoot pins the key separation: Protect
// wraps under HKDF-SHA256 of the root under softwareProtectKeyInfo, never under
// the root UnsealRoot exports.
func TestSoftwareProvider_ProtectKeyIsNotTheRoot(t *testing.T) {
	p := newSoftwareProvider()
	t.Cleanup(func() { _ = p.Destroy() })

	if _, err := p.Protect(t.Context(), make([]byte, RootKeyBytes)); err != nil {
		t.Fatalf("Protect: %v", err)
	}
	root := make([]byte, RootKeyBytes)
	if err := p.UnsealRoot(t.Context(), root); err != nil {
		t.Fatalf("UnsealRoot: %v", err)
	}

	var pk []byte
	if err := p.s.protectKey.WithBytes(func(b []byte) error {
		pk = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("reading the Protect key: %v", err)
	}
	if bytes.Equal(pk, root) {
		t.Fatal("Protect wraps under the root UnsealRoot exports")
	}
	want, err := hkdf.Key(sha256.New, root, nil, softwareProtectKeyInfo, RootKeyBytes)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	if !bytes.Equal(pk, want) {
		t.Error("the Protect key is not HKDF-SHA256 of the root under softwareProtectKeyInfo")
	}
}

// TestSoftwareProvider_DeriveFailure fails the Protect-key derivation and
// checks the refused Protect leaves nothing behind: no blob, no budget
// charge, no derived key, no leaked region, and the same root on retry.
func TestSoftwareProvider_DeriveFailure(t *testing.T) {
	p := newSoftwareProvider()
	t.Cleanup(func() { _ = p.Destroy() })
	ctx := t.Context()

	rootBefore := make([]byte, RootKeyBytes)
	if err := p.UnsealRoot(ctx, rootBefore); err != nil {
		t.Fatalf("UnsealRoot: %v", err)
	}
	baseline := liveCount()

	seamErr := errors.New("hkdf failed")
	calls := 0
	prev := swapSeam(t, &hkdfKey, func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error) {
		calls++
		return nil, seamErr
	})

	key := bytes.Repeat([]byte{0x5a}, RootKeyBytes)
	blob, err := p.Protect(ctx, key)
	if !errors.Is(err, ErrSealFailed) {
		t.Fatalf("Protect = %v, want ErrSealFailed", err)
	}
	var se *SealError
	if !errors.As(err, &se) || se.Cause != seamErr {
		t.Fatalf("Protect = %v, want a *SealError carrying the seam's error", err)
	}
	if blob != nil {
		t.Error("a refused Protect returned a blob")
	}
	if calls != 1 {
		t.Errorf("hkdfKey called %d times, want 1", calls)
	}
	if p.s.protects != 0 {
		t.Errorf("protects = %d after a refused derivation, want 0", p.s.protects)
	}
	if p.s.protectKey != nil {
		t.Error("protectKey set after a refused derivation")
	}
	if p.s.root == nil {
		t.Error("root cleared by a refused derivation")
	}
	if got := liveCount(); got != baseline {
		t.Errorf("liveCount = %d after a refused derivation, want %d: the derived region leaked", got, baseline)
	}

	hkdfKey = prev
	blob, err = p.Protect(ctx, key)
	if err != nil {
		t.Fatalf("Protect after the seam is restored: %v", err)
	}
	if got := liveCount(); got != baseline+1 {
		t.Errorf("liveCount = %d after the derived key exists, want %d", got, baseline+1)
	}
	got := make([]byte, RootKeyBytes)
	if err := p.Unprotect(ctx, blob, got); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("Unprotect did not recover the key")
	}
	rootAfter := make([]byte, RootKeyBytes)
	if err := p.UnsealRoot(ctx, rootAfter); err != nil {
		t.Fatalf("UnsealRoot after retry: %v", err)
	}
	if !bytes.Equal(rootAfter, rootBefore) {
		t.Error("the root was regenerated by the refused derivation")
	}

	calls = 0
	swapSeam(t, &hkdfKey, func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error) {
		calls++
		return nil, seamErr
	})
	if err := p.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := p.Protect(ctx, key); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("Protect after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if calls != 0 {
		t.Errorf("hkdfKey called %d times after Destroy, want 0", calls)
	}
}

// TestSoftwareProvider_CopySharesState pins that a copy of a provider is the
// same provider: one root, one lock, one Destroy.
func TestSoftwareProvider_CopySharesState(t *testing.T) {
	p := newSoftwareProvider()
	t.Cleanup(func() { _ = p.Destroy() })

	// Copied through reflect, as vet's copylocks would refuse a plain copy.
	cp := new(softwareProvider)
	reflect.ValueOf(cp).Elem().Set(reflect.ValueOf(p).Elem())

	key := bytes.Repeat([]byte{0x5a}, RootKeyBytes)
	blob, err := cp.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect through the copy: %v", err)
	}
	got := make([]byte, RootKeyBytes)
	if err := p.Unprotect(t.Context(), blob, got); err != nil {
		t.Fatalf("the original cannot open the copy's blob: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("the original recovered a different key from the copy's blob")
	}

	if err := p.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := cp.Health(); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("copy Health after the original's Destroy = %v, want ErrSealerDestroyed", err)
	}
}

// TestSoftwareProvider_ZeroValue pins that a provider NewSoftwareProvider did
// not build is refused, not used.
func TestSoftwareProvider_ZeroValue(t *testing.T) {
	var p softwareProvider
	ctx := t.Context()

	if _, err := p.Protect(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrProviderNotConstructed) {
		t.Errorf("zero-value Protect = %v, want ErrProviderNotConstructed", err)
	}
	if err := p.Unprotect(ctx, nil, make([]byte, RootKeyBytes)); !errors.Is(err, ErrProviderNotConstructed) {
		t.Errorf("zero-value Unprotect = %v, want ErrProviderNotConstructed", err)
	}
	if err := p.UnsealRoot(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrProviderNotConstructed) {
		t.Errorf("zero-value UnsealRoot = %v, want ErrProviderNotConstructed", err)
	}
	if err := p.Health(); !errors.Is(err, ErrProviderNotConstructed) {
		t.Errorf("zero-value Health = %v, want ErrProviderNotConstructed", err)
	}
	if err := p.Destroy(); err != nil {
		t.Errorf("zero-value Destroy = %v, want nil", err)
	}
}

// TestNewSoftwareProvider_ReturnsTheInterface pins that NewSoftwareProvider
// hands out the [SoftwareProvider] interface, never a pointer a caller could
// hold as a concrete type, and that the interface carries every seam a
// [Sealer] consults and the Destroy that releases the root.
func TestNewSoftwareProvider_ReturnsTheInterface(t *testing.T) {
	p := NewSoftwareProvider()
	if _, ok := p.(*softwareProvider); !ok {
		t.Fatalf("NewSoftwareProvider returned a %T, want *softwareProvider", p)
	}
	s, err := newEnvelopeSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer(WithKeyProtector): %v", err)
	}
	defer s.Destroy()
	v, err := s.sealData(t.Context(), []byte("material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := v.Openable(); err != nil {
		t.Errorf("Openable = %v, want nil while the provider is healthy", err)
	}
	if err := p.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := p.Health(); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("Health after Destroy = %v, want ErrSealerDestroyed", err)
	}
	if err := p.UnsealRoot(t.Context(), make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("UnsealRoot after Destroy = %v, want ErrSealerDestroyed", err)
	}
}
