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
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"sync"
	"testing"
)

// recordWrapSalts wraps the HKDF seam so a test can read the salt of every
// wrapping-key derivation and recompute the key independently.
func recordWrapSalts(t *testing.T) *[][]byte {
	t.Helper()
	prev := hkdfKey
	t.Cleanup(func() { hkdfKey = prev })
	var salts [][]byte
	hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, n int) ([]byte, error) {
		salts = append(salts, bytes.Clone(salt))
		return prev(h, secret, salt, info, n)
	}
	return &salts
}

// failNthLock makes the nth mlock from now fail, once.
func failNthLock(t *testing.T, n int) {
	t.Helper()
	prev := lockMemory
	t.Cleanup(func() { lockMemory = prev })
	calls := 0
	lockMemory = func(b []byte) error {
		calls++
		if calls == n {
			lockMemory = prev
			return errors.New("mlock: cannot allocate memory")
		}
		return prev(b)
	}
}

// failNthRandRead makes the nth CSPRNG read from now fail, once.
func failNthRandRead(t *testing.T, n int) {
	t.Helper()
	prev := randRead
	t.Cleanup(func() { randRead = prev })
	calls := 0
	randRead = func(b []byte) (int, error) {
		calls++
		if calls == n {
			return 0, errors.New("csprng unavailable")
		}
		return prev(b)
	}
}

func TestSealer_DestroyReleasesEverythingAndFailsClosed(t *testing.T) {
	cases := map[string][]SealerOption{
		"root key, default provider":    nil,
		"root key, rotated generations": {WithKEKRotationLimit(1)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			base := ledgerCount()

			s, err := NewSealer(opts...)
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			var values []*SealedEnclave
			for i := range 3 {
				v, err := s.Seal(ctx, fmt.Appendf(nil, "secret-%d", i))
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				values = append(values, v)
			}
			if ledgerCount() == base {
				t.Fatal("sealing registered no keys; the test would prove nothing")
			}

			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			if got := ledgerCount(); got != base {
				t.Errorf("ledger holds %d entries after Destroy, want %d: the sealer's keys were not released", got, base)
			}
			if s.owned == nil || s.owned.Health() == nil {
				t.Error("the default provider the sealer created was not destroyed with it")
			}
			if s.kekBlobs != nil {
				t.Error("retired KEK blobs are still retained after Destroy")
			}

			data := []byte("after-destroy")
			if _, err := s.Seal(ctx, data); !errors.Is(err, ErrSealerDestroyed) {
				t.Errorf("Seal after Destroy = %v, want ErrSealerDestroyed", err)
			}
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("Seal after Destroy did not wipe the caller's material")
			}
			for _, v := range values {
				if e, err := v.Open(ctx); !errors.Is(err, ErrSealerDestroyed) {
					_ = e.Destroy()
					t.Errorf("Open after Destroy = %v, want ErrSealerDestroyed", err)
				}
				if err := v.Openable(); !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Openable after Destroy = %v, want ErrSealerDestroyed", err)
				}
				v.Destroy()
			}
			if err := s.Destroy(); err != nil {
				t.Errorf("second Destroy = %v, want nil", err)
			}
		})
	}

	var nilSealer *Sealer
	if err := nilSealer.Destroy(); err != nil {
		t.Errorf("nil Sealer Destroy = %v, want nil", err)
	}
}

// TestSealer_RepeatedSealersDoNotAccumulateLockedMemory pins that a destroyed
// sealer unregisters its root, KEK and provider root, so creating and
// destroying many sealers does not exhaust RLIMIT_MEMLOCK.
func TestSealer_RepeatedSealersDoNotAccumulateLockedMemory(t *testing.T) {
	ctx := t.Context()
	a, err := NewAllocator(openBudget(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	base := ledgerCount()
	for i := range 200 {
		s, err := NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(ctx, []byte("credential"))
		if err != nil {
			t.Fatalf("iteration %d: Seal: %v", i, err)
		}
		e, err := v.OpenWith(ctx, a)
		if err != nil {
			t.Fatalf("iteration %d: OpenWith: %v", i, err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("iteration %d: destroying the opened enclave: %v", i, err)
		}
		v.Destroy()
		if err := s.Destroy(); err != nil {
			t.Fatalf("iteration %d: Destroy: %v", i, err)
		}
		if got := ledgerCount(); got != base {
			t.Fatalf("iteration %d: ledger holds %d entries, want %d: locked memory grows per sealer", i, got, base)
		}
	}
}

func TestSealer_DestroyNeverDestroysAnInjectedProvider(t *testing.T) {
	ctx := t.Context()
	for _, mode := range []Mode{ModeRootKey, ModePerOperation} {
		t.Run(mode.String(), func(t *testing.T) {
			p := NewSoftwareProvider()
			t.Cleanup(func() { _ = p.Destroy() })
			s, err := NewSealer(providerOption(p, mode))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.Seal(ctx, []byte("x"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			v.Destroy()
			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			blob, err := p.Protect(ctx, make([]byte, RootKeyBytes))
			if err != nil {
				t.Fatalf("the injected provider stopped working after the sealer's Destroy: %v", err)
			}
			if len(blob) == 0 {
				t.Fatal("empty blob")
			}
		})
	}
}

// TestSealer_DestroyDuringABlockedUnsealReleasesThePendingRoot pins that
// Destroy does not wait on a provider, and that the initialization it raced
// releases the root it produced instead of publishing it.
func TestSealer_DestroyDuringABlockedUnsealReleasesThePendingRoot(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()
	u := &gatedRootUnsealer{entered: make(chan struct{}), release: make(chan struct{})}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		v, err := s.Seal(ctx, []byte("x"))
		v.Destroy()
		done <- err
	}()
	<-u.entered

	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	close(u.release)
	if err := <-done; !errors.Is(err, ErrSealerDestroyed) {
		t.Fatalf("Seal raced by Destroy = %v, want ErrSealerDestroyed", err)
	}
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d: the pending root outlived Destroy", got, base)
	}
	if s.root != nil {
		t.Error("a root was published after Destroy")
	}
	if u.callCount() != 1 {
		t.Errorf("UnsealRoot called %d times, want 1", u.callCount())
	}
}

// TestSealer_DestroyReleasesAPendingRootLeftByAFailedMint covers the pending
// state with no initialization in flight: a successful unseal whose KEK mint
// failed retains the root, and Destroy must take it.
func TestSealer_DestroyReleasesAPendingRootLeftByAFailedMint(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()
	s, err := NewSealer(WithRootUnsealer(&fixedRootUnsealer{fill: 0x11}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// Seal locks the DEK, then the root destination, then the KEK.
	failNthLock(t, 3)
	if _, err := s.Seal(ctx, []byte("x")); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the KEK mint refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if s.pendingRoot == nil {
		t.Fatal("no pending root after a failed mint; the test would prove nothing")
	}
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d: the pending root outlived Destroy", got, base)
	}
}

func TestSealer_DestroyRacesSealsAndOpens(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()
	s, err := NewSealer(WithKEKRotationLimit(3))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(ctx, []byte("shared"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 20 {
				if w, err := s.Seal(ctx, []byte("x")); err == nil {
					w.Destroy()
				} else if !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Seal: %v", err)
				}
				if e, err := v.Open(ctx); err == nil {
					_ = e.Destroy()
				} else if !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Open: %v", err)
				}
			}
		})
	}
	close(start)
	if err := s.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
	wg.Wait()
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d", got, base)
	}
}

// TestSealer_DestroyDuringAProviderCallFailsTheCall pins that a seal or open
// whose provider call straddles Destroy does not succeed after Destroy
// returned: Destroy waits for no provider, so the call rechecks.
func TestSealer_DestroyDuringAProviderCallFailsTheCall(t *testing.T) {
	ctx := t.Context()
	newSealer := func(t *testing.T) (*Sealer, *blockingProvider) {
		t.Helper()
		p := newBlockingProvider()
		t.Cleanup(func() { _ = p.inner.Destroy() })
		s, err := NewSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		return s, p
	}

	t.Run("seal", func(t *testing.T) {
		s, p := newSealer(t)
		p.beforeReturn = func() {
			if err := s.Destroy(); err != nil {
				t.Errorf("Destroy: %v", err)
			}
		}
		v, err := s.Seal(ctx, []byte("x"))
		if !errors.Is(err, ErrSealerDestroyed) {
			v.Destroy()
			t.Fatalf("Seal straddling Destroy = %v, want ErrSealerDestroyed", err)
		}
	})

	t.Run("open", func(t *testing.T) {
		base := ledgerCount()
		s, p := newSealer(t)
		v, err := s.Seal(ctx, []byte("x"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()
		p.beforeReturn = func() {
			if err := s.Destroy(); err != nil {
				t.Errorf("Destroy: %v", err)
			}
		}
		e, err := v.Open(ctx)
		if !errors.Is(err, ErrSealerDestroyed) {
			_ = e.Destroy()
			t.Fatalf("Open straddling Destroy = %v, want ErrSealerDestroyed", err)
		}
		_ = p.inner.Destroy()
		if got := ledgerCount(); got != base {
			t.Errorf("ledger holds %d entries, want %d", got, base)
		}
	})
}

func TestSoftwareProvider_Destroy(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()

	p := NewSoftwareProvider()
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
	fresh := NewSoftwareProvider()
	if err := fresh.Destroy(); err != nil {
		t.Fatalf("Destroy of an unused provider: %v", err)
	}
	if err := fresh.UnsealRoot(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("UnsealRoot on a provider destroyed unused = %v, want ErrSealerDestroyed", err)
	}
	if fresh.root != nil {
		t.Error("a destroyed provider generated a root")
	}

	var nilProvider *SoftwareProvider
	if err := nilProvider.Destroy(); err != nil {
		t.Errorf("nil provider Destroy = %v, want nil", err)
	}
}

// reusingProtector returns every blob in ONE buffer it owns and overwrites on
// the next Protect — legal under the KeyProtector contract.
type reusingProtector struct {
	inner *SoftwareProvider
	mu    sync.Mutex
	buf   []byte
}

func (r *reusingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	b, err := r.inner.Protect(ctx, key)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf[:0], b...)
	return r.buf, nil
}

func (r *reusingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return r.inner.Unprotect(ctx, blob, key)
}

func TestSealer_ProviderBlobIsCopied(t *testing.T) {
	ctx := t.Context()
	p := &reusingProtector{inner: NewSoftwareProvider(), buf: make([]byte, 0, 256)}
	t.Cleanup(func() { _ = p.inner.Destroy() })
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	a, err := s.Seal(ctx, []byte("first"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := s.Seal(ctx, []byte("second"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer b.Destroy()

	e, err := a.Open(ctx)
	if err != nil {
		t.Fatalf("opening the first value after the provider reused its blob buffer: %v", err)
	}
	_ = e.Destroy()

	// Destroying a value wipes the sealer's copy, never the provider's slice.
	held := bytes.Clone(p.buf)
	a.Destroy()
	if !bytes.Equal(p.buf, held) {
		t.Fatal("SealedEnclave.Destroy wiped the provider's own blob slice")
	}
	e, err = b.Open(ctx)
	if err != nil {
		t.Fatalf("opening the second value: %v", err)
	}
	_ = e.Destroy()
}

func TestSealer_ZeroValueFailsWithoutPanicking(t *testing.T) {
	ctx := t.Context()
	var s Sealer
	data := []byte("material")
	if _, err := s.Seal(ctx, data); !errors.Is(err, ErrSealerNotConstructed) {
		t.Errorf("zero-value Seal = %v, want ErrSealerNotConstructed", err)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Error("zero-value Seal did not wipe the caller's material")
	}
	if _, err := s.open(ctx, nil, []byte("blob"), []byte("sealed"), 4); !errors.Is(err, ErrSealerNotConstructed) {
		t.Errorf("zero-value open = %v, want ErrSealerNotConstructed", err)
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("zero-value Destroy = %v, want nil", err)
	}
}

func TestSealableWithin_BoundsTheSealedLengthByInt(t *testing.T) {
	const maxInt32 = math.MaxInt32
	cases := []struct {
		n, maxInt uint64
		want      error
	}{
		{maxInt32 - sealedOverhead, maxInt32, nil},
		{maxInt32 - sealedOverhead + 1, maxInt32, ErrMaterialTooLarge},
		{maxSealedPlaintext, math.MaxInt64, nil},
		{maxSealedPlaintext + 1, math.MaxInt64, ErrMaterialTooLarge},
	}
	for _, c := range cases {
		if err := sealableWithin(c.n, c.maxInt); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("sealableWithin(%d, %d) = %v, want %v", c.n, c.maxInt, err, c.want)
		}
	}
	if err := sealableLength(maxSealedPlaintext + 1); !errors.Is(err, ErrMaterialTooLarge) {
		t.Errorf("sealableLength above the GCM bound = %v, want ErrMaterialTooLarge", err)
	}
}

func TestEnclaves_GoStringIsRedacted(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	v, err := s.Seal(ctx, []byte("gostring-material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := fmt.Sprintf("%#v", v); got != "SealedEnclave(sealed)" {
		t.Errorf("%%#v of a SealedEnclave = %q, want the redacted form", got)
	}
	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := fmt.Sprintf("%#v", e); got != "MemoryEnclave(redacted)" {
		t.Errorf("%%#v of a MemoryEnclave = %q, want the redacted form", got)
	}
	_ = e.Destroy()
	v.Destroy()
	if got := fmt.Sprintf("%#v", v); got != "SealedEnclave(destroyed)" {
		t.Errorf("%%#v of a destroyed SealedEnclave = %q", got)
	}
}

func TestDeriveWrappingKey_MatchesHKDF(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, RootKeyBytes)
	salt := bytes.Repeat([]byte{0x24}, wrappingSaltBytes)
	want, err := hkdf.Key(sha256.New, root, salt, wrappingKeyInfo, RootKeyBytes)
	if err != nil {
		t.Fatalf("hkdf.Key: %v", err)
	}
	got := bytes.Clone(root)
	if err := deriveWrappingKey(got, salt); err != nil {
		t.Fatalf("deriveWrappingKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("deriveWrappingKey is not HKDF-SHA256 of the root under the salt and info")
	}
}

// TestSealer_InitializationFailurePaths covers the steps of the first seal
// that can fail only on a broken CSPRNG or HKDF.
func TestSealer_InitializationFailurePaths(t *testing.T) {
	ctx := t.Context()

	t.Run("salt draw fails before the provider is asked", func(t *testing.T) {
		u := &countingRootUnsealer{inner: fixedRootUnsealer{fill: 1}}
		s, err := NewSealer(WithRootUnsealer(u))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		t.Cleanup(func() { _ = s.Destroy() })
		failNthRandRead(t, 2) // the DEK, then the salt
		if _, err := s.Seal(ctx, []byte("x")); !errors.Is(err, ErrSealFailed) {
			t.Fatalf("Seal = %v, want ErrSealFailed", err)
		}
		if u.calls != 0 {
			t.Fatalf("UnsealRoot called %d times despite the salt failing first", u.calls)
		}
		if _, err := s.Seal(ctx, []byte("x")); err != nil {
			t.Fatalf("Seal after the CSPRNG recovered: %v", err)
		}
	})

	t.Run("derivation fails after a successful unseal", func(t *testing.T) {
		u := &countingRootUnsealer{inner: fixedRootUnsealer{fill: 2}}
		s, err := NewSealer(WithRootUnsealer(u))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		t.Cleanup(func() { _ = s.Destroy() })
		prev := hkdfKey
		t.Cleanup(func() { hkdfKey = prev })
		hkdfKey = func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error) {
			return nil, errors.New("hkdf failed")
		}
		_, err = s.Seal(ctx, []byte("x"))
		if !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrSealFailed) {
			t.Fatalf("Seal = %v, want ErrSealerWiped and ErrSealFailed", err)
		}
		hkdfKey = prev
		if _, err := s.Seal(ctx, []byte("x")); !errors.Is(err, ErrSealerWiped) {
			t.Fatalf("second Seal = %v, want ErrSealerWiped", err)
		}
		if u.calls != 1 {
			t.Fatalf("UnsealRoot called %d times, want 1: a succeeded unseal must not be repeated", u.calls)
		}
	})

	t.Run("key fill fails", func(t *testing.T) {
		failNthRandRead(t, 1)
		if _, err := newKeyEnclave(dekBytes); !errors.Is(err, ErrSealFailed) {
			t.Fatalf("newKeyEnclave = %v, want ErrSealFailed", err)
		}
	})

	t.Run("software provider root fill fails", func(t *testing.T) {
		p := NewSoftwareProvider()
		t.Cleanup(func() { _ = p.Destroy() })
		failNthRandRead(t, 1)
		if _, err := p.Protect(ctx, make([]byte, RootKeyBytes)); !errors.Is(err, ErrSealFailed) {
			t.Fatalf("Protect = %v, want ErrSealFailed", err)
		}
		if p.root != nil {
			t.Fatal("a root whose fill failed was kept")
		}
	})
}

func TestSealer_RotationAndRetiredGenerationFailurePaths(t *testing.T) {
	ctx := t.Context()

	newRotating := func(t *testing.T) *Sealer {
		t.Helper()
		s, err := NewSealer(WithKEKRotationLimit(1))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		t.Cleanup(func() { _ = s.Destroy() })
		return s
	}
	seal := func(t *testing.T, s *Sealer, data string) *SealedEnclave {
		t.Helper()
		v, err := s.Seal(ctx, []byte(data))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		t.Cleanup(func() { _ = v.Destroy() })
		return v
	}

	t.Run("a failed rotation mint keeps the current generation", func(t *testing.T) {
		s := newRotating(t)
		v1 := seal(t, s, "one")
		failNthLock(t, 2) // the DEK, then the new KEK
		if _, err := s.Seal(ctx, []byte("two")); !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Fatalf("Seal with the rotation mint refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		if s.kekGen != 1 {
			t.Fatalf("generation %d after a failed rotation, want 1", s.kekGen)
		}
		seal(t, s, "three")
		e, err := v1.Open(ctx)
		if err != nil {
			t.Fatalf("opening a value of the retained generation: %v", err)
		}
		_ = e.Destroy()
	})

	t.Run("rotation finds the hierarchy dead", func(t *testing.T) {
		s := newRotating(t)
		seal(t, s, "one")
		s.kekUsed.Store(5)
		if err := s.kek.Destroy(); err != nil {
			t.Fatalf("destroying the KEK: %v", err)
		}
		if err := s.rotateKEK(); !errors.Is(err, ErrSealerWiped) {
			t.Fatalf("rotateKEK = %v, want ErrSealerWiped", err)
		}
		if s.root.IsAlive() {
			t.Fatal("rotation over a dead KEK left the root alive")
		}
	})

	t.Run("retired KEK cannot be materialized", func(t *testing.T) {
		s := newRotating(t)
		v1 := seal(t, s, "one")
		seal(t, s, "two") // rotates: v1 is now under a retired generation
		failNthLock(t, 3) // the destination, the DEK, then the retired KEK
		if _, err := v1.Open(ctx); !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Fatalf("Open = %v, want ErrLockedMemoryUnavailable", err)
		}
		e, err := v1.Open(ctx)
		if err != nil {
			t.Fatalf("Open after the ceiling lifted: %v", err)
		}
		_ = e.Destroy()
	})

	t.Run("retired KEK blob does not authenticate", func(t *testing.T) {
		s := newRotating(t)
		v1 := seal(t, s, "one")
		seal(t, s, "two")
		s.mu.Lock()
		s.kekBlobs[1][len(s.kekBlobs[1])-1] ^= 1
		s.mu.Unlock()
		if _, err := v1.Open(ctx); !errors.Is(err, ErrSealedAuthentication) {
			t.Fatalf("Open = %v, want ErrSealedAuthentication", err)
		}
	})

	t.Run("blobs this hierarchy never produced", func(t *testing.T) {
		dek, err := NewMemoryEnclaveSized(dekBytes)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		t.Cleanup(func() { _ = dek.Destroy() })

		fresh := newRotating(t)
		blob := append(blobHeader(blobKindDEK, 1), make([]byte, 60)...)
		if err := fresh.unprotectRootKey(ctx, blob, dek); !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("unprotect on a sealer that sealed nothing = %v, want ErrSealedAuthentication", err)
		}

		s := newRotating(t)
		seal(t, s, "one")
		unknown := append(blobHeader(blobKindDEK, 99), make([]byte, 60)...)
		if err := s.unprotectRootKey(ctx, unknown, dek); !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("unprotect of an unminted generation = %v, want ErrSealedAuthentication", err)
		}
	})
}

// misbehavingAEAD is an AEAD whose Open does what crypto/cipher never does,
// so the guards in openInto can be reached.
type misbehavingAEAD struct {
	open func(dst, ciphertext []byte) ([]byte, error)
}

func (misbehavingAEAD) NonceSize() int { return 0 }
func (misbehavingAEAD) Overhead() int  { return sealedOverhead }
func (misbehavingAEAD) Seal(dst, _, plaintext, _ []byte) []byte {
	return append(dst, plaintext...)
}

func (m misbehavingAEAD) Open(dst, _, ciphertext, _ []byte) ([]byte, error) {
	return m.open(dst, ciphertext)
}

var _ cipher.AEAD = misbehavingAEAD{}

func TestOpenInto_Guards(t *testing.T) {
	const n = 8
	sealed := make([]byte, n+sealedOverhead)
	var escaped []byte

	cases := map[string]struct {
		open func(dst, ciphertext []byte) ([]byte, error)
		want error
	}{
		"reported failure with full output": {
			open: func(dst, _ []byte) ([]byte, error) { return dst[:n], errors.New("tag mismatch") },
			want: ErrSealedAuthentication,
		},
		"plaintext reallocated onto the heap": {
			open: func(_, _ []byte) ([]byte, error) {
				escaped = bytes.Repeat([]byte{0xAA}, n)
				return escaped, nil
			},
			want: ErrPlaintextEscaped,
		},
		"short plaintext in place": {
			open: func(dst, _ []byte) ([]byte, error) { return dst[:n-1], nil },
			want: ErrSealedAuthentication,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dst := make([]byte, n)
			if err := openInto(misbehavingAEAD{open: c.open}, sealed, nil, dst); !errors.Is(err, c.want) {
				t.Fatalf("openInto = %v, want %v", err, c.want)
			}
		})
	}
	if !bytes.Equal(escaped, make([]byte, n)) {
		t.Error("escaped plaintext was not wiped")
	}

	if err := openInto(misbehavingAEAD{}, make([]byte, sealedOverhead), nil, nil); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("openInto of an empty message = %v, want ErrSealedAuthentication", err)
	}
	if err := openInto(misbehavingAEAD{}, sealed, nil, make([]byte, n+1)); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("openInto into a mis-sized destination = %v, want ErrSealedAuthentication", err)
	}
}

func TestErrSealerDestroyed_PassesThroughProviderShaping(t *testing.T) {
	if err := providerSealFailure(ErrSealerDestroyed); err != ErrSealerDestroyed { //nolint:errorlint // identity is the point
		t.Errorf("providerSealFailure joined ErrSealerDestroyed: %v", err)
	}
	if err := providerOpenFailure(ErrSealerDestroyed); err != ErrSealerDestroyed { //nolint:errorlint // identity is the point
		t.Errorf("providerOpenFailure joined ErrSealerDestroyed: %v", err)
	}
	if !strings.HasPrefix(ErrSealerDestroyed.Error(), "enclave: ") || !strings.HasPrefix(ErrSealerNotConstructed.Error(), "enclave: ") {
		t.Error("sentinels must carry the package prefix")
	}
}
