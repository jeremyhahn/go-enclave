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
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// hierarchyState reads s's hierarchy state under the read lock.
func hierarchyState(s *Sealer) (published bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hierarchyStateLocked()
}

// recordWrapSalts wraps the HKDF seam so a test can read the salt of every
// wrapping-key derivation and recompute the key independently.
func recordWrapSalts(t *testing.T) *[][]byte {
	t.Helper()
	var salts [][]byte
	prev := hkdfKey
	swapSeam(t, &hkdfKey, func(h func() hash.Hash, secret, salt []byte, info string, n int) ([]byte, error) {
		salts = append(salts, bytes.Clone(salt))
		return prev(h, secret, salt, info, n)
	})
	return &salts
}

// failNthLock makes the nth mlock from now fail, once.
func failNthLock(t *testing.T, n int) {
	t.Helper()
	prev := lockMemory
	calls := 0
	swapSeam(t, &lockMemory, func(b []byte) error {
		calls++
		if calls == n {
			lockMemory = prev
			return errors.New("mlock: cannot allocate memory")
		}
		return prev(b)
	})
}

// failNthRandRead makes the nth CSPRNG read from now fail, once.
func failNthRandRead(t *testing.T, n int) {
	t.Helper()
	prev := randRead
	calls := 0
	swapSeam(t, &randRead, func(b []byte) (int, error) {
		calls++
		if calls == n {
			return 0, errors.New("csprng unavailable")
		}
		return prev(b)
	})
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
		prev := swapSeam(t, &hkdfKey, func(func() hash.Hash, []byte, []byte, string, int) ([]byte, error) {
			return nil, errors.New("hkdf failed")
		})
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

// TestSealer_KEKRotatesAtTheMessageLimit pins rotation at the KEK's GCM
// message bound, driving kekUsed directly instead of sealing 2^31 times, and
// that values sealed under the retired generation still open while its live
// enclave is destroyed.
func TestSealer_KEKRotatesAtTheMessageLimit(t *testing.T) {
	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	older := []byte("sealed-under-the-generation-about-to-be-retired")
	before, err := s.Seal(t.Context(), append([]byte(nil), older...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer before.Destroy()

	s.mu.RLock()
	retiring, retiringGen := s.kek, s.kekGen
	s.mu.RUnlock()
	if retiring == nil {
		t.Fatal("no live KEK after the first seal")
	}

	// One seal short of the limit, so the next seal is the generation's last
	// and the one after rotates.
	s.kekUsed.Store(kekMessageLimit - 1)

	atLimit, err := s.Seal(t.Context(), append([]byte(nil), older...))
	if err != nil {
		t.Fatalf("Seal at the limit: %v", err)
	}
	defer atLimit.Destroy()
	s.mu.RLock()
	genAtLimit := s.kekGen
	s.mu.RUnlock()
	if genAtLimit != retiringGen {
		t.Error("the seal that reached the limit already used a new generation; it should be the last on the old one")
	}

	after, err := s.Seal(t.Context(), append([]byte(nil), older...))
	if err != nil {
		t.Fatalf("Seal past the limit: %v", err)
	}
	defer after.Destroy()

	s.mu.RLock()
	newGen, newKek, blobCount := s.kekGen, s.kek, len(s.kekBlobs)
	s.mu.RUnlock()

	if newGen == retiringGen {
		t.Fatal("the KEK did not rotate past the message limit: it is still wrapping under a generation that reached its bound")
	}
	if !newKek.IsAlive() {
		t.Error("the new generation's KEK is not alive")
	}
	if retiring.IsAlive() {
		t.Error("the retired generation's KEK enclave is still alive; retirement is supposed to cost bytes, not a locked page")
	}
	if blobCount != 2 {
		t.Errorf("kekBlobs holds %d generations, want 2: the retired generation's blob must be retained", blobCount)
	}

	// Rotation must not strand what came before it: the retired-generation
	// values open through the root-unwrap path.
	for name, v := range map[string]*SealedEnclave{"sealed before": before, "sealed at the limit": atLimit} {
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("%s: Open after rotation: %v", name, err)
		}
		if !holds(e, older) {
			t.Errorf("%s: opened to the wrong material after rotation", name)
		}
		e.Destroy()
	}

	// And the new generation round-trips too.
	e, err := after.Open(t.Context())
	if err != nil {
		t.Fatalf("Open under the new generation: %v", err)
	}
	if !holds(e, older) {
		t.Error("the value sealed under the new generation opened to the wrong material")
	}
	e.Destroy()
}

// TestSealer_ConcurrentSealsAcrossRotation hammers a sealer whose counter
// sits at the rotation boundary from many goroutines. Under -race it is the
// oracle for the hierarchy's locking; without it, it still proves no seal is
// lost or stranded by a rotation racing other seals.
func TestSealer_ConcurrentSealsAcrossRotation(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// Initialize the hierarchy, then park the counter one short of the limit
	// so the very first concurrent wave forces a rotation.
	warm, err := s.Seal(t.Context(), []byte("warm-up"))
	if err != nil {
		t.Fatalf("warm-up Seal: %v", err)
	}
	defer warm.Destroy()
	s.kekUsed.Store(kekMessageLimit - 1)

	const goroutines, seals = 8, 12
	values := make([][]*SealedEnclave, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < seals; i++ {
				v, err := s.Seal(t.Context(), fmt.Appendf(nil, "concurrent-rotation-%d-%d", g, i))
				if err != nil {
					t.Errorf("Seal(%d,%d): %v", g, i, err)
					return
				}
				values[g] = append(values[g], v)
			}
		}(g)
	}
	wg.Wait()

	for g, vs := range values {
		for i, v := range vs {
			e, err := v.Open(t.Context())
			if err != nil {
				t.Fatalf("Open(%d,%d): %v", g, i, err)
			}
			if !holds(e, fmt.Appendf(nil, "concurrent-rotation-%d-%d", g, i)) {
				t.Errorf("value (%d,%d) opened to the wrong material", g, i)
			}
			e.Destroy()
			v.Destroy()
		}
	}
}

// TestSealer_ProviderRootReachesTheHierarchy pins that the hierarchy runs on
// the injected provider's root: a KEK blob from a sealer over a deterministic
// RootUnsealer unwraps under the wrapping key derived from that root, not
// under any other root, and not with its generation frame rewritten.
func TestSealer_ProviderRootReachesTheHierarchy(t *testing.T) {
	salts := recordWrapSalts(t)
	s, err := NewSealer(WithRootUnsealer(&fixedRootUnsealer{fill: 0x5A}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal(t.Context(), []byte("initialize-the-hierarchy")); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	s.mu.RLock()
	kekBlob := append([]byte(nil), s.kekBlobs[1]...)
	s.mu.RUnlock()

	buildRoot := func(fill byte) *MemoryEnclave {
		t.Helper()
		root, err := NewMemoryEnclaveSized(RootKeyBytes)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		if err := root.WithBytes(func(b []byte) error {
			for i := range b {
				b[i] = fill
			}
			return nil
		}); err != nil {
			t.Fatalf("filling root: %v", err)
		}
		return root
	}

	// The unwrapped KEK lands in locked memory, never an ordinary buffer.
	kekEnclave, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		t.Fatalf("allocating the KEK destination: %v", err)
	}
	defer func() { _ = kekEnclave.Destroy() }()
	unwrapInto := func(root *MemoryEnclave, aad []byte) error {
		return kekEnclave.WithBytes(func(kek []byte) error {
			return openWithKeyInto(root, kekBlob[blobHeaderLen:], aad, kek)
		})
	}

	// The wrapping key derived from the provider's known root under the
	// sealer's salt unwraps the sealer's KEK blob: the hierarchy is keyed by
	// what UnsealRoot supplied, not by anything self-minted.
	if len(*salts) != 1 {
		t.Fatalf("%d wrapping-key derivations, want 1", len(*salts))
	}
	salt := (*salts)[0]
	providerRoot := buildRoot(0x5A)
	defer providerRoot.Destroy()
	if err := unwrapInto(providerRoot, kekBlob[:blobHeaderLen]); !errors.Is(err, ErrSealedAuthentication) {
		t.Fatalf("the provider's root itself unwrapping the KEK blob = %v, want ErrSealedAuthentication: "+
			"the sealer must wrap under a key derived from the root, never the root", err)
	}
	if err := providerRoot.WithBytes(func(r []byte) error { return deriveWrappingKey(r, salt) }); err != nil {
		t.Fatalf("deriveWrappingKey: %v", err)
	}
	if err := unwrapInto(providerRoot, kekBlob[:blobHeaderLen]); err != nil {
		t.Fatalf("the key derived from the provider-supplied root does not unwrap the sealer's KEK blob (%v): "+
			"the hierarchy is not keyed by the injected provider's root", err)
	}

	// A different root does not — so the success above was the root's doing.
	otherRoot := buildRoot(0x00)
	defer otherRoot.Destroy()
	if err := unwrapInto(otherRoot, kekBlob[:blobHeaderLen]); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("a different root unwrapped the KEK blob (%v); the wrap is not bound to the provider root", err)
	}

	// And the KEK blob is bound to its generation frame: the right root with
	// a rewritten frame is refused, which is what stops a retired blob being
	// refiled under another generation.
	rewritten := blobHeader(blobKindKEK, 7)
	if err := unwrapInto(providerRoot, rewritten); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("a generation-rewritten frame still unwrapped the KEK blob (%v); the frame is not bound as AAD", err)
	}
}

// TestSealer_RootUnsealFailureSurfacesAndRetries pins that a failed root
// unseal surfaces under ErrSealFailed with the provider's cause, and that the
// next seal retries the unseal instead of replaying a memoized failure.
func TestSealer_RootUnsealFailureSurfacesAndRetries(t *testing.T) {
	flaky := &flakyRootUnsealer{failures: 1, inner: fixedRootUnsealer{fill: 0x33}}
	s, err := NewSealer(WithRootUnsealer(flaky))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal(t.Context(), []byte("first-attempt"))
	if !errors.Is(err, ErrSealFailed) {
		t.Fatalf("Seal with a failing UnsealRoot = %v, want ErrSealFailed", err)
	}
	if err == nil || !strings.Contains(err.Error(), "device busy") {
		t.Errorf("Seal error %v does not preserve the provider's cause", err)
	}

	// The retry: same sealer, provider now healthy, and the hierarchy
	// initializes as if the failure never happened.
	want := []byte("second-attempt-material")
	v, err := s.Seal(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal after a transient unseal failure = %v; the failure was memoized", err)
	}
	defer v.Destroy()
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !holds(e, want) {
		t.Error("round trip after the retry returned the wrong material")
	}
	e.Destroy()
	if flaky.calls != 2 {
		t.Errorf("UnsealRoot was called %d times, want 2 (one failure, one retry)", flaky.calls)
	}

	// A permanently failing provider fails every seal, typed, with no panic
	// and no fallback root.
	dead, err := NewSealer(WithRootUnsealer(&erroringProvider{err: errors.New("device gone")}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := dead.Seal(t.Context(), []byte("never")); !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with a dead RootUnsealer = %v, want ErrSealFailed", err)
	}
}

// TestSealer_PerCallLossDuringRotationIsNotAWipe pins that a seal whose own
// DEK is lost mid-wrap reports ErrEnclaveDestroyed, never ErrSealerWiped,
// however rotation interleaves. It cannot pin that protectRootKeyInner
// translates before releasing s.mu; no seam holds that window open.
func TestSealer_PerCallLossDuringRotationIsNotAWipe(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer(WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(ctx, []byte("initialize"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	v.Destroy()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				v, err := s.Seal(ctx, []byte("rotate on every wrap"))
				if err != nil {
					t.Errorf("rotating Seal: %v", err)
					return
				}
				v.Destroy()
			}
		}()
	}
	for range 200 {
		dead, err := NewMemoryEnclaveSized(dekBytes)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		if err := dead.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		_, err = s.protectRootKey(ctx, dead)
		if !errors.Is(err, ErrEnclaveDestroyed) || errors.Is(err, ErrSealerWiped) {
			close(stop)
			wg.Wait()
			t.Fatalf("wrap of a lost per-call DEK during rotation = %v, want ErrEnclaveDestroyed and not ErrSealerWiped", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestSealer_WipedDoesNotReconsultAWillingProvider pins that a swept sealer
// does not re-key even when its provider would re-supply a root. With the
// software provider, the provider's own refusal would mask a sealer that
// re-initializes, so this provider always answers and the refusal can only
// come from the sealer.
func TestSealer_WipedDoesNotReconsultAWillingProvider(t *testing.T) {
	willing := &flakyRootUnsealer{failures: 0, inner: fixedRootUnsealer{fill: 0x66}}
	s, err := NewSealer(WithRootUnsealer(willing))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	if willing.calls != 1 {
		t.Fatalf("UnsealRoot called %d times before the sweep, want 1", willing.calls)
	}

	sweep(t)

	if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Seal after sweep = %v, want ErrSealerWiped", err)
	}
	if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
	}
	// The provider was never asked again.
	if willing.calls != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: the sealer reconsulted its provider after a sweep", willing.calls)
	}
}

// TestSealer_RotationOverlappingASweepLeavesTheSealerWiped pins that a
// WipeAll landing while rotation borrows the root (so it destroys only the
// old KEK) leaves the sealer wiped instead of publishing the new generation.
// The sweep is injected from inside the new KEK's mlock, with an
// already-ended context so it never waits on a borrow.
func TestSealer_RotationOverlappingASweepLeavesTheSealerWiped(t *testing.T) {
	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	earlier, err := s.Seal(ctx, []byte("sealed before the rotation"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer earlier.Destroy()

	s.kekUsed.Store(kekMessageLimit + 1) // the next rotation is due

	registryMu.Lock()
	before := make(map[*MemoryEnclave]struct{}, len(live))
	for e := range live {
		before[e] = struct{}{}
	}
	registryMu.Unlock()

	// The sweep must land while the root is borrowed: the window in which
	// WipeAll skips the root but reclaims the old KEK. The test holds that borrow
	// across the sweep and releases it before the mint continues.
	s.mu.RLock()
	root := s.root
	s.mu.RUnlock()
	prev := lockMemory
	swept := false
	swapSeam(t, &lockMemory, func(b []byte) error {
		if !swept {
			swept = true
			held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				done <- root.WithBytes(func([]byte) error { close(held); <-release; return nil })
			}()
			<-held
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended) // an ended ctx sweeps what is free and never waits
			close(release)
			if err := <-done; err != nil {
				t.Errorf("the borrow holding the root across the sweep failed: %v", err)
			}
		}
		return prev(b)
	})

	if err := s.rotateKEK(); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("rotateKEK with a sweep inside its mint = %v, want ErrSealerWiped", err)
	}
	if !swept {
		t.Fatal("the injected sweep never ran: the rotation allocated nothing, so this test would be vacuous")
	}
	lockMemory = prev

	s.mu.RLock()
	rootAlive, kekAlive := s.root.IsAlive(), s.kek.IsAlive()
	s.mu.RUnlock()
	if rootAlive || kekAlive {
		t.Fatalf("after an overlapping sweep: root alive %t, current KEK alive %t; want both destroyed", rootAlive, kekAlive)
	}
	if root.IsAlive() {
		t.Fatal("the root the sweep skipped (it was borrowed) survived the rotation that overlapped it")
	}
	if _, err := s.Seal(ctx, []byte("after the sweep")); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal after rotation overlapped a sweep = %v, want ErrSealerWiped (no silent re-keying)", err)
	}
	// A value sealed BEFORE the sweep must not open afterwards either: its
	// KEK generation's blob is retained, so a revived root would open it.
	if _, err := earlier.Open(ctx); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Open of a value sealed before the sweep = %v, want ErrSealerWiped", err)
	}
	if err := earlier.Openable(); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Openable of a value sealed before the sweep = %v, want ErrSealerWiped", err)
	}
	// The discarded generation itself must be gone, not merely unreachable: a
	// final WipeAll would reclaim a leaked KEK and still return zero, so the
	// check is that nothing the rotation registered is still alive.
	registryMu.Lock()
	var leaked int
	for e := range live {
		if _, ok := before[e]; !ok && e.IsAlive() {
			leaked++
		}
	}
	registryMu.Unlock()
	if leaked != 0 {
		t.Fatalf("%d enclave(s) the overlapped rotation created are still alive: the discarded KEK leaked", leaked)
	}
}

// TestSealer_RotationCleanupReportsAndRetriesARefusedRelease pins that when
// the kernel refuses to unmap keys a sweep overlapped, rotation reports it.
// The sealer retries its published root and KEK at the seal/open boundary
// until allowed; the never-published generation is left to the WipeAll
// ledger.
func TestSealer_RotationCleanupReportsAndRetriesARefusedRelease(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	v, err := s.Seal(ctx, []byte("sealed before the rotation"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	s.kekUsed.Store(kekMessageLimit + 1)

	s.mu.RLock()
	root := s.root
	s.mu.RUnlock()
	prevLock, prevUnmap := lockMemory, unmapMemory
	refused := errors.New("munmap: cannot allocate memory")
	swept := false
	swapSeam(t, &lockMemory, func(b []byte) error {
		if !swept {
			swept = true
			// The sweep runs with the root borrowed (as the rotation's own
			// wrap would hold it), so the mint completes and the overlap is
			// caught at the end — the path that discards a fully minted
			// generation. From here every unmap is refused: the sweep's own
			// and the rotation's cleanup alike; wiping still happens first.
			held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				done <- root.WithBytes(func([]byte) error { close(held); <-release; return nil })
			}()
			<-held
			swapSeam(t, &unmapMemory, func([]byte) error { return refused })
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended)
			close(release)
			if err := <-done; err != nil {
				t.Errorf("the borrow holding the root across the sweep failed: %v", err)
			}
		}
		return prevLock(b)
	})

	err = s.rotateKEK()
	lockMemory = prevLock
	if !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("rotateKEK with its cleanup refused = %v, want ErrSealerWiped joined with the refusal (ErrLockedMemoryUnavailable)", err)
	}
	// Through the PUBLIC path: a dead sealer never rotates again, so the
	// retry of the keys it still references — the published root and KEK —
	// rides on the seals and opens that keep arriving. While the kernel still
	// refuses, each reports the outstanding failure...
	if _, err := s.Seal(ctx, []byte("while unmap is still refused")); !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the cleanup still refused = %v, want ErrSealerWiped joined with the refusal", err)
	}
	if _, err := v.Open(ctx); !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Open with the cleanup still refused = %v, want ErrSealerWiped joined with the refusal", err)
	}

	// ...and once it allows the unmap, the next seal releases them: a clean
	// ErrSealerWiped, the published keys off the ledger WITHOUT a sweep. The
	// discarded generation was never published; its refusal was reported
	// above and the ledger owns it, so the next sweep reclaims it.
	unmapMemory = prevUnmap
	if _, err := s.Seal(ctx, []byte("after the refusal lifted")); !errors.Is(err, ErrSealerWiped) || errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with unmap allowed = %v, want a clean ErrSealerWiped", err)
	}
	s.mu.RLock()
	rootK, curK := s.root, s.kek
	s.mu.RUnlock()
	registryMu.Lock()
	_, rootOnLedger := live[rootK]
	_, kekOnLedger := live[curK]
	registryMu.Unlock()
	if rootOnLedger || kekOnLedger {
		t.Fatalf("after the public retry: root on ledger %t, KEK on ledger %t; want both released without a sweep", rootOnLedger, kekOnLedger)
	}
	if n, err := WipeAll(ctx); n != 0 || err != nil {
		t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
	}
}

// TestSealer_RotationKeepsAFailedMintsRefusedKEK pins the mint-failure case:
// a sweep reclaims the root mid-mint, the wrap fails, and the kernel refuses
// to release the half-made KEK. The refusal is reported with the failure, and
// the WipeAll ledger reclaims the KEK once it lifts.
func TestSealer_RotationKeepsAFailedMintsRefusedKEK(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	v, err := s.Seal(ctx, []byte("sealed before the rotation"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	s.kekUsed.Store(kekMessageLimit + 1)

	prevLock, prevUnmap := lockMemory, unmapMemory
	var newKEK uintptr
	refused := errors.New("munmap: cannot allocate memory")
	swapSeam(t, &lockMemory, func(b []byte) error {
		if newKEK == 0 {
			newKEK = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			// Nothing is borrowed: the sweep reclaims the root and the
			// current KEK, so the wrap that follows fails.
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended)
			// From here only the NEW KEK's unmap is refused.
			swapSeam(t, &unmapMemory, func(region []byte) error {
				lo := uintptr(unsafe.Pointer(unsafe.SliceData(region)))
				if newKEK >= lo && newKEK < lo+uintptr(len(region)) {
					return refused
				}
				return prevUnmap(region)
			})
		}
		return prevLock(b)
	})

	err = s.rotateKEK()
	lockMemory = prevLock
	if !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("rotateKEK whose mint failed and whose KEK release was refused = %v, want ErrSealerWiped joined with the refusal", err)
	}
	// The failed mint's KEK was never published: its refusal is reported
	// above, and the WipeAll ledger owns it from here. Once the refusal
	// lifts, the next sweep reclaims it.
	unmapMemory = prevUnmap
	if n, err := WipeAll(ctx); n != 0 || err != nil {
		t.Fatalf("WipeAll after the refusal lifted = (%d, %v), want (0, nil): the ledger did not own the refused KEK", n, err)
	}
	registryMu.Lock()
	var leftover int
	for e := range live {
		if !e.IsAlive() && e.m != nil {
			leftover++
		}
	}
	registryMu.Unlock()
	if leftover != 0 {
		t.Fatalf("%d wiped enclave(s) still mapped on the ledger after the public retry", leftover)
	}
}

// TestSealer_InitializationReportsAFailedMintsRefusedRelease is the
// initialization counterpart: a sweep reclaims the just-unsealed root, the
// first KEK's wrap fails, and the kernel refuses to release that KEK. The
// first seal reports the refusal with ErrSealerWiped, and the ledger reclaims
// the KEK once the refusal lifts.
func TestSealer_InitializationReportsAFailedMintsRefusedRelease(t *testing.T) {
	s, err := NewSealer() // ModeRootKey: the first seal initializes
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()

	prevLock, prevUnmap := lockMemory, unmapMemory
	var newKEK uintptr
	refused := errors.New("munmap: cannot allocate memory")
	swapSeam(t, &lockMemory, func(b []byte) error {
		// The root has been unsealed and is pending publication, so this
		// allocation is the first KEK's mint (same goroutine: no race).
		if newKEK == 0 && s.pendingRoot != nil {
			newKEK = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended) // reclaims the pending root: nothing borrows it
			swapSeam(t, &unmapMemory, func(region []byte) error {
				lo := uintptr(unsafe.Pointer(unsafe.SliceData(region)))
				if newKEK >= lo && newKEK < lo+uintptr(len(region)) {
					return refused
				}
				return prevUnmap(region)
			})
		}
		return prevLock(b)
	})

	_, err = s.Seal(ctx, []byte("the first seal initializes"))
	lockMemory = prevLock
	if newKEK == 0 {
		t.Fatal("the hook never saw the first KEK's mint; this test would be vacuous")
	}
	if !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("the first Seal = %v, want ErrSealerWiped joined with the refused KEK release", err)
	}

	unmapMemory = prevUnmap
	if n, err := WipeAll(ctx); n != 0 || err != nil {
		t.Fatalf("WipeAll after the refusal lifted = (%d, %v), want (0, nil): the ledger did not own the refused KEK", n, err)
	}
}

// TestSealer_DeadHierarchyCleanupRunsAtTheBoundary pins that the seal/open
// boundary retries the release of a dead hierarchy's keys for every path
// that reports ErrSealerWiped; driving it with the bare sentinel stands in
// for all of them. A refused release is reported, and released once allowed.
func TestSealer_DeadHierarchyCleanupRunsAtTheBoundary(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	v, err := s.Seal(ctx, []byte("initializes the hierarchy"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	prevUnmap := swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap: cannot allocate memory") })
	_, _ = WipeAll(ctx) // wipes the root and KEK; their unmaps are refused

	if err := s.withDeadHierarchyCleanup(ErrSealerWiped); !errors.Is(err, ErrSealerWiped) || !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("boundary over a dead hierarchy with refused releases = %v, want ErrSealerWiped joined with the refusal", err)
	}
	unmapMemory = prevUnmap
	if err := s.withDeadHierarchyCleanup(ErrSealerWiped); !errors.Is(err, ErrSealerWiped) || errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("boundary once the refusal lifted = %v, want a clean ErrSealerWiped", err)
	}
	s.mu.RLock()
	rootK, curK := s.root, s.kek
	s.mu.RUnlock()
	registryMu.Lock()
	_, rootOnLedger := live[rootK]
	_, kekOnLedger := live[curK]
	registryMu.Unlock()
	if rootOnLedger || kekOnLedger {
		t.Fatalf("after the boundary retry: root on ledger %t, KEK on ledger %t; want both released", rootOnLedger, kekOnLedger)
	}
	// A live hierarchy is never touched: the sentinel alone is not proof.
	live2, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := live2.Seal(ctx, []byte("live")); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := live2.withDeadHierarchyCleanup(ErrSealerWiped); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("boundary on a live hierarchy = %v, want the error unchanged", err)
	}
	live2.mu.RLock()
	alive := live2.root.IsAlive() && live2.kek.IsAlive()
	live2.mu.RUnlock()
	if !alive {
		t.Fatal("the boundary destroyed a LIVE hierarchy because an error said ErrSealerWiped")
	}
}

// TestSealer_RotatesAtTheConfiguredLimit drives rotation through the public
// API: with a crypto-period of three wraps, ten seals span four KEK
// generations, every retired blob is retained, and every value opens.
func TestSealer_RotatesAtTheConfiguredLimit(t *testing.T) {
	s, err := NewSealer(WithKEKRotationLimit(3))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	var vals []*SealedEnclave
	for i := 0; i < 10; i++ {
		v, err := s.Seal(ctx, []byte(fmt.Sprintf("value-%02d", i)))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		vals = append(vals, v)
	}
	defer func() {
		for _, v := range vals {
			v.Destroy()
		}
	}()
	s.mu.RLock()
	gen, blobs := s.kekGen, len(s.kekBlobs)
	s.mu.RUnlock()
	if gen != 4 || blobs != 4 {
		t.Fatalf("after 10 seals at 3 wraps per generation: generation %d with %d retained blobs, want 4 and 4", gen, blobs)
	}
	for i, v := range vals {
		e, err := v.Open(ctx)
		if err != nil {
			t.Fatalf("Open of value %d: %v", i, err)
		}
		want := []byte(fmt.Sprintf("value-%02d", i))
		if !holds(e, want) {
			t.Errorf("value %d opened to the wrong material", i)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
	}
}

// TestSealer_ConcurrentSealsRotateWithoutLosingAValue drives rotation from
// many goroutines at the smallest crypto-periods, where nearly every seal
// crosses a limit: every value must open to its own material, and no
// generation may wrap more than the limit allows.
func TestSealer_ConcurrentSealsRotateWithoutLosingAValue(t *testing.T) {
	for _, limit := range []uint64{1, 3} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			ctx := t.Context()
			s, err := NewSealer(WithKEKRotationLimit(limit))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			const workers, each = 8, 12
			vals := make([][]*SealedEnclave, workers)
			errs := make(chan error, workers)
			var wg sync.WaitGroup
			for w := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range each {
						v, err := s.Seal(ctx, []byte(fmt.Sprintf("worker-%d-value-%02d", w, i)))
						if err != nil {
							errs <- err
							return
						}
						vals[w] = append(vals[w], v)
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("concurrent Seal: %v", err)
			}
			s.mu.RLock()
			gen := uint64(s.kekGen)
			s.mu.RUnlock()
			if minGen := (workers*each + limit - 1) / limit; gen < minGen {
				t.Errorf("generation %d after %d seals at %d per generation, want at least %d", gen, workers*each, limit, minGen)
			}
			perGen := map[uint32]uint64{}
			for w := range workers {
				for _, v := range vals[w] {
					_, g, err := parseBlobHeader(v.blob)
					if err != nil {
						t.Fatalf("parseBlobHeader: %v", err)
					}
					if perGen[g]++; perGen[g] > limit {
						t.Fatalf("generation %d wrapped %d DEKs, over its limit of %d", g, perGen[g], limit)
					}
				}
			}
			for w := range workers {
				for i, v := range vals[w] {
					e, err := v.Open(ctx)
					if err != nil {
						t.Fatalf("Open worker %d value %d: %v", w, i, err)
					}
					if !holds(e, []byte(fmt.Sprintf("worker-%d-value-%02d", w, i))) {
						t.Errorf("worker %d value %d opened to the wrong material", w, i)
					}
					_ = e.Destroy()
					v.Destroy()
				}
			}
		})
	}
}

// TestSealer_SealersSharingARootWrapUnderDistinctKeys pins that two sealers
// over the same provider derive distinct wrapping keys (a per-sealer salt),
// so neither's KEK blob unwraps under the other's.
func TestSealer_SealersSharingARootWrapUnderDistinctKeys(t *testing.T) {
	ctx := t.Context()
	p := &fixedRootUnsealer{fill: 0x5A}
	salts := recordWrapSalts(t)
	var sealers [2]*Sealer
	for i := range sealers {
		s, err := NewSealer(WithRootUnsealer(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(ctx, []byte("initialize-the-hierarchy"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		v.Destroy()
		sealers[i] = s
	}
	a, b := sealers[0], sealers[1]
	if len(*salts) != 2 || bytes.Equal((*salts)[0], (*salts)[1]) {
		t.Fatal("two sealers drew the same wrapping salt")
	}
	if ok, err := a.root.EqualTo(mustBytes(t, b.root)); ok || err != nil {
		t.Fatalf("two sealers over one root wrap under the same key (equal=%t, err=%v)", ok, err)
	}
	blob := a.kekBlobs[1]
	kek, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer kek.Destroy()
	err = kek.WithBytes(func(k []byte) error {
		return openWithKeyInto(b.root, blob[blobHeaderLen:], blob[:blobHeaderLen], k)
	})
	if !errors.Is(err, ErrSealedAuthentication) {
		t.Fatalf("one sealer's KEK blob under the other's wrapping key = %v, want ErrSealedAuthentication", err)
	}
}

// mustBytes copies an enclave's material out for a comparison in a test.
func mustBytes(t *testing.T, e *MemoryEnclave) []byte {
	t.Helper()
	var out []byte
	if err := e.WithBytes(func(b []byte) error { out = append(out, b...); return nil }); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	return out
}

// TestSealer_RefusesAGenerationPastTheRootCeiling pins the root's usage bound:
// one root wrap per KEK generation, refused once maxKEKGenerations are spent
// (which also keeps the uint32 generation identifier from wrapping onto a
// retired generation). The refusal is fail-closed for new seals only: nothing
// is minted, the hierarchy stays published, and every existing value opens.
func TestSealer_RefusesAGenerationPastTheRootCeiling(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer(WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	first, err := s.Seal(ctx, []byte("sealed under generation 1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer first.Destroy()

	// Position the counters one generation below the ceiling: generation 1's
	// key is relabelled as the second-to-last generation, keeping its blob
	// under the old identifier as well so the value above still opens.
	s.mu.Lock()
	s.kekGen = maxKEKGenerations - 1
	s.kekBlobs[s.kekGen] = s.kekBlobs[1]
	s.mu.Unlock()

	// One more generation is allowed: the seal spends generation
	// maxKEKGenerations-1's budget and rotates to the last one.
	last, err := s.Seal(ctx, []byte("sealed under the last generation"))
	if err != nil {
		t.Fatalf("Seal into the last generation: %v", err)
	}
	defer last.Destroy()
	s.mu.RLock()
	gen := s.kekGen
	s.mu.RUnlock()
	if gen != maxKEKGenerations {
		t.Fatalf("generation = %d after the last allowed rotation, want %d", gen, uint32(maxKEKGenerations))
	}

	// The last generation's one wrap is spent; the next rotation is refused.
	for i := range 2 {
		v, err := s.Seal(ctx, []byte("one too many"))
		if err == nil {
			v.Destroy()
			t.Fatalf("seal %d past the ceiling succeeded", i)
		}
		if !errors.Is(err, ErrSealerExhausted) || !errors.Is(err, ErrSealFailed) {
			t.Fatalf("seal %d past the ceiling = %v, want ErrSealerExhausted joined with ErrSealFailed", i, err)
		}
	}
	s.mu.RLock()
	gen, alive := s.kekGen, s.root.IsAlive() && s.kek.IsAlive()
	s.mu.RUnlock()
	if gen != maxKEKGenerations || !alive {
		t.Fatalf("after the refusal: generation %d, hierarchy alive %t; want %d and true", gen, alive, uint32(maxKEKGenerations))
	}

	for name, v := range map[string]*SealedEnclave{"first": first, "last": last} {
		e, err := v.Open(ctx)
		if err != nil {
			t.Fatalf("Open of the %s value after the refusal: %v", name, err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
	}
}

// TestSealer_KEKFailureDoesNotReunsealTheRoot pins that a failed first KEK
// mint after a successful unseal retries only the mint: UnsealRoot is called
// at most once unless it failed, and a one-shot root provider cannot answer
// twice.
func TestSealer_KEKFailureDoesNotReunsealTheRoot(t *testing.T) {
	ru := &countingRootUnsealer{inner: fixedRootUnsealer{fill: 0x5A}}
	// The root's pages are already locked when UnsealRoot runs, so the next
	// mlock in this goroutine is the first KEK's.
	ru.after = func() {
		if ru.calls == 1 {
			failNthLock(t, 1)
		}
	}
	s, err := NewSealer(WithRootUnsealer(ru))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	if _, err := s.Seal(t.Context(), []byte("first attempt")); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the KEK mint refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if ru.calls != 1 {
		t.Fatalf("UnsealRoot was called %d times by the first seal, want 1", ru.calls)
	}
	if _, err := hierarchyState(s); err != nil {
		t.Errorf("hierarchy state = %v after a failed mint; nothing was sealed, so nothing was wiped", err)
	}

	want := []byte("second attempt")
	v, err := s.Seal(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal after the mint failure = %v", err)
	}
	defer v.Destroy()
	if ru.calls != 1 {
		t.Fatalf("UnsealRoot was called %d times, want 1: a successful unseal was retried "+
			"because the KEK mint after it failed", ru.calls)
	}

	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()
	if !holds(e, want) {
		t.Error("the round trip after the retry returned the wrong material")
	}
}

// TestSealer_SweptPendingRootIsWipedNotReunsealed covers the retained root's
// interaction with a shutdown sweep. A root unsealed but not yet published —
// its KEK mint failed — is a live enclave on the ledger like any other, so
// WipeAll must destroy it; and the sealer must then report ErrSealerWiped
// rather than quietly unsealing a fresh root, which is both the silent re-keying
// that sentinel exists to prevent and a second UnsealRoot call.
func TestSealer_SweptPendingRootIsWipedNotReunsealed(t *testing.T) {
	ru := &countingRootUnsealer{inner: fixedRootUnsealer{fill: 0x6B}}
	ru.after = func() {
		if ru.calls == 1 {
			failNthLock(t, 1)
		}
	}
	s, err := NewSealer(WithRootUnsealer(ru))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal(t.Context(), []byte("first attempt")); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the KEK mint refused = %v, want ErrLockedMemoryUnavailable", err)
	}

	s.mu.RLock()
	pending := s.pendingRoot
	s.mu.RUnlock()
	if pending == nil || !pending.IsAlive() {
		t.Fatal("the unsealed root was not retained after the mint failed")
	}
	if !isRegistered(pending) {
		t.Fatal("the retained root is not on the ledger, so a sweep cannot reach it")
	}

	if _, err := WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}
	if pending.IsAlive() {
		t.Fatal("WipeAll left the retained root alive")
	}

	if _, err := s.Seal(t.Context(), []byte("after the sweep")); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Seal after the sweep = %v, want ErrSealerWiped", err)
	}
	if ru.calls != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: a swept root was re-unsealed", ru.calls)
	}
}

// TestSealer_BlockedUnsealDoesNotStallOthers pins that a provider stuck in
// UnsealRoot, ignoring its context, stalls only callers that need its
// hierarchy, each until its own context ends:
//
//   - another, initialized Sealer seals and opens normally;
//   - a second Seal on the SAME Sealer, queued for the init slot, returns
//     DeadlineExceeded when its deadline passes, instead of waiting out the
//     provider;
//   - the stuck caller completes once the provider does.
func TestSealer_BlockedUnsealDoesNotStallOthers(t *testing.T) {
	stuck := newBlockingProvider()
	stuck.release = make(chan struct{})
	s, err := NewSealer(WithRootUnsealer(stuck))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	other, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	warm, err := other.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("warm-up Seal: %v", err)
	}
	defer warm.Destroy()

	first := make(chan error, 1)
	go func() {
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if v != nil {
			v.Destroy()
		}
		first <- err
	}()
	<-stuck.entered // the first caller is inside UnsealRoot, holding the init slot

	// Another Sealer is untouched.
	v, err := other.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal on a different Sealer while a provider is stuck in UnsealRoot: %v", err)
	}
	v.Destroy()
	e, err := warm.Open(t.Context())
	if err != nil {
		t.Fatalf("Open on a different Sealer while a provider is stuck in UnsealRoot: %v", err)
	}
	e.Destroy()

	// The stuck Sealer's own state stays readable: nothing holds mu.
	if _, err := hierarchyState(s); err != nil {
		t.Fatalf("hierarchy state during a stuck unseal = %v", err)
	}

	// A second Seal on the stuck Sealer queues for the slot and leaves when
	// its deadline passes.
	deadline := newManualContext()
	second := make(chan error, 1)
	go func() {
		_, err := s.Seal(deadline, append([]byte(nil), sealedMaterial...))
		second <- err
	}()
	<-deadline.waiting // queued on the init slot
	deadline.end(context.DeadlineExceeded)
	requireSealCanceled(t, <-second, context.DeadlineExceeded)
	if got := stuck.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: the queued caller reached the provider", got)
	}

	close(stuck.release)
	if err := <-first; err != nil {
		t.Fatalf("the stuck caller's Seal after the provider returned: %v", err)
	}
}

// TestSealer_UnsealRootAtMostOnceUnderConcurrentFirstUse pins that many
// callers arriving at a fresh Sealer together cause exactly one UnsealRoot
// and all seal. Every caller is observed queued at the init slot before the
// provider is released.
func TestSealer_UnsealRootAtMostOnceUnderConcurrentFirstUse(t *testing.T) {
	const callers = 8
	p := newBlockingProvider()
	p.release = make(chan struct{})
	s, err := NewSealer(WithRootUnsealer(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	ctxs := make([]*manualContext, callers)
	results := make(chan error, callers)
	for i := range ctxs {
		ctxs[i] = newManualContext()
		go func(ctx context.Context) {
			v, err := s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			if v != nil {
				v.Destroy()
			}
			results <- err
		}(ctxs[i])
	}
	for _, c := range ctxs {
		<-c.waiting // every caller has reached the slot
	}
	<-p.entered // and exactly one of them is inside the provider
	close(p.release)

	for range callers {
		if err := <-results; err != nil {
			t.Errorf("concurrent first Seal: %v", err)
		}
	}
	if got := p.callCount(); got != 1 {
		t.Fatalf("UnsealRoot was called %d times by %d concurrent first seals, want exactly 1", got, callers)
	}
}

// TestSealer_CanceledUnsealIsRetriedByTheNextCaller pins the other half of
// at-most-once: a call refused because its context ended is a FAILED call,
// so the next caller in the queue asks again — once — and succeeds.
func TestSealer_CanceledUnsealIsRetriedByTheNextCaller(t *testing.T) {
	p := newBlockingProvider()
	p.honor = true
	p.release = make(chan struct{})
	s, err := NewSealer(WithRootUnsealer(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	holderCtx, cancelHolder := context.WithCancel(t.Context())
	holder := make(chan error, 1)
	go func() {
		_, err := s.Seal(holderCtx, append([]byte(nil), sealedMaterial...))
		holder <- err
	}()
	<-p.entered

	waiterCtx := newManualContext()
	waiter := make(chan error, 1)
	go func() {
		v, err := s.Seal(waiterCtx, append([]byte(nil), sealedMaterial...))
		if v != nil {
			v.Destroy()
		}
		waiter <- err
	}()
	<-waiterCtx.waiting

	cancelHolder()
	requireSealCanceled(t, <-holder, context.Canceled)

	<-p.entered // the waiter's retry reached the provider
	close(p.release)
	if err := <-waiter; err != nil {
		t.Fatalf("the queued Seal after the holder's unseal was canceled: %v", err)
	}
	if got := p.callCount(); got != 2 {
		t.Errorf("UnsealRoot was called %d times, want 2: one canceled, one retry", got)
	}
}

// sweepOnceWaiting arms sweepWaitingForTest for one test and returns a
// channel closed the first time a sweep is about to block on a borrow.
func sweepOnceWaiting(t *testing.T) <-chan struct{} {
	t.Helper()
	waiting := make(chan struct{})
	var once sync.Once
	swapSeam(t, &sweepWaitingForTest, func() { once.Do(func() { close(waiting) }) })
	return waiting
}

// sweepAbandoningBorrow runs a sweep that reaches a borrowed enclave, waits
// on it, and then has its context ended by the test — the shutdown whose
// deadline passes while a provider still holds a borrow. It returns what the
// sweep left held, which includes the borrowed enclave.
func sweepAbandoningBorrow(t *testing.T) int {
	t.Helper()
	waiting := sweepOnceWaiting(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		n   int
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := WipeAll(ctx)
		out <- result{n, err}
	}()
	<-waiting
	cancel()
	r := <-out
	if r.err != nil {
		t.Fatalf("WipeAll: %v", r.err)
	}
	return r.n
}

// TestSealer_SweepDuringABlockedUnsealLeavesTheSealerWiped pins the overlap
// rule in initHierarchy against BOTH ways a sweep can meet a root the provider
// is still writing into:
//
//   - the sweep's deadline ends while it waits on the borrow, so the root
//     SURVIVES it — and publishing that root would leave the key that opens
//     everything live after the sweep that exists to remove it;
//   - the sweep waits the borrow out and destroys the root the moment the
//     provider lets go.
//
// Either way the sealer must report ErrSealerWiped, hold no live root, and
// never ask the provider again.
func TestSealer_SweepDuringABlockedUnsealLeavesTheSealerWiped(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sweep func(t *testing.T, release func())
	}{
		{"the sweep gives up on the borrow", func(t *testing.T, release func()) {
			if remaining := sweepAbandoningBorrow(t); remaining == 0 {
				t.Fatal("the sweep reclaimed the root UnsealRoot is writing into; the premise no longer holds")
			}
			release()
		}},
		{"the sweep waits the borrow out", func(t *testing.T, release func()) {
			waiting := sweepOnceWaiting(t)
			done := make(chan int, 1)
			go func() { done <- sweep(t) }()
			<-waiting // the sweep is blocked on the root's borrow
			release()
			<-done
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// gatedRootUnsealer, not blockingProvider: the provider must
			// allocate NOTHING once released. A provider that builds an
			// enclave of its own after release (SoftwareProvider's root) lets
			// that allocation's borrow wake the waiting sweep, which can then
			// destroy the provider's enclave before the provider borrows it —
			// an unseal failure decided by the scheduler, not by the sealer.
			p := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
			s, err := NewSealer(WithRootUnsealer(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}

			first := make(chan error, 1)
			go func() {
				_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
				first <- err
			}()
			<-p.entered

			tc.sweep(t, func() { close(p.release) })

			if err := <-first; !errors.Is(err, ErrSealerWiped) {
				t.Fatalf("Seal whose unseal overlapped a sweep = %v, want ErrSealerWiped", err)
			}
			if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
				t.Error("the root delivered across the sweep is still alive; the sweep's purpose was defeated")
			}
			if published, _ := hierarchyState(s); published {
				t.Error("a hierarchy was published from a root that overlapped a sweep")
			}
			if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
				t.Errorf("Seal after the overlapped init = %v, want ErrSealerWiped", err)
			}
			if got := p.callCount(); got != 1 {
				t.Errorf("UnsealRoot was called %d times, want 1: the sealer re-unsealed after a sweep", got)
			}
		})
	}
}

// TestSealer_InitSlotRefusesAnEndedContext drives initHierarchy directly with
// an ended context. select picks at random between a free slot and a closed
// Done channel, so both arms are taken across the iterations; neither may
// reach the provider, and both must report the cancellation.
func TestSealer_InitSlotRefusesAnEndedContext(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithRootUnsealer(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for range 64 {
		requireSealCanceled(t, s.initHierarchy(ctx), context.Canceled)
	}
	if got := p.callCount(); got != 0 {
		t.Errorf("UnsealRoot was called %d times for an ended context", got)
	}
}

// TestSealer_InitAfterASweepOfThePublishedHierarchyIsWiped pins the slot
// holder's re-read of the published state. protectRootKey normally sees a
// swept hierarchy itself, but a sweep can land between its read and the slot
// — and the slot holder must then refuse, not treat the dead hierarchy as
// absent and unseal again.
func TestSealer_InitAfterASweepOfThePublishedHierarchyIsWiped(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithRootUnsealer(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	sweep(t)

	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("initHierarchy after the published hierarchy was swept = %v, want ErrSealerWiped", err)
	}
	if got := p.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: a swept hierarchy was rebuilt", got)
	}
}

// TestSealer_SweepOverlapIsCheckedBeforeTheMint pins that a sweep completing
// while UnsealRoot holds the root's borrow is caught before the mint, not
// only at publication, which a failed mint never reaches: the root is
// destroyed and the sealer is wiped despite continued allocation failures.
func TestSealer_SweepOverlapIsCheckedBeforeTheMint(t *testing.T) {
	u := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		first <- err
	}()
	<-u.entered
	if remaining := sweepAbandoningBorrow(t); remaining == 0 {
		t.Fatal("the sweep reclaimed the borrowed root; the premise of this test no longer holds")
	}
	failNthLock(t, 1) // the KEK mint is refused, if it is ever attempted
	close(u.release)

	if err := <-first; !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal whose unseal overlapped a sweep, with the mint refused = %v, want ErrSealerWiped", err)
	}
	if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
		t.Fatal("the root delivered across the sweep is still alive")
	}
	// Later attempts while the mint would still be refused. They are driven
	// at the hierarchy directly: a whole Seal allocates its DEK first, and
	// that refusal would answer before the hierarchy was ever consulted.
	for range 2 {
		failNthLock(t, 1)
		if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("a later initialization under continued allocation failure = %v, want ErrSealerWiped", err)
		}
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestSealer_SweepDuringAFailedMintIsWiped covers the mint's own exit: a sweep
// runs while the first KEK is being allocated — inside the refused mlock — and
// the mint fails. The attempt reports the sweep, not the allocation error.
func TestSealer_SweepDuringAFailedMintIsWiped(t *testing.T) {
	u := &gatedRootUnsealer{}
	u.after = func() {
		prev := lockMemory
		swapSeam(t, &lockMemory, func([]byte) error {
			lockMemory = prev
			sweep(t)
			return errors.New("mlock: cannot allocate memory")
		})
	}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal whose mint failed across a sweep = %v, want ErrSealerWiped", err)
	}
	if s.pendingRoot == nil || s.pendingRoot.IsAlive() {
		t.Error("the root survived a sweep that overlapped its mint")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestSealer_CancellationShapesAFailedMint pins that when the context ends
// during a successful unseal and the mint fails, the root is kept and the
// error carries the cancellation and the mint failure under ErrSealFailed.
func TestSealer_CancellationShapesAFailedMint(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("request abandoned")
	u := &gatedRootUnsealer{}
	u.after = func() {
		failNthLock(t, 1)
		cancel(why)
	}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
	for _, want := range []error{ErrSealFailed, context.Canceled, why, ErrLockedMemoryUnavailable} {
		if !errors.Is(err, want) {
			t.Errorf("Seal = %v, does not match %v", err, want)
		}
	}
	if s.pendingRoot == nil || !s.pendingRoot.IsAlive() {
		t.Fatal("the delivered root was not retained across the failed mint")
	}

	u.after = nil
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal after the failed mint: %v", err)
	}
	v.Destroy()
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}

// TestSealer_RefusedReleaseOfASweptRootIsReportedAndRetried pins discardIfSwept
// against a kernel that refuses to take the root's pages back. The mapping must
// not be dropped: the root stays on the WipeAll ledger, the refusal is reported
// alongside ErrSealerWiped rather than swallowed, and the next attempt — the
// state is wiped for good — retries the release.
func TestSealer_RefusedReleaseOfASweptRootIsReportedAndRetried(t *testing.T) {
	u := &gatedRootUnsealer{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		first <- err
	}()
	<-u.entered
	if remaining := sweepAbandoningBorrow(t); remaining == 0 {
		t.Fatal("the sweep reclaimed the borrowed root; the premise of this test no longer holds")
	}

	prevUnmap := swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap: operation not permitted") })
	close(u.release)

	err = <-first
	if !errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal = %v, want ErrSealerWiped", err)
	}
	if !pagesHeld(err) {
		t.Errorf("Seal = %v: the refused release of the swept root was not reported", err)
	}
	root := s.pendingRoot
	if root == nil || !isRegistered(root) {
		t.Fatal("the swept root whose release was refused fell off the WipeAll ledger")
	}

	unmapMemory = prevUnmap
	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) || pagesHeld(err) {
		t.Errorf("the next initialization = %v, want a clean ErrSealerWiped after the retried release", err)
	}
	if isRegistered(root) {
		t.Error("the next attempt did not retry the refused release of the swept root")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
	sweep(t) // reclaim the scratch DEK whose release was refused alongside
}

// regionContains reports whether region contains the byte at addr.
func regionContains(region []byte, addr uintptr) bool {
	if len(region) == 0 {
		return false
	}
	lo := uintptr(unsafe.Pointer(&region[0]))
	return addr >= lo && addr < lo+uintptr(len(region))
}

// TestSealer_RefusedReleaseOfADiscardedKEKIsRetried pins that when a sweep
// overlaps initialization after the unseal, publication destroys the root
// and the minted KEK, and the kernel refuses the KEK's unmap, the sealer
// keeps a reference and retries the KEK's release with the root's on the
// next attempt.
//
// The overlap is placed deterministically. The KEK's own mlock — the first
// step of the mint — runs a sweep while the test holds a borrow on the root,
// and ends that sweep's context once it is waiting on the borrow: the
// sequence moves, the root survives, and the mint then completes under it.
func TestSealer_RefusedReleaseOfADiscardedKEKIsRetried(t *testing.T) {
	u := &gatedRootUnsealer{}
	s, err := NewSealer(WithRootUnsealer(u))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	prevLock, prevUnmap := lockMemory, unmapMemory

	var kekAt uintptr
	u.after = func() {
		// Runs inside UnsealRoot; the next mlock in this goroutine is the
		// KEK's, so arm the hook for it.
		swapSeam(t, &lockMemory, func(b []byte) error {
			lockMemory = prevLock
			kekAt = uintptr(unsafe.Pointer(&b[0]))

			held, letGo := make(chan struct{}), make(chan struct{})
			go func() {
				_ = s.pendingRoot.WithBytes(func([]byte) error {
					close(held)
					<-letGo
					return nil
				})
			}()
			<-held
			sweepAbandoningBorrow(t) // the root survives; the sequence moves
			close(letGo)

			// Refuse the KEK's unmap — and only the KEK's.
			swapSeam(t, &unmapMemory, func(m []byte) error {
				if regionContains(m, kekAt) {
					return errors.New("munmap: operation not permitted")
				}
				return prevUnmap(m)
			})
			return prevLock(b)
		})
	}

	_, err = s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if !errors.Is(err, ErrSealerWiped) || !pagesHeld(err) {
		t.Fatalf("Seal = %v, want ErrSealerWiped with the KEK's refused release reported", err)
	}
	kek := s.pendingKEK
	if kek == nil {
		t.Fatal("the KEK whose release was refused is no longer referenced by the sealer; nothing will retry it")
	}
	if !isRegistered(kek) {
		t.Fatal("the KEK whose release was refused fell off the WipeAll ledger")
	}
	if isRegistered(s.pendingRoot) {
		t.Error("the root's release was not refused, so it should be off the ledger")
	}

	unmapMemory = prevUnmap
	if err := s.initHierarchy(t.Context()); !errors.Is(err, ErrSealerWiped) || pagesHeld(err) {
		t.Errorf("the next initialization = %v, want a clean ErrSealerWiped after the retried releases", err)
	}
	if isRegistered(kek) {
		t.Error("the next attempt did not retry the refused release of the discarded KEK")
	}
	if s.pendingKEK != nil {
		t.Error("pendingKEK was not cleared after its release succeeded")
	}
	if got := u.callCount(); got != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1", got)
	}
}
