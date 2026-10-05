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
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// mapKeyProtector is a KeyProtector whose "device" is a map of locked
// mappings outside the package ledger. Its key store survives a WipeAll, as a
// device-held key does, and a test can mint alias blobs in it.
type mapKeyProtector struct {
	mu         sync.Mutex
	n          int
	keys       map[string]*mapping // a device's key store: locked, outside the ledger
	protects   int
	unprotects int
}

func newMapKeyProtector(t testing.TB) *mapKeyProtector {
	m := &mapKeyProtector{keys: make(map[string]*mapping)}
	t.Cleanup(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		releaseDeviceStore(t, m.keys)
	})
	return m
}

func (m *mapKeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	m.protects++
	blob := fmt.Appendf(nil, "map-key-protector-blob-%d", m.n)
	stored, err := deviceCopy(key)
	if err != nil {
		return nil, err
	}
	m.keys[string(blob)] = stored
	return blob, nil
}

func (m *mapKeyProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unprotects++
	k, ok := m.keys[string(blob)]
	if !ok || len(k.data) != len(key) {
		return ErrSealedAuthentication
	}
	copy(key, k.data)
	return nil
}

// protectCount reports how many Protects ran, so a test can prove WHICH
// provider a seal went through rather than inferring it.
func (m *mapKeyProtector) protectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.protects
}

// unprotectCount reports how many Unprotects ran, so a test can prove that an
// open refused by its budget never reached the key at all.
func (m *mapKeyProtector) unprotectCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unprotects
}

// alias registers a second valid blob for the key filed under existing, so a
// test can build an envelope whose blob recovers the right DEK yet differs
// from the blob the value was sealed with.
func (m *mapKeyProtector) alias(existing, alias []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[string(existing)]
	if !ok {
		return false
	}
	m.keys[string(alias)] = k // the same stored key, filed under a second blob
	return true
}

// releaseDeviceStore releases every distinct mapping of a fake device's key
// store. WipeAll cannot reach these and the garbage collector never unmaps
// them; aliases share a mapping, so each is released once.
func releaseDeviceStore(t testing.TB, store map[string]*mapping) {
	t.Helper()
	seen := make(map[*mapping]struct{}, len(store))
	for blob, m := range store {
		delete(store, blob)
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		if err := m.release(); err != nil {
			t.Errorf("releasing a fake device's stored key: %v", err)
		}
	}
}

// deviceCopy files a copy of key in a raw locked mapping outside the package
// ledger, as a device would hold it, so a sweep cannot reach it.
func deviceCopy(key []byte) (*mapping, error) {
	m, err := newMapping(len(key))
	if err != nil {
		return nil, err
	}
	copy(m.data, key)
	return m, nil
}

// fixedRootUnsealer is a RootUnsealer and nothing else: it fills dst with a
// fixed byte. It exists for the capability-mismatch checks and for proving a
// provider-supplied root actually reaches the hierarchy.
type fixedRootUnsealer struct{ fill byte }

func (f *fixedRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	for i := range dst {
		dst[i] = f.fill
	}
	return nil
}

// erroringProvider fails every operation with its own error, standing in for
// a device that is present but unhealthy.
type erroringProvider struct{ err error }

func (e *erroringProvider) Protect(context.Context, []byte) ([]byte, error) { return nil, e.err }

func (e *erroringProvider) Unprotect(context.Context, []byte, []byte) error { return e.err }

func (e *erroringProvider) UnsealRoot(context.Context, []byte) error { return e.err }

// emptyBlobProtector violates the Protect contract by returning an empty
// blob, so the sealer's guard against sealing an unrecoverable value is
// reachable.
type emptyBlobProtector struct{}

func (emptyBlobProtector) Protect(context.Context, []byte) ([]byte, error) { return []byte{}, nil }

func (emptyBlobProtector) Unprotect(context.Context, []byte, []byte) error {
	return ErrSealedAuthentication
}

// providerOption injects p in mode m, for tests that range over both modes.
func providerOption(p any, m Mode) SealerOption {
	if m == ModePerOperation {
		kp, _ := p.(KeyProtector)
		return WithKeyProtector(kp)
	}
	ru, _ := p.(RootUnsealer)
	return WithRootUnsealer(ru)
}

// TestSealer_ProviderOptionSelectsTheMode pins that the provider option fixes
// the mode, and that two provider options are refused rather than resolved by
// order.
func TestSealer_ProviderOptionSelectsTheMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  SealerOption
		want Mode
	}{
		{"KeyProtector", WithKeyProtector(newMapKeyProtector(t)), ModePerOperation},
		{"RootUnsealer", WithRootUnsealer(&fixedRootUnsealer{fill: 0x42}), ModeRootKey},
		{"software as KeyProtector", WithKeyProtector(NewSoftwareProvider()), ModePerOperation},
		{"software as RootUnsealer", WithRootUnsealer(NewSoftwareProvider()), ModeRootKey},
	} {
		s, err := NewSealer(tc.opt)
		if err != nil {
			t.Errorf("NewSealer(%s): %v", tc.name, err)
			continue
		}
		if s.Mode() != tc.want {
			t.Errorf("NewSealer(%s).Mode() = %v, want %v", tc.name, s.Mode(), tc.want)
		}
		if s.owned != nil {
			t.Errorf("NewSealer(%s) owns a provider it was given", tc.name)
		}
	}

	sp := NewSoftwareProvider()
	for name, opts := range map[string][]SealerOption{
		"both":                 {WithKeyProtector(sp), WithRootUnsealer(sp)},
		"KeyProtector twice":   {WithKeyProtector(sp), WithKeyProtector(sp)},
		"RootUnsealer twice":   {WithRootUnsealer(sp), WithRootUnsealer(sp)},
		"nil after a live one": {WithRootUnsealer(sp), WithKeyProtector(nil)},
	} {
		if s, err := NewSealer(opts...); !errors.Is(err, ErrInvalidProvider) || s != nil {
			t.Errorf("NewSealer(%s) = (%v, %v), want (nil, ErrInvalidProvider)", name, s, err)
		}
	}
}

// TestSealer_DefaultIsSoftwareRootKey pins that no options means the
// pure-software provider in ModeRootKey, that it round trips, and that the
// process default NewSealed installs has the same shape.
func TestSealer_DefaultIsSoftwareRootKey(t *testing.T) {
	freshProcessSealer(t)
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer(): %v", err)
	}
	if s.Mode() != ModeRootKey {
		t.Errorf("default Mode() = %v, want ModeRootKey", s.Mode())
	}

	want := []byte("default-sealer-round-trip-material")
	v, err := s.Seal(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()
	if !holds(e, want) {
		t.Error("default sealer round trip returned the wrong material")
	}

	p, err := NewSealed(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer p.Destroy()
	if got := p.sealer.Mode(); got != ModeRootKey {
		t.Errorf("process default sealer mode = %v, want ModeRootKey", got)
	}
}

// TestSealer_PerOperationRoundTrip runs both modes against the software
// provider through an explicit Sealer; the process default never exercises
// the per-operation path.
func TestSealer_PerOperationRoundTrip(t *testing.T) {
	for _, m := range []Mode{ModePerOperation, ModeRootKey} {
		t.Run(m.String(), func(t *testing.T) {
			s, err := NewSealer(providerOption(NewSoftwareProvider(), m))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			want := []byte("mode-parity-material-for-" + m.String())
			v, err := s.Seal(t.Context(), append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()
			e, err := v.Open(t.Context())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer e.Destroy()
			if !holds(e, want) {
				t.Error("round trip returned the wrong material")
			}
		})
	}
}

// TestSealer_RefusesForeignProvider pins that a value sealed under one
// provider does not open under another, in either mode. The envelope is
// rebuilt against the second sealer directly, since normal use has no path
// for that misuse.
func TestSealer_RefusesForeignProvider(t *testing.T) {
	build := func(t *testing.T, m Mode) (*Sealer, *Sealer) {
		t.Helper()
		a, err := NewSealer(providerOption(NewSoftwareProvider(), m))
		if err != nil {
			t.Fatalf("NewSealer A: %v", err)
		}
		b, err := NewSealer(providerOption(NewSoftwareProvider(), m))
		if err != nil {
			t.Fatalf("NewSealer B: %v", err)
		}
		return a, b
	}

	for _, m := range []Mode{ModePerOperation, ModeRootKey} {
		t.Run(m.String(), func(t *testing.T) {
			a, b := build(t, m)

			want := []byte("cross-provider-material")
			v, err := a.Seal(t.Context(), append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			// Give B a live hierarchy of its own, so the refusal below is a key
			// mismatch and not "B never sealed anything".
			warm, err := b.Seal(t.Context(), []byte("warm-up"))
			if err != nil {
				t.Fatalf("warm-up Seal: %v", err)
			}
			defer warm.Destroy()

			foreign := &SealedEnclave{sealer: b, sealed: v.sealed, blob: v.blob, size: v.size}
			if e, err := foreign.Open(t.Context()); !errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open under a foreign provider = %v, want ErrSealedAuthentication", err)
				if e != nil {
					e.Destroy()
				}
			}

			// Control: the same envelope opens under its own sealer.
			e, err := v.Open(t.Context())
			if err != nil {
				t.Fatalf("Open under the sealing provider: %v", err)
			}
			if !holds(e, want) {
				t.Error("control open returned the wrong material")
			}
			e.Destroy()
		})
	}
}

// TestSealer_EnvelopeBindsBlobToCiphertext pins the AAD binding end to end.
// The map provider files an alias blob that recovers the exact DEK the value
// was sealed with, so the envelope differs only in the blob bytes; without
// the AAD binding it would open.
func TestSealer_EnvelopeBindsBlobToCiphertext(t *testing.T) {
	kp := newMapKeyProtector(t)
	s, err := NewSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	want := []byte("blob-binding-material")
	v, err := s.Seal(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	aliasBlob := []byte("map-key-protector-alias-blob")
	if !kp.alias(v.blob, aliasBlob) {
		t.Fatal("could not alias the sealed value's blob; the fake provider does not hold it")
	}

	// Setup sanity: the alias must recover the same DEK, or the refusal below
	// would be a key mismatch. Compared inside locked borrows, never copied to
	// the heap.
	dekA, err := NewMemoryEnclaveSized(dekBytes)
	if err != nil {
		t.Fatalf("allocating dekA: %v", err)
	}
	defer func() { _ = dekA.Destroy() }()
	dekB, err := NewMemoryEnclaveSized(dekBytes)
	if err != nil {
		t.Fatalf("allocating dekB: %v", err)
	}
	defer func() { _ = dekB.Destroy() }()
	same := false
	if err := dekA.WithBytes(func(a []byte) error {
		if err := kp.Unprotect(t.Context(), v.blob, a); err != nil {
			return fmt.Errorf("Unprotect(original): %w", err)
		}
		return dekB.WithBytes(func(b []byte) error {
			if err := kp.Unprotect(t.Context(), aliasBlob, b); err != nil {
				return fmt.Errorf("Unprotect(alias): %w", err)
			}
			same = bytes.Equal(a, b)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Fatal("the alias blob recovers a different DEK; the test setup is broken")
	}

	repaired := &SealedEnclave{sealer: s, sealed: v.sealed, blob: aliasBlob, size: v.size}
	if e, err := repaired.Open(t.Context()); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open with a re-paired (valid, same-DEK) blob = %v, want ErrSealedAuthentication: "+
			"the ciphertext is not bound to the exact blob it was sealed with", err)
		if e != nil {
			e.Destroy()
		}
	}

	// Control: untouched, the value opens.
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("control Open: %v", err)
	}
	if !holds(e, want) {
		t.Error("control open returned the wrong material")
	}
	e.Destroy()
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

// TestSealer_WipedFailsClosedPerMode pins the mode asymmetry around a
// shutdown sweep:
//
//   - ModeRootKey: the hierarchy is swept; new seals and existing values
//     report ErrSealerWiped, and the sealer never re-keys.
//   - ModePerOperation over the in-process software provider: the same, from
//     the provider's side.
//   - ModePerOperation over a device-held key (the map provider): the sweep
//     destroys nothing the values depend on, so sealing and opening keep
//     working.
func TestSealer_WipedFailsClosedPerMode(t *testing.T) {
	material := []byte("mode-asymmetry-material")

	t.Run("ModeRootKey", func(t *testing.T) {
		s, err := NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.Seal(t.Context(), append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped: the sealer must fail closed, never re-key", err)
		}
	})

	t.Run("ModePerOperation_software", func(t *testing.T) {
		s, err := NewSealer(WithKeyProtector(NewSoftwareProvider()))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.Seal(t.Context(), append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped", err)
		}
	})

	t.Run("ModePerOperation_deviceHeld", func(t *testing.T) {
		s, err := NewSealer(WithKeyProtector(newMapKeyProtector(t)))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		// The device still holds the keys: existing values open and new seals
		// work, because nothing in this process's memory protected the DEKs.
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open after sweep with a device-held key = %v; "+
				"a sweep must not invalidate values whose keys the process never held", err)
		}
		if !holds(e, material) {
			t.Error("post-sweep open returned the wrong material")
		}
		e.Destroy()

		fresh, err := s.Seal(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal after sweep with a device-held key: %v", err)
		}
		fresh.Destroy()
	})
}

// TestSealer_ProviderErrorsSurfaceHonestly pins the error shaping on both
// paths: a provider's own failure surfaces under ErrSealFailed on seal and
// ErrOpenFailed on open, with the cause reachable, and is never reported as
// an authentication failure.
func TestSealer_ProviderErrorsSurfaceHonestly(t *testing.T) {
	deviceDown := errors.New("device unreachable: session pool exhausted")
	s, err := NewSealer(WithKeyProtector(&erroringProvider{err: deviceDown}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal(t.Context(), []byte("provider-error-material"))
	if !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with a failing provider = %v, want it to match ErrSealFailed", err)
	}
	if !errors.Is(err, deviceDown) {
		t.Errorf("Seal error %v does not preserve the provider's cause", err)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Seal error %v reads as an authentication failure; an infrastructure fault must not", err)
	}

	// The open path: seal under a healthy provider, open under one that
	// fails with its own error. The sealer must keep that error reachable and
	// join it under ErrOpenFailed — the open-side "could not", never a
	// forgery verdict.
	kp := newMapKeyProtector(t)
	healthy, err := NewSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := healthy.Seal(t.Context(), []byte("provider-error-material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	v.sealer = s // the erroring provider now answers this value's opens
	_, err = v.Open(t.Context())
	if !errors.Is(err, deviceDown) {
		t.Errorf("Open with a failing provider = %v, want the provider's own error to surface", err)
	}
	if !errors.Is(err, ErrOpenFailed) {
		t.Errorf("Open with a failing provider = %v, want it to match ErrOpenFailed", err)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open error %v reads as an authentication failure; an operator would hunt an attacker who does not exist", err)
	}
	v.sealer = healthy

	// A provider returning an empty blob is a contract violation caught at
	// seal time, not at the first failed open months later.
	eb, err := NewSealer(WithKeyProtector(emptyBlobProtector{}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := eb.Seal(t.Context(), []byte("empty-blob-material")); !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with an empty-blob provider = %v, want ErrSealFailed", err)
	}
}

// TestSealer_SetSealerIsOneShot pins the installation contract: the first
// install wins, the lazy default counts as an install, and NewSealed routes
// through the installed sealer (counted by its provider's operations).
func TestSealer_SetSealerIsOneShot(t *testing.T) {
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)

	if err := SetSealer(nil); !errors.Is(err, ErrNilSealer) {
		t.Errorf("SetSealer(nil) = %v, want ErrNilSealer", err)
	}

	kp := newMapKeyProtector(t)
	own, err := NewSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(own); err != nil {
		t.Fatalf("SetSealer: %v", err)
	}

	// The second install fails closed whatever it carries.
	other, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(other); !errors.Is(err, ErrSealerInstalled) {
		t.Errorf("second SetSealer = %v, want ErrSealerInstalled", err)
	}

	// NewSealed routes through the installed sealer: the provider's Protect
	// count moves.
	before := kp.protectCount()
	v, err := NewSealed(t.Context(), []byte("routed-material"))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer v.Destroy()
	if got := kp.protectCount(); got != before+1 {
		t.Errorf("installed provider saw %d Protects, want %d: NewSealed did not route through the installed sealer", got, before+1)
	}

	// A stray early seal locks the configuration: after the lazy default is
	// installed, SetSealer fails closed.
	resetProcessSealerForTest()
	if _, err := NewSealed(t.Context(), []byte("stray-early-seal")); err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	if err := SetSealer(own); !errors.Is(err, ErrSealerInstalled) {
		t.Errorf("SetSealer after a lazy default = %v, want ErrSealerInstalled", err)
	}
}

// TestSealer_NilReceiver pins the nil contract: a nil *Sealer refuses with a
// typed error AND still honors the ownership contract on the caller's slice —
// losing your sealer must not mean leaving the material behind.
func TestSealer_NilReceiver(t *testing.T) {
	data := append([]byte(nil), sealedMaterial...)
	var s *Sealer
	if _, err := s.Seal(t.Context(), data); !errors.Is(err, ErrNilSealer) {
		t.Errorf("nil Sealer.Seal = %v, want ErrNilSealer", err)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("data[%d] = %#x after a refused Seal; the ownership contract wipes on every path", i, b)
		}
	}
}

// TestSealer_ModeString covers the diagnostic surface, including a value that
// names no mode, which prints its number rather than garbage.
func TestSealer_ModeString(t *testing.T) {
	for want, m := range map[string]Mode{
		"ModeRootKey":      ModeRootKey,
		"ModePerOperation": ModePerOperation,
		"Mode(99)":         Mode(99),
	} {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", uint8(m), got, want)
		}
	}
}

// TestSoftwareProvider_ProtectUnprotect covers the software provider as a
// bare KeyProtector: round trip, the authenticated-by-contract refusals with
// their controls, and the framing checks.
func TestSoftwareProvider_ProtectUnprotect(t *testing.T) {
	p := NewSoftwareProvider()

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
	other := NewSoftwareProvider()
	otherBlob, err := other.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect (other): %v", err)
	}
	if err := p.Unprotect(t.Context(), otherBlob, got); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect(foreign blob) = %v, want ErrSealedAuthentication", err)
	}

	// A provider that has protected nothing owns no blobs at all.
	if err := NewSoftwareProvider().Unprotect(t.Context(), blob, got); !errors.Is(err, ErrSealedAuthentication) {
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
	p := NewSoftwareProvider()
	key := make([]byte, RootKeyBytes)

	blob, err := p.Protect(t.Context(), append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	p.mu.Lock()
	p.protects = softwareProtectLimit
	p.mu.Unlock()

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
	p := NewSoftwareProvider()

	if err := p.UnsealRoot(t.Context(), make([]byte, RootKeyBytes-1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(short dst) = %v, want ErrInvalidSize", err)
	}
	if err := p.UnsealRoot(t.Context(), make([]byte, RootKeyBytes+1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(long dst) = %v, want ErrInvalidSize", err)
	}

	// Generated key material: unsealed into locked destinations and compared
	// inside their borrows, never copied onto the heap.
	a, err := NewMemoryEnclaveSized(RootKeyBytes)
	if err != nil {
		t.Fatalf("allocating a: %v", err)
	}
	defer func() { _ = a.Destroy() }()
	b, err := NewMemoryEnclaveSized(RootKeyBytes)
	if err != nil {
		t.Fatalf("allocating b: %v", err)
	}
	defer func() { _ = b.Destroy() }()
	var same, zero bool
	if err := a.WithBytes(func(ra []byte) error {
		if err := p.UnsealRoot(t.Context(), ra); err != nil {
			return err
		}
		zero = allZero(ra)
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

// flakyRootUnsealer fails a set number of UnsealRoot calls before succeeding,
// so the retry-not-memoize contract on hierarchy initialization is testable:
// a transient provider failure (a busy TPM, a ceiling that lifts) must not be
// latched into a permanent one.
type flakyRootUnsealer struct {
	failures int
	calls    int
	inner    fixedRootUnsealer
}

func (f *flakyRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("transient: device busy")
	}
	return f.inner.UnsealRoot(ctx, dst)
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

// TestSealer_SweptTranslation pins hierarchyFailure as a pure function, since
// the race it serves (a WipeAll between an operation's liveness check and its
// borrow) cannot be held open deterministically. A dead hierarchy key reports
// ErrSealerWiped; a destroyed per-call enclave with the hierarchy intact stays
// ErrEnclaveDestroyed; every other error passes through.
func TestSealer_SweptTranslation(t *testing.T) {
	other := errors.New("unrelated failure")

	if got := swept(ErrEnclaveDestroyed); !errors.Is(got, ErrSealerWiped) {
		t.Errorf("swept(ErrEnclaveDestroyed) = %v, want ErrSealerWiped", got)
	}
	if got := swept(other); !errors.Is(got, other) || errors.Is(got, ErrSealerWiped) {
		t.Errorf("swept(unrelated) = %v, want it untouched", got)
	}

	alive, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		t.Fatalf("allocating a live key: %v", err)
	}
	defer func() { _ = alive.Destroy() }()
	dead, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		t.Fatalf("allocating a key to kill: %v", err)
	}
	if err := dead.Destroy(); err != nil {
		t.Fatalf("destroying it: %v", err)
	}

	if got := hierarchyFailure(ErrEnclaveDestroyed, alive, dead); !errors.Is(got, ErrSealerWiped) {
		t.Errorf("hierarchyFailure with a dead hierarchy key = %v, want ErrSealerWiped", got)
	}
	got := hierarchyFailure(ErrEnclaveDestroyed, alive)
	if errors.Is(got, ErrSealerWiped) || !errors.Is(got, ErrEnclaveDestroyed) {
		t.Errorf("hierarchyFailure with the hierarchy intact = %v, want ErrEnclaveDestroyed and NOT ErrSealerWiped: "+
			"a per-call enclave lost to a sweep is not a wiped sealer", got)
	}
	if got := hierarchyFailure(other, dead); !errors.Is(got, other) || errors.Is(got, ErrSealerWiped) {
		t.Errorf("hierarchyFailure(unrelated) = %v, want it untouched", got)
	}
	if got := hierarchyFailure(ErrSealedAuthentication, dead); !errors.Is(got, ErrSealedAuthentication) {
		t.Errorf("hierarchyFailure must not rewrite authentication failures; got %v", got)
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
		_, err = s.protectRootKeyInner(ctx, dead)
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

// TestSealer_NilProvidersAreRefusedAtConstruction pins that a typed nil (a
// non-nil interface value that would panic at the first Seal) and an untyped
// nil are both refused rather than defaulted to the software provider.
func TestSealer_NilProvidersAreRefusedAtConstruction(t *testing.T) {
	providers := map[string]any{
		"untyped nil":            nil,
		"typed-nil software":     (*SoftwareProvider)(nil),
		"typed-nil KeyProtector": (*mapKeyProtector)(nil),
		"typed-nil RootUnsealer": (*fixedRootUnsealer)(nil),
	}
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		for name, p := range providers {
			t.Run(m.String()+"/"+name, func(t *testing.T) {
				s, err := NewSealer(providerOption(p, m))
				if !errors.Is(err, ErrInvalidProvider) {
					t.Errorf("NewSealer(%s, %v) = %v, want ErrInvalidProvider", name, m, err)
				}
				if s != nil {
					t.Errorf("NewSealer(%s, %v) returned a sealer alongside its refusal", name, m)
				}
			})
		}
	}

	// Control: the refusal is about nil, not about the option — the same
	// call with live providers still constructs (the mismatch test covers
	// the wrong-interface cases).
	if _, err := NewSealer(WithRootUnsealer(NewSoftwareProvider())); err != nil {
		t.Errorf("NewSealer(live provider): %v", err)
	}
}

// countingRootUnsealer counts UnsealRoot calls and runs an optional hook after
// a successful one, so a test can arrange for the step AFTER the unseal to fail.
type countingRootUnsealer struct {
	calls int
	after func()
	inner fixedRootUnsealer
}

func (c *countingRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	c.calls++
	if err := c.inner.UnsealRoot(ctx, dst); err != nil {
		return err
	}
	if c.after != nil {
		c.after()
	}
	return nil
}

// failNextLock makes the next mlock in the package fail, once, and restores the
// real one on the test's cleanup whatever happens.
func failNextLock(t *testing.T) {
	t.Helper()
	prev := lockMemory
	t.Cleanup(func() { lockMemory = prev })
	lockMemory = func([]byte) error {
		lockMemory = prev
		return errors.New("mlock: cannot allocate memory")
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
	t.Cleanup(func() { lockMemory = prev })
	swept := false
	lockMemory = func(b []byte) error {
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
	}

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
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })
	refused := errors.New("munmap: cannot allocate memory")
	swept := false
	lockMemory = func(b []byte) error {
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
			unmapMemory = func([]byte) error { return refused }
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended)
			close(release)
			if err := <-done; err != nil {
				t.Errorf("the borrow holding the root across the sweep failed: %v", err)
			}
		}
		return prevLock(b)
	}

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
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })
	var newKEK uintptr
	refused := errors.New("munmap: cannot allocate memory")
	lockMemory = func(b []byte) error {
		if newKEK == 0 {
			newKEK = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			// Nothing is borrowed: the sweep reclaims the root and the
			// current KEK, so the wrap that follows fails.
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended)
			// From here only the NEW KEK's unmap is refused.
			unmapMemory = func(region []byte) error {
				lo := uintptr(unsafe.Pointer(unsafe.SliceData(region)))
				if newKEK >= lo && newKEK < lo+uintptr(len(region)) {
					return refused
				}
				return prevUnmap(region)
			}
		}
		return prevLock(b)
	}

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
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })
	var newKEK uintptr
	refused := errors.New("munmap: cannot allocate memory")
	lockMemory = func(b []byte) error {
		// The root has been unsealed and is pending publication, so this
		// allocation is the first KEK's mint (same goroutine: no race).
		if newKEK == 0 && s.pendingRoot != nil {
			newKEK = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			_, _ = WipeAll(ended) // reclaims the pending root: nothing borrows it
			unmapMemory = func(region []byte) error {
				lo := uintptr(unsafe.Pointer(unsafe.SliceData(region)))
				if newKEK >= lo && newKEK < lo+uintptr(len(region)) {
					return refused
				}
				return prevUnmap(region)
			}
		}
		return prevLock(b)
	}

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

	prevUnmap := unmapMemory
	t.Cleanup(func() { unmapMemory = prevUnmap })
	unmapMemory = func([]byte) error { return errors.New("munmap: cannot allocate memory") }
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

// TestSealer_WithKEKRotationLimitIsValidated pins the option's bounds: zero,
// one above 2^31, or any value for ModePerOperation is refused at
// construction; the bounds themselves are accepted.
func TestSealer_WithKEKRotationLimitIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []SealerOption
		ok   bool
	}{
		{"zero", []SealerOption{WithKEKRotationLimit(0)}, false},
		{"above the safe bound", []SealerOption{WithKEKRotationLimit(kekMessageLimit + 1)}, false},
		{"per-operation mode has no KEK", []SealerOption{WithKeyProtector(NewSoftwareProvider()), WithKEKRotationLimit(10)}, false},
		{"one", []SealerOption{WithKEKRotationLimit(1)}, true},
		{"the safe bound", []SealerOption{WithKEKRotationLimit(kekMessageLimit)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSealer(tc.opts...)
			if tc.ok {
				if err != nil {
					t.Fatalf("NewSealer = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRotationLimit) || s != nil {
				t.Fatalf("NewSealer = (%v, %v), want (nil, ErrInvalidRotationLimit)", s, err)
			}
		})
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

// TestSealedEnclave_OpenReturnsAFrozenEnclave pins that Open returns a
// read-only enclave, and that a refused freeze fails the open closed with no
// enclave and no reservation kept. It uses its own sealer, independent of the
// process sealer's state.
func TestSealedEnclave_OpenReturnsAFrozenEnclave(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(ctx, []byte("final plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	e.mu.RLock()
	mutable := e.m.mutable
	e.mu.RUnlock()
	if mutable {
		t.Error("Open returned a writable enclave; final plaintext must be frozen")
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	a, err := NewAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prev(b, p)
	}
	got, err := v.OpenWith(ctx, a)
	protectMemory = prev
	if err == nil {
		_ = got.Destroy()
		t.Fatal("OpenWith succeeded although its freeze was refused: writable plaintext was returned")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("OpenWith with the freeze refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if got != nil {
		t.Error("OpenWith returned an enclave alongside its error")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the open failed closed, want 0: the reservation was kept", used)
	}
}

// TestSealedEnclave_OpenWithKeepsTheChargeWhenARefusedFreezeCannotRelease
// pins that when both the freeze and the destination's release are refused,
// the open fails closed and OpenWith's reservation stays charged until the
// WipeAll ledger reclaims the pages.
func TestSealedEnclave_OpenWithKeepsTheChargeWhenARefusedFreezeCannotRelease(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(ctx, []byte("final plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	a, err := NewAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	prevProtect, prevUnmap := protectMemory, unmapMemory
	// The stranded destination is on the orphan ledger, so it is reclaimed the
	// way production reclaims it — by a sweep once the refusal lifts.
	t.Cleanup(func() {
		protectMemory, unmapMemory = prevProtect, prevUnmap
		_, _ = WipeAll(context.Background())
	})
	protectMemory = func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prevProtect(b, p)
	}
	unmapMemory = func([]byte) error { return errors.New("munmap: cannot allocate memory") }

	got, err := v.OpenWith(ctx, a)
	protectMemory, unmapMemory = prevProtect, prevUnmap
	if err == nil {
		_ = got.Destroy()
		t.Fatal("OpenWith succeeded although its freeze was refused")
	}
	if got != nil {
		t.Error("OpenWith returned an enclave alongside its error")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("OpenWith = %v, want ErrLockedMemoryUnavailable", err)
	}
	if used := a.InUse(); used == 0 {
		t.Fatal("InUse = 0 although the destination's pages were never released: the charge was refunded early")
	}

	// Once the refusal lifts, the ledger reclaims the pages and the charge
	// goes back with them.
	if _, err := WipeAll(ctx); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the sweep reclaimed the destination, want 0", used)
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
					_, g, _, err := parseBlobHeader(v.blob)
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
			failNextLock(t)
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
	if err := s.hierarchyOpenable(); err != nil {
		t.Errorf("hierarchyOpenable = %v after a failed mint; nothing was sealed, so nothing was wiped", err)
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
			failNextLock(t)
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

// The tests below pin context handling: every provider-reaching path honors
// the caller's context, and no Sealer or SealedEnclave lock is held across a
// provider call. Nothing sleeps or races a clock: providers block on channels
// the test closes, and deadlines are manualContexts the test expires.

// manualContext is a context the test ends by hand, with the error of its
// choosing, and that REPORTS when somebody first waits on it.
//
// The second property is what makes the waiter tests exact: the only place a
// Sealer selects on ctx.Done() is the init slot, so a closed waiting channel
// means the caller has reached the slot and is queued on it — not merely that
// its goroutine was started.
type manualContext struct {
	context.Context

	done    chan struct{}
	waiting chan struct{}
	once    sync.Once

	mu  sync.Mutex
	err error
}

func newManualContext() *manualContext {
	return &manualContext{
		Context: context.Background(),
		done:    make(chan struct{}),
		waiting: make(chan struct{}),
	}
}

func (c *manualContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.done
}

func (c *manualContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// end ends the context with err — context.DeadlineExceeded to model a
// deadline passing, without a clock.
func (c *manualContext) end(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	close(c.done)
}

// blockingProvider is a provider whose every operation can be held open by the
// test. It implements both seam interfaces so one type serves both modes.
//
// entered receives once per call that reaches the provider, before it blocks;
// the call then waits for release (or, when honor is set, for its own
// context to end, returning ctx.Err() — the conforming behavior). A nil
// release channel means "do not block".
type blockingProvider struct {
	inner *SoftwareProvider

	entered chan struct{}
	release chan struct{}
	honor   bool

	// beforeReturn runs after the provider has done its work and before it
	// returns success — the seam for "the caller's context ended while the
	// device was working".
	beforeReturn func()

	mu     sync.Mutex
	calls  int
	gotCtx []context.Context
}

func newBlockingProvider() *blockingProvider {
	return &blockingProvider{
		inner:   NewSoftwareProvider(),
		entered: make(chan struct{}, 64),
	}
}

func (p *blockingProvider) arrive(ctx context.Context) error {
	p.mu.Lock()
	p.calls++
	p.gotCtx = append(p.gotCtx, ctx)
	release := p.release
	p.mu.Unlock()

	p.entered <- struct{}{}
	if release == nil {
		return nil
	}
	if p.honor {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-release
	return nil
}

func (p *blockingProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *blockingProvider) finish() {
	if p.beforeReturn != nil {
		p.beforeReturn()
	}
}

func (p *blockingProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := p.arrive(ctx); err != nil {
		return nil, err
	}
	blob, err := p.inner.Protect(context.WithoutCancel(ctx), key)
	p.finish()
	return blob, err
}

func (p *blockingProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.arrive(ctx); err != nil {
		return err
	}
	err := p.inner.Unprotect(context.WithoutCancel(ctx), blob, key)
	p.finish()
	return err
}

func (p *blockingProvider) UnsealRoot(ctx context.Context, dst []byte) error {
	if err := p.arrive(ctx); err != nil {
		return err
	}
	err := p.inner.UnsealRoot(context.WithoutCancel(ctx), dst)
	p.finish()
	return err
}

// endedContexts are the two ways a context ends, constructed already ended:
// a cancellation, and a deadline in the past (expired at construction, so no
// timer is involved).
func endedContexts(t *testing.T) map[string]struct {
	ctx  context.Context
	want error
} {
	t.Helper()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, release := context.WithDeadline(t.Context(), time.Unix(0, 0))
	t.Cleanup(release)
	return map[string]struct {
		ctx  context.Context
		want error
	}{
		"canceled": {canceled, context.Canceled},
		"expired":  {expired, context.DeadlineExceeded},
	}
}

// requireSealCanceled asserts the seal-side shape of an abandoned call.
func requireSealCanceled(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, ErrSealFailed) || !errors.Is(err, want) {
		t.Fatalf("Seal = %v, want an error matching BOTH ErrSealFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) || errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal = %v: an abandoned call must not read as a forgery or a sweep", err)
	}
}

// requireOpenCanceled asserts the open-side shape of an abandoned call.
func requireOpenCanceled(t *testing.T, e *MemoryEnclave, err, want error) {
	t.Helper()
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	if !errors.Is(err, ErrOpenFailed) || !errors.Is(err, want) {
		t.Fatalf("Open = %v, want an error matching BOTH ErrOpenFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Fatalf("Open = %v: a caller that gave up was reported as a forgery", err)
	}
}

// TestSealer_EndedContextIsRefusedBeforeAnyWork pins the entry half of the
// contract, for both modes and both ways a context ends: the call fails with
// the operation's sentinel AND the context's error, the provider is never
// reached, the ownership contract still wipes the caller's material, and the
// sealed value an abandoned Open was aimed at is intact.
func TestSealer_EndedContextIsRefusedBeforeAnyWork(t *testing.T) {
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		for name, ec := range endedContexts(t) {
			t.Run(m.String()+"/"+name, func(t *testing.T) {
				p := newBlockingProvider()
				s, err := NewSealer(providerOption(p, m))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}

				data := append([]byte(nil), sealedMaterial...)
				_, err = s.Seal(ec.ctx, data)
				requireSealCanceled(t, err, ec.want)
				if !bytes.Equal(data, make([]byte, len(data))) {
					t.Error("a refused Seal left the caller's material in place; the ownership contract wipes on every path")
				}
				if got := p.callCount(); got != 0 {
					t.Errorf("the provider was called %d times by a Seal whose context had already ended", got)
				}

				v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
				if err != nil {
					t.Fatalf("control Seal with a live context: %v", err)
				}
				defer v.Destroy()
				before := p.callCount()

				e, err := v.Open(ec.ctx)
				requireOpenCanceled(t, e, err, ec.want)

				a, err := NewAllocator(16 * LockedSize(1))
				if err != nil {
					t.Fatalf("NewAllocator: %v", err)
				}
				e, err = v.OpenWith(ec.ctx, a)
				requireOpenCanceled(t, e, err, ec.want)
				if a.InUse() != 0 {
					t.Errorf("an abandoned OpenWith charged %d bytes to the budget; it must cost nothing", a.InUse())
				}
				if got := p.callCount(); got != before {
					t.Errorf("the provider was called by an Open whose context had already ended")
				}

				// The value is intact: an abandoned open is retryable.
				e, err = v.Open(t.Context())
				if err != nil {
					t.Fatalf("Open with a live context after the refusals: %v", err)
				}
				defer e.Destroy()
				if !holds(e, sealedMaterial) {
					t.Error("the value opened to the wrong material after an abandoned open")
				}
			})
		}
	}
}

// TestSealer_CancellationReachesTheProvider pins propagation: the context a
// provider receives is the caller's, so canceling the caller's context
// releases a provider that honors it — on each of the three provider
// operations — and the call fails as canceled.
func TestSealer_CancellationReachesTheProvider(t *testing.T) {
	type op struct {
		mode Mode
		// prepare returns the call to cancel; it runs with the provider not
		// yet blocking, so a value can be sealed first.
		prepare func(t *testing.T, s *Sealer) func(ctx context.Context) error
		isOpen  bool
	}
	seal := func(t *testing.T, s *Sealer) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			return err
		}
	}
	open := func(t *testing.T, s *Sealer) func(ctx context.Context) error {
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		t.Cleanup(func() { _ = v.Destroy() })
		return func(ctx context.Context) error {
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
			}
			return err
		}
	}
	ops := map[string]op{
		"UnsealRoot via Seal": {mode: ModeRootKey, prepare: seal},
		"Protect via Seal":    {mode: ModePerOperation, prepare: seal},
		"Unprotect via Open":  {mode: ModePerOperation, prepare: open, isOpen: true},
	}

	for name, tc := range ops {
		t.Run(name, func(t *testing.T) {
			p := newBlockingProvider()
			p.honor = true
			s, err := NewSealer(providerOption(p, tc.mode))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			call := tc.prepare(t, s)

			// Block from here on; drain what preparation produced.
			p.mu.Lock()
			p.release = make(chan struct{})
			p.mu.Unlock()
			for len(p.entered) > 0 {
				<-p.entered
			}

			ctx, cancel := context.WithCancelCause(t.Context())
			why := errors.New("the request this seal served was abandoned")
			result := make(chan error, 1)
			go func() { result <- call(ctx) }()

			<-p.entered // inside the provider, blocked on the caller's context
			cancel(why)
			err = <-result

			sentinel := ErrSealFailed
			if tc.isOpen {
				sentinel = ErrOpenFailed
			}
			if !errors.Is(err, sentinel) || !errors.Is(err, context.Canceled) {
				t.Fatalf("%s = %v, want an error matching %v and context.Canceled", name, err, sentinel)
			}
			if !errors.Is(err, why) {
				t.Errorf("%s = %v, want the canceler's context.Cause reachable too", name, err)
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("%s = %v: cancellation reported as a forgery", name, err)
			}

			p.mu.Lock()
			got := p.gotCtx[len(p.gotCtx)-1]
			p.mu.Unlock()
			if got.Err() == nil {
				t.Error("the context the provider received did not end when the caller's did; it is not the caller's context")
			}
		})
	}
}

// TestSealer_ContextEndingDuringASuccessfulCallIsHonoured pins the AFTER half:
// a provider that completes its work while the caller's context ends must not
// turn into a success the caller stopped waiting for — and, for the root
// unseal, must not cost the root: the unseal succeeded, so it is published
// and never asked for again.
func TestSealer_ContextEndingDuringASuccessfulCallIsHonoured(t *testing.T) {
	t.Run("Protect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
	})

	t.Run("Unprotect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		e, err := v.Open(ctx)
		requireOpenCanceled(t, e, err, context.Canceled)
	})

	t.Run("UnsealRoot", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := NewSealer(WithRootUnsealer(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
		p.beforeReturn = nil

		if done, herr := s.publishedHierarchy(); !done || herr != nil {
			t.Fatalf("publishedHierarchy = (%t, %v) after a successful unseal whose caller gave up; "+
				"the root it delivered was discarded", done, herr)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("the next Seal: %v", err)
		}
		v.Destroy()
		if got := p.callCount(); got != 1 {
			t.Errorf("UnsealRoot was called %d times, want 1: a successful unseal was repeated because "+
				"the caller that triggered it had gone", got)
		}
	})
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
	if err := s.hierarchyOpenable(); err != nil {
		t.Fatalf("hierarchyOpenable during a stuck unseal = %v", err)
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
	prev := sweepWaitingForTest
	sweepWaitingForTest = func() { once.Do(func() { close(waiting) }) }
	t.Cleanup(func() { sweepWaitingForTest = prev })
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
			if done, _ := s.publishedHierarchy(); done {
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

// TestSealedEnclave_DestroyDoesNotWaitForABlockedOpen pins the SealedEnclave
// half of "no lock across a provider": Destroy has no context, so it must not
// wait for an Open stuck in Unprotect. The in-flight open completes against
// the envelope it pinned, the ciphertext is wiped by the last open out, and
// opens after the Destroy are refused.
func TestSealedEnclave_DestroyDoesNotWaitForABlockedOpen(t *testing.T) {
	p := newBlockingProvider()
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	<-p.entered // the Protect
	sealed, blob := v.sealed, v.blob

	p.mu.Lock()
	p.release = make(chan struct{})
	p.mu.Unlock()

	opened := make(chan *MemoryEnclave, 1)
	openErr := make(chan error, 1)
	go func() {
		e, err := v.Open(t.Context())
		opened <- e
		openErr <- err
	}()
	<-p.entered // the open is inside Unprotect

	v.Destroy() // must return while the open is still blocked
	if v.IsAlive() {
		t.Error("IsAlive after Destroy")
	}
	if _, err := v.Open(t.Context()); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if bytes.Equal(sealed, make([]byte, len(sealed))) {
		t.Fatal("Destroy wiped the ciphertext under an open still reading it")
	}

	close(p.release)
	e := <-opened
	if err := <-openErr; err != nil {
		t.Fatalf("the open in flight across Destroy: %v", err)
	}
	defer e.Destroy()
	if !holds(e, sealedMaterial) {
		t.Error("the open in flight across Destroy recovered the wrong material")
	}
	if !bytes.Equal(sealed, make([]byte, len(sealed))) || !bytes.Equal(blob, make([]byte, len(blob))) {
		t.Error("the last open out did not wipe the envelope Destroy left to it")
	}
}

// TestSoftwareProvider_RefusesAnEndedContext pins the shipped provider's half
// of the contract directly: every method refuses an ended context with its
// error, a refused first call generates no root, and a refused Protect is not
// charged to the message budget.
func TestSoftwareProvider_RefusesAnEndedContext(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			p := NewSoftwareProvider()
			key := bytes.Repeat([]byte{0x3C}, RootKeyBytes)

			if _, err := p.Protect(ec.ctx, key); !errors.Is(err, ec.want) {
				t.Errorf("Protect = %v, want %v", err, ec.want)
			}
			dst := make([]byte, RootKeyBytes)
			if err := p.UnsealRoot(ec.ctx, dst); !errors.Is(err, ec.want) {
				t.Errorf("UnsealRoot = %v, want %v", err, ec.want)
			}
			p.mu.Lock()
			root, protects := p.root, p.protects
			p.mu.Unlock()
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

// TestContextFailure pins the shape of the cancellation error as a pure
// function: nil while live; otherwise the operation's sentinel AND the
// context's error, with a provider's own wrapping of that error preferred to
// the bare one, an unrelated provider error kept alongside, and a distinct
// cancellation cause kept too.
func TestContextFailure(t *testing.T) {
	if err := contextFailure(t.Context(), ErrSealFailed, nil); err != nil {
		t.Fatalf("contextFailure(live) = %v, want nil", err)
	}

	ctx, cancel := context.WithCancelCause(t.Context())
	why := errors.New("shutting down")
	cancel(why)

	wrapped := &providerWrapError{err: context.Canceled}
	unrelated := errors.New("tpm: resource manager busy")
	for name, tc := range map[string]struct {
		cause error
		want  []error
	}{
		"no provider error": {nil, []error{ErrOpenFailed, context.Canceled, why}},
		"provider wrapped":  {wrapped, []error{ErrOpenFailed, context.Canceled, why}},
		"provider other":    {unrelated, []error{ErrOpenFailed, context.Canceled, why, unrelated}},
	} {
		err := contextFailure(ctx, ErrOpenFailed, tc.cause)
		for _, w := range tc.want {
			if !errors.Is(err, w) {
				t.Errorf("%s: contextFailure = %v, does not match %v", name, err, w)
			}
		}
		var pw *providerWrapError
		if tc.cause == wrapped && !errors.As(err, &pw) {
			t.Errorf("%s: the provider's own wrapping was dropped: %v", name, err)
		}
	}

	// A plain cancellation has no distinct cause to add.
	plain, cancelPlain := context.WithCancel(t.Context())
	cancelPlain()
	if got := contextFailure(plain, ErrSealFailed, nil).Error(); got != errors.Join(ErrSealFailed, context.Canceled).Error() {
		t.Errorf("contextFailure(plain cancel) = %q, want only the sentinel and context.Canceled", got)
	}
}

// providerWrapError is a provider's own wrapping of a context error.
type providerWrapError struct{ err error }

func (e *providerWrapError) Error() string { return "device: call aborted: " + e.err.Error() }

func (e *providerWrapError) Unwrap() error { return e.err }

// TestProviderOpenFailure pins the open-side shaping: a verdict on the blob
// and this package's own sentinels pass through untouched, and an
// infrastructure failure is joined under ErrOpenFailed — reachable, and never
// readable as a forgery.
func TestProviderOpenFailure(t *testing.T) {
	if providerOpenFailure(nil) != nil {
		t.Error("providerOpenFailure(nil) is not nil")
	}
	for _, sentinel := range []error{ErrSealedAuthentication, ErrSealerWiped, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed} {
		if got := providerOpenFailure(sentinel); got != sentinel {
			t.Errorf("providerOpenFailure(%v) = %v, want it untouched", sentinel, got)
		}
	}
	down := errors.New("hsm: no session available")
	got := providerOpenFailure(down)
	if !errors.Is(got, ErrOpenFailed) || !errors.Is(got, down) || errors.Is(got, ErrSealedAuthentication) {
		t.Errorf("providerOpenFailure(infrastructure) = %v, want ErrOpenFailed joined with the cause, and not ErrSealedAuthentication", got)
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

// gatedRootUnsealer fills dst with a fixed byte once the test releases it.
// It allocates nothing, so an armed failNextLock is consumed by the sealer's
// own next mlock — the KEK mint — and not by the provider.
type gatedRootUnsealer struct {
	entered chan struct{}
	release chan struct{}
	after   func() // runs after a successful fill, before returning

	mu    sync.Mutex
	calls int
}

func (u *gatedRootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	if u.entered != nil {
		u.entered <- struct{}{}
		<-u.release
	}
	for i := range dst {
		dst[i] = 0x7E
	}
	if u.after != nil {
		u.after()
	}
	return nil
}

func (u *gatedRootUnsealer) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
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
	failNextLock(t) // the KEK mint is refused, if it is ever attempted
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
		failNextLock(t)
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
		t.Cleanup(func() { lockMemory = prev })
		lockMemory = func([]byte) error {
			lockMemory = prev
			sweep(t)
			return errors.New("mlock: cannot allocate memory")
		}
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
		failNextLock(t)
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

// TestNewSealed_EndedContextInstallsNothing pins that NewSealed with an ended
// context does not lazily install the software default, which would make the
// deployment's own SetSealer fail with ErrSealerInstalled.
func TestNewSealed_EndedContextInstallsNothing(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			freshProcessSealer(t)

			data := append([]byte(nil), sealedMaterial...)
			_, err := NewSealed(ec.ctx, data)
			requireSealCanceled(t, err, ec.want)
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("a refused NewSealed left the caller's material in place")
			}

			own, err := NewSealer(WithKeyProtector(newMapKeyProtector(t)))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			if err := SetSealer(own); err != nil {
				t.Fatalf("SetSealer after a refused NewSealed = %v: the refusal installed the default", err)
			}
		})
	}
}

// authThenCancelProtector refuses every Unprotect as a forgery and ends the
// caller's context before returning.
type authThenCancelProtector struct {
	inner  *SoftwareProvider
	cancel context.CancelFunc
}

func (p *authThenCancelProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *authThenCancelProtector) Unprotect(context.Context, []byte, []byte) error {
	p.cancel()
	return ErrSealedAuthentication
}

// TestSealer_AuthenticationVerdictSurvivesCancellation pins the documented
// precedence: an authentication failure the PROVIDER reported is a security
// signal and stays visible even when the caller's context ended before the
// post-call check — the error matches ErrSealedAuthentication AND the
// cancellation. Only a refusal the provider attributed to the context alone is
// kept clear of ErrSealedAuthentication.
func TestSealer_AuthenticationVerdictSurvivesCancellation(t *testing.T) {
	p := &authThenCancelProtector{inner: NewSoftwareProvider()}
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	ctx, cancel := context.WithCancel(t.Context())
	p.cancel = cancel
	e, err := v.Open(ctx)
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	for _, want := range []error{ErrSealedAuthentication, ErrOpenFailed, context.Canceled} {
		if !errors.Is(err, want) {
			t.Errorf("Open = %v, does not match %v", err, want)
		}
	}
}

// parkingProtector parks every Unprotect until the test hands it a verdict on
// the gate it publishes: nil to proceed, or an error to return instead.
type parkingProtector struct {
	inner    *SoftwareProvider
	arrivals chan chan error
}

func (p *parkingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *parkingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	gate := make(chan error)
	p.arrivals <- gate
	if err := <-gate; err != nil {
		return err
	}
	return p.inner.Unprotect(ctx, blob, key)
}

// TestSealedEnclave_OnlyTheLastOpenOutWipes parks two opens, runs Destroy,
// and releases them one at a time (the first succeeding, the second
// canceled): the envelope must survive the first exit and be wiped by the
// second.
func TestSealedEnclave_OnlyTheLastOpenOutWipes(t *testing.T) {
	p := &parkingProtector{inner: NewSoftwareProvider(), arrivals: make(chan chan error)}
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, blob := v.sealed, v.blob
	zero := func(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

	type result struct {
		e   *MemoryEnclave
		err error
	}
	firstOut, secondOut := make(chan result, 1), make(chan result, 1)
	secondCtx, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()

	go func() { e, err := v.Open(t.Context()); firstOut <- result{e, err} }()
	firstGate := <-p.arrivals
	go func() { e, err := v.Open(secondCtx); secondOut <- result{e, err} }()
	secondGate := <-p.arrivals

	v.Destroy()

	firstGate <- nil
	r := <-firstOut
	if r.err != nil {
		t.Fatalf("the first open in flight across Destroy: %v", r.err)
	}
	if !holds(r.e, sealedMaterial) {
		t.Error("the first open recovered the wrong material")
	}
	r.e.Destroy()
	if zero(sealed) || zero(blob) {
		t.Fatal("the first open out wiped the envelope while the second was still reading it")
	}

	cancelSecond()
	secondGate <- secondCtx.Err()
	r = <-secondOut
	requireOpenCanceled(t, r.e, r.err, context.Canceled)
	if !zero(sealed) || !zero(blob) {
		t.Error("the last open out — leaving through a cancellation — did not wipe the envelope")
	}
}

// errorThenCancelProtector returns a chosen error from Protect or Unprotect,
// a sentinel normally passed through untouched, and ends the caller's
// context before returning.
type errorThenCancelProtector struct {
	inner      *SoftwareProvider
	cancel     context.CancelFunc
	protectErr error
	openErr    error
}

func (p *errorThenCancelProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if p.protectErr == nil {
		return p.inner.Protect(ctx, key)
	}
	p.cancel()
	return nil, p.protectErr
}

func (p *errorThenCancelProtector) Unprotect(_ context.Context, _, _ []byte) error {
	p.cancel()
	return p.openErr
}

// TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds pins that a
// pass-through sentinel the provider returns (ErrSealerWiped,
// ErrLockedMemoryUnavailable, ErrProviderMessageLimit) is joined with the
// cancellation when the caller's context has ended by the time the provider
// returns: it matches the operation's sentinel, the context's error and the
// provider's sentinel.
func TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds(t *testing.T) {
	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable} {
		t.Run("open/"+sentinel.Error(), func(t *testing.T) {
			p := &errorThenCancelProtector{inner: NewSoftwareProvider()}
			s, err := NewSealer(WithKeyProtector(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			ctx, cancel := context.WithCancel(t.Context())
			p.cancel, p.openErr = cancel, sentinel
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
				t.Fatal("Open returned a destination alongside its error")
			}
			for _, want := range []error{sentinel, ErrOpenFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Open = %v, does not match %v", err, want)
				}
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open = %v reads as a forgery", err)
			}

			// Control: with a live context the same sentinel passes through
			// untouched — not joined under ErrOpenFailed.
			p.cancel = func() {}
			if _, err := v.Open(t.Context()); err != sentinel {
				t.Errorf("Open with a live context = %v, want %v untouched", err, sentinel)
			}
		})
	}

	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable, ErrProviderMessageLimit} {
		t.Run("seal/"+sentinel.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			p := &errorThenCancelProtector{inner: NewSoftwareProvider(), cancel: cancel, protectErr: sentinel}
			s, err := NewSealer(WithKeyProtector(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			_, err = s.Seal(ctx, append([]byte(nil), sealedMaterial...))
			for _, want := range []error{sentinel, ErrSealFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Seal = %v, does not match %v", err, want)
				}
			}

			p.cancel = func() {}
			if _, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...)); err != sentinel {
				t.Errorf("Seal with a live context = %v, want %v untouched", err, sentinel)
			}
		})
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

	prevUnmap := unmapMemory
	t.Cleanup(func() { unmapMemory = prevUnmap })
	unmapMemory = func([]byte) error { return errors.New("munmap: operation not permitted") }
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
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })

	var kekAt uintptr
	u.after = func() {
		// Runs inside UnsealRoot; the next mlock in this goroutine is the
		// KEK's, so arm the hook for it.
		lockMemory = func(b []byte) error {
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
			unmapMemory = func(m []byte) error {
				if regionContains(m, kekAt) {
					return errors.New("munmap: operation not permitted")
				}
				return prevUnmap(m)
			}
			return prevLock(b)
		}
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
