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
)

// mapKeyProtector is a working KeyProtector whose "device" is a plain map:
// Protect files a HEAP COPY of the key under a fresh opaque blob, Unprotect
// looks it up. Deliberately insecure — it exists to stand in for a hardware
// provider in tests, with two properties no real provider offers: its key
// store survives a WipeAll untouched (which is exactly what a device-held key
// does, and what the mode-asymmetry test needs), and the test can reach into
// it to mint alias blobs (which the envelope-binding test needs).
type mapKeyProtector struct {
	mu         sync.Mutex
	n          int
	keys       map[string][]byte
	protects   int
	unprotects int
}

func newMapKeyProtector() *mapKeyProtector {
	return &mapKeyProtector{keys: make(map[string][]byte)}
}

func (m *mapKeyProtector) Protect(key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	m.protects++
	blob := fmt.Appendf(nil, "map-key-protector-blob-%d", m.n)
	m.keys[string(blob)] = append([]byte(nil), key...)
	return blob, nil
}

func (m *mapKeyProtector) Unprotect(blob, key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unprotects++
	k, ok := m.keys[string(blob)]
	if !ok || len(k) != len(key) {
		return ErrSealedAuthentication
	}
	copy(key, k)
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

// alias registers a SECOND valid blob for the key already filed under
// existing, so a test can build an envelope whose blob authenticates and
// recovers the right DEK while differing from the blob the value was sealed
// with. That is the one configuration where the AAD binding — and nothing
// else — stands between a re-paired envelope and a successful Open.
func (m *mapKeyProtector) alias(existing, alias []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[string(existing)]
	if !ok {
		return false
	}
	m.keys[string(alias)] = append([]byte(nil), k...)
	return true
}

// fixedRootUnsealer is a RootUnsealer and nothing else: it fills dst with a
// fixed byte. It exists for the capability-mismatch checks and for proving a
// provider-supplied root actually reaches the hierarchy.
type fixedRootUnsealer struct{ fill byte }

func (f *fixedRootUnsealer) UnsealRoot(dst []byte) error {
	for i := range dst {
		dst[i] = f.fill
	}
	return nil
}

// erroringProvider fails every operation with its own error, standing in for
// a device that is present but unhealthy.
type erroringProvider struct{ err error }

func (e *erroringProvider) Protect([]byte) ([]byte, error) { return nil, e.err }
func (e *erroringProvider) Unprotect(_, _ []byte) error    { return e.err }
func (e *erroringProvider) UnsealRoot([]byte) error        { return e.err }

// emptyBlobProtector violates the Protect contract by returning an empty
// blob, so the sealer's guard against sealing an unrecoverable value is
// reachable.
type emptyBlobProtector struct{}

func (emptyBlobProtector) Protect([]byte) ([]byte, error) { return []byte{}, nil }
func (emptyBlobProtector) Unprotect(_, _ []byte) error    { return ErrSealedAuthentication }

// TestSealer_ModeProviderMismatchIsRefusedAtConstruction pins the reason the
// seam is two interfaces: a provider that cannot serve the selected mode is
// refused by NewSealer, so the misconfiguration dies at boot instead of at
// the first credential.
func TestSealer_ModeProviderMismatchIsRefusedAtConstruction(t *testing.T) {
	// A KeyProtector-only provider cannot serve ModeRootKey.
	if _, err := NewSealer(WithProvider(newMapKeyProtector()), WithMode(ModeRootKey)); !errors.Is(err, ErrProviderMode) {
		t.Errorf("NewSealer(KeyProtector-only, ModeRootKey) = %v, want ErrProviderMode", err)
	}
	// A RootUnsealer-only provider cannot serve ModePerOperation.
	if _, err := NewSealer(WithProvider(&fixedRootUnsealer{}), WithMode(ModePerOperation)); !errors.Is(err, ErrProviderMode) {
		t.Errorf("NewSealer(RootUnsealer-only, ModePerOperation) = %v, want ErrProviderMode", err)
	}
	// A mode that names nothing is invalid whatever the provider offers.
	if _, err := NewSealer(WithMode(Mode(99))); !errors.Is(err, ErrInvalidMode) {
		t.Errorf("NewSealer(Mode(99)) = %v, want ErrInvalidMode", err)
	}

	// Controls: each refused pairing succeeds the right way around, and the
	// dual-capability software provider serves both.
	if _, err := NewSealer(WithProvider(newMapKeyProtector()), WithMode(ModePerOperation)); err != nil {
		t.Errorf("NewSealer(KeyProtector, ModePerOperation): %v", err)
	}
	if _, err := NewSealer(WithProvider(&fixedRootUnsealer{fill: 0x42}), WithMode(ModeRootKey)); err != nil {
		t.Errorf("NewSealer(RootUnsealer, ModeRootKey): %v", err)
	}
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		s, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(m))
		if err != nil {
			t.Errorf("NewSealer(SoftwareProvider, %v): %v", m, err)
			continue
		}
		if s.Mode() != m {
			t.Errorf("Mode() = %v, want %v", s.Mode(), m)
		}
	}
}

// TestSealer_DefaultIsSoftwareRootKey pins the out-of-the-box shape: no
// options means the pure-software provider in ModeRootKey, and it round
// trips. The process default NewSealed installs must match, or a consumer
// that later configures a provider explicitly would be changing more than the
// provider.
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
	v, err := s.Seal(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	e, err := v.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()
	if !e.EqualTo(want) {
		t.Error("default sealer round trip returned the wrong material")
	}

	p, err := NewSealed(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer p.Destroy()
	if got := p.sealer.Mode(); got != ModeRootKey {
		t.Errorf("process default sealer mode = %v, want ModeRootKey", got)
	}
}

// TestSealer_PerOperationRoundTrip runs both modes against the software
// provider through an explicit Sealer, so mode parity is a tested property
// rather than an assumption. The per-operation path is the one the process
// default never exercises.
func TestSealer_PerOperationRoundTrip(t *testing.T) {
	for _, m := range []Mode{ModePerOperation, ModeRootKey} {
		t.Run(m.String(), func(t *testing.T) {
			s, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(m))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			want := []byte("mode-parity-material-for-" + m.String())
			v, err := s.Seal(append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()
			e, err := v.Open()
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer e.Destroy()
			if !e.EqualTo(want) {
				t.Error("round trip returned the wrong material")
			}
		})
	}
}

// TestSealer_RefusesForeignProvider pins the cross-provider property: a value
// sealed under one provider must not open under another, in either mode. The
// envelope is rebuilt against the second sealer directly — in normal use
// there is no path by which a value reaches a foreign sealer, which is
// exactly why the property has to be tested by constructing the misuse.
func TestSealer_RefusesForeignProvider(t *testing.T) {
	build := func(t *testing.T, m Mode) (*Sealer, *Sealer) {
		t.Helper()
		a, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(m))
		if err != nil {
			t.Fatalf("NewSealer A: %v", err)
		}
		b, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(m))
		if err != nil {
			t.Fatalf("NewSealer B: %v", err)
		}
		return a, b
	}

	for _, m := range []Mode{ModePerOperation, ModeRootKey} {
		t.Run(m.String(), func(t *testing.T) {
			a, b := build(t, m)

			want := []byte("cross-provider-material")
			v, err := a.Seal(append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			// Ensure B has a live hierarchy/root of its own, so the refusal
			// below is a key mismatch and not merely "B never sealed
			// anything" — the stricter of the two conditions.
			warm, err := b.Seal([]byte("warm-up"))
			if err != nil {
				t.Fatalf("warm-up Seal: %v", err)
			}
			defer warm.Destroy()

			foreign := &SealedEnclave{sealer: b, sealed: v.sealed, blob: v.blob, size: v.size}
			if e, err := foreign.Open(); !errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open under a foreign provider = %v, want ErrSealedAuthentication", err)
				if e != nil {
					e.Destroy()
				}
			}

			// Control: the same envelope opens under its own sealer.
			e, err := v.Open()
			if err != nil {
				t.Fatalf("Open under the sealing provider: %v", err)
			}
			if !e.EqualTo(want) {
				t.Error("control open returned the wrong material")
			}
			e.Destroy()
		})
	}
}

// TestSealer_EnvelopeBindsBlobToCiphertext pins the AAD binding END TO END,
// in the one configuration where nothing else would catch a re-paired
// envelope.
//
// Ordinarily a substituted blob dies twice — the DEK unwrap refuses the
// foreign blob, and even a recovered wrong DEK fails the bulk tag — so a
// mutant that drops the AAD binding passes every ordinary test. This test
// removes both other defenses ON THE PROVIDER SIDE, legitimately: the map
// provider files an ALIAS blob that authenticates and recovers the exact DEK
// the value was sealed with. The envelope then differs from the sealed one in
// exactly one way — the blob is not the bytes the ciphertext was bound to —
// and Open must still refuse. Drop the AAD from either half of the envelope
// construction and this opens successfully; that is the mutation this test
// exists to catch.
func TestSealer_EnvelopeBindsBlobToCiphertext(t *testing.T) {
	kp := newMapKeyProtector()
	s, err := NewSealer(WithProvider(kp), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	want := []byte("blob-binding-material")
	v, err := s.Seal(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	aliasBlob := []byte("map-key-protector-alias-blob")
	if !kp.alias(v.blob, aliasBlob) {
		t.Fatal("could not alias the sealed value's blob; the fake provider does not hold it")
	}

	// Sanity of the setup, not of the code under test: the alias must
	// actually recover the same DEK, or the refusal below would be a key
	// mismatch and the test would pass with the AAD binding deleted.
	dekA := make([]byte, dekBytes)
	dekB := make([]byte, dekBytes)
	if err := kp.Unprotect(v.blob, dekA); err != nil {
		t.Fatalf("Unprotect(original): %v", err)
	}
	if err := kp.Unprotect(aliasBlob, dekB); err != nil {
		t.Fatalf("Unprotect(alias): %v", err)
	}
	if !bytes.Equal(dekA, dekB) {
		t.Fatal("the alias blob recovers a different DEK; the test setup is broken")
	}

	repaired := &SealedEnclave{sealer: s, sealed: v.sealed, blob: aliasBlob, size: v.size}
	if e, err := repaired.Open(); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open with a re-paired (valid, same-DEK) blob = %v, want ErrSealedAuthentication: "+
			"the ciphertext is not bound to the exact blob it was sealed with", err)
		if e != nil {
			e.Destroy()
		}
	}

	// Control: untouched, the value opens.
	e, err := v.Open()
	if err != nil {
		t.Fatalf("control Open: %v", err)
	}
	if !e.EqualTo(want) {
		t.Error("control open returned the wrong material")
	}
	e.Destroy()
}

// TestSealer_KEKRotatesAtTheMessageLimit covers the bound crypto/cipher
// states as a MUST NOT: "A given key MUST NOT be used to encrypt more than
// 2^32 messages." In ModeRootKey the KEK is the one key that approaches it —
// it wraps one DEK per sealed value — so the rotation machinery lives on the
// KEK and nowhere else.
//
// The counter is driven directly rather than by performing two billion
// seals. That is reading and writing this package's own state from an
// in-package test, not a fault-injection seam in production code: kekUsed has
// to exist for the limit to work at all.
//
// The second half is the half that matters. Rotation is only correct if a
// value sealed under the RETIRED generation still opens — otherwise the bound
// would be enforced by silently destroying every credential in flight — and
// if the retired generation's LIVE enclave is destroyed, since retention as a
// root-wrapped heap blob rather than a locked page is the design's stated
// cost model.
func TestSealer_KEKRotatesAtTheMessageLimit(t *testing.T) {
	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	older := []byte("sealed-under-the-generation-about-to-be-retired")
	before, err := s.Seal(append([]byte(nil), older...))
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

	atLimit, err := s.Seal(append([]byte(nil), older...))
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

	after, err := s.Seal(append([]byte(nil), older...))
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
		e, err := v.Open()
		if err != nil {
			t.Fatalf("%s: Open after rotation: %v", name, err)
		}
		if !e.EqualTo(older) {
			t.Errorf("%s: opened to the wrong material after rotation", name)
		}
		e.Destroy()
	}

	// And the new generation round-trips too.
	e, err := after.Open()
	if err != nil {
		t.Fatalf("Open under the new generation: %v", err)
	}
	if !e.EqualTo(older) {
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
	warm, err := s.Seal([]byte("warm-up"))
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
				v, err := s.Seal(fmt.Appendf(nil, "concurrent-rotation-%d-%d", g, i))
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
			e, err := v.Open()
			if err != nil {
				t.Fatalf("Open(%d,%d): %v", g, i, err)
			}
			if !e.EqualTo(fmt.Appendf(nil, "concurrent-rotation-%d-%d", g, i)) {
				t.Errorf("value (%d,%d) opened to the wrong material", g, i)
			}
			e.Destroy()
			v.Destroy()
		}
	}
}

// TestSealer_ProviderRootReachesTheHierarchy proves the injected provider's
// root is what the hierarchy actually runs on, rather than the sealer quietly
// generating its own: a KEK blob minted by a sealer over a deterministic
// RootUnsealer unwraps under a root built independently from that provider's
// known output — and does not unwrap under any other root, and does not
// unwrap with its generation frame rewritten, which pins the KEK blob's AAD
// binding at the same time.
func TestSealer_ProviderRootReachesTheHierarchy(t *testing.T) {
	s, err := NewSealer(WithProvider(&fixedRootUnsealer{fill: 0x5A}), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal([]byte("initialize-the-hierarchy")); err != nil {
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

	kek := make([]byte, kekBytes)

	// The provider's known root unwraps the sealer's KEK blob: the hierarchy
	// is keyed by what UnsealRoot supplied, not by anything self-minted.
	providerRoot := buildRoot(0x5A)
	defer providerRoot.Destroy()
	if err := openWithKeyInto(providerRoot, kekBlob[blobHeaderLen:], kekBlob[:blobHeaderLen], kek); err != nil {
		t.Fatalf("the provider-supplied root does not unwrap the sealer's KEK blob (%v): "+
			"the hierarchy is not keyed by the injected provider's root", err)
	}

	// A different root does not — so the success above was the root's doing.
	otherRoot := buildRoot(0x00)
	defer otherRoot.Destroy()
	if err := openWithKeyInto(otherRoot, kekBlob[blobHeaderLen:], kekBlob[:blobHeaderLen], kek); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("a different root unwrapped the KEK blob (%v); the wrap is not bound to the provider root", err)
	}

	// And the KEK blob is bound to its generation frame: the right root with
	// a rewritten frame is refused, which is what stops a retired blob being
	// refiled under another generation.
	rewritten := blobHeader(blobKindKEK, 7)
	if err := openWithKeyInto(providerRoot, kekBlob[blobHeaderLen:], rewritten, kek); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("a generation-rewritten frame still unwrapped the KEK blob (%v); the frame is not bound as AAD", err)
	}
}

// TestSealer_WipedFailsClosedPerMode pins #22 §14's mode asymmetry around a
// shutdown sweep, explicitly, because it is exactly the sort of thing a
// reader will assume away:
//
//   - ModeRootKey: the hierarchy's enclaves are swept; the sealer reports
//     ErrSealerWiped for both new seals and existing values, and never
//     re-keys.
//   - ModePerOperation over an in-process software provider: same, from the
//     provider's side.
//   - ModePerOperation over a device-held key (the map provider): a sweep
//     destroys nothing the values depend on — sealing and opening keep
//     working. The sweep is a statement about this process's memory, and in
//     this mode the material never depended on it.
func TestSealer_WipedFailsClosedPerMode(t *testing.T) {
	material := []byte("mode-asymmetry-material")

	t.Run("ModeRootKey", func(t *testing.T) {
		s, err := NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.Seal(append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped: the sealer must fail closed, never re-key", err)
		}
	})

	t.Run("ModePerOperation_software", func(t *testing.T) {
		s, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(ModePerOperation))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.Seal(append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped", err)
		}
	})

	t.Run("ModePerOperation_deviceHeld", func(t *testing.T) {
		s, err := NewSealer(WithProvider(newMapKeyProtector()), WithMode(ModePerOperation))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		// The device still holds the keys: existing values open and new
		// seals work. This is the asymmetry, and it is the correct behavior,
		// not a hole — nothing in this process's memory protected the DEKs.
		e, err := v.Open()
		if err != nil {
			t.Fatalf("Open after sweep with a device-held key = %v; "+
				"a sweep must not invalidate values whose keys the process never held", err)
		}
		if !e.EqualTo(material) {
			t.Error("post-sweep open returned the wrong material")
		}
		e.Destroy()

		fresh, err := s.Seal(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal after sweep with a device-held key: %v", err)
		}
		fresh.Destroy()
	})
}

// TestSealer_ProviderErrorsSurfaceHonestly pins the error-shaping contract on
// both paths: a provider's own failure must NOT be dressed as an
// authentication failure on open — the misattribution #22 §14 warns about,
// aimed at providers this time — and must surface under ErrSealFailed on
// seal, where "could not seal" is the honest summary, with the cause still
// reachable.
func TestSealer_ProviderErrorsSurfaceHonestly(t *testing.T) {
	deviceDown := errors.New("device unreachable: session pool exhausted")
	s, err := NewSealer(WithProvider(&erroringProvider{err: deviceDown}), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal([]byte("provider-error-material"))
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
	// fails with its own error. The sealer must pass it through untouched.
	kp := newMapKeyProtector()
	healthy, err := NewSealer(WithProvider(kp), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := healthy.Seal([]byte("provider-error-material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	v.sealer = s // the erroring provider now answers this value's opens
	_, err = v.Open()
	if !errors.Is(err, deviceDown) {
		t.Errorf("Open with a failing provider = %v, want the provider's own error to surface", err)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open error %v reads as an authentication failure; an operator would hunt an attacker who does not exist", err)
	}
	v.sealer = healthy

	// A provider returning an empty blob is a contract violation caught at
	// seal time, not at the first failed open months later.
	eb, err := NewSealer(WithProvider(emptyBlobProtector{}), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := eb.Seal([]byte("empty-blob-material")); !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with an empty-blob provider = %v, want ErrSealFailed", err)
	}
}

// TestSealer_SetSealerIsOneShot pins the installation contract from #21
// §11.4, carried into #22 §8: one installer, first write wins, the lazy
// default counts as a write, and the routing actually changes — proven by
// counting the installed provider's operations rather than inferring.
func TestSealer_SetSealerIsOneShot(t *testing.T) {
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)

	if err := SetSealer(nil); !errors.Is(err, ErrNilSealer) {
		t.Errorf("SetSealer(nil) = %v, want ErrNilSealer", err)
	}

	kp := newMapKeyProtector()
	own, err := NewSealer(WithProvider(kp), WithMode(ModePerOperation))
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
	v, err := NewSealed([]byte("routed-material"))
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
	if _, err := NewSealed([]byte("stray-early-seal")); err != nil {
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
	if _, err := s.Seal(data); !errors.Is(err, ErrNilSealer) {
		t.Errorf("nil Sealer.Seal = %v, want ErrNilSealer", err)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("data[%d] = %#x after a refused Seal; the ownership contract wipes on every path", i, b)
		}
	}
}

// TestSealer_ModeString covers the diagnostic surface, including the value
// ErrInvalidMode refuses, so a log line during that refusal names the number
// rather than printing garbage.
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
	blob, err := p.Protect(append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	got := make([]byte, len(key))
	if err := p.Unprotect(blob, got); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("Unprotect recovered the wrong key")
	}

	// Foreign: a blob from a different provider instance must be refused.
	other := NewSoftwareProvider()
	otherBlob, err := other.Protect(append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect (other): %v", err)
	}
	if err := p.Unprotect(otherBlob, got); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect(foreign blob) = %v, want ErrSealedAuthentication", err)
	}

	// A provider that has protected nothing owns no blobs at all.
	if err := NewSoftwareProvider().Unprotect(blob, got); !errors.Is(err, ErrSealedAuthentication) {
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
		if err := p.Unprotect(corrupt(blob), got); !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("Unprotect(%s) = %v, want ErrSealedAuthentication", name, err)
		}
	}

	// Wrong destination length is an authentication failure, decided before
	// anything is decrypted — the same no-reallocation rule as everywhere.
	if err := p.Unprotect(blob, make([]byte, 16)); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Unprotect into a short destination = %v, want ErrSealedAuthentication", err)
	}

	// Control after all the refusals: the original still unprotects.
	if err := p.Unprotect(blob, got); err != nil {
		t.Fatalf("control Unprotect: %v", err)
	}
}

// TestSoftwareProvider_MessageLimit pins the provider's refusal at its
// per-key encryption budget — the alternative to rotation machinery it
// deliberately does not have; see ErrProviderMessageLimit for why. The
// counter is driven directly, exactly as the KEK rotation test drives its
// own.
func TestSoftwareProvider_MessageLimit(t *testing.T) {
	p := NewSoftwareProvider()
	key := make([]byte, RootKeyBytes)

	blob, err := p.Protect(append([]byte(nil), key...))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	p.mu.Lock()
	p.protects = softwareProtectLimit
	p.mu.Unlock()

	if _, err := p.Protect(append([]byte(nil), key...)); !errors.Is(err, ErrProviderMessageLimit) {
		t.Errorf("Protect at the limit = %v, want ErrProviderMessageLimit", err)
	}

	// The refusal is on ENCRYPTION only: existing blobs still unprotect,
	// because the bound protects nonce uniqueness, not decryption.
	got := make([]byte, len(key))
	if err := p.Unprotect(blob, got); err != nil {
		t.Errorf("Unprotect past the Protect limit = %v; the bound must not strand existing blobs", err)
	}
}

// TestSoftwareProvider_UnsealRoot covers the RootUnsealer half: the size
// contract, and determinism across calls — two sealers over one provider
// must receive the same root, or "the provider's root" would not be a
// meaningful phrase.
func TestSoftwareProvider_UnsealRoot(t *testing.T) {
	p := NewSoftwareProvider()

	if err := p.UnsealRoot(make([]byte, RootKeyBytes-1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(short dst) = %v, want ErrInvalidSize", err)
	}
	if err := p.UnsealRoot(make([]byte, RootKeyBytes+1)); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("UnsealRoot(long dst) = %v, want ErrInvalidSize", err)
	}

	a := make([]byte, RootKeyBytes)
	b := make([]byte, RootKeyBytes)
	if err := p.UnsealRoot(a); err != nil {
		t.Fatalf("UnsealRoot: %v", err)
	}
	if err := p.UnsealRoot(b); err != nil {
		t.Fatalf("UnsealRoot: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two UnsealRoot calls yielded different roots")
	}
	if bytes.Equal(a, make([]byte, RootKeyBytes)) {
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

func (f *flakyRootUnsealer) UnsealRoot(dst []byte) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("transient: device busy")
	}
	return f.inner.UnsealRoot(dst)
}

// TestSealer_RootUnsealFailureSurfacesAndRetries covers ModeRootKey against
// an unhealthy provider: the first seal fails with the provider's cause
// preserved under ErrSealFailed — and, the half that matters, the NEXT seal
// retries the unseal rather than replaying a memoized failure. A sync.Once
// here would turn one busy device into a sealer that never works; see
// initHierarchy for the design note this pins.
func TestSealer_RootUnsealFailureSurfacesAndRetries(t *testing.T) {
	flaky := &flakyRootUnsealer{failures: 1, inner: fixedRootUnsealer{fill: 0x33}}
	s, err := NewSealer(WithProvider(flaky), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.Seal([]byte("first-attempt"))
	if !errors.Is(err, ErrSealFailed) {
		t.Fatalf("Seal with a failing UnsealRoot = %v, want ErrSealFailed", err)
	}
	if err == nil || !strings.Contains(err.Error(), "device busy") {
		t.Errorf("Seal error %v does not preserve the provider's cause", err)
	}

	// The retry: same sealer, provider now healthy, and the hierarchy
	// initializes as if the failure never happened.
	want := []byte("second-attempt-material")
	v, err := s.Seal(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal after a transient unseal failure = %v; the failure was memoized", err)
	}
	defer v.Destroy()
	e, err := v.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !e.EqualTo(want) {
		t.Error("round trip after the retry returned the wrong material")
	}
	e.Destroy()
	if flaky.calls != 2 {
		t.Errorf("UnsealRoot was called %d times, want 2 (one failure, one retry)", flaky.calls)
	}

	// A permanently failing provider fails every seal, typed, with no panic
	// and no fallback root.
	dead, err := NewSealer(WithProvider(&erroringProvider{err: errors.New("device gone")}), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := dead.Seal([]byte("never")); !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with a dead RootUnsealer = %v, want ErrSealFailed", err)
	}
}

// TestSealer_SweptTranslation pins the two translation helpers directly.
// They exist for a race window — a WipeAll destroying hierarchy or provider
// keys between an op's liveness check and its borrow — that no unit test can
// hold open deterministically, so the translation itself is pinned as a pure
// function: a destroyed hierarchy key reports the sealer wiped, and every
// other error passes through untouched.
func TestSealer_SweptTranslation(t *testing.T) {
	other := errors.New("unrelated failure")
	for name, fn := range map[string]func(error) error{"swept": swept, "hierarchyFailure": hierarchyFailure} {
		if got := fn(ErrEnclaveDestroyed); !errors.Is(got, ErrSealerWiped) {
			t.Errorf("%s(ErrEnclaveDestroyed) = %v, want ErrSealerWiped: a mid-operation sweep would "+
				"surface as a destroyed enclave the caller never created", name, got)
		}
		if got := fn(other); !errors.Is(got, other) || errors.Is(got, ErrSealerWiped) {
			t.Errorf("%s(unrelated) = %v, want it untouched", name, got)
		}
		if got := fn(ErrSealedAuthentication); !errors.Is(got, ErrSealedAuthentication) {
			t.Errorf("%s must not rewrite authentication failures; got %v", name, got)
		}
	}
}

// TestSealer_WipedDoesNotReconsultAWillingProvider is the sealer-level half
// of the fail-closed ruling, and it exists because mutation testing showed
// the other post-sweep tests do not pin it: with the SOFTWARE provider, a
// sealer that wrongly re-initialized after a sweep would still fail — the
// provider itself refuses — so a regeneration mutant in the SEALER survived
// every test. The masking is defense in depth working, but the ruling is on
// the sealer: it must not re-key even when its provider WOULD cheerfully
// re-supply a root, because with a hardware RootUnsealer that re-supply is
// exactly what turns a sweep into silently re-minted keys. So the provider
// here is one that always answers, and the refusal below can only come from
// the sealer.
func TestSealer_WipedDoesNotReconsultAWillingProvider(t *testing.T) {
	willing := &flakyRootUnsealer{failures: 0, inner: fixedRootUnsealer{fill: 0x66}}
	s, err := NewSealer(WithProvider(willing), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	if willing.calls != 1 {
		t.Fatalf("UnsealRoot called %d times before the sweep, want 1", willing.calls)
	}

	sweep(t)

	if _, err := s.Seal(append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Seal after sweep = %v, want ErrSealerWiped", err)
	}
	if _, err := v.Open(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
	}
	// The sharpest assertion: the provider was never asked again. A sealer
	// that consults it here has decided to re-key and merely happens to be
	// interruptible; the ruling is that the decision itself is never made.
	if willing.calls != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: the sealer reconsulted its provider after a sweep", willing.calls)
	}
}

// TestSealer_NilProvidersAreRefusedAtConstruction pins the typed-nil trap
// found by review on PR #45: (*SoftwareProvider)(nil) is a NON-nil interface
// that satisfies both seam type assertions, so without a value-level check
// NewSealer succeeded and the first Seal panicked dereferencing the
// provider — a panic where a typed construction error belongs, in a library
// that fails closed. Untyped nil is refused too rather than defaulted:
// WithProvider(nil) is a lost configuration step, and silently substituting
// the software provider for the hardware one somebody meant to pass is the
// fail-open this constructor exists to prevent.
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
				s, err := NewSealer(WithProvider(p), WithMode(m))
				if !errors.Is(err, ErrProviderMode) {
					t.Errorf("NewSealer(%s, %v) = %v, want ErrProviderMode", name, m, err)
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
	if _, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(ModeRootKey)); err != nil {
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

func (c *countingRootUnsealer) UnsealRoot(dst []byte) error {
	c.calls++
	if err := c.inner.UnsealRoot(dst); err != nil {
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

// TestSealer_KEKFailureDoesNotReunsealTheRoot is the regression for the
// root-unseal finding in #83.
//
// initHierarchy unsealed the root, then minted the first KEK; when the MINT
// failed — memlock exhausted, the case the retry exists for — it destroyed the
// successfully unsealed root, and the next seal called UnsealRoot AGAIN. The
// RootUnsealer contract says a Sealer calls it at most once, retrying only if
// that call failed, and a one-shot root provider (a consumed unseal handle;
// providertest's Config.SingleUseRoot) cannot answer twice. The retry must
// re-attempt only the step that failed.
func TestSealer_KEKFailureDoesNotReunsealTheRoot(t *testing.T) {
	ru := &countingRootUnsealer{inner: fixedRootUnsealer{fill: 0x5A}}
	// The root's pages are already locked when UnsealRoot runs, so the next
	// mlock in this goroutine is the first KEK's.
	ru.after = func() {
		if ru.calls == 1 {
			failNextLock(t)
		}
	}
	s, err := NewSealer(WithProvider(ru), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	if _, err := s.Seal([]byte("first attempt")); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the KEK mint refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if ru.calls != 1 {
		t.Fatalf("UnsealRoot was called %d times by the first seal, want 1", ru.calls)
	}
	if err := s.hierarchyOpenable(); err != nil {
		t.Errorf("hierarchyOpenable = %v after a failed mint; nothing was sealed, so nothing was wiped", err)
	}

	want := []byte("second attempt")
	v, err := s.Seal(append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal after the mint failure = %v", err)
	}
	defer v.Destroy()
	if ru.calls != 1 {
		t.Fatalf("UnsealRoot was called %d times, want 1: a successful unseal was retried "+
			"because the KEK mint after it failed", ru.calls)
	}

	e, err := v.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()
	if !e.EqualTo(want) {
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
	s, err := NewSealer(WithProvider(ru), WithMode(ModeRootKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Seal([]byte("first attempt")); !errors.Is(err, ErrLockedMemoryUnavailable) {
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

	if _, err := s.Seal([]byte("after the sweep")); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Seal after the sweep = %v, want ErrSealerWiped", err)
	}
	if ru.calls != 1 {
		t.Errorf("UnsealRoot was called %d times, want 1: a swept root was re-unsealed", ru.calls)
	}
}
