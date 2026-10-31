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
	"reflect"
	"testing"
	"time"
)

// requireCapability fails t unless err is a *CapabilityError naming backend
// and capability.
func requireCapability(t *testing.T, err error, backend string, capability Capability) {
	t.Helper()
	var ce *CapabilityError
	if !errors.As(err, &ce) || !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err = %v, want a *CapabilityError naming %q", err, capability)
	}
	if ce.Backend != backend || ce.Capability != capability {
		t.Fatalf("CapabilityError{%q, %q}, want {%q, %q}", ce.Backend, ce.Capability, backend, capability)
	}
}

// TestNewSealed_RefusesAFrozenView reproduces the crash B1 fixes: sealing a
// view into a frozen enclave from inside its WithBytes wiped the view, and the
// write to the read-only page killed the process.
func TestNewSealed_RefusesAFrozenView(t *testing.T) {
	freshProcessSealer(t)
	ctx := t.Context()
	material := []byte("frozen-view-material")

	v, err := newSealed(ctx, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer v.Destroy()
	opened, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.Destroy()

	err = opened.WithBytes(func(b []byte) error {
		_, err := newSealed(ctx, b)
		return err
	})
	if !errors.Is(err, ErrSealSourceReadOnly) {
		t.Fatalf("NewSealed over a frozen view = %v, want ErrSealSourceReadOnly", err)
	}

	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()
	err = opened.WithBytes(func(b []byte) error {
		_, err := s.sealData(ctx, b)
		return err
	})
	if !errors.Is(err, ErrSealSourceReadOnly) {
		t.Fatalf("Seal over a frozen view = %v, want ErrSealSourceReadOnly", err)
	}
	if !holds(opened, material) {
		t.Fatal("a refused seal changed the frozen source")
	}

	// A writable source is still sealed and wiped.
	data := append([]byte(nil), material...)
	w, err := s.sealData(ctx, data)
	if err != nil {
		t.Fatalf("Seal over writable data: %v", err)
	}
	defer w.Destroy()
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("Seal left writable data unwiped")
	}
}

// TestSealFrom_LeavesTheSourceIntact pins SealFrom and NewSealedFrom: they
// read a frozen source under its own borrow and neither wipe nor destroy it.
func TestSealFrom_LeavesTheSourceIntact(t *testing.T) {
	freshProcessSealer(t)
	ctx := t.Context()
	material := []byte("seal-from-material")

	src, err := newMemoryCopy(material)
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer src.Destroy()

	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()

	for name, seal := range map[string]func() (*sealedValue, error){
		"SealFrom":      func() (*sealedValue, error) { return s.sealFromHandle(ctx, src) },
		"NewSealedFrom": func() (*sealedValue, error) { return newSealedFrom(ctx, src) },
	} {
		v, err := seal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !holds(src, material) {
			t.Fatalf("%s changed its source", name)
		}
		e, err := v.Open(ctx)
		if err != nil {
			t.Fatalf("Open of the %s value: %v", name, err)
		}
		if !holds(e, material) {
			t.Fatalf("the %s value opened to the wrong material", name)
		}
		_ = e.Destroy()
		_ = v.Destroy()
	}
}

// TestSealFrom_Refusals pins SealFrom's argument checks.
func TestSealFrom_Refusals(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()

	if _, err := (*envelopeSealer)(nil).sealFromHandle(ctx, nil); !errors.Is(err, ErrNilSealer) {
		t.Errorf("nil Sealer: %v, want ErrNilSealer", err)
	}
	if _, err := s.sealFromHandle(ctx, nil); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("nil source: %v, want ErrEnclaveDestroyed", err)
	}
	if _, err := s.sealFromHandle(ctx, (*lockedRegion)(nil)); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("typed-nil source: %v, want ErrEnclaveDestroyed", err)
	}
	dead, err := newMemoryCopy([]byte("dead"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	_ = dead.Destroy()
	if _, err := s.sealFromHandle(ctx, dead); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("destroyed source: %v, want ErrEnclaveDestroyed", err)
	}

	m, err := newMemoryCopy([]byte("device-only-material"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer m.Destroy()
	_, err = s.sealFromHandle(ctx, &opaqueHandle{m: m, b: &fakeImporter{}})
	requireCapability(t, err, fakeImporterName, CapabilityBytes)
}

// copyOf returns a shallow copy of *p, made through reflect so vet's
// copylocks check does not refuse the test.
func copyOf[T any](p *T) *T {
	c := reflect.New(reflect.TypeFor[T]())
	c.Elem().Set(reflect.ValueOf(p).Elem())
	return c.Interface().(*T)
}

// TestSealer_CopiesShareState pins B3 for Sealer: a copy is the same sealer,
// so destroying it destroys the original.
func TestSealer_CopiesShareState(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	c := copyOf(s)

	v, err := c.sealData(ctx, []byte("sealed-by-the-copy"))
	if err != nil {
		t.Fatalf("Seal through the copy: %v", err)
	}
	defer v.Destroy()
	if err := c.Destroy(); err != nil {
		t.Fatalf("Destroy through the copy: %v", err)
	}
	if _, err := s.sealData(ctx, []byte("after")); !errors.Is(err, ErrSealerDestroyed) {
		t.Fatalf("Seal through the original after the copy's Destroy = %v, want ErrSealerDestroyed", err)
	}
}

// TestSealed_CopiesShareState pins B3 for Sealed: a copy is the same value,
// so destroying it destroys the original.
func TestSealed_CopiesShareState(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()
	v, err := s.sealData(ctx, []byte("copied-value"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	c := copyOf(v)
	if err := c.Destroy(); err != nil {
		t.Fatalf("Destroy through the copy: %v", err)
	}
	if v.IsAlive() {
		t.Fatal("the original is alive after its copy was destroyed")
	}
	if _, err := v.Open(ctx); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Fatalf("Open of the original = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestSealer_StrictModeRefusesAnExposedKeySchedule pins B4: under
// WithRequireKeyScheduleErasure, NewSealer refuses a configuration that
// leaves a key schedule on the heap and names the first exposed class.
func TestSealer_StrictModeRefusesAnExposedKeySchedule(t *testing.T) {
	swapSeam(t, &erasesKeySchedules, false)
	kp := newMapKeyProtector(t)

	for _, tc := range []struct {
		name string
		opts []SealerOption
		want string // the class named, or "" for accepted
	}{
		{"root key in locked memory", nil, "wrapping-key"},
		{"root key on the default backend", []SealerOption{WithBackend(DefaultBackend())}, "wrapping-key"},
		{"per operation", []SealerOption{WithKeyProtector(kp)}, "dek"},
		// Offload alone never satisfies the option: DEKs stay in-process.
		{"offloaded keys", []SealerOption{WithBackend(&fakeImporter{keys: importAEAD})}, "dek"},
		{"non-confining backend", []SealerOption{WithKeyProtector(kp), WithBackend(&fakeImporter{})}, "dek"},
		{"confining backend", []SealerOption{WithBackend(&fakeImporter{confines: true})}, ""},
		{"confining backend, per operation", []SealerOption{WithKeyProtector(kp), WithBackend(&fakeImporter{confines: true})}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newEnvelopeSealer(append(tc.opts, WithRequireKeyScheduleErasure())...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("NewSealer: %v, want accepted", err)
				}
				_ = s.Destroy()
				return
			}
			var exposed *KeyScheduleExposedError
			if !errors.As(err, &exposed) || !errors.Is(err, ErrKeyScheduleExposed) {
				t.Fatalf("NewSealer = %v, want a *KeyScheduleExposedError", err)
			}
			if exposed.Name != tc.want {
				t.Fatalf("exposed class %q, want %q", exposed.Name, tc.want)
			}
			// Without the option the same configuration is accepted.
			s, err = newEnvelopeSealer(tc.opts...)
			if err != nil {
				t.Fatalf("NewSealer without strict mode: %v", err)
			}
			_ = s.Destroy()
		})
	}

	// A build that erases covers every class.
	swapSeam(t, &erasesKeySchedules, true)
	s, err := newEnvelopeSealer(WithRequireKeyScheduleErasure())
	if err != nil {
		t.Fatalf("NewSealer on an erasing build: %v", err)
	}
	_ = s.Destroy()
}

// TestSealer_RetiredGenerationsAreDropped pins M2: a retired KEK generation
// is dropped with its last value, so seal-and-destroy under rotation keeps
// kekBlobs bounded.
func TestSealer_RetiredGenerationsAreDropped(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer(WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()

	retained := func() (blobs, refs int, gen uint32) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.kekBlobs), len(s.kekRefs), s.kekGen
	}

	const n = 64
	for i := range n {
		v, err := s.sealData(ctx, fmt.Appendf(nil, "value-%02d", i))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		if err := v.Destroy(); err != nil {
			t.Fatalf("Destroy %d: %v", i, err)
		}
	}
	blobs, refs, gen := retained()
	if gen < n {
		t.Fatalf("generation %d after %d seals at one wrap each: the sealer did not rotate", gen, n)
	}
	if blobs != 1 || refs != 1 {
		t.Fatalf("%d seals and destroys left %d KEK blobs and %d counters, want 1 and 1", n, blobs, refs)
	}

	// Live values keep their generations, and each goes with its last value.
	var live []*sealedValue
	for i := range 4 {
		v, err := s.sealData(ctx, fmt.Appendf(nil, "live-%d", i))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		live = append(live, v)
	}
	if blobs, _, _ := retained(); blobs != 4 {
		t.Fatalf("%d KEK blobs for 4 live values in 4 generations, want 4", blobs)
	}
	for i, v := range live {
		e, err := v.Open(ctx)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		_ = e.Destroy()
		_ = v.Destroy()
	}
	if blobs, _, _ := retained(); blobs != 1 {
		t.Fatalf("%d KEK blobs once every live value is gone, want 1 (the current generation)", blobs)
	}
}

// TestSealer_AnOpenInFlightKeepsItsGeneration pins M2's other half: a value
// destroyed while an open is in flight keeps its generation until the open
// ends.
func TestSealer_AnOpenInFlightKeepsItsGeneration(t *testing.T) {
	ctx := t.Context()
	material := []byte("open-in-flight")
	s, err := newEnvelopeSealer(WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()

	v, err := s.sealData(ctx, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealer, blob, sealed, size, ok := v.pin()
	if !ok {
		t.Fatal("pin refused a live value")
	}
	if err := v.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	// Rotate past the value's generation.
	w, err := s.sealData(ctx, []byte("rotates"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer w.Destroy()

	e, err := sealer.open(ctx, v.version, blob, sealed, size, newMemorySized, true)
	if err != nil {
		t.Fatalf("the open in flight lost its generation to the value's Destroy: %v", err)
	}
	if !holds(e, material) {
		t.Fatal("the open in flight recovered the wrong material")
	}
	_ = e.Destroy()

	v.unpin(sealer, blob, sealed)
	s.mu.RLock()
	blobs := len(s.kekBlobs)
	s.mu.RUnlock()
	if blobs != 1 {
		t.Fatalf("%d KEK blobs after the last open of a destroyed value ended, want 1", blobs)
	}
}

// TestSetSealer_RefusesAnUnusableSealer pins L3: SetSealer refuses a zero
// Sealer and a destroyed one, and either refusal leaves the slot free.
func TestSetSealer_RefusesAnUnusableSealer(t *testing.T) {
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)

	if err := SetSealer(&envelopeSealer{}); !errors.Is(err, ErrSealerNotConstructed) {
		t.Errorf("SetSealer(&envelopeSealer{}) = %v, want ErrSealerNotConstructed", err)
	}
	dead, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	_ = dead.Destroy()
	if err := SetSealer(dead); !errors.Is(err, ErrSealerDestroyed) {
		t.Errorf("SetSealer(destroyed) = %v, want ErrSealerDestroyed", err)
	}

	live, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(live); err != nil {
		t.Fatalf("SetSealer after the refusals: %v", err)
	}
}

// foreignSealer is a Sealer this package did not build.
type foreignSealer struct{}

func (foreignSealer) Seal(context.Context, []byte) (Sealed, error)     { return nil, nil }
func (foreignSealer) SealFrom(context.Context, Handle) (Sealed, error) { return nil, nil }
func (foreignSealer) Mode() Mode                                       { return ModeRootKey }
func (foreignSealer) Destroy() error                                   { return nil }

// TestSetSealer_RefusesAForeignSealer: SetSealer refuses another
// implementation of the interface with ErrSealerNotConstructed and every nil
// shape with ErrNilSealer, and none of the refusals takes the slot.
func TestSetSealer_RefusesAForeignSealer(t *testing.T) {
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)

	for name, s := range map[string]Sealer{
		"value":   foreignSealer{},
		"pointer": &foreignSealer{},
	} {
		if err := SetSealer(s); !errors.Is(err, ErrSealerNotConstructed) {
			t.Errorf("SetSealer(foreign %s) = %v, want ErrSealerNotConstructed", name, err)
		}
	}
	for name, s := range map[string]Sealer{
		"nil interface":          nil,
		"typed-nil foreign":      (*foreignSealer)(nil),
		"typed-nil this package": (*envelopeSealer)(nil),
	} {
		if err := SetSealer(s); !errors.Is(err, ErrNilSealer) {
			t.Errorf("SetSealer(%s) = %v, want ErrNilSealer", name, err)
		}
	}

	live, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(live); err != nil {
		t.Fatalf("SetSealer after the refusals: %v", err)
	}
	got, err := processSealer()
	if err != nil || Sealer(got) != live {
		t.Errorf("processSealer() = (%v, %v), want the installed sealer", got, err)
	}
}

// hookedSource is a locked-memory source whose borrow runs before first.
type hookedSource struct {
	*lockedRegion
	before func()
}

func (h *hookedSource) WithBytes(fn func([]byte) error) error {
	h.before()
	return h.lockedRegion.WithBytes(fn)
}

// TestSealer_DataAEADRunsOutsideTheLock pins L4: the value's own encryption
// does not hold off Destroy, and a seal Destroy overlapped fails closed.
func TestSealer_DataAEADRunsOutsideTheLock(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	m, err := newMemoryCopy([]byte("straddles-destroy"))
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}
	defer m.Destroy()

	src := &hookedSource{lockedRegion: m, before: func() {
		done := make(chan error, 1)
		go func() { done <- s.Destroy() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Destroy: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Destroy waited for the data AEAD: the sealer's lock is held across it")
		}
	}}
	v, err := s.sealFromHandle(ctx, src)
	if !errors.Is(err, ErrSealerDestroyed) {
		_ = v.Destroy()
		t.Fatalf("a seal Destroy overlapped = %v, want ErrSealerDestroyed", err)
	}
	if v != nil {
		t.Fatal("a seal Destroy overlapped returned a value")
	}
}

// TestSealer_NilOptionsAndReceivers pins L6.
func TestSealer_NilOptionsAndReceivers(t *testing.T) {
	if s, err := NewSealer(nil); s != nil || !errors.Is(err, ErrInvalidSealerOption) {
		t.Errorf("NewSealer(nil) = (%v, %v), want (nil, ErrInvalidSealerOption)", s, err)
	}
	if s, err := NewSealer(WithKEKRotationLimit(1), nil); s != nil || !errors.Is(err, ErrInvalidSealerOption) {
		t.Errorf("NewSealer(opt, nil) = (%v, %v), want (nil, ErrInvalidSealerOption)", s, err)
	}
	if got := (*envelopeSealer)(nil).Mode(); got != ModeRootKey {
		t.Errorf("nil Mode() = %v, want the zero Mode", got)
	}
	if got := (&envelopeSealer{}).Mode(); got != ModeRootKey {
		t.Errorf("zero Mode() = %v, want the zero Mode", got)
	}
}

// TestSealer_DefaultProviderIsReleasedAfterTheUnseal pins L7: the root of the
// SoftwareProvider NewSealer created serves one unseal and is then destroyed.
func TestSealer_DefaultProviderIsReleasedAfterTheUnseal(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()
	v, err := s.sealData(ctx, []byte("first-seal"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	p := s.owned.s
	p.mu.Lock()
	destroyed, root := p.destroyed, p.root
	p.mu.Unlock()
	if !destroyed || root.IsAlive() {
		t.Fatal("the default provider still holds its root after the sealer unsealed it")
	}
	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open after the provider's release: %v", err)
	}
	_ = e.Destroy()
}
