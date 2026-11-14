// Copyright 2025 The go-enclave Authors
// SPDX-License-Identifier: Apache-2.0

package enclave

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// sealedOpenMaterial is the plaintext these tests seal.
var sealedOpenMaterial = []byte("sealed open targets material")

// sealForOpenTest seals sealedOpenMaterial under a fresh sealer and returns
// the value and the sealer that answers its opens.
func sealForOpenTest(t *testing.T) (*sealedValue, *envelopeSealer) {
	t.Helper()
	sealer, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() { _ = sealer.Destroy() })
	data := append([]byte(nil), sealedOpenMaterial...)
	sealed, err := sealer.Seal(t.Context(), data)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	t.Cleanup(func() { _ = sealed.Destroy() })
	v := sealed.(*sealedValue)
	es, _, ok := v.openableSnapshot()
	if !ok {
		t.Fatal("openableSnapshot of a fresh value reports ok false")
	}
	return v, es
}

// openTestAllocator returns a budgeted allocator for the open paths.
func openTestAllocator(t *testing.T) *budgetAllocator {
	t.Helper()
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	return a.(*budgetAllocator)
}

// fakeRegionTarget is a regionTarget whose allocRegion fails with err, or
// admits from a when err is nil.
type fakeRegionTarget struct {
	a   *budgetAllocator
	err error
}

func (f *fakeRegionTarget) Name() string { return "fake-region" }

func (f *fakeRegionTarget) allocRegion(n int) (*lockedRegion, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.a.admitSized(n)
}

func (f *fakeRegionTarget) regionHandle(r *lockedRegion) Handle {
	return &fakeRegionHandle{lockedRegion: r, backend: f}
}

// fakeRegionHandle reports the fake target as its backend.
type fakeRegionHandle struct {
	*lockedRegion
	backend Backend
}

func (h *fakeRegionHandle) Backend() Backend { return h.backend }

// fakeOpaqueHandle is a Handle without ByteAccess.
type fakeOpaqueHandle struct {
	backend   Backend
	destroyed atomic.Bool
}

func (h *fakeOpaqueHandle) Size() int {
	if h.destroyed.Load() {
		return 0
	}
	return 1
}
func (h *fakeOpaqueHandle) IsAlive() bool    { return !h.destroyed.Load() }
func (h *fakeOpaqueHandle) Destroy() error   { h.destroyed.Store(true); return nil }
func (h *fakeOpaqueHandle) Backend() Backend { return h.backend }

// openTestImporter answers Import with do, after wiping the material.
type openTestImporter struct {
	do   func(ctx context.Context, material []byte) (Handle, error)
	seen []byte
}

func (f *openTestImporter) Name() string { return "fake-import" }

func (f *openTestImporter) Import(ctx context.Context, material []byte, _ ...ImportOption) (Handle, error) {
	f.seen = append([]byte(nil), material...)
	h, err := f.do(ctx, material)
	clear(material)
	return h, err
}

func TestSealedOpenTargets_SealedOutNil(t *testing.T) {
	want := errors.New("seal refused")
	got, err := sealedOut(nil, want)
	if got != nil {
		t.Errorf("sealedOut(nil) = %#v, want an untyped nil Sealed", got)
	}
	if !errors.Is(err, want) {
		t.Errorf("sealedOut(nil) error = %v, want %v", err, want)
	}

	v := &sealedValue{}
	got, err = sealedOut(v, nil)
	if err != nil || got != Sealed(v) {
		t.Errorf("sealedOut(v, nil) = %v, %v; want v, nil", got, err)
	}
}

func TestSealedOpenTargets_OpenRegionAllocFailure(t *testing.T) {
	v, _ := sealForOpenTest(t)
	cause := errors.New("region refused")
	h, err := v.openRegion(t.Context(), &fakeRegionTarget{err: cause})
	if h != nil {
		t.Errorf("openRegion with a failing allocRegion returned a handle")
		_ = h.Destroy()
	}
	var oe *OpenError
	if !errors.As(err, &oe) {
		t.Fatalf("openRegion error = %v (%T), want *OpenError", err, err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("openRegion error = %v, want it to carry the cause", err)
	}
}

func TestSealedOpenTargets_OpenRegionSuccess(t *testing.T) {
	v, _ := sealForOpenTest(t)
	target := &fakeRegionTarget{a: openTestAllocator(t)}
	h, err := v.openRegion(t.Context(), target)
	if err != nil {
		t.Fatalf("openRegion = %v", err)
	}
	defer func() { _ = h.Destroy() }()
	if h.Backend() != Backend(target) {
		t.Errorf("handle Backend = %v, want the target", h.Backend())
	}
	if h.Size() != len(sealedOpenMaterial) {
		t.Errorf("handle Size = %d, want %d", h.Size(), len(sealedOpenMaterial))
	}
}

func TestSealedOpenTargets_OpenRegionDestroyed(t *testing.T) {
	v, _ := sealForOpenTest(t)
	if err := v.Destroy(); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	h, err := v.openRegion(t.Context(), &fakeRegionTarget{a: openTestAllocator(t)})
	if h != nil || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("openRegion after Destroy = %v, %v; want nil, ErrEnclaveDestroyed", h, err)
	}
}

func TestSealedOpenTargets_OpenAdmitted(t *testing.T) {
	v, _ := sealForOpenTest(t)

	r, err := v.openAdmitted(t.Context(), nil)
	if r != nil || !errors.Is(err, ErrNilAllocator) {
		t.Errorf("openAdmitted(nil allocator) = %v, %v; want nil, ErrNilAllocator", r, err)
	}

	var nilValue *sealedValue
	r, err = nilValue.openAdmitted(t.Context(), nil)
	if r != nil || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("nil receiver openAdmitted = %v, %v; want openIn's ErrEnclaveDestroyed", r, err)
	}

	r, err = v.openAdmitted(t.Context(), openTestAllocator(t))
	if err != nil {
		t.Fatalf("openAdmitted = %v", err)
	}
	defer func() { _ = r.Destroy() }()
	if r.Size() != len(sealedOpenMaterial) {
		t.Errorf("region Size = %d, want %d", r.Size(), len(sealedOpenMaterial))
	}
}

func TestSealedOpenTargets_OpenImportedDestroyed(t *testing.T) {
	imp := &openTestImporter{do: func(context.Context, []byte) (Handle, error) {
		t.Error("Import called on a destroyed value")
		return nil, nil
	}}

	var nilValue *sealedValue
	if h, err := nilValue.openImported(t.Context(), imp); h != nil || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("nil openImported = %v, %v; want nil, ErrEnclaveDestroyed", h, err)
	}
	if h, err := (&sealedValue{}).openImported(t.Context(), imp); h != nil || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("zero openImported = %v, %v; want nil, ErrEnclaveDestroyed", h, err)
	}

	v, _ := sealForOpenTest(t)
	if err := v.Destroy(); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if h, err := v.openImported(t.Context(), imp); h != nil || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("destroyed openImported = %v, %v; want nil, ErrEnclaveDestroyed", h, err)
	}
}

func TestSealedOpenTargets_OpenImportedImportFails(t *testing.T) {
	v, _ := sealForOpenTest(t)
	cause := errors.New("device refused")
	imp := &openTestImporter{do: func(context.Context, []byte) (Handle, error) { return nil, cause }}
	h, err := v.openImported(t.Context(), imp)
	if h != nil {
		t.Error("openImported with a failing Import returned a handle")
	}
	var oe *OpenError
	if !errors.As(err, &oe) || !errors.Is(err, cause) {
		t.Errorf("openImported error = %v (%T), want an *OpenError carrying the cause", err, err)
	}
	if string(imp.seen) != string(sealedOpenMaterial) {
		t.Errorf("Import saw %q, want the sealed plaintext", imp.seen)
	}
}

func TestSealedOpenTargets_OpenImportedContextCanceled(t *testing.T) {
	v, _ := sealForOpenTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	imp := &openTestImporter{do: func(ctx context.Context, _ []byte) (Handle, error) {
		cancel()
		return nil, ctx.Err()
	}}
	h, err := v.openImported(ctx, imp)
	if h != nil {
		t.Error("openImported under a canceled ctx returned a handle")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("openImported error = %v, want context.Canceled", err)
	}
}

func TestSealedOpenTargets_OpenImportedNilHandle(t *testing.T) {
	v, _ := sealForOpenTest(t)
	imp := &openTestImporter{do: func(context.Context, []byte) (Handle, error) { return nil, nil }}
	h, err := v.openImported(t.Context(), imp)
	if h != nil {
		t.Error("openImported returned a handle for a nil import")
	}
	var ce *CapabilityError
	if !errors.As(err, &ce) || ce.Capability != CapabilityBytes || ce.Backend != imp.Name() {
		t.Errorf("openImported error = %v, want a CapabilityError naming %q and CapabilityBytes", err, imp.Name())
	}
}

func TestSealedOpenTargets_OpenImportedNoByteAccess(t *testing.T) {
	v, _ := sealForOpenTest(t)
	opaque := &fakeOpaqueHandle{}
	imp := &openTestImporter{do: func(context.Context, []byte) (Handle, error) { return opaque, nil }}
	opaque.backend = imp
	h, err := v.openImported(t.Context(), imp)
	if h != nil {
		t.Error("openImported returned a handle without ByteAccess")
	}
	var ce *CapabilityError
	if !errors.As(err, &ce) || ce.Capability != CapabilityBytes {
		t.Errorf("openImported error = %v, want a CapabilityError naming CapabilityBytes", err)
	}
	if !opaque.destroyed.Load() {
		t.Error("the refused handle was not destroyed")
	}
}

func TestSealedOpenTargets_OpenImportedSealerDestroyedMeanwhile(t *testing.T) {
	v, sealer := sealForOpenTest(t)
	a := openTestAllocator(t)
	var got Handle
	imp := &openTestImporter{do: func(ctx context.Context, material []byte) (Handle, error) {
		h, err := a.Import(ctx, append([]byte(nil), material...))
		got = h
		go func() { _ = sealer.Destroy() }()
		deadline := time.Now().Add(5 * time.Second)
		for sealer.usable() == nil {
			if time.Now().After(deadline) {
				t.Fatal("the sealer did not become unusable within 5s of Destroy while the open was in flight")
			}
			time.Sleep(time.Millisecond)
		}
		return h, err
	}}
	h, err := v.openImported(t.Context(), imp)
	if h != nil {
		t.Error("openImported returned a handle under a destroyed sealer")
	}
	if err == nil {
		t.Error("openImported under a destroyed sealer = nil error")
	}
	if got != nil && got.IsAlive() {
		t.Error("the handle opened under a destroyed sealer is still alive")
	}
}

func TestSealedOpenTargets_OpenImportedSuccess(t *testing.T) {
	v, _ := sealForOpenTest(t)
	a := openTestAllocator(t)
	h, err := v.openImported(t.Context(), a)
	if err != nil {
		t.Fatalf("openImported = %v", err)
	}
	defer func() { _ = h.Destroy() }()
	ba, ok := h.(ByteAccess)
	if !ok {
		t.Fatalf("handle %T has no ByteAccess", h)
	}
	if err := ba.WithBytes(func(p []byte) error {
		if string(p) != string(sealedOpenMaterial) {
			t.Errorf("imported bytes = %q, want the sealed plaintext", p)
		}
		return nil
	}); err != nil {
		t.Errorf("WithBytes = %v", err)
	}
}

func TestSealedOpenTargets_OpenableSnapshot(t *testing.T) {
	v, sealer := sealForOpenTest(t)
	got, _, ok := v.openableSnapshot()
	if !ok || got != sealer {
		t.Errorf("openableSnapshot = %p, %v; want the sealer, true", got, ok)
	}
	if err := v.Destroy(); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if got, gen, ok := v.openableSnapshot(); ok || got != nil || gen != 0 {
		t.Errorf("openableSnapshot after Destroy = %p, %d, %v; want nil, 0, false", got, gen, ok)
	}
}

func TestSealedOpenTargets_SecretMemoryAllocRegion(t *testing.T) {
	if r, err := (&secretMemory{}).allocRegion(16); r != nil || !errors.Is(err, ErrNilAllocator) {
		t.Errorf("allocRegion with a nil allocator = %v, %v; want nil, ErrNilAllocator", r, err)
	}
	if r, err := (&secretMemory{allocator: &budgetAllocator{}}).allocRegion(16); r != nil || !errors.Is(err, ErrAllocatorNotConstructed) {
		t.Errorf("allocRegion with an unconstructed allocator = %v, %v; want nil, ErrAllocatorNotConstructed", r, err)
	}
}

func TestSealedOpenTargets_SecretMemoryRegionHandle(t *testing.T) {
	s := &secretMemory{allocator: openTestAllocator(t)}
	r, err := s.allocator.admitSized(16)
	if err != nil {
		t.Fatalf("admitSized = %v", err)
	}
	h := s.regionHandle(r)
	defer func() { _ = h.Destroy() }()
	if h.Backend() != Backend(s) {
		t.Errorf("regionHandle Backend = %v, want the secretmem backend", h.Backend())
	}
	if h.Size() != 16 {
		t.Errorf("regionHandle Size = %d, want 16", h.Size())
	}
}
