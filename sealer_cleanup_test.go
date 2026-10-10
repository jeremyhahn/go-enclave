// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// errDestroyRefused is what a stickyImporter's handle returns from Destroy
// while it refuses.
var errDestroyRefused = errors.New("test: destroy refused")

// errImportFailed is what a stickyImporter returns, with its handle, while
// failing.
var errImportFailed = errors.New("test: import failed")

// stickyImporter is a fakeImporter of ByteAccess handles whose Destroy can be
// refused, whose Import can fail while still returning its handle, and whose
// material imports can be parked.
type stickyImporter struct {
	*fakeImporter

	refuse atomic.Bool // every handle's Destroy fails, holding its material
	fail   atomic.Bool // Import returns its handle and errImportFailed

	// When park is non-nil, a material import signals entered and waits for
	// park to close.
	park    chan struct{}
	entered chan struct{}

	mu      sync.Mutex
	handles []*stickyHandle
}

func newStickyImporter() *stickyImporter {
	return &stickyImporter{fakeImporter: &fakeImporter{keys: importBytes, material: importBytes}}
}

// parked makes the next material import wait until the returned func runs.
func (b *stickyImporter) parked() func() {
	b.park, b.entered = make(chan struct{}), make(chan struct{})
	return func() { close(b.park) }
}

func (b *stickyImporter) Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error) {
	spec, err := NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	h, err := b.fakeImporter.Import(ctx, material, opts...)
	if err != nil {
		return nil, err
	}
	sh := &stickyHandle{importedBytes: h.(*importedBytes), b: b}
	b.mu.Lock()
	b.handles = append(b.handles, sh)
	b.mu.Unlock()
	if spec.Purpose == PurposeMaterial && b.park != nil {
		close(b.entered)
		<-b.park
	}
	if b.fail.Load() {
		return sh, errImportFailed
	}
	return sh, nil
}

// live returns every handle Import returned that still holds its material.
func (b *stickyImporter) live() []*stickyHandle {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*stickyHandle
	for _, h := range b.handles {
		if h.IsAlive() {
			out = append(out, h)
		}
	}
	return out
}

// stickyHandle is a ByteAccess handle that refuses Destroy, keeping its
// material, while its importer refuses.
type stickyHandle struct {
	*importedBytes
	b *stickyImporter
}

func (h *stickyHandle) Backend() Backend { return h.b }

func (h *stickyHandle) Destroy() error {
	if h.b.refuse.Load() {
		return errDestroyRefused
	}
	return h.importedBytes.Destroy()
}

// requireCleanupFailure fails t unless err is a *CleanupError carrying
// errDestroyRefused and matching every one of failures.
func requireCleanupFailure(t *testing.T, err error, failures ...error) {
	t.Helper()
	var ce *CleanupError
	if !errors.As(err, &ce) || !errors.Is(err, ErrCleanupFailed) || !errors.Is(err, errDestroyRefused) {
		t.Fatalf("err = %v, want a *CleanupError carrying the refused Destroy", err)
	}
	if !errors.Is(ce.Cause, errDestroyRefused) {
		t.Fatalf("CleanupError.Cause = %v, want the refused Destroy", ce.Cause)
	}
	for _, f := range failures {
		if !errors.Is(err, f) {
			t.Fatalf("err = %v, want it to match %v", err, f)
		}
	}
}

// destroyRetried lets b's handles go, destroys s again, and fails t unless that
// released every handle b still had live.
func destroyRetried(t *testing.T, s *Sealer, b *stickyImporter) {
	t.Helper()
	b.refuse.Store(false)
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy retry: %v", err)
	}
	if live := b.live(); len(live) != 0 {
		t.Fatalf("%d handles still hold material after the retried Destroy", len(live))
	}
}

// TestSealed_OpenInRechecksTheSealerAfterImport reproduces Codex's P1: a
// Sealer destroyed while OpenIn's import blocked handed out a live plaintext
// handle. The import is released only after Destroy returned.
func TestSealed_OpenInRechecksTheSealerAfterImport(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		name := "destroyed"
		if refuse {
			name = "destroy-refused"
		}
		t.Run(name, func(t *testing.T) {
			s, err := NewSealer()
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.Seal(t.Context(), []byte("opened-across-destroy"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			b := newStickyImporter()
			release := b.parked()
			type result struct {
				h   Handle
				err error
			}
			done := make(chan result, 1)
			go func() {
				h, err := v.OpenIn(t.Context(), b)
				done <- result{h, err}
			}()
			<-b.entered
			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			b.refuse.Store(refuse)
			release()
			r := <-done

			if r.h != nil {
				t.Fatalf("OpenIn across Destroy returned a handle (err %v)", r.err)
			}
			if !errors.Is(r.err, ErrSealerDestroyed) {
				t.Fatalf("OpenIn across Destroy = %v, want ErrSealerDestroyed", r.err)
			}
			if !refuse {
				if live := b.live(); len(live) != 0 {
					t.Fatal("OpenIn across Destroy left the imported plaintext live")
				}
				return
			}
			requireCleanupFailure(t, r.err, ErrSealerDestroyed)
			if len(b.live()) != 1 {
				t.Fatal("the handle whose Destroy was refused was not kept live")
			}
			destroyRetried(t, s, b)
		})
	}
}

// TestSealed_OpenInKeepsAFailedImportsRefusedCleanup reproduces Codex's P1: an
// importer returning a handle with its error, whose Destroy then failed, lost
// both the handle and the cleanup failure.
func TestSealed_OpenInKeepsAFailedImportsRefusedCleanup(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), []byte("failed-import"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	b := newStickyImporter()
	b.fail.Store(true)
	b.refuse.Store(true)
	h, err := v.OpenIn(t.Context(), b)
	if h != nil {
		t.Fatal("a failed import returned a handle")
	}
	requireCleanupFailure(t, err, ErrOpenFailed, errImportFailed)
	if len(b.live()) != 1 {
		t.Fatal("the handle whose Destroy was refused was not kept live")
	}
	destroyRetried(t, s, b)
}

// TestSealer_ImportKeyKeepsARefusedCleanup is the same finding for the
// sealer's own keys: a failed wrapping-key import whose handle refused Destroy.
func TestSealer_ImportKeyKeepsARefusedCleanup(t *testing.T) {
	b := newStickyImporter()
	s, err := NewSealer(WithBackend(b))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	b.fail.Store(true)
	b.refuse.Store(true)
	if _, err := s.Seal(t.Context(), []byte("failed-key-import")); err == nil {
		t.Fatal("Seal over a failing import succeeded")
	} else {
		requireCleanupFailure(t, err, ErrSealFailed, errImportFailed)
	}
	if len(b.live()) != 1 {
		t.Fatal("the key whose Destroy was refused was not kept live")
	}
	destroyRetried(t, s, b)
}

// TestSealer_RotationKeepsARefusedOutgoingKEK reproduces Codex's P1: a
// rotation whose outgoing backend KEK refused Destroy dropped it live and
// reported success.
func TestSealer_RotationKeepsARefusedOutgoingKEK(t *testing.T) {
	b := newStickyImporter()
	s, err := NewSealer(WithBackend(b), WithKEKRotationLimit(1))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ctx := t.Context()
	first, err := s.Seal(ctx, []byte("before-rotation"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer first.Destroy()
	keys := len(b.live()) // the wrapping key and generation 1

	b.refuse.Store(true)
	if _, err := s.Seal(ctx, []byte("rotating")); err == nil {
		t.Fatal("a rotation whose outgoing KEK refused Destroy reported success")
	} else {
		requireCleanupFailure(t, err)
	}
	if got := len(b.live()); got != keys+1 {
		t.Fatalf("%d live keys after the refused rotation, want %d: the outgoing KEK is held", got, keys+1)
	}

	// The new generation is published: sealing goes on under it, and the
	// value sealed before the rotation still opens.
	b.refuse.Store(false)
	second, err := s.Seal(ctx, []byte("after-rotation"))
	if err != nil {
		t.Fatalf("Seal after the refused rotation: %v", err)
	}
	defer second.Destroy()
	m, err := first.Open(ctx)
	if err != nil {
		t.Fatalf("Open of a value sealed before the rotation: %v", err)
	}
	_ = m.Destroy()
	destroyRetried(t, s, b)
}

// TestReadOnly_ProbesEveryPage reproduces Codex's P2: a writable first and
// last page around a read-only interior page passed the probe, and the wipe
// that followed killed the process.
func TestReadOnly_ProbesEveryPage(t *testing.T) {
	ps := int(pageSize)
	b, err := sysMap(3 * ps)
	if err != nil {
		t.Skipf("sysMap: %v", err)
	}
	defer func() { _ = sysUnmap(b) }()
	if err := sysProtect(b[ps:2*ps], protReadOnly); err != nil {
		t.Skipf("sysProtect: %v", err)
	}
	defer func() { _ = sysProtect(b, protReadWrite) }()

	for _, tc := range []struct {
		name string
		p    []byte
	}{
		{"whole mapping", b},
		{"interior page only", b[ps+1 : 2*ps-1]},
		{"ends unaligned", b[ps/2 : 3*ps-ps/2]},
	} {
		if !readOnly(tc.p) {
			t.Errorf("%s: readOnly = false over a read-only interior page", tc.name)
		}
	}
	if readOnly(b[:ps]) || readOnly(b[2*ps:]) {
		t.Error("readOnly = true over a writable page")
	}
	if t.Failed() {
		t.FailNow() // Seal would wipe the read-only page and kill the process
	}

	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()
	if _, err := s.Seal(t.Context(), b); !errors.Is(err, ErrSealSourceReadOnly) {
		t.Fatalf("Seal over a read-only interior page = %v, want ErrSealSourceReadOnly", err)
	}
}
