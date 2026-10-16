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
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

const fakeImporterName = "fake-importer"

// importMode is the kind of handle a fakeImporter returns.
type importMode int

const (
	importBytes  importMode = iota // a ByteAccess handle
	importAEAD                     // an AEAD handle whose key never leaves it
	importOpaque                   // a handle with neither
	importNil                      // a nil handle and no error
)

func (m importMode) String() string {
	return [...]string{"bytes", "aead", "opaque", "nil"}[m]
}

// fakeImporter is an Importer whose handles hold their material in locked
// memory. keys picks the handle for a key purpose, material for
// PurposeMaterial.
type fakeImporter struct {
	keys, material importMode
	confines       bool
	err            error // returned by every Import

	mu      sync.Mutex
	specs   []ImportSpec
	handles []Handle
}

var (
	_ Importer = (*fakeImporter)(nil)
	_ Confiner = (*fakeImporter)(nil)
	_ AEAD     = (*deviceKey)(nil)
)

func (b *fakeImporter) Name() string          { return fakeImporterName }
func (b *fakeImporter) ConfinesProcess() bool { return b.confines }

func (b *fakeImporter) Import(_ context.Context, material []byte, opts ...ImportOption) (Handle, error) {
	defer Wipe(material)
	spec, err := NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.specs = append(b.specs, spec)
	if b.err != nil {
		return nil, b.err
	}

	mode := b.keys
	if spec.Purpose == PurposeMaterial {
		mode = b.material
	} else if len(material) != dekBytes {
		return nil, ErrInvalidImport
	}
	if mode == importNil {
		return nil, nil
	}
	m, err := newMemoryCopy(material)
	if err != nil {
		return nil, err
	}
	var h Handle
	switch mode {
	case importAEAD:
		h = &deviceKey{m: m, b: b}
	case importOpaque:
		h = &opaqueHandle{m: m, b: b}
	default:
		h = &importedBytes{lockedRegion: m, b: b}
	}
	b.handles = append(b.handles, h)
	return h, nil
}

// imported returns every spec Import was called with and every handle it
// returned.
func (b *fakeImporter) imported() ([]ImportSpec, []Handle) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]ImportSpec(nil), b.specs...), append([]Handle(nil), b.handles...)
}

// importedBytes is a ByteAccess handle of a fakeImporter.
type importedBytes struct {
	*lockedRegion
	b Backend
}

func (h *importedBytes) Backend() Backend { return h.b }

// opaqueHandle is a handle with neither ByteAccess nor AEAD.
type opaqueHandle struct {
	m *lockedRegion
	b Backend
}

func (h *opaqueHandle) Size() int        { return h.m.Size() }
func (h *opaqueHandle) IsAlive() bool    { return h.m.IsAlive() }
func (h *opaqueHandle) Destroy() error   { return h.m.Destroy() }
func (h *opaqueHandle) Backend() Backend { return h.b }

// deviceKey is an AES-256-GCM key that encrypts in its device: it implements
// AEAD and not ByteAccess.
type deviceKey struct {
	opaqueHandle
	seals, opens atomic.Int64
}

// FIPS 140-only mode refuses AES-GCM under a caller-chosen nonce, so there
// the key draws its own and carries it in the ciphertext (NonceSize 0), as
// the AEAD contract allows.
func (k *deviceKey) NonceSize() int {
	if fips140.Enforced() {
		return 0
	}
	return 12
}

func (k *deviceKey) Overhead() int {
	if fips140.Enforced() {
		return 12 + 16
	}
	return 16
}

func (k *deviceKey) Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error) {
	k.seals.Add(1)
	var out []byte
	err := k.gcm(func(g cipher.AEAD) error {
		out = g.Seal(dst, nonce, plaintext, additionalData)
		return nil
	})
	return out, err
}

func (k *deviceKey) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	k.opens.Add(1)
	var out []byte
	err := k.gcm(func(g cipher.AEAD) error {
		var oerr error
		if out, oerr = g.Open(dst, nonce, ciphertext, additionalData); oerr != nil {
			return ErrAEADAuthentication
		}
		return nil
	})
	return out, err
}

func (k *deviceKey) gcm(fn func(cipher.AEAD) error) error {
	return k.m.WithBytes(func(key []byte) error {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		newGCM := cipher.NewGCM
		if fips140.Enforced() {
			newGCM = cipher.NewGCMWithRandomNonce
		}
		g, err := newGCM(block)
		if err != nil {
			return err
		}
		return fn(g)
	})
}

// namedBackend is a backend with no optional capability.
type namedBackend struct{}

func (namedBackend) Name() string { return "named-backend" }

func sealForSeamTest(t *testing.T, material []byte) *sealedValue {
	t.Helper()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	v, err := s.sealData(t.Context(), append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	t.Cleanup(func() { _ = v.Destroy() })
	return v
}

// TestSealed_OpenInTheDefaultBackend pins OpenIn(DefaultBackend()) as Open.
func TestSealed_OpenInTheDefaultBackend(t *testing.T) {
	material := []byte("open-in-default")
	v := sealForSeamTest(t, material)

	h, err := v.OpenIn(t.Context(), DefaultBackend())
	if err != nil {
		t.Fatalf("OpenIn: %v", err)
	}
	defer h.Destroy()
	m, ok := h.(*lockedRegion)
	if !ok {
		t.Fatalf("OpenIn(DefaultBackend()) returned a %T, want a *lockedRegion", h)
	}
	if !holds(m, material) {
		t.Fatal("OpenIn opened the wrong material")
	}
	if m.Backend().Name() != LockedMemoryBackendName {
		t.Fatalf("the opened handle reports backend %q", m.Backend().Name())
	}
}

// TestSealed_OpenInAnImporter pins the scratch-enclave import: the material is
// imported as PurposeMaterial and the handle is the importer's.
func TestSealed_OpenInAnImporter(t *testing.T) {
	material := []byte("open-in-an-importer")
	v := sealForSeamTest(t, material)
	b := &fakeImporter{}

	h, err := v.OpenIn(t.Context(), b)
	if err != nil {
		t.Fatalf("OpenIn: %v", err)
	}
	defer h.Destroy()
	if h.Backend() != Backend(b) {
		t.Fatalf("the opened handle reports backend %v, want the importer", h.Backend())
	}
	ba, ok := h.(ByteAccess)
	if !ok {
		t.Fatalf("the opened handle is a %T without ByteAccess", h)
	}
	if eq, err := ba.EqualTo(material); err != nil || !eq {
		t.Fatalf("the opened handle does not hold the material (%v)", err)
	}
	specs, _ := b.imported()
	if len(specs) != 1 || specs[0] != (ImportSpec{Purpose: PurposeMaterial}) {
		t.Fatalf("imports %+v, want one PurposeMaterial import", specs)
	}
}

// TestSealed_OpenInRefusals pins OpenIn's refusals, each of which leaves the
// value openable and no imported handle alive.
func TestSealed_OpenInRefusals(t *testing.T) {
	ctx := t.Context()
	material := []byte("open-in-refusals")
	v := sealForSeamTest(t, material)

	if _, err := v.OpenIn(ctx, nil); !errors.Is(err, ErrInvalidBackend) {
		t.Errorf("OpenIn(nil) = %v, want ErrInvalidBackend", err)
	}
	if _, err := v.OpenIn(ctx, (*fakeImporter)(nil)); !errors.Is(err, ErrInvalidBackend) {
		t.Errorf("OpenIn(typed nil) = %v, want ErrInvalidBackend", err)
	}
	_, err := v.OpenIn(ctx, namedBackend{})
	requireCapability(t, err, "named-backend", CapabilityImport)

	for _, mode := range []importMode{importOpaque, importNil} {
		b := &fakeImporter{material: mode}
		_, err := v.OpenIn(ctx, b)
		requireCapability(t, err, fakeImporterName, CapabilityBytes)
		_, handles := b.imported()
		for _, h := range handles {
			if h.IsAlive() {
				t.Errorf("a refused handle of mode %v was left alive", mode)
			}
		}
	}

	if _, err := v.OpenIn(ctx, &fakeImporter{err: ErrInvalidImport}); !errors.Is(err, ErrInvalidImport) {
		t.Errorf("a refused import = %v, want ErrInvalidImport", err)
	}

	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open after the refusals: %v", err)
	}
	defer e.Destroy()
	if !holds(e, material) {
		t.Fatal("the value opened to the wrong material after the refusals")
	}
}

// TestSealer_WithBackendIsValidated pins NewSealer's checks of WithBackend.
func TestSealer_WithBackendIsValidated(t *testing.T) {
	if _, err := newEnvelopeSealer(WithBackend(nil)); !errors.Is(err, ErrInvalidBackend) {
		t.Errorf("WithBackend(nil) = %v, want ErrInvalidBackend", err)
	}
	if _, err := newEnvelopeSealer(WithBackend((*fakeImporter)(nil))); !errors.Is(err, ErrInvalidBackend) {
		t.Errorf("WithBackend(typed nil) = %v, want ErrInvalidBackend", err)
	}
	_, err := newEnvelopeSealer(WithBackend(namedBackend{}))
	requireCapability(t, err, "named-backend", CapabilityImport)

	// A per-operation sealer holds no keys of its own, so it imports nothing.
	s, err := newEnvelopeSealer(WithKeyProtector(newMapKeyProtector(t)), WithBackend(namedBackend{}))
	if err != nil {
		t.Fatalf("WithBackend on a per-operation sealer: %v", err)
	}
	_ = s.Destroy()

	// The default backend keeps the keys in this process's locked memory.
	s, err = newEnvelopeSealer(WithBackend(DefaultBackend()))
	if err != nil {
		t.Fatalf("WithBackend(DefaultBackend()): %v", err)
	}
	defer s.Destroy()
	v, err := s.sealData(t.Context(), []byte("default-backend-keys"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	if _, ok := s.root.(*lockedRegion); !ok {
		t.Fatalf("the wrapping key is a %T, want a *lockedRegion", s.root)
	}
}

// TestSealer_KeysLiveInTheBackend pins WithBackend for an importer: the
// wrapping key and every KEK are imported as AES-256-GCM wrapping keys, wrap
// in the device when the handle is an AEAD, survive rotation, and are released
// by Destroy.
func TestSealer_KeysLiveInTheBackend(t *testing.T) {
	for _, mode := range []importMode{importAEAD, importBytes} {
		t.Run(mode.String(), func(t *testing.T) {
			ctx := t.Context()
			b := &fakeImporter{keys: mode}
			s, err := newEnvelopeSealer(WithBackend(b), WithKEKRotationLimit(2))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}

			var vals []*sealedValue
			for i := range 6 {
				v, err := s.sealData(ctx, fmt.Appendf(nil, "backend-value-%d", i))
				if err != nil {
					t.Fatalf("Seal %d: %v", i, err)
				}
				vals = append(vals, v)
			}
			for i, v := range vals {
				e, err := v.Open(ctx)
				if err != nil {
					t.Fatalf("Open %d: %v", i, err)
				}
				if !holds(e, fmt.Appendf(nil, "backend-value-%d", i)) {
					t.Fatalf("value %d opened to the wrong material", i)
				}
				_ = e.Destroy()
				_ = v.Destroy()
			}

			specs, handles := b.imported()
			// The wrapping key and one KEK per generation.
			if want := 1 + int(s.kekGen); len(specs) != want {
				t.Fatalf("%d imports, want %d", len(specs), want)
			}
			for _, spec := range specs {
				if spec != (ImportSpec{Purpose: PurposeWrappingKey, Algorithm: AlgorithmAES256GCM}) {
					t.Fatalf("import %+v, want an AES-256-GCM wrapping key", spec)
				}
			}
			if s.root != handles[0] || s.kek != handles[len(handles)-1] {
				t.Fatal("the sealer's keys are not the imported handles")
			}
			if dk, ok := s.root.(*deviceKey); ok && (dk.seals.Load() == 0 || dk.opens.Load() == 0) {
				t.Fatal("the device wrapping key never wrapped or unwrapped")
			}

			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			for i, h := range handles {
				if h.IsAlive() {
					t.Errorf("imported key %d is alive after Destroy", i)
				}
			}
		})
	}
}

// TestSealer_KeyHandleWithoutAEADOrBytesIsRefused pins the check that runs
// where a key is imported: a handle that can neither wrap in the device nor
// lend its bytes is destroyed and refused at the first seal.
func TestSealer_KeyHandleWithoutAEADOrBytesIsRefused(t *testing.T) {
	for _, mode := range []importMode{importOpaque, importNil} {
		b := &fakeImporter{keys: mode}
		s, err := newEnvelopeSealer(WithBackend(b))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		_, err = s.sealData(t.Context(), []byte("refused-key"))
		requireCapability(t, err, fakeImporterName, CapabilityAEAD)
		_, handles := b.imported()
		for _, h := range handles {
			if h.IsAlive() {
				t.Errorf("a refused key handle of mode %v was left alive", mode)
			}
		}
		_ = s.Destroy()
	}
}
