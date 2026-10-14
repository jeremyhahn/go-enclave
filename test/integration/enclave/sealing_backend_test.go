// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The sealing tests that put a backend under a Sealer: the key hierarchy held
// by a device, SealFrom, OpenIn into another backend and the refusals each
// has. The fakes are in backend_fakes_test.go.

// rootSealerOn is a ModeRootKey sealer whose key hierarchy lives in b, torn
// down with the test.
func rootSealerOn(t *testing.T, b enclave.Backend, opts ...enclave.SealerOption) *enclave.Sealer {
	t.Helper()
	all := append([]enclave.SealerOption{enclave.WithRootUnsealer(newDevice()), enclave.WithBackend(b)}, opts...)
	s, err := enclave.NewSealer(all...)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	return s
}

// frozenNeedle is an enclave holding n, frozen read-only.
func frozenNeedle(t *testing.T, n needle) enclave.ByteAccess {
	t.Helper()
	m := enclaveFromNeedle(t, n)
	if err := m.(enclave.Freezer).Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	t.Cleanup(func() { _ = m.Destroy() })
	return m
}

// requireCapabilityError asserts err is a *CapabilityError for capability and
// matches ErrCapabilityUnsupported, and returns it.
func requireCapabilityError(t *testing.T, what string, err error, capability enclave.Capability) *enclave.CapabilityError {
	t.Helper()
	var ce *enclave.CapabilityError
	if !errors.As(err, &ce) || !errors.Is(err, enclave.ErrCapabilityUnsupported) {
		t.Fatalf("%s: err = %v, want a *CapabilityError matching ErrCapabilityUnsupported", what, err)
	}
	if ce.Capability != capability {
		t.Fatalf("%s: capability = %q, want %q", what, ce.Capability, capability)
	}
	return ce
}

func TestSealing_SealFromAFrozenEnclaveSealsItAndLeavesItIntact(t *testing.T) {
	ctx := context.Background()
	s := rootSealerOn(t, enclave.DefaultBackend())
	n := newNeedle(t)
	m := frozenNeedle(t, n)

	v, err := s.SealFrom(ctx, m)
	if err != nil {
		t.Fatalf("SealFrom a frozen enclave: %v", err)
	}
	defer v.Destroy()
	if !m.IsAlive() {
		t.Fatalf("SealFrom destroyed its source")
	}
	var intact bool
	if err := m.WithBytes(func(b []byte) error { intact = n.equals(b); return nil }); err != nil || !intact {
		t.Fatalf("the source after SealFrom: matches %t, err %v; want it untouched", intact, err)
	}
	requireOpensTo(t, ctx, v, n)

	// The same frozen pages through Seal, as a slice: Seal wipes what it is
	// given, which a read-only mapping cannot take, so it refuses up front.
	err = m.WithBytes(func(b []byte) error {
		_, serr := s.Seal(ctx, b)
		return serr
	})
	if !errors.Is(err, enclave.ErrSealSourceReadOnly) {
		t.Fatalf("Seal of a read-only view: %v, want ErrSealSourceReadOnly", err)
	}
}

func TestSealing_SealFromRefusesWhatItCannotSeal(t *testing.T) {
	ctx := context.Background()
	dev := newDeviceBackend()
	s := rootSealerOn(t, enclave.DefaultBackend())

	t.Run("NilSealer", func(t *testing.T) {
		var none *enclave.Sealer
		if _, err := none.SealFrom(ctx, enclaveFromNeedle(t, newNeedle(t))); !errors.Is(err, enclave.ErrNilSealer) {
			t.Fatalf("SealFrom on a nil sealer: %v, want ErrNilSealer", err)
		}
	})
	t.Run("NilSource", func(t *testing.T) {
		if _, err := s.SealFrom(ctx, nil); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("SealFrom(nil): %v, want ErrEnclaveDestroyed", err)
		}
		var typedNil *enclave.Memory
		if _, err := s.SealFrom(ctx, typedNil); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("SealFrom of a typed-nil *Memory: %v, want ErrEnclaveDestroyed", err)
		}
	})
	t.Run("DestroyedSource", func(t *testing.T) {
		m := enclaveFromNeedle(t, newNeedle(t))
		if err := m.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if _, err := s.SealFrom(ctx, m); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("SealFrom a destroyed enclave: %v, want ErrEnclaveDestroyed", err)
		}
	})
	t.Run("SourceWithoutByteAccess", func(t *testing.T) {
		opaque := &opaqueHandle{deviceHandle: &deviceHandle{b: dev, size: 32}}
		_, err := s.SealFrom(ctx, opaque)
		ce := requireCapabilityError(t, "SealFrom a handle with no byte access", err, enclave.CapabilityBytes)
		if ce.Backend != dev.Name() {
			t.Fatalf("CapabilityError.Backend = %q, want the source's backend %q", ce.Backend, dev.Name())
		}
	})
	t.Run("EmptySource", func(t *testing.T) {
		if _, err := s.SealFrom(ctx, &phantom{b: dev}); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Fatalf("SealFrom a zero-size handle: %v, want ErrEmptyEnclave", err)
		}
	})
	t.Run("OversizedSource", func(t *testing.T) {
		if _, err := s.SealFrom(ctx, &phantom{b: dev, size: math.MaxInt}); !errors.Is(err, enclave.ErrMaterialTooLarge) {
			t.Fatalf("SealFrom a handle too large to seal: %v, want ErrMaterialTooLarge", err)
		}
	})
}

func TestSealing_NewSealedFromSealsUnderTheProcessSealer(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		live := context.Background()
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		if err := enclave.SetSealer(s); err != nil {
			t.Fatalf("SetSealer: %v", err)
		}

		n := newNeedle(t)
		m := frozenNeedle(t, n)
		v, err := enclave.NewSealedFrom(live, m)
		if err != nil {
			t.Fatalf("NewSealedFrom: %v", err)
		}
		defer v.Destroy()
		requireOpensTo(t, live, v, n)

		ended, cancel := context.WithCancel(live)
		cancel()
		_, err = enclave.NewSealedFrom(ended, m)
		requireContextFailure(t, "NewSealedFrom with an ended context", err, enclave.ErrSealFailed, context.Canceled)

		if _, err := enclave.NewSealedFrom(live, nil); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("NewSealedFrom(nil): %v, want ErrEnclaveDestroyed", err)
		}

		// NewSealed refuses a read-only slice before it reaches the sealer.
		err = m.WithBytes(func(b []byte) error {
			_, serr := enclave.NewSealed(live, b)
			return serr
		})
		if !errors.Is(err, enclave.ErrSealSourceReadOnly) {
			t.Fatalf("NewSealed of a read-only view: %v, want ErrSealSourceReadOnly", err)
		}
	})
}

func TestSealing_WithBackendRefusesWhatCannotHoldAKeyHierarchy(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		if _, err := enclave.NewSealer(enclave.WithRootUnsealer(newDevice()), enclave.WithBackend(nil)); !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Fatalf("WithBackend(nil): %v, want ErrInvalidBackend", err)
		}
		var typedNil *deviceBackend
		if _, err := enclave.NewSealer(enclave.WithRootUnsealer(newDevice()), enclave.WithBackend(typedNil)); !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Fatalf("WithBackend of a typed-nil backend: %v, want ErrInvalidBackend", err)
		}
	})
	t.Run("RootModeNeedsAnImporter", func(t *testing.T) {
		b := &fakeBackend{name: uniqueBackendName("plain")}
		_, err := enclave.NewSealer(enclave.WithRootUnsealer(newDevice()), enclave.WithBackend(b))
		ce := requireCapabilityError(t, "ModeRootKey on a backend that cannot import", err, enclave.CapabilityImport)
		if ce.Backend != b.Name() {
			t.Fatalf("CapabilityError.Backend = %q, want %q", ce.Backend, b.Name())
		}
	})
	t.Run("PerOperationModeNeedsNoImporter", func(t *testing.T) {
		b := &fakeBackend{name: uniqueBackendName("plain")}
		s, err := enclave.NewSealer(enclave.WithKeyProtector(&heapProtector{keys: map[string][]byte{}}), enclave.WithBackend(b))
		if err != nil {
			t.Fatalf("ModePerOperation on a backend that cannot import: %v", err)
		}
		defer s.Destroy()
		n := newNeedle(t)
		v := sealNeedle(t, context.Background(), s, n)
		defer v.Destroy()
		requireOpensTo(t, context.Background(), v, n)
	})
	t.Run("TheDefaultBackendNeedsNoImporter", func(t *testing.T) {
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(newDevice()), enclave.WithBackend(enclave.DefaultBackend()))
		if err != nil {
			t.Fatalf("WithBackend(DefaultBackend()): %v", err)
		}
		defer s.Destroy()
	})
}

func TestSealing_ADeviceHoldsTheKeyHierarchy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape shape
	}{
		{"AEAD", shapeDefault},
		{"AEADThatDrawsItsOwnNonce", shapeInlineAEAD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shape == shapeDefault && fipsOnly() {
				t.Skip("GODEBUG=fips140=only refuses AES-GCM with a caller-chosen nonce, so a device that takes the nonce from the caller cannot be built; the inline-nonce subcase covers the rest")
			}
			ctx := context.Background()
			dev := newDeviceBackend()
			dev.setShapes(tc.shape, shapeDefault)
			s := rootSealerOn(t, dev, enclave.WithKEKRotationLimit(2))

			const values = 7
			needles := make([]needle, values)
			sealed := make([]enclave.Sealed, values)
			for i := range sealed {
				needles[i] = newNeedle(t)
				sealed[i] = sealNeedle(t, ctx, s, needles[i])
				defer sealed[i].Destroy()
			}

			// The wrapping key first, then a KEK per generation: two seals a
			// generation makes four, and the first generation's import.
			calls := dev.imports()
			if len(calls) < 5 {
				t.Fatalf("%d imports for %d seals at a limit of 2, want at least 5 (wrapping key and 4 KEKs)", len(calls), values)
			}
			for i, c := range calls {
				if c.spec.Purpose != enclave.PurposeWrappingKey || c.spec.Algorithm != enclave.AlgorithmAES256GCM || c.size != enclave.RootKeyBytes {
					t.Fatalf("import %d = %+v of %d bytes, want an AES-256-GCM wrapping key of %d bytes", i+1, c.spec, c.size, enclave.RootKeyBytes)
				}
			}
			if dev.sealOps.Load() == 0 {
				t.Fatalf("no key sealed in the device: the hierarchy ran in this process")
			}

			// Retired generations still open, and opening goes through the device.
			for i, v := range sealed {
				requireOpensTo(t, ctx, v, needles[i])
			}
			if dev.openOps.Load() == 0 {
				t.Fatalf("no key opened in the device")
			}

			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			if live := dev.live(); live != 0 {
				t.Fatalf("%d device handles live after Destroy, want 0", live)
			}
		})
	}
}

func TestSealing_ADeviceThatCannotImportAKeyFailsClosed(t *testing.T) {
	ctx := context.Background()
	seal := func(s *enclave.Sealer) error {
		buf := heapBytes(needleLen)
		newNeedle(t).fill(buf)
		v, err := s.Seal(ctx, buf)
		if err == nil {
			_ = v.Destroy()
		}
		return err
	}

	t.Run("OpaqueWrappingKey", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setShapes(shapeOpaque, shapeDefault)
		s := rootSealerOn(t, dev)
		ce := requireCapabilityError(t, "a wrapping key with no AEAD", seal(s), enclave.CapabilityAEAD)
		if ce.Backend != dev.Name() {
			t.Fatalf("CapabilityError.Backend = %q, want %q", ce.Backend, dev.Name())
		}
		if h := dev.handle(1); h == nil || h.IsAlive() {
			t.Fatalf("the refused handle is %v, want it destroyed", h)
		}
	})
	t.Run("NilWrappingKey", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setShapes(shapeNil, shapeDefault)
		s := rootSealerOn(t, dev)
		requireCapabilityError(t, "a nil wrapping key", seal(s), enclave.CapabilityAEAD)
	})
	t.Run("ImportFailureIsASealError", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setHook(func(int, enclave.ImportSpec) error { return errDevice })
		s := rootSealerOn(t, dev)
		err := seal(s)
		var se *enclave.SealError
		if !errors.As(err, &se) || !errors.Is(err, enclave.ErrSealFailed) || !errors.Is(err, errDevice) {
			t.Fatalf("a failed import: %v, want a *SealError for ErrSealFailed carrying the device's error", err)
		}
	})
	t.Run("ImportVerdictsPassThrough", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setHook(func(call int, _ enclave.ImportSpec) error {
			if call == 1 {
				return enclave.ErrInvalidImport
			}
			return &enclave.CapabilityError{Backend: "device", Capability: enclave.CapabilityAEAD}
		})
		s := rootSealerOn(t, dev)
		if err := seal(s); !errors.Is(err, enclave.ErrInvalidImport) || errors.Is(err, enclave.ErrSealFailed) {
			t.Fatalf("an import refused as invalid: %v, want ErrInvalidImport unwrapped", err)
		}
		requireCapabilityError(t, "a capability refusal from the device", seal(s), enclave.CapabilityAEAD)
	})
	t.Run("HandleReturnedWithTheError", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setReturnsHandleWithError(true)
		dev.setHook(func(int, enclave.ImportSpec) error { return errDevice })
		s := rootSealerOn(t, dev)
		if err := seal(s); !errors.Is(err, errDevice) {
			t.Fatalf("a failed import that returned a handle: %v, want the device's error", err)
		}
		if h := dev.handle(1); h == nil || h.IsAlive() {
			t.Fatalf("the handle returned with the error is %v, want it destroyed", h)
		}
	})
	t.Run("ContextEndedDuringTheImport", func(t *testing.T) {
		dev := newDeviceBackend()
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		dev.setHook(func(int, enclave.ImportSpec) error { cancel(); return nil })
		s := rootSealerOn(t, dev)
		buf := heapBytes(needleLen)
		newNeedle(t).fill(buf)
		_, err := s.Seal(cctx, buf)
		requireContextFailure(t, "Seal whose context ended in the import", err, enclave.ErrSealFailed, context.Canceled)
	})
	t.Run("KEKImportFailsThenRetries", func(t *testing.T) {
		dev := newDeviceBackend()
		dev.setHook(func(call int, _ enclave.ImportSpec) error {
			if call == 2 {
				return errDevice
			}
			return nil
		})
		s := rootSealerOn(t, dev)
		if err := seal(s); !errors.Is(err, errDevice) {
			t.Fatalf("Seal whose KEK import failed: %v, want the device's error", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)
		defer v.Destroy()
		requireOpensTo(t, ctx, v, n)
		if got := len(dev.imports()); got != 3 {
			t.Fatalf("%d imports after a retry, want 3: the wrapping key kept, the KEK imported twice", got)
		}
	})
}

func TestSealing_ADeviceFailureInItsAEADIsTyped(t *testing.T) {
	ctx := context.Background()
	n := newNeedle(t)

	// A sealer past its first seal, so the hierarchy is built and only the
	// AEAD calls of the next seal or open are left to fail.
	setup := func(t *testing.T) (*deviceBackend, *enclave.Sealer, enclave.Sealed) {
		dev := newDeviceBackend()
		s := rootSealerOn(t, dev)
		v := sealNeedle(t, ctx, s, n)
		t.Cleanup(func() { _ = v.Destroy() })
		return dev, s, v
	}
	seal := func(s *enclave.Sealer) error {
		buf := heapBytes(needleLen)
		n.fill(buf)
		v, err := s.Seal(ctx, buf)
		if err == nil {
			_ = v.Destroy()
		}
		return err
	}

	t.Run("SealFailure", func(t *testing.T) {
		dev, s, _ := setup(t)
		dev.setFaults(deviceFaults{seal: errDevice})
		err := seal(s)
		var se *enclave.SealError
		if !errors.As(err, &se) || !errors.Is(err, enclave.ErrSealFailed) || !errors.Is(err, errDevice) {
			t.Fatalf("a device seal failure: %v, want a *SealError carrying the device's error", err)
		}
		dev.setFaults(deviceFaults{})
		if err := seal(s); err != nil {
			t.Fatalf("Seal after the device recovered: %v", err)
		}
	})
	t.Run("SealAuthentication", func(t *testing.T) {
		dev, s, _ := setup(t)
		dev.setFaults(deviceFaults{seal: enclave.ErrAEADAuthentication})
		if err := seal(s); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("a device authentication failure on seal: %v, want ErrSealedAuthentication", err)
		}
	})
	t.Run("SealDestroyedKey", func(t *testing.T) {
		dev, s, _ := setup(t)
		dev.setFaults(deviceFaults{seal: enclave.ErrEnclaveDestroyed})
		if err := seal(s); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("a device key destroyed under a seal: %v, want ErrEnclaveDestroyed", err)
		}
	})
	t.Run("OpenFailure", func(t *testing.T) {
		dev, _, v := setup(t)
		dev.setFaults(deviceFaults{open: errDevice})
		_, err := v.Open(ctx)
		var oe *enclave.OpenError
		if !errors.As(err, &oe) || !errors.Is(err, enclave.ErrOpenFailed) || !errors.Is(err, errDevice) {
			t.Fatalf("a device open failure: %v, want an *OpenError carrying the device's error", err)
		}
		dev.setFaults(deviceFaults{})
		requireOpensTo(t, ctx, v, n)
	})
	t.Run("OpenAuthentication", func(t *testing.T) {
		dev, _, v := setup(t)
		dev.setFaults(deviceFaults{open: enclave.ErrAEADAuthentication})
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("a device authentication failure on open: %v, want ErrSealedAuthentication", err)
		}
	})
	t.Run("PlaintextEscapes", func(t *testing.T) {
		dev, _, v := setup(t)
		dev.setFaults(deviceFaults{escape: true})
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrPlaintextEscaped) {
			t.Fatalf("a device that returned the key outside the buffer it was given: %v, want ErrPlaintextEscaped", err)
		}
		dev.setFaults(deviceFaults{})
		requireOpensTo(t, ctx, v, n)
	})
	t.Run("ShortPlaintext", func(t *testing.T) {
		dev, _, v := setup(t)
		dev.setFaults(deviceFaults{short: true})
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("a device that returned a short key: %v, want ErrSealedAuthentication", err)
		}
	})
}

func TestSealing_OpenInPlacesTheValueInAnImporter(t *testing.T) {
	ctx := context.Background()
	dev := newDeviceBackend()
	s := rootSealerOn(t, dev)
	n := newNeedle(t)
	v := sealNeedle(t, ctx, s, n)
	defer v.Destroy()
	before := len(dev.imports())

	h, err := v.OpenIn(ctx, dev)
	if err != nil {
		t.Fatalf("OpenIn an importer: %v", err)
	}
	defer h.Destroy()

	calls := dev.imports()
	if len(calls) != before+1 || calls[before].spec.Purpose != enclave.PurposeMaterial || calls[before].size != needleLen {
		t.Fatalf("imports = %+v after OpenIn, want one more of %d bytes with PurposeMaterial", calls, needleLen)
	}
	if h.Backend() != enclave.Backend(dev) {
		t.Fatalf("the opened handle's backend is %v, want the importer it was opened in", h.Backend())
	}
	ba, ok := h.(enclave.ByteAccess)
	if !ok {
		t.Fatalf("OpenIn returned a %T, want one with byte access", h)
	}
	var matches bool
	if err := ba.WithBytes(func(b []byte) error { matches = n.equals(b); return nil }); err != nil || !matches {
		t.Fatalf("the imported value: matches %t, err %v", matches, err)
	}
}

func TestSealing_OpenInRefusesWhatCannotHoldTheValue(t *testing.T) {
	ctx := context.Background()
	dev := newDeviceBackend()
	s := rootSealerOn(t, dev)
	n := newNeedle(t)
	v := sealNeedle(t, ctx, s, n)
	defer v.Destroy()

	t.Run("BackendWithoutImport", func(t *testing.T) {
		plain := &fakeBackend{name: uniqueBackendName("plain")}
		_, err := v.OpenIn(ctx, plain)
		ce := requireCapabilityError(t, "OpenIn a backend that cannot import", err, enclave.CapabilityImport)
		if ce.Backend != plain.Name() {
			t.Fatalf("CapabilityError.Backend = %q, want %q", ce.Backend, plain.Name())
		}
	})
	t.Run("NilBackend", func(t *testing.T) {
		if _, err := v.OpenIn(ctx, nil); !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Fatalf("OpenIn(nil): %v, want ErrInvalidBackend", err)
		}
		var typedNil *deviceBackend
		if _, err := v.OpenIn(ctx, typedNil); !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Fatalf("OpenIn a typed-nil backend: %v, want ErrInvalidBackend", err)
		}
	})
	t.Run("TheDefaultBackendOpensAnEnclave", func(t *testing.T) {
		h, err := v.OpenIn(ctx, enclave.DefaultBackend())
		if err != nil {
			t.Fatalf("OpenIn the default backend: %v", err)
		}
		defer h.Destroy()
		if _, ok := h.(*enclave.Memory); !ok {
			t.Fatalf("OpenIn the default backend returned a %T, want *enclave.Memory", h)
		}
	})
	t.Run("DestroyedValue", func(t *testing.T) {
		gone := sealNeedle(t, ctx, s, n)
		if err := gone.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if _, err := gone.OpenIn(ctx, dev); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Fatalf("OpenIn a destroyed value: %v, want ErrEnclaveDestroyed", err)
		}
		plain := &fakeBackend{name: uniqueBackendName("plain")}
		requireCapabilityError(t, "OpenIn a destroyed value into a backend that cannot import", firstErr(gone.OpenIn(ctx, plain)), enclave.CapabilityImport)
	})
	t.Run("ImportFailure", func(t *testing.T) {
		target := newDeviceBackend()
		target.setHook(func(int, enclave.ImportSpec) error { return errDevice })
		target.setReturnsHandleWithError(true)
		_, err := v.OpenIn(ctx, target)
		var oe *enclave.OpenError
		if !errors.As(err, &oe) || !errors.Is(err, enclave.ErrOpenFailed) || !errors.Is(err, errDevice) {
			t.Fatalf("OpenIn an importer that failed: %v, want an *OpenError carrying its error", err)
		}
		if h := target.handle(1); h == nil || h.IsAlive() {
			t.Fatalf("the handle returned with the failure is %v, want it destroyed", h)
		}
	})
	t.Run("ImportVerdictPassesThrough", func(t *testing.T) {
		target := newDeviceBackend()
		target.setHook(func(int, enclave.ImportSpec) error { return enclave.ErrInvalidImport })
		if _, err := v.OpenIn(ctx, target); !errors.Is(err, enclave.ErrInvalidImport) {
			t.Fatalf("OpenIn an importer that refused the import: %v, want ErrInvalidImport", err)
		}
	})
	t.Run("ContextEndedDuringTheImport", func(t *testing.T) {
		target := newDeviceBackend()
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		target.setHook(func(int, enclave.ImportSpec) error { cancel(); return nil })
		_, err := v.OpenIn(cctx, target)
		requireContextFailure(t, "OpenIn whose context ended in the import", err, enclave.ErrOpenFailed, context.Canceled)
	})
	t.Run("MaterialWithoutByteAccess", func(t *testing.T) {
		target := newDeviceBackend()
		target.setShapes(shapeDefault, shapeOpaque)
		_, err := v.OpenIn(ctx, target)
		requireCapabilityError(t, "OpenIn an importer whose handle has no byte access", err, enclave.CapabilityBytes)
		if h := target.handle(1); h == nil || h.IsAlive() {
			t.Fatalf("the refused handle is %v, want it destroyed", h)
		}
	})
	t.Run("NilMaterialHandle", func(t *testing.T) {
		target := newDeviceBackend()
		target.setShapes(shapeDefault, shapeNil)
		_, err := v.OpenIn(ctx, target)
		requireCapabilityError(t, "OpenIn an importer that returned no handle", err, enclave.CapabilityBytes)
	})
}

// firstErr is the error of a call that also returned a handle.
func firstErr(_ enclave.Handle, err error) error { return err }

func TestSealing_RequiredKeyScheduleErasureIsAcceptedOrRefused(t *testing.T) {
	erases := enclave.KeyScheduleErasure()
	newSealer := func(b enclave.Backend, opts ...enclave.SealerOption) (*enclave.Sealer, error) {
		return enclave.NewSealer(append([]enclave.SealerOption{
			enclave.WithBackend(b), enclave.WithRequireKeyScheduleErasure(),
		}, opts...)...)
	}
	// requireRefusal asserts err names the key class whose schedule would
	// reach the heap.
	requireRefusal := func(t *testing.T, err error, name string) {
		t.Helper()
		var ke *enclave.KeyScheduleExposedError
		if !errors.As(err, &ke) || !errors.Is(err, enclave.ErrKeyScheduleExposed) {
			t.Fatalf("NewSealer: %v, want a *KeyScheduleExposedError matching ErrKeyScheduleExposed", err)
		}
		if ke.Name != name {
			t.Fatalf("KeyScheduleExposedError.Name = %q, want %q", ke.Name, name)
		}
		if ke.Error() == "" {
			t.Fatalf("KeyScheduleExposedError renders as an empty string")
		}
	}
	// requireOutcome asserts a sealer is built exactly when the build erases
	// key schedules, and otherwise is refused for the key class name.
	requireOutcome := func(t *testing.T, s *enclave.Sealer, err error, name string) {
		t.Helper()
		if erases {
			if err != nil {
				t.Fatalf("NewSealer on a build that erases key schedules: %v", err)
			}
			_ = s.Destroy()
			return
		}
		requireRefusal(t, err, name)
	}

	t.Run("RootKeyInTheDefaultBackend", func(t *testing.T) {
		s, err := newSealer(enclave.DefaultBackend(), enclave.WithRootUnsealer(newDevice()))
		requireOutcome(t, s, err, "wrapping-key")
	})
	t.Run("PerOperationKeys", func(t *testing.T) {
		s, err := newSealer(enclave.DefaultBackend(), enclave.WithKeyProtector(&heapProtector{keys: map[string][]byte{}}))
		requireOutcome(t, s, err, "dek")
	})
	t.Run("ImporterThatDoesNotConfine", func(t *testing.T) {
		s, err := newSealer(newDeviceBackend(), enclave.WithRootUnsealer(newDevice()))
		requireOutcome(t, s, err, "dek")
	})
	t.Run("ImporterOutsideAConfinement", func(t *testing.T) {
		s, err := newSealer(confinedDevice{deviceBackend: newDeviceBackend(), confines: false}, enclave.WithRootUnsealer(newDevice()))
		requireOutcome(t, s, err, "dek")
	})
	t.Run("ImporterInsideAConfinement", func(t *testing.T) {
		s, err := newSealer(confinedDevice{deviceBackend: newDeviceBackend(), confines: true}, enclave.WithRootUnsealer(newDevice()))
		if err != nil {
			t.Fatalf("NewSealer on a backend that confines the process: %v, want it accepted whatever the build", err)
		}
		defer s.Destroy()
		n := newNeedle(t)
		v := sealNeedle(t, context.Background(), s, n)
		defer v.Destroy()
		requireOpensTo(t, context.Background(), v, n)
	})
}

func TestSealing_ARotationThatLosesTheRaceDestroysItsKey(t *testing.T) {
	ctx := context.Background()
	dev := newDeviceBackend()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	// The third import is the first rotation's: it parks until released.
	dev.setHook(func(call int, _ enclave.ImportSpec) error {
		if call == 3 {
			close(entered)
			<-release
		}
		return nil
	})
	s := rootSealerOn(t, dev, enclave.WithKEKRotationLimit(1))

	needles := []needle{newNeedle(t), newNeedle(t), newNeedle(t)}
	sealed := make([]enclave.Sealed, len(needles))
	sealed[0] = sealNeedle(t, ctx, s, needles[0])

	// The second seal outlives the generation's limit and parks in the import
	// of the next one.
	done := make(chan error, 1)
	go func() {
		buf := heapBytes(needleLen)
		needles[1].fill(buf)
		v, err := s.Seal(ctx, buf)
		sealed[1] = v
		done <- err
	}()
	<-entered

	// A third seal rotates past it and publishes the next generation.
	sealed[2] = sealNeedle(t, ctx, s, needles[2])
	free()
	if err := <-done; err != nil {
		t.Fatalf("the seal that lost the rotation race: %v", err)
	}
	defer func() {
		for _, v := range sealed {
			_ = v.Destroy()
		}
	}()

	if h := dev.handle(3); h == nil || h.IsAlive() {
		t.Fatalf("the loser's KEK handle is %v, want it destroyed: another seal's generation stands", h)
	}
	for i, v := range sealed {
		requireOpensTo(t, ctx, v, needles[i])
	}
}

func TestSealing_DestroyDuringARotationImportReleasesTheNewKey(t *testing.T) {
	ctx := context.Background()
	dev := newDeviceBackend()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free)
	dev.setHook(func(call int, _ enclave.ImportSpec) error {
		if call == 3 {
			close(entered)
			<-release
		}
		return nil
	})
	s := rootSealerOn(t, dev, enclave.WithKEKRotationLimit(1))
	first := sealNeedle(t, ctx, s, newNeedle(t))
	defer first.Destroy()

	done := make(chan error, 1)
	go func() {
		buf := heapBytes(needleLen)
		newNeedle(t).fill(buf)
		v, err := s.Seal(ctx, buf)
		if err == nil {
			_ = v.Destroy()
		}
		done <- err
	}()
	<-entered
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy during a rotation import: %v", err)
	}
	free()
	if err := <-done; !errors.Is(err, enclave.ErrSealerDestroyed) {
		t.Fatalf("the seal that overlapped Destroy: %v, want ErrSealerDestroyed", err)
	}
	if live := dev.live(); live != 0 {
		t.Fatalf("%d device handles live after Destroy and the rotation's return, want 0", live)
	}
}

func TestSealing_ASealerOnABudgetedAllocatorReturnsItsBudget(t *testing.T) {
	ctx := context.Background()
	unit := enclave.LockedSize(enclave.RootKeyBytes)

	t.Run("RotatesWithinTheBudget", func(t *testing.T) {
		a, err := enclave.NewAllocator(16 * unit)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		s := rootSealerOn(t, a, enclave.WithKEKRotationLimit(2))
		n := newNeedle(t)
		var sealed []enclave.Sealed
		for range 7 {
			sealed = append(sealed, sealNeedle(t, ctx, s, n))
		}
		defer func() {
			for _, v := range sealed {
				_ = v.Destroy()
			}
		}()
		if a.InUse() < 2*unit {
			t.Fatalf("InUse = %d after sealing, want at least the wrapping key and a KEK (%d)", a.InUse(), 2*unit)
		}
		for _, v := range sealed {
			requireOpensTo(t, ctx, v, n)
		}
		if err := s.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		for _, v := range sealed {
			_ = v.Destroy()
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("InUse = %d after Destroy, want 0: the sealer returned its keys' budget", got)
		}
	})
	t.Run("RunsOutMidHierarchy", func(t *testing.T) {
		a, err := enclave.NewAllocator(unit)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		s := rootSealerOn(t, a)
		buf := heapBytes(needleLen)
		newNeedle(t).fill(buf)
		if _, err := s.Seal(ctx, buf); !errors.Is(err, enclave.ErrBudgetExhausted) {
			t.Fatalf("Seal with room for the wrapping key only: %v, want ErrBudgetExhausted", err)
		}
		if err := s.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("InUse = %d after Destroy, want 0: the wrapping key that was imported must be returned", got)
		}
	})
}

// cancelingProtector ends its context with a cause, then fails.
type cancelingProtector struct {
	heapProtector
	cancel context.CancelCauseFunc
	cause  error
}

func (p *cancelingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	p.cancel(p.cause)
	return nil, errDevice
}

func TestSealing_AFailureThatEndedTheContextReportsAllOfIt(t *testing.T) {
	cause := errors.New("operator pulled the plug")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	p := &cancelingProtector{heapProtector: heapProtector{keys: map[string][]byte{}}, cancel: cancel, cause: cause}
	s, err := enclave.NewSealer(enclave.WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	defer s.Destroy()

	buf := heapBytes(needleLen)
	newNeedle(t).fill(buf)
	_, err = s.Seal(ctx, buf)
	// The sentinel, the context's own error, its cause, and what the provider
	// said, all reachable.
	for _, want := range []error{enclave.ErrSealFailed, context.Canceled, cause, errDevice} {
		if !errors.Is(err, want) {
			t.Fatalf("Seal: %v, want it to match %v", err, want)
		}
	}
	if errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("Seal: %v also matches ErrSealedAuthentication — a cancellation reported as a forgery", err)
	}
	for _, part := range []string{context.Canceled.Error(), cause.Error(), errDevice.Error()} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("Seal error %q does not render %q", err.Error(), part)
		}
	}
}
