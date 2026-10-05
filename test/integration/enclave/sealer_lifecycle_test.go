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
	"fmt"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers Sealer.Destroy and SoftwareProvider.Destroy as the kernel sees them:
// locked memory returns to its baseline however many sealers come and go,
// and a destroyed sealer or provider fails closed.

// TestDestroyedSealersReturnTheirLockedMemory creates, uses and destroys many
// sealers of each shape and requires VmLck back at its baseline: before
// Destroy existed every retired sealer kept its keys locked until
// RLIMIT_MEMLOCK ran out.
func TestDestroyedSealersReturnTheirLockedMemory(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		a, err := enclave.NewAllocator(1 << 16)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		// Each shape returns its options and, for an injected provider the
		// sealer does not own, the provider's own release.
		shapes := map[string]func() ([]enclave.SealerOption, func() error){
			"default": func() ([]enclave.SealerOption, func() error) { return nil, nil },
			"per-operation": func() ([]enclave.SealerOption, func() error) {
				p := enclave.NewSoftwareProvider()
				return []enclave.SealerOption{enclave.WithKeyProtector(p)}, p.Destroy
			},
			"rotating root key": func() ([]enclave.SealerOption, func() error) {
				return []enclave.SealerOption{enclave.WithKEKRotationLimit(1)}, nil
			},
		}
		base := vmLck(t)
		for name, shape := range shapes {
			for i := range 64 {
				opts, release := shape()
				s, err := enclave.NewSealer(opts...)
				if err != nil {
					t.Fatalf("%s: NewSealer: %v", name, err)
				}
				n := newNeedle(t)
				v := sealNeedle(t, ctx, s, n)
				w := sealNeedle(t, ctx, s, newNeedle(t))
				o, err := v.OpenWith(ctx, a)
				if err != nil {
					t.Fatalf("%s %d: OpenWith: %v", name, i, err)
				}
				_ = o.Destroy()
				if err := s.Destroy(); err != nil {
					t.Fatalf("%s %d: Destroy: %v", name, i, err)
				}
				if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrSealerDestroyed) {
					t.Errorf("%s: Open after Destroy = %v, want ErrSealerDestroyed", name, err)
				}
				if err := w.Openable(); !errors.Is(err, enclave.ErrSealerDestroyed) {
					t.Errorf("%s: Openable after Destroy = %v, want ErrSealerDestroyed", name, err)
				}
				buf := heapBytes(needleLen)
				if _, err := s.Seal(ctx, buf); !errors.Is(err, enclave.ErrSealerDestroyed) || !allZero(buf) {
					t.Errorf("%s: Seal after Destroy = %v (wiped=%t), want ErrSealerDestroyed and a wiped slice", name, err, allZero(buf))
				}
				if err := s.Destroy(); err != nil {
					t.Errorf("%s: second Destroy = %v", name, err)
				}
				if err := v.Destroy(); err != nil {
					t.Errorf("%s: SealedEnclave.Destroy = %v", name, err)
				}
				_ = w.Destroy()
				if release != nil {
					if err := release(); err != nil {
						t.Errorf("%s: provider Destroy = %v", name, err)
					}
				}
			}
		}
		if got := vmLck(t); got != base {
			t.Errorf("VmLck = %d after destroying every sealer, want the baseline %d", got, base)
		}
		if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v), want (0, nil): Destroy left something on the ledger", held, err)
		}
	})
}

// TestSealerDestroyLeavesAnInjectedProviderToItsOwner: an injected
// SoftwareProvider survives the sealer's Destroy, and its own Destroy then
// fails every sealer that uses it closed.
func TestSealerDestroyLeavesAnInjectedProviderToItsOwner(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		p := enclave.NewSoftwareProvider()

		first, err := enclave.NewSealer(enclave.WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		sealNeedle(t, ctx, first, newNeedle(t)).Destroy()
		if err := first.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}

		perOp, err := enclave.NewSealer(enclave.WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, perOp, n)
		defer v.Destroy()
		requireOpensTo(t, ctx, v, n)

		rootKey, err := enclave.NewSealer(enclave.WithRootUnsealer(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}

		if err := p.Destroy(); err != nil {
			t.Fatalf("provider Destroy: %v", err)
		}
		if err := p.Destroy(); err != nil {
			t.Errorf("second provider Destroy = %v", err)
		}
		if _, err := perOp.Seal(ctx, heapBytes(needleLen)); !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Errorf("per-operation Seal after the provider's Destroy = %v, want ErrSealerDestroyed", err)
		}
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Errorf("Open after the provider's Destroy = %v, want ErrSealerDestroyed", err)
		}
		if err := v.Openable(); !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Errorf("Openable after the provider's Destroy = %v, want ErrSealerDestroyed", err)
		}
		if _, err := rootKey.Seal(ctx, heapBytes(needleLen)); !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Errorf("root-key Seal over a destroyed provider = %v, want ErrSealerDestroyed", err)
		}
		if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v), want (0, nil)", held, err)
		}
	})
}

// TestSealerDestroyDuringABlockedUnseal: Destroy returns while the provider
// is still unsealing, and the root it then delivers is released, never
// published.
func TestSealerDestroyDuringABlockedUnseal(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		g := &gatedUnsealer{soft: enclave.NewSoftwareProvider(), entered: make(chan struct{}), release: make(chan struct{})}
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(g))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := s.Seal(ctx, heapBytes(needleLen))
			result <- err
		}()
		<-g.entered
		if err := s.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		close(g.release)
		if err := <-result; !errors.Is(err, enclave.ErrSealerDestroyed) {
			t.Fatalf("Seal raced by Destroy = %v, want ErrSealerDestroyed", err)
		}
		if err := g.soft.Destroy(); err != nil {
			t.Fatalf("provider Destroy: %v", err)
		}
		if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v), want (0, nil): the pending root outlived Destroy", held, err)
		}
	})
}

// TestUnconstructedSealerAndRedactedFormatting: a zero-value Sealer refuses
// without panicking and wipes its input, and %#v never prints an enclave's
// contents.
func TestUnconstructedSealerAndRedactedFormatting(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		var zero enclave.Sealer
		buf := heapBytes(needleLen)
		newNeedle(t).fill(buf)
		if _, err := zero.Seal(ctx, buf); !errors.Is(err, enclave.ErrSealerNotConstructed) || !allZero(buf) {
			t.Errorf("zero-value Seal = %v (wiped=%t), want ErrSealerNotConstructed and a wiped slice", err, allZero(buf))
		}
		if err := zero.Destroy(); err != nil {
			t.Errorf("zero-value Destroy = %v", err)
		}

		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		defer func() { _ = s.Destroy() }()
		v := sealNeedle(t, ctx, s, newNeedle(t))
		o, err := v.Open(ctx)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		for what, got := range map[string]string{
			"SealedEnclave": fmt.Sprintf("%#v", v),
			"MemoryEnclave": fmt.Sprintf("%#v", o),
		} {
			if got != what+"(sealed)" && got != what+"(redacted)" {
				t.Errorf("%%#v of a %s = %q, want its redacted form", what, got)
			}
		}
		_ = o.Destroy()
		v.Destroy()
		if got := fmt.Sprintf("%#v", v); got != "SealedEnclave(destroyed)" {
			t.Errorf("%%#v of a destroyed SealedEnclave = %q", got)
		}
	})
}
