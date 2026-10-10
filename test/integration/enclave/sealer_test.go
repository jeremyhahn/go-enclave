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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// Covers sealer.go: sealing end to end with the shipped SoftwareProvider
// behind the provider seam, in both modes; the context contract through to the
// provider; the root-unseal serialization; the one-shot process Sealer; KEK
// rotation through WithKEKRotationLimit; locked memory refused at each step of
// the hierarchy; and what a shutdown sweep does to a sealer's keys.
//
// The 2^31 ceilings (ErrSealerExhausted, and the software provider's Protect
// budget) are not configurable and take 2^31 locked-memory operations to
// reach; the in-package unit tests position those counters at the boundary.

var sealerModes = []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation}

// TestSealing_SealerRoundTripsManyValuesInBothModes seals many distinct values from
// concurrent goroutines and opens every one of them, in both modes, through a
// consumer-injected provider backed by the SoftwareProvider. It checks the
// ownership contract (each caller slice is wiped by Seal), that every value
// opens to exactly its own material, how often the Sealer reached the
// provider (ModeRootKey: one root unseal for the sealer's whole life and no
// per-value calls; ModePerOperation: one Protect per seal and one Unprotect per
// open), that two opens are independent enclaves, and the lifecycle answers
// of IsAlive/Openable/Open after Destroy and after a shutdown sweep.
func TestSealing_SealerRoundTripsManyValuesInBothModes(t *testing.T) {
	for _, mode := range sealerModes {
		t.Run(mode.String(), func(t *testing.T) {
			isolated(t, childOpts{}, func(t *testing.T) {
				ctx := context.Background()
				dev := newDevice()
				s, err := enclave.NewSealer(providerOption(dev, mode))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}
				if s.Mode() != mode {
					t.Fatalf("Mode() = %v, want %v", s.Mode(), mode)
				}

				const values, workers = 1024, 8
				needles := make([]needle, values)
				sealed := make([]*enclave.Sealed, values)
				for i := range needles {
					needles[i] = newNeedle(t)
				}
				forEach(t, values, workers, func(i int) error {
					buf := heapBytes(needleLen)
					needles[i].fill(buf)
					sv, err := s.Seal(ctx, buf)
					if err != nil {
						return err
					}
					if !memscan.AllZero(buf) {
						return errors.New("Seal did not wipe the caller's slice")
					}
					sealed[i] = sv
					return nil
				})
				forEach(t, values, workers, func(i int) error {
					o, err := sealed[i].Open(ctx)
					if err != nil {
						return err
					}
					defer func() { _ = o.Destroy() }()
					var ok bool
					if err := o.WithBytes(func(b []byte) error { ok = needles[i].equals(b); return nil }); err != nil {
						return err
					}
					if !ok {
						return errors.New("opened to material other than what was sealed")
					}
					return nil
				})

				switch mode {
				case enclave.ModeRootKey:
					if dev.unseals.Load() != 1 || dev.unsealAttempts.Load() != 1 || dev.protects.Load() != 0 || dev.unprotects.Load() != 0 {
						t.Fatalf("provider calls: %d root unseal attempts (%d succeeded), %d Protect, %d Unprotect; want exactly one root unseal and no per-value calls",
							dev.unsealAttempts.Load(), dev.unseals.Load(), dev.protects.Load(), dev.unprotects.Load())
					}
				case enclave.ModePerOperation:
					if dev.protects.Load() != values || dev.unprotects.Load() != values || dev.unsealAttempts.Load() != 0 {
						t.Fatalf("provider calls: %d Protect, %d Unprotect, %d root unseal; want %d, %d, 0",
							dev.protects.Load(), dev.unprotects.Load(), dev.unsealAttempts.Load(), values, values)
					}
				}

				// Two opens are two independent enclaves.
				v := sealed[0]
				o1, err := v.Open(ctx)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				o2, err := v.Open(ctx)
				if err != nil {
					t.Fatalf("second Open: %v", err)
				}
				if dataAddr(t, o1) == dataAddr(t, o2) {
					t.Fatalf("two opens returned the same pages")
				}
				if err := o1.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				var ok bool
				if err := o2.WithBytes(func(b []byte) error { ok = needles[0].equals(b); return nil }); err != nil || !ok {
					t.Fatalf("the second open after destroying the first: ok %t, err %v", ok, err)
				}
				if err := o2.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}

				// Destroying a sealed value.
				if !v.IsAlive() || v.Openable() != nil {
					t.Fatalf("live sealed value: IsAlive %t, Openable %v", v.IsAlive(), v.Openable())
				}
				v.Destroy()
				v.Destroy() // idempotent
				if v.IsAlive() {
					t.Errorf("IsAlive after Destroy")
				}
				if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
					t.Errorf("Open after Destroy: %v, want ErrEnclaveDestroyed", err)
				}
				if err := v.Openable(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
					t.Errorf("Openable after Destroy: %v, want ErrEnclaveDestroyed", err)
				}

				// A shutdown sweep destroys the sealer's in-process keys: in
				// ModeRootKey the hierarchy, in ModePerOperation the
				// SoftwareProvider's root behind the device. The values keep their
				// ciphertext, none opens, and the sealer fails closed. Openable
				// answers ErrSealerWiped in ModeRootKey and, with no HealthReporter,
				// ErrOpenabilityUnknown (never nil) in ModePerOperation.
				if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
					t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
				}
				w := sealed[1]
				if !w.IsAlive() {
					t.Errorf("IsAlive after WipeAll = false; the ciphertext is still held")
				}
				wantOpenable := enclave.ErrSealerWiped
				if mode == enclave.ModePerOperation {
					wantOpenable = enclave.ErrOpenabilityUnknown
				}
				if err := w.Openable(); !errors.Is(err, wantOpenable) {
					t.Errorf("Openable after WipeAll: %v, want %v", err, wantOpenable)
				}
				if _, err := w.Open(ctx); !errors.Is(err, enclave.ErrSealerWiped) || errors.Is(err, enclave.ErrSealedAuthentication) {
					t.Errorf("Open after WipeAll: %v, want ErrSealerWiped and not ErrSealedAuthentication", err)
				}
				if _, err := s.Seal(ctx, []byte("after the sweep")); !errors.Is(err, enclave.ErrSealerWiped) {
					t.Errorf("Seal after WipeAll: %v, want ErrSealerWiped (no silent re-keying)", err)
				}
				t.Logf("%v: %d values sealed and opened by %d workers; provider: %d root unseal(s), %d Protect, %d Unprotect",
					mode, values, workers, dev.unseals.Load(), dev.protects.Load(), dev.unprotects.Load())
			})
		})
	}
}

// TestSealing_SealerContextReachesTheProvider exercises the context contract with a
// provider that blocks until told otherwise (ModePerOperation, where every
// seal and open calls the provider):
//
//   - a context that ended before the call fails the seal (ErrSealFailed) and
//     the open (ErrOpenFailed), each also matching context.Canceled, never
//     ErrSealedAuthentication; the provider is not called; the caller's slice
//     is still wiped; and the value opens afterwards with a live context;
//   - a DEADLINE reaches a stalled provider: the seal and the open return
//     ErrSealFailed/ErrOpenFailed matching context.DeadlineExceeded, and the
//     value is intact;
//   - no Sealer or Sealed lock is held across a provider call:
//     while one seal and one open are stalled inside the provider, a second
//     seal and open on the SAME sealer complete, and Destroy of the value
//     being opened returns without waiting for that open.
func TestSealing_SealerContextReachesTheProvider(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		live := context.Background()
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithKeyProtector(dev))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, live, s, n)

		// Ended before the call.
		canceled, cancel := context.WithCancel(live)
		cancel()
		before := dev.protects.Load()
		buf := heapBytes(needleLen)
		n.fill(buf)
		_, err = s.Seal(canceled, buf)
		requireContextFailure(t, "Seal with an ended context", err, enclave.ErrSealFailed, context.Canceled)
		if !memscan.AllZero(buf) {
			t.Errorf("Seal with an ended context did not wipe the caller's slice")
		}
		if dev.protects.Load() != before {
			t.Errorf("Seal with an ended context reached the provider")
		}
		_, err = v.Open(canceled)
		requireContextFailure(t, "Open with an ended context", err, enclave.ErrOpenFailed, context.Canceled)
		requireOpensTo(t, live, v, n)

		// A deadline reaches a stalled provider. The deadline passes only once
		// the provider is known to be blocked on it (see deadlineContext), so
		// the result cannot depend on how fast this host is.
		dl := newDeadlineContext()
		stalled, entered := stallingContext(dl)
		n.fill(buf)
		sealErr := make(chan error, 1)
		go func() { _, err := s.Seal(stalled, buf); sealErr <- err }()
		<-entered
		dl.expire()
		requireContextFailure(t, "Seal past its deadline in the provider", <-sealErr, enclave.ErrSealFailed, context.DeadlineExceeded)
		if !memscan.AllZero(buf) {
			t.Errorf("Seal that timed out in the provider did not wipe the caller's slice")
		}
		dl = newDeadlineContext()
		stalled, entered = stallingContext(dl)
		openErr := make(chan error, 1)
		go func() {
			o, err := v.Open(stalled)
			if err == nil {
				_ = o.Destroy()
			}
			openErr <- err
		}()
		<-entered
		dl.expire()
		requireContextFailure(t, "Open past its deadline in the provider", <-openErr, enclave.ErrOpenFailed, context.DeadlineExceeded)
		requireOpensTo(t, live, v, n)

		// No lock across a provider call: park a seal and an open inside the
		// provider, then use the same sealer and the same value around them.
		sealCtx, cancelSeal := context.WithCancel(live)
		sealCtx, sealEntered := stallingContext(sealCtx)
		sealDone := make(chan error, 1)
		go func() {
			b := heapBytes(needleLen)
			b[0] = 1
			_, err := s.Seal(sealCtx, b)
			sealDone <- err
		}()
		openCtx, cancelOpen := context.WithCancel(live)
		openCtx, openEntered := stallingContext(openCtx)
		openDone := make(chan error, 1)
		go func() {
			o, err := v.Open(openCtx)
			if err == nil {
				_ = o.Destroy()
			}
			openDone <- err
		}()
		<-sealEntered
		<-openEntered

		m := newNeedle(t)
		other := sealNeedle(t, live, s, m) // same sealer, while a seal is parked in the provider
		requireOpensTo(t, live, other, m)
		requireOpensTo(t, live, v, n) // same value, while an open of it is parked in the provider
		v.Destroy()                   // must not wait for the parked open

		cancelSeal()
		cancelOpen()
		requireContextFailure(t, "the parked Seal, once canceled", <-sealDone, enclave.ErrSealFailed, context.Canceled)
		requireContextFailure(t, "the parked Open, once canceled", <-openDone, enclave.ErrOpenFailed, context.Canceled)
		if _, err := v.Open(live); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Open after Destroy: %v, want ErrEnclaveDestroyed", err)
		}

		if n, err := enclave.WipeAll(live); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestSealing_SealerRootUnsealIsSerializedAndAbandonable is the ModeRootKey first-use
// path. The first seal unseals the root through the provider; a second caller
// arriving meanwhile QUEUES behind it rather than unsealing a second time, and
// leaves the queue as soon as ITS OWN context ends — while the first is still
// stuck in the provider. When the first caller gives up too, nothing was
// unsealed, so the next caller unseals the root (once) and every later seal
// reuses it.
func TestSealing_SealerRootUnsealIsSerializedAndAbandonable(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		live := context.Background()
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}

		ctxA, cancelA := context.WithCancel(live)
		ctxA, enteredA := stallingContext(ctxA)
		doneA := make(chan error, 1)
		go func() { _, err := s.Seal(ctxA, []byte{1}); doneA <- err }()
		<-enteredA

		ctxB, cancelB := context.WithCancel(live)
		ctxB, queuedB := waitObservingContext(ctxB)
		doneB := make(chan error, 1)
		go func() { _, err := s.Seal(ctxB, []byte{2}); doneB <- err }()
		<-queuedB // B is waiting on the initialization slot, not still at entry
		cancelB()
		requireContextFailure(t, "the queued second caller, canceled", <-doneB, enclave.ErrSealFailed, context.Canceled)
		select {
		case err := <-doneA:
			t.Fatalf("the first caller returned (%v) while its provider call was still parked", err)
		default:
		}

		cancelA()
		requireContextFailure(t, "the first caller, canceled inside UnsealRoot", <-doneA, enclave.ErrSealFailed, context.Canceled)

		n := newNeedle(t)
		v := sealNeedle(t, live, s, n)
		for i := 0; i < 64; i++ {
			sealNeedle(t, live, s, newNeedle(t)).Destroy()
		}
		requireOpensTo(t, live, v, n)
		if dev.unsealAttempts.Load() != 2 || dev.unseals.Load() != 1 {
			t.Fatalf("UnsealRoot: %d attempts, %d succeeded; want 2 attempts (the abandoned first caller and the next) and exactly 1 success — the queued caller must never have reached the provider",
				dev.unsealAttempts.Load(), dev.unseals.Load())
		}
		if n, err := enclave.WipeAll(live); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestSealing_ProcessSealerIsInstalledOnce covers NewSealed and SetSealer, the
// process-wide pair, in the two orders a program can use them.
func TestSealing_ProcessSealerIsInstalledOnce(t *testing.T) {
	// The binary installs its sealer first; NewSealed then uses it. A seal
	// refused for an ended context before that must NOT have installed the
	// software default in the meantime.
	t.Run("SetSealerFirst", func(t *testing.T) {
		isolated(t, childOpts{}, func(t *testing.T) {
			live := context.Background()
			if err := enclave.SetSealer(nil); !errors.Is(err, enclave.ErrNilSealer) {
				t.Fatalf("SetSealer(nil): %v, want ErrNilSealer", err)
			}
			canceled, cancel := context.WithCancel(live)
			cancel()
			_, err := enclave.NewSealed(canceled, []byte{1})
			requireContextFailure(t, "NewSealed with an ended context", err, enclave.ErrSealFailed, context.Canceled)

			dev := newDevice()
			s, err := enclave.NewSealer(enclave.WithKeyProtector(dev))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			if err := enclave.SetSealer(s); err != nil {
				t.Fatalf("SetSealer after a refused NewSealed: %v — the refused call installed a default", err)
			}
			n := newNeedle(t)
			buf := heapBytes(needleLen)
			n.fill(buf)
			v, err := enclave.NewSealed(live, buf)
			if err != nil {
				t.Fatalf("NewSealed: %v", err)
			}
			if dev.protects.Load() != 1 {
				t.Fatalf("NewSealed reached the installed sealer's provider %d times, want 1", dev.protects.Load())
			}
			requireOpensTo(t, live, v, n)
			if err := enclave.SetSealer(s); !errors.Is(err, enclave.ErrSealerInstalled) {
				t.Fatalf("second SetSealer: %v, want ErrSealerInstalled", err)
			}
			if n, err := enclave.WipeAll(live); n != 0 || err != nil {
				t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
			}
		})
	})
	// Out of the box: the first NewSealed installs the pure-software default,
	// and the configuration is then locked.
	t.Run("DefaultInstalledByFirstSeal", func(t *testing.T) {
		isolated(t, childOpts{}, func(t *testing.T) {
			live := context.Background()
			n := newNeedle(t)
			buf := heapBytes(needleLen)
			n.fill(buf)
			v, err := enclave.NewSealed(live, buf)
			if err != nil {
				t.Fatalf("NewSealed: %v", err)
			}
			requireOpensTo(t, live, v, n)
			s, err := enclave.NewSealer()
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			if err := enclave.SetSealer(s); !errors.Is(err, enclave.ErrSealerInstalled) {
				t.Fatalf("SetSealer after the default was installed: %v, want ErrSealerInstalled", err)
			}
			if n, err := enclave.WipeAll(live); n != 0 || err != nil {
				t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
			}
			if _, err := enclave.NewSealed(live, []byte{1}); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Fatalf("NewSealed after the sweep destroyed the default's keys: %v, want ErrSealerWiped", err)
			}
		})
	})
}

// TestSealing_SealerRotatesKEKGenerationsUnderRealLockedMemory drives ModeRootKey KEK
// rotation through the public crypto-period option against real locked
// memory: concurrent seals at a three-wrap crypto-period cross many
// generations; every value — sealed under the current generation or a retired
// one — opens to its own material; rotation never goes back to the provider
// (one root unseal for the sealer's life); and a retired generation costs no
// locked memory, so the locked footprint after many rotations is the same as
// after one.
func TestSealing_SealerRotatesKEKGenerationsUnderRealLockedMemory(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev), enclave.WithKEKRotationLimit(3))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}

		// One generation's worth first, to measure the steady footprint: the
		// wrapping key and one KEK.
		first := newNeedle(t)
		v0 := sealNeedle(t, ctx, s, first)
		defer v0.Destroy()
		steady := vmLck(t)

		const values, workers = 96, 8
		needles := make([]needle, values)
		sealed := make([]*enclave.Sealed, values)
		for i := range needles {
			needles[i] = newNeedle(t)
		}
		forEach(t, values, workers, func(i int) error {
			buf := heapBytes(needleLen)
			needles[i].fill(buf)
			v, err := s.Seal(ctx, buf)
			if err != nil {
				return err
			}
			sealed[i] = v
			return nil
		})
		defer func() {
			for _, v := range sealed {
				v.Destroy()
			}
		}()
		if after := vmLck(t); after != steady {
			t.Errorf("VmLck = %d after %d seals across ~%d generations, want %d as after the first: a retired generation must cost no locked memory",
				after, values, values/3, steady)
		}

		requireOpensTo(t, ctx, v0, first)
		forEach(t, values, workers, func(i int) error {
			o, err := sealed[i].Open(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = o.Destroy() }()
			var ok bool
			if err := o.WithBytes(func(b []byte) error { ok = needles[i].equals(b); return nil }); err != nil {
				return err
			}
			if !ok {
				return errors.New("a value opened to material other than what was sealed")
			}
			return nil
		})
		if dev.unsealAttempts.Load() != 1 {
			t.Errorf("UnsealRoot attempts = %d across many rotations, want 1: rotation must never go back to the provider", dev.unsealAttempts.Load())
		}
	})
}

// TestShutdownSweep_SealerIsWipedForGoodAfterASweep: a ModeRootKey sealer whose keys a
// shutdown sweep destroyed refuses every later seal and open with
// ErrSealerWiped — including a seal that would have rotated — reports it from
// Openable, and never goes back to its provider for a new root.
func TestShutdownSweep_SealerIsWipedForGoodAfterASweep(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev), enclave.WithKEKRotationLimit(1))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)
		defer v.Destroy()
		retired := sealNeedle(t, ctx, s, newNeedle(t)) // rotates: v is now under a retired generation
		defer retired.Destroy()

		if c, err := enclave.WipeAll(ctx); c != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v)", c, err)
		}
		for i := range 2 {
			if _, err := s.Seal(ctx, heapBytes(needleLen)); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Errorf("Seal %d after the sweep = %v, want ErrSealerWiped", i, err)
			}
		}
		for name, sv := range map[string]*enclave.Sealed{"retired-generation value": v, "current-generation value": retired} {
			if _, err := sv.Open(ctx); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Errorf("Open of the %s after the sweep = %v, want ErrSealerWiped", name, err)
			}
			if err := sv.Openable(); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Errorf("Openable of the %s after the sweep = %v, want ErrSealerWiped", name, err)
			}
		}
		if got := dev.unsealAttempts.Load(); got != 1 {
			t.Errorf("UnsealRoot attempts = %d, want 1: a wiped sealer must not ask its provider again", got)
		}
	})
}

// TestSealing_SealerFailsCleanlyWhenLockedMemoryRunsOutMidHierarchy refuses the
// kernel lock at each step of building and using a ModeRootKey hierarchy —
// the root destination, the provider's own root, the first KEK, a rotated KEK, a retired KEK materialized for an
// open, and an open's own DEK — and requires every one to fail with
// ErrLockedMemoryUnavailable, keep what already succeeded (a root unsealed is
// never unsealed again), leave every existing value openable, and succeed on
// the next attempt once memory is available again.
func TestSealing_SealerFailsCleanlyWhenLockedMemoryRunsOutMidHierarchy(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		f := installFaultInjector(t, 0)
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev), enclave.WithKEKRotationLimit(1))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}

		// refusedAt runs op with the lock refused after skip successful ones,
		// requires the documented failure, then lifts the refusal.
		refusedAt := func(what string, skip uint64, op func() error) {
			t.Helper()
			f.refuseAfter(unix.SYS_MLOCK, unix.ENOMEM, skip)
			err := op()
			f.allow(unix.SYS_MLOCK)
			requireRefused(t, f, unix.SYS_MLOCK)
			if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
				t.Fatalf("%s with the lock refused = %v, want ErrLockedMemoryUnavailable", what, err)
			}
		}
		seal := func() error {
			// Real (nonzero) material, so a refusal that skipped the wipe is
			// visible in the check below.
			buf := heapBytes(needleLen)
			newNeedle(t).fill(buf)
			_, err := s.Seal(ctx, buf)
			if err != nil && !memscan.AllZero(buf) {
				t.Error("a refused Seal did not wipe the caller's slice")
			}
			return err
		}

		// The DEK, then the sealer's root destination: nothing reaches the
		// provider until the root has locked pages to land in.
		refusedAt("Seal (its DEK)", 0, seal)
		refusedAt("Seal (the root destination)", 1, seal)
		if got := dev.unsealAttempts.Load(); got != 0 {
			t.Fatalf("UnsealRoot attempts = %d before any root had locked pages, want 0", got)
		}
		// The provider's own root (the SoftwareProvider behind this device
		// generates it at first use): the unseal FAILS, so asking again is
		// permitted.
		refusedAt("Seal (the provider's root)", 2, seal)
		if a, ok := dev.unsealAttempts.Load(), dev.unseals.Load(); a != 1 || ok != 0 {
			t.Fatalf("after the provider's root was refused: %d unseal attempts, %d succeeded; want 1 and 0", a, ok)
		}
		// The first KEK: the unseal SUCCEEDED, so the root is kept for the
		// retry and never unsealed again.
		refusedAt("Seal (the first KEK)", 3, seal)
		if a, ok := dev.unsealAttempts.Load(), dev.unseals.Load(); a != 2 || ok != 1 {
			t.Fatalf("after the KEK mint was refused: %d unseal attempts, %d succeeded; want 2 and 1", a, ok)
		}
		first := newNeedle(t)
		v1 := sealNeedle(t, ctx, s, first)
		defer v1.Destroy()
		if a := dev.unsealAttempts.Load(); a != 2 {
			t.Fatalf("UnsealRoot attempts = %d after the retry, want still 2: a root unsealed once is kept, never unsealed again", a)
		}

		// A rotation's KEK (the DEK locks first): the spent generation stays
		// published and its values keep opening.
		refusedAt("Seal (a rotated KEK)", 1, seal)
		requireOpensTo(t, ctx, v1, first)
		second := newNeedle(t)
		v2 := sealNeedle(t, ctx, s, second) // rotates: v1 is now under a retired generation
		defer v2.Destroy()

		// An open locks its destination, its DEK, then — for a retired
		// generation — that KEK for the one unwrap.
		refusedAt("Open (its DEK)", 1, func() error { _, err := v1.Open(ctx); return err })
		refusedAt("Open (a retired KEK)", 2, func() error { _, err := v1.Open(ctx); return err })
		requireOpensTo(t, ctx, v1, first)
		requireOpensTo(t, ctx, v2, second)
		if got := dev.unsealAttempts.Load(); got != 2 {
			t.Errorf("UnsealRoot attempts = %d at the end, want 2", got)
		}
		if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil): a refused step left something behind", n, err)
		}
	})
}

// TestSealing_OpenFailsClosedWhenTheFreezeIsRefused: the plaintext an open returns
// is frozen before it is handed back, so a kernel that refuses that mprotect
// fails the open — no enclave, the destination wiped and released, OpenIn's
// reservation returned — rather than returning writable plaintext; the value
// opens normally once the refusal lifts.
func TestSealing_OpenFailsClosedWhenTheFreezeIsRefused(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)
		defer v.Destroy()
		a, err := enclave.NewAllocator(4 * enclave.LockedSize(needleLen))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		f := installFaultInjector(t, 0)
		f.refuseProt(unix.SYS_MPROTECT, unix.EPERM, unix.PROT_READ)
		e, err := openInAllocator(t, ctx, v, a)
		f.allow(unix.SYS_MPROTECT)
		requireRefused(t, f, unix.SYS_MPROTECT)
		if err == nil || e != nil {
			t.Fatalf("OpenIn with the freeze refused = (%v, %v), want (nil, an error)", e, err)
		}
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Errorf("OpenIn with the freeze refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		if used := a.InUse(); used != 0 {
			t.Errorf("InUse = %d after the open failed closed, want 0", used)
		}
		hits, scanned := sweep(t, n)
		requireHitsExactly(t, "the plaintext of an open whose freeze was refused", hits, scanned)
		requireOpensTo(t, ctx, v, n)
	})
}

// gatedUnsealer is a RootUnsealer whose UnsealRoot announces it has started
// — with the sealer's root destination borrowed — and then waits to be
// released, so a test can run a shutdown sweep inside the unseal.
type gatedUnsealer struct {
	soft             *enclave.SoftwareProvider
	entered, release chan struct{}
	calls            atomic.Int64
}

func (g *gatedUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	if g.calls.Add(1) == 1 {
		close(g.entered)
	}
	<-g.release
	return g.soft.UnsealRoot(ctx, dst)
}

// TestSealing_SealerOverlappingASweepIsWiped runs a shutdown sweep while a
// ModeRootKey sealer is unsealing its root. The sweep cannot reclaim the
// root's destination — the unseal is writing into it — and a successful
// unseal may never be repeated, so the only fail-closed outcome is the one
// required here: the seal reports ErrSealerWiped, the surviving root is
// destroyed rather than published, and every later seal is refused without
// asking the provider again. A sealer that published that root would hand
// back working keys after a WipeAll.
func TestSealing_SealerOverlappingASweepIsWiped(t *testing.T) {
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

		// An ended context: the sweep reclaims everything not borrowed and
		// declines to wait for the root destination, which is.
		ended, cancel := context.WithCancel(ctx)
		cancel()
		if held, err := enclave.WipeAll(ended); held != 1 || err != nil {
			t.Fatalf("WipeAll during the unseal = (%d, %v), want (1, nil): only the borrowed root destination survives", held, err)
		}
		close(g.release)

		if err := <-result; !errors.Is(err, enclave.ErrSealerWiped) {
			t.Fatalf("Seal overlapping the sweep = %v, want ErrSealerWiped", err)
		}
		for i := range 2 {
			if _, err := s.Seal(ctx, heapBytes(needleLen)); !errors.Is(err, enclave.ErrSealerWiped) {
				t.Errorf("Seal %d after the overlap = %v, want ErrSealerWiped", i, err)
			}
		}
		if got := g.calls.Load(); got != 1 {
			t.Errorf("UnsealRoot calls = %d, want 1: a wiped sealer must not ask its provider again", got)
		}
		if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
			t.Fatalf("WipeAll afterwards = (%d, %v), want (0, nil): the surviving root was published or leaked", held, err)
		}
	})
}

// TestSealing_SealerKeyUseOverlappingASweepIsWiped parks the lock of a hierarchy
// key being minted or materialized, runs a shutdown sweep while it is parked,
// then lets it finish. The key it is about to use the root with is fresh, but
// the root is gone, so the operation must report ErrSealerWiped rather than a
// destroyed per-call key, and the sealer stays wiped. With every key release
// refused, the refusals are reported alongside and the keys stay on the
// ledger until the next sweep reclaims them.
func TestSealing_SealerKeyUseOverlappingASweepIsWiped(t *testing.T) {
	for _, tc := range []struct {
		name string
		// prior is how many values to seal first; skip is how many locks the
		// operation takes before the parked one.
		prior       int
		skip        uint64
		refuseUnmap bool
		op          func(ctx context.Context, s *enclave.Sealer, prior []*enclave.Sealed) error
	}{
		// DEK, root destination, the provider's root, then the first KEK.
		{"first KEK mint", 0, 3, false, func(ctx context.Context, s *enclave.Sealer, _ []*enclave.Sealed) error {
			_, err := s.Seal(ctx, heapBytes(needleLen))
			return err
		}},
		// DEK, then the rotated KEK.
		{"rotated KEK mint", 1, 1, false, func(ctx context.Context, s *enclave.Sealer, _ []*enclave.Sealed) error {
			_, err := s.Seal(ctx, heapBytes(needleLen))
			return err
		}},
		{"first KEK mint, releases refused", 0, 3, true, func(ctx context.Context, s *enclave.Sealer, _ []*enclave.Sealed) error {
			_, err := s.Seal(ctx, heapBytes(needleLen))
			return err
		}},
		{"rotated KEK mint, releases refused", 1, 1, true, func(ctx context.Context, s *enclave.Sealer, _ []*enclave.Sealed) error {
			_, err := s.Seal(ctx, heapBytes(needleLen))
			return err
		}},
		// Destination, DEK, then the retired KEK for the unwrap.
		{"retired KEK unwrap", 2, 2, false, func(ctx context.Context, _ *enclave.Sealer, prior []*enclave.Sealed) error {
			_, err := prior[0].Open(ctx)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolated(t, childOpts{}, func(t *testing.T) {
				ctx := context.Background()
				// Every hierarchy key and DEK has this one mapping length.
				f := installFaultInjector(t, mappingLen(enclave.RootKeyBytes))
				dev := newDevice()
				s, err := enclave.NewSealer(enclave.WithRootUnsealer(dev), enclave.WithKEKRotationLimit(1))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}
				var prior []*enclave.Sealed
				for range tc.prior {
					v := sealNeedle(t, ctx, s, newNeedle(t))
					defer v.Destroy()
					prior = append(prior, v)
				}

				if tc.refuseUnmap {
					f.refuse(unix.SYS_MUNMAP, unix.ENOMEM, 0)
				}
				f.holdAfter(unix.SYS_MLOCK, tc.skip)
				result := make(chan error, 1)
				go func() { result <- tc.op(ctx, s, prior) }()
				id := f.awaitHeld(t)
				held, err := enclave.WipeAll(ctx)
				if err != nil || (held != 0) != tc.refuseUnmap {
					t.Fatalf("WipeAll while the key's lock is parked = (%d, %v), want nil and held > 0 only if releases are refused", held, err)
				}
				f.release(t, id)

				err = <-result
				if !errors.Is(err, enclave.ErrSealerWiped) {
					t.Fatalf("operation overlapping the sweep = %v, want ErrSealerWiped", err)
				}
				if got := errors.Is(err, enclave.ErrLockedMemoryUnavailable); got != tc.refuseUnmap {
					t.Errorf("operation overlapping the sweep = %v: reports a refused release %t, want %t", err, got, tc.refuseUnmap)
				}
				if _, err := s.Seal(ctx, heapBytes(needleLen)); !errors.Is(err, enclave.ErrSealerWiped) {
					t.Errorf("Seal after the overlap = %v, want ErrSealerWiped", err)
				}
				if got := dev.unsealAttempts.Load(); got != 1 {
					t.Errorf("UnsealRoot attempts = %d, want 1: a wiped sealer must not ask its provider again", got)
				}
				if tc.refuseUnmap {
					requireRefused(t, f, unix.SYS_MUNMAP)
					f.allow(unix.SYS_MUNMAP)
				}
				if held, err := enclave.WipeAll(ctx); held != 0 || err != nil {
					t.Fatalf("WipeAll afterwards = (%d, %v), want (0, nil): the parked key outlived the failure", held, err)
				}
			})
		})
	}
}

// TestSealing_SealerQueuedFirstSealUsesThePublishedRoot: a second first-use seal
// that queued for the initialization slot while the first was unsealing finds
// the published hierarchy once it gets the slot, and seals under it without
// asking the provider again.
func TestSealing_SealerQueuedFirstSealUsesThePublishedRoot(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		g := &gatedUnsealer{soft: enclave.NewSoftwareProvider(), entered: make(chan struct{}), release: make(chan struct{})}
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(g))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		type sealed struct {
			v   *enclave.Sealed
			err error
		}
		seal := func(ctx context.Context, n needle, done chan<- sealed) {
			buf := heapBytes(needleLen)
			n.fill(buf)
			v, err := s.Seal(ctx, buf)
			done <- sealed{v, err}
		}
		first, second := newNeedle(t), newNeedle(t)
		doneA, doneB := make(chan sealed, 1), make(chan sealed, 1)
		go seal(ctx, first, doneA)
		<-g.entered
		ctxB, queuedB := waitObservingContext(ctx)
		go seal(ctxB, second, doneB)
		<-queuedB // B waits on the initialization slot A holds
		close(g.release)

		a, b := <-doneA, <-doneB
		if a.err != nil || b.err != nil {
			t.Fatalf("Seal: first = %v, queued = %v; want both to succeed", a.err, b.err)
		}
		vA, vB := a.v, b.v
		defer vA.Destroy()
		defer vB.Destroy()
		requireOpensTo(t, ctx, vA, first)
		requireOpensTo(t, ctx, vB, second)
		if got := g.calls.Load(); got != 1 {
			t.Errorf("UnsealRoot calls = %d, want 1: the queued seal must reuse the published root", got)
		}
	})
}

// cancelAfterUnseal unseals successfully and then ends the caller's context,
// so the rest of the initialization runs for a caller that has given up.
type cancelAfterUnseal struct {
	*device
	cancel context.CancelFunc
}

func (c cancelAfterUnseal) UnsealRoot(ctx context.Context, dst []byte) error {
	defer c.cancel()
	return c.device.UnsealRoot(ctx, dst)
}

// TestSealing_SealerAbandonedInitReportsBothCauses: the root unseals, the caller's
// context ends, then the first KEK's lock is refused. The seal reports the
// context and the refusal together, keeps the unsealed root, and the next
// seal mints under it without unsealing again.
func TestSealing_SealerAbandonedInitReportsBothCauses(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		dev := newDevice()
		s, err := enclave.NewSealer(enclave.WithRootUnsealer(cancelAfterUnseal{dev, cancel}))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		// DEK, root destination, the provider's root, then the refused KEK.
		f.refuseAfter(unix.SYS_MLOCK, unix.ENOMEM, 3)
		_, err = s.Seal(ctx, heapBytes(needleLen))
		f.allow(unix.SYS_MLOCK)
		requireRefused(t, f, unix.SYS_MLOCK)
		requireContextFailure(t, "Seal abandoned during a successful unseal", err, enclave.ErrSealFailed, context.Canceled)
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Errorf("Seal = %v, want the refused KEK lock reported too", err)
		}

		n := newNeedle(t)
		v := sealNeedle(t, context.Background(), s, n)
		defer v.Destroy()
		requireOpensTo(t, context.Background(), v, n)
		if a, ok := dev.unsealAttempts.Load(), dev.unseals.Load(); a != 1 || ok != 1 {
			t.Errorf("UnsealRoot: %d attempts, %d succeeded; want 1 and 1: the unsealed root is kept", a, ok)
		}
	})
}

// sealNeedle seals the material through s from a heap slice that Seal wipes.
func sealNeedle(t *testing.T, ctx context.Context, s *enclave.Sealer, n needle) *enclave.Sealed {
	t.Helper()
	buf := heapBytes(needleLen)
	n.fill(buf)
	v, err := s.Seal(ctx, buf)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !memscan.AllZero(buf) {
		t.Fatalf("Seal did not wipe the caller's slice")
	}
	return v
}

// requireOpensTo opens v and requires exactly the material, compared in place.
func requireOpensTo(t *testing.T, ctx context.Context, v *enclave.Sealed, n needle) {
	t.Helper()
	o, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var ok bool
	if err := o.WithBytes(func(b []byte) error { ok = n.equals(b); return nil }); err != nil || !ok {
		t.Fatalf("opened value: matches %t, err %v", ok, err)
	}
	if err := o.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}

// openInAllocator is v.OpenIn(ctx, a), as the *enclave.Memory it returns for
// an *enclave.Allocator.
func openInAllocator(t *testing.T, ctx context.Context, v *enclave.Sealed, a *enclave.Allocator) (*enclave.Memory, error) {
	t.Helper()
	h, err := v.OpenIn(ctx, a)
	if err != nil {
		return nil, err
	}
	m, ok := h.(*enclave.Memory)
	if !ok {
		t.Fatalf("OpenIn into an *Allocator returned a %T, want *enclave.Memory", h)
	}
	return m, nil
}

// requireContextFailure asserts err is the documented shape of a call whose
// context ended: the operation's sentinel AND the context's own error, and
// never a forgery verdict.
func requireContextFailure(t *testing.T, what string, err, sentinel, ctxErr error) {
	t.Helper()
	if !errors.Is(err, sentinel) || !errors.Is(err, ctxErr) {
		t.Fatalf("%s: err = %v, want one matching both %v and %v", what, err, sentinel, ctxErr)
	}
	if errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("%s: err = %v also matches ErrSealedAuthentication — a deadline reported as a forgery", what, err)
	}
}

// forEach runs fn(0..n-1) on workers goroutines and fails on the first error.
func forEach(t *testing.T, n, workers int, fn func(i int) error) {
	t.Helper()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(i); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("%d of %d operations failed; first: %v", len(errs), n, errs[0])
	}
}

// deadlineContext is a context with a deadline that passes when the test says
// so rather than when a clock does. Its Deadline reports a time, its Done
// closes and its Err becomes context.DeadlineExceeded exactly when expire is
// called — which is everything the code under test can observe of a deadline,
// and lets a test expire it only after the provider is known to be blocked.
// A real timer would race the code path it is meant to interrupt.
type deadlineContext struct {
	context.Context
	done    chan struct{}
	once    sync.Once
	expired atomic.Bool
}

func newDeadlineContext() *deadlineContext {
	return &deadlineContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *deadlineContext) expire() {
	c.once.Do(func() { c.expired.Store(true); close(c.done) })
}

func (c *deadlineContext) Deadline() (time.Time, bool) { return time.Unix(1<<40, 0), true }
func (c *deadlineContext) Done() <-chan struct{}       { return c.done }
func (c *deadlineContext) Err() error {
	if c.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

// reportingDevice is a device that implements enclave.HealthReporter with a
// report the test controls.
type reportingDevice struct {
	*device
	healthy bool
}

func (d *reportingDevice) Health() error {
	if d.healthy {
		return nil
	}
	return enclave.ErrSealerWiped
}

// TestSealing_SealerReportsItsConfiguration covers what a sealer and a sealed value
// tell an operator: the mode it was built in, a provider health report it
// believes, and a String that never prints the envelope.
func TestSealing_SealerReportsItsConfiguration(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		dev := &reportingDevice{device: newDevice(), healthy: true}
		s, err := enclave.NewSealer(enclave.WithKeyProtector(dev))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		if s.Mode() != enclave.ModePerOperation {
			t.Fatalf("Mode() = %v, want ModePerOperation", s.Mode())
		}
		for _, m := range []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation, enclave.Mode(250)} {
			if m.String() == "" {
				t.Errorf("Mode(%d).String() is empty", uint8(m))
			}
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)
		defer v.Destroy()
		if str := v.String(); str == "" {
			t.Error("Sealed.String() is empty")
		}

		// After a sweep the sealer asks the provider; it believes the answer.
		if c, err := enclave.WipeAll(ctx); c != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v)", c, err)
		}
		// Openable answers from the provider's own report — it is the
		// provider's statement about where its key lives that the sealer
		// believes. (This fake device keeps its key in-process, so the sweep
		// did destroy it; an Open would fail. Openable reporting nil anyway is
		// exactly the documented contract: believed, not second-guessed.)
		if err := v.Openable(); err != nil {
			t.Errorf("Openable with a provider reporting healthy = %v, want nil", err)
		}
		dev.healthy = false
		if err := v.Openable(); !errors.Is(err, enclave.ErrSealerWiped) {
			t.Errorf("Openable with a provider reporting wiped = %v, want ErrSealerWiped", err)
		}
	})
}

// TestSealing_SealerRefusesInvalidArgumentsBeforeAnyLockedMemory drives every
// argument check a consumer of the sealing API can trip, against real locked
// memory: each is refused with its documented sentinel, wipes the caller's
// slice where the contract says so, and locks nothing.
func TestSealing_SealerRefusesInvalidArgumentsBeforeAnyLockedMemory(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		before := vmLck(t)

		if _, err := enclave.NewSealed(ctx, nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("NewSealed(nil) = %v, want ErrEmptyEnclave", err)
		}
		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		if _, err := s.Seal(ctx, []byte{}); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("Seal(empty) = %v, want ErrEmptyEnclave", err)
		}
		ended, cancel := context.WithCancelCause(ctx)
		why := errors.New("the caller gave up")
		cancel(why)
		buf := []byte("refused before sealing")
		if _, err := s.Seal(ended, buf); !errors.Is(err, enclave.ErrSealFailed) || !errors.Is(err, context.Canceled) || !errors.Is(err, why) {
			t.Errorf("Seal with a canceled context = %v, want ErrSealFailed, context.Canceled and the cause", err)
		}
		if !memscan.AllZero(buf) {
			t.Error("Seal refused for its context did not wipe the caller's slice")
		}
		var nilSealer *enclave.Sealer
		buf = []byte("sealed by nobody")
		if _, err := nilSealer.Seal(ctx, buf); !errors.Is(err, enclave.ErrNilSealer) || !memscan.AllZero(buf) {
			t.Errorf("Seal on a nil *Sealer = %v (caller's slice wiped: %t), want ErrNilSealer and a wiped slice", err, memscan.AllZero(buf))
		}
		buf = []byte("refused before the process sealer")
		if _, err := enclave.NewSealed(ended, buf); !errors.Is(err, enclave.ErrSealFailed) || !errors.Is(err, context.Canceled) || !memscan.AllZero(buf) {
			t.Errorf("NewSealed with a canceled context = %v (slice wiped: %t), want ErrSealFailed, context.Canceled and a wiped slice", err, memscan.AllZero(buf))
		}
		for _, n := range []uint64{0, 1<<31 + 1} {
			if _, err := enclave.NewSealer(enclave.WithKEKRotationLimit(n)); !errors.Is(err, enclave.ErrInvalidRotationLimit) {
				t.Errorf("WithKEKRotationLimit(%d) = %v, want ErrInvalidRotationLimit", n, err)
			}
		}
		if _, err := enclave.NewSealer(enclave.WithKeyProtector(enclave.NewSoftwareProvider()), enclave.WithKEKRotationLimit(1)); !errors.Is(err, enclave.ErrInvalidRotationLimit) {
			t.Errorf("WithKEKRotationLimit with ModePerOperation = %v, want ErrInvalidRotationLimit", err)
		}
		var typedNil *enclave.SoftwareProvider
		for name, opt := range map[string]enclave.SealerOption{
			"nil RootUnsealer":       enclave.WithRootUnsealer(nil),
			"nil KeyProtector":       enclave.WithKeyProtector(nil),
			"typed-nil RootUnsealer": enclave.WithRootUnsealer(typedNil),
			"typed-nil KeyProtector": enclave.WithKeyProtector(typedNil),
		} {
			if _, err := enclave.NewSealer(opt); !errors.Is(err, enclave.ErrInvalidProvider) {
				t.Errorf("NewSealer(%s) = %v, want ErrInvalidProvider", name, err)
			}
		}

		if after := vmLck(t); after != before {
			t.Errorf("VmLck = %d after only refusals, want %d: a refusal locked memory", after, before)
		}
	})
}

// TestSealing_NewSealerRefusesMisconfiguration: the provider option fixes the mode,
// and two providers are refused at CONSTRUCTION rather than resolved by order.
func TestSealing_NewSealerRefusesMisconfiguration(t *testing.T) {
	ro := rootOnly{soft: enclave.NewSoftwareProvider()}
	if s, err := enclave.NewSealer(enclave.WithRootUnsealer(ro)); err != nil || s.Mode() != enclave.ModeRootKey {
		t.Errorf("NewSealer(WithRootUnsealer) = (%v, %v), want a ModeRootKey sealer", s, err)
	}
	soft := enclave.NewSoftwareProvider()
	if s, err := enclave.NewSealer(enclave.WithKeyProtector(soft)); err != nil || s.Mode() != enclave.ModePerOperation {
		t.Errorf("NewSealer(WithKeyProtector) = (%v, %v), want a ModePerOperation sealer", s, err)
	}
	s, err := enclave.NewSealer(enclave.WithKeyProtector(soft), enclave.WithRootUnsealer(ro))
	if !errors.Is(err, enclave.ErrInvalidProvider) || s != nil {
		t.Errorf("NewSealer(two providers) = (%v, %v), want (nil, ErrInvalidProvider)", s, err)
	}
}
