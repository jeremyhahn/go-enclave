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
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// Covers provider.go and provider_software.go: the shipped SoftwareProvider
// run through providertest's conformance suite — the instrument a provider
// author is told to use — inside the devcontainer, where its residue sweep can
// run, and in a child without locked memory, where it cannot; and the provider
// seam as a consumer injects into it.

// providerOption injects p in mode m, for tests that range over both modes.
func providerOption(p any, m enclave.Mode) enclave.SealerOption {
	if m == enclave.ModePerOperation {
		kp, _ := p.(enclave.KeyProtector)
		return enclave.WithKeyProtector(kp)
	}
	ru, _ := p.(enclave.RootUnsealer)
	return enclave.WithRootUnsealer(ru)
}

// device is a provider a consumer injects through WithKeyProtector or
// WithRootUnsealer: the shipped SoftwareProvider doing all of the
// cryptography, behind the seam as a hardware provider would sit. It adds two
// things a real device has:
//
//   - it can stall. A context carrying a stall request makes the call block
//     until that context ends and then return ctx.Err(), which shows through
//     the public API that a caller's deadline reaches the provider and that no
//     Sealer lock is held across the call. Only the endpoint is stood in for;
//     the cryptography is never faked.
//   - it counts, so a test can assert how often the Sealer reached it.
type device struct {
	soft enclave.SoftwareProvider

	protects, unprotects    atomic.Int64
	unsealAttempts, unseals atomic.Int64
}

func newDevice() *device { return &device{soft: enclave.NewSoftwareProvider()} }

// stallKey marks a context whose provider calls must stall.
type stallKey struct{}

// stallingContext returns a context whose provider calls block until it ends,
// and a channel closed once a provider call has started blocking on it.
func stallingContext(parent context.Context) (context.Context, <-chan struct{}) {
	entered := make(chan struct{})
	return context.WithValue(parent, stallKey{}, entered), entered
}

// waitObservingContext wraps parent so that the first call to Done() closes
// the returned channel. On the Seal path the library checks an ended context at
// entry with Err() and first selects on Done() when it queues for the
// initialization slot, so receiving from the channel proves the caller is
// QUEUED — not merely started. Canceling before that would let a caller fail
// at entry and pass a test about cancellation while queued.
func waitObservingContext(parent context.Context) (context.Context, <-chan struct{}) {
	c := &observedDone{Context: parent, observed: make(chan struct{})}
	return c, c.observed
}

type observedDone struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *observedDone) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

// stall blocks a provider call until ctx ends, if ctx asked for that.
func stall(ctx context.Context) error {
	entered, ok := ctx.Value(stallKey{}).(chan struct{})
	if !ok {
		return nil
	}
	select {
	case <-entered:
	default:
		close(entered)
	}
	<-ctx.Done()
	return ctx.Err()
}

func (d *device) Protect(ctx context.Context, key []byte) ([]byte, error) {
	d.protects.Add(1)
	if err := stall(ctx); err != nil {
		return nil, err
	}
	return d.soft.Protect(ctx, key)
}

func (d *device) Unprotect(ctx context.Context, blob, key []byte) error {
	d.unprotects.Add(1)
	if err := stall(ctx); err != nil {
		return err
	}
	return d.soft.Unprotect(ctx, blob, key)
}

func (d *device) UnsealRoot(ctx context.Context, dst []byte) error {
	d.unsealAttempts.Add(1)
	if err := stall(ctx); err != nil {
		return err
	}
	if err := d.soft.UnsealRoot(ctx, dst); err != nil {
		return err
	}
	d.unseals.Add(1)
	return nil
}

// rootOnly implements only the ModeRootKey half of the seam.
type rootOnly struct{ soft enclave.SoftwareProvider }

func (r rootOnly) UnsealRoot(ctx context.Context, dst []byte) error {
	return r.soft.UnsealRoot(ctx, dst)
}

// TestProviderConformance_SoftwareProviderConformance runs providertest.TestProvider against the
// shipped SoftwareProvider for both modes it serves, and requires the residue
// sweep (which needs Linux and /proc/self/mem) to have run rather than been
// skipped.
//
// Control: told the provider serves ModeRootKey only, the suite must fail,
// because the provider also satisfies ModePerOperation.
func TestProviderConformance_SoftwareProviderConformance(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		var (
			mu    sync.Mutex
			notes []string
		)
		cfg := providertest.Config{
			New:   func() (any, error) { return enclave.NewSoftwareProvider(), nil },
			Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
			Logf: func(format string, args ...any) {
				t.Logf(format, args...)
				mu.Lock()
				notes = append(notes, format)
				mu.Unlock()
			},
		}
		if err := providertest.TestProvider(ctx, cfg); err != nil {
			t.Fatalf("SoftwareProvider fails conformance: %v", err)
		}
		sweptRan := false
		mu.Lock()
		for _, n := range notes {
			if strings.HasPrefix(n, "providertest: residue sweep ran") {
				sweptRan = true
			}
		}
		mu.Unlock()
		if !sweptRan {
			t.Fatalf("providertest's residue sweep did not run in the devcontainer (notes: %q); retention by copy went unmeasured", notes)
		}

		// The control.
		cfg.Modes = []enclave.Mode{enclave.ModeRootKey}
		cfg.Logf = t.Logf
		err := providertest.TestProvider(ctx, cfg)
		var pe *providertest.PropertyError
		if err == nil || !errors.As(err, &pe) {
			t.Fatalf("conformance with an under-claimed mode list: err = %v, want a PropertyError — the suite must catch a provider serving a mode it does not claim", err)
		}
		t.Logf("control run failed as required: %v", err)

		if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// heapProtector keeps a copy of each key under its blob in ordinary heap, so
// it runs without locked memory.
type heapProtector struct {
	mu   sync.Mutex
	n    int
	keys map[string][]byte
}

func (p *heapProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	blob := []byte{byte(p.n >> 24), byte(p.n >> 16), byte(p.n >> 8), byte(p.n)}
	p.keys[string(blob)] = bytes.Clone(key)
	return blob, nil
}

func (p *heapProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k, ok := p.keys[string(blob)]
	if !ok || len(k) != len(key) {
		return enclave.ErrSealedAuthentication
	}
	copy(key, k)
	return nil
}

// TestProviderConformance_AResidueSweepWithoutLockedMemoryIsNotAPass runs providertest.TestProvider
// in a child whose RLIMIT_MEMLOCK is zero, so the residue sweep cannot place its
// needle, and requires the run to report the property as ErrNotMeasured —
// unless SkipResidueSweep accepts that.
func TestProviderConformance_AResidueSweepWithoutLockedMemoryIsNotAPass(t *testing.T) {
	isolated(t, childOpts{memlockZero: true}, func(t *testing.T) {
		const property = "no copy of the key is findable in the process after Unprotect returns"
		cfg := providertest.Config{
			New:   func() (any, error) { return &heapProtector{keys: map[string][]byte{}}, nil },
			Modes: []enclave.Mode{enclave.ModePerOperation},
			Logf:  t.Logf,
		}
		err := providertest.TestProvider(t.Context(), cfg)
		var nm *providertest.NotMeasuredError
		if !errors.Is(err, providertest.ErrNotMeasured) || !errors.As(err, &nm) || nm.Property != property {
			t.Fatalf("TestProvider = %v; want a *NotMeasuredError for %q", err, property)
		}
		if !strings.HasPrefix(nm.Error(), "providertest: "+property+": not measured: ") {
			t.Errorf("NotMeasuredError renders %q", nm.Error())
		}

		cfg.SkipResidueSweep = "this run has no locked memory; accepted for the test"
		if err := providertest.TestProvider(t.Context(), cfg); errors.Is(err, providertest.ErrNotMeasured) {
			t.Errorf("with SkipResidueSweep set the unmeasured sweep is accepted, got %v", err)
		}
	})
}

// TestSealing_SoftwareProviderRefusesMisuse calls the software provider directly the
// way a misbehaving caller would: a destination of the wrong size, a forged
// blob, and — after a shutdown sweep has destroyed its root — any further
// use, which fails closed with ErrSealerWiped instead of minting a new root.
func TestSealing_SoftwareProviderRefusesMisuse(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		p := enclave.NewSoftwareProvider()
		if err := p.UnsealRoot(ctx, make([]byte, enclave.RootKeyBytes-1)); !errors.Is(err, enclave.ErrInvalidSize) {
			t.Errorf("UnsealRoot into a short destination = %v, want ErrInvalidSize", err)
		}
		key := make([]byte, enclave.RootKeyBytes)
		if err := p.Unprotect(ctx, make([]byte, 64), key); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("Unprotect before any root exists = %v, want ErrSealedAuthentication", err)
		}
		blob, err := p.Protect(ctx, key)
		if err != nil {
			t.Fatalf("Protect: %v", err)
		}
		blob[len(blob)-1] ^= 0xFF
		if err := p.Unprotect(ctx, blob, key); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("Unprotect of a tampered blob = %v, want ErrSealedAuthentication", err)
		}
		if err := p.Unprotect(ctx, blob[:3], key); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("Unprotect of a truncated blob = %v, want ErrSealedAuthentication", err)
		}

		if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
		if _, err := p.Protect(ctx, key); !errors.Is(err, enclave.ErrSealerWiped) {
			t.Errorf("Protect after the sweep = %v, want ErrSealerWiped", err)
		}
		if err := p.UnsealRoot(ctx, make([]byte, enclave.RootKeyBytes)); !errors.Is(err, enclave.ErrSealerWiped) {
			t.Errorf("UnsealRoot after the sweep = %v, want ErrSealerWiped", err)
		}
	})
}
