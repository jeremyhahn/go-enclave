// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package providertest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

const residueProperty = "no copy of the key is findable in the process after Unprotect returns"

// Package-level stores for the cases that keep the key in a global. Each run
// generates a fresh key, so what an earlier case left here cannot satisfy a
// later case's sweep.
var (
	matrixSlice   [][]byte
	matrixStrings []string
	matrixMap     = map[int][]byte{}
	matrixPool    sync.Pool
	matrixChan    = make(chan [keyBytes]byte, 256)
)

// leakyProvider is the software provider with one retention strategy bolted
// onto Unprotect: keep sees each recovered key after the inner provider wrote
// it, and keeps it however the case says.
type leakyProvider struct {
	inner enclave.SoftwareProvider
	mu    sync.Mutex
	keep  func(key []byte)
	kept  int
}

func (p *leakyProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *leakyProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keep(key)
	p.kept++
	return nil
}

// parkOnStack copies key into an array local to a new goroutine, which then
// blocks until stop closes: the key lives only on that goroutine's stack.
func parkOnStack(key []byte, stop <-chan struct{}, parked *sync.WaitGroup) {
	var onStack [keyBytes]byte
	copy(onStack[:], key)
	ready := make(chan struct{})
	parked.Add(1)
	go func(a [keyBytes]byte) {
		defer parked.Done()
		close(ready)
		<-stop
		holdArray(a)
	}(onStack)
	<-ready
}

// holdArray takes the array by value so it stays on the caller's stack.
//
//go:noinline
func holdArray(a [keyBytes]byte) { _ = a }

// anonMapping returns a page of anonymous memory, private or shared, unmapped
// when the test ends.
func anonMapping(t *testing.T, flags int) []byte {
	t.Helper()
	b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|flags)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	t.Cleanup(func() { _ = unix.Munmap(b) })
	return b
}

// wantResidueFinding runs the suite and requires exactly one finding: a
// *PropertyError on the residue property saying the key was retained.
func wantResidueFinding(t *testing.T, p *leakyProvider) {
	t.Helper()
	err := TestProvider(t.Context(), Config{
		New:   func() (any, error) { return p, nil },
		Modes: []enclave.Mode{enclave.ModePerOperation},
		Logf:  t.Logf,
	})
	if p.kept == 0 {
		t.Fatal("the planted provider kept nothing; the case proved nothing")
	}
	var fe *FindingsError
	if !errors.As(err, &fe) {
		t.Fatalf("the suite PASSED a provider that keeps the key (err = %v); the residue check missed it", err)
	}
	if len(fe.Findings) != 1 {
		t.Fatalf("want exactly the residue finding, got %d:\n%v", len(fe.Findings), err)
	}
	var pe *PropertyError
	if !errors.As(fe.Findings[0], &pe) || pe.Property != residueProperty {
		t.Fatalf("want a *PropertyError on %q, got %T:\n%v", residueProperty, fe.Findings[0], err)
	}
	if !bytes.Contains([]byte(pe.Detail), []byte("RETAINED")) {
		t.Fatalf("the residue finding does not say the key was retained:\n%v", err)
	}
	t.Logf("caught, as required:\n%v", err)
}

// TestResidueMatrix holds the residue check to each way a provider can keep a
// key past Unprotect, and to the clean provider, which must pass.
func TestResidueMatrix(t *testing.T) {
	half := keyBytes / 2
	tests := []struct {
		name string
		miss string // non-empty: the check misses this case today
		keep func(t *testing.T) func(key []byte)
	}{
		{"package-level slice", "", func(*testing.T) func([]byte) {
			return func(k []byte) { matrixSlice = append(matrixSlice, bytes.Clone(k)) }
		}},
		{"map value", "", func(*testing.T) func([]byte) {
			return func(k []byte) { matrixMap[len(matrixMap)] = bytes.Clone(k) }
		}},
		{"sync.Pool", "", func(*testing.T) func([]byte) {
			return func(k []byte) {
				b := bytes.Clone(k)
				matrixPool.Put(&b)
			}
		}},
		{"buffered channel", "", func(*testing.T) func([]byte) {
			return func(k []byte) {
				var a [keyBytes]byte
				copy(a[:], k)
				select {
				case matrixChan <- a:
				default:
				}
			}
		}},
		{"parked goroutine stack", "", func(t *testing.T) func([]byte) {
			stop := make(chan struct{})
			var parked sync.WaitGroup
			t.Cleanup(func() { close(stop); parked.Wait() })
			return func(k []byte) { parkOnStack(k, stop, &parked) }
		}},
		{"kept string conversion", "", func(*testing.T) func([]byte) {
			return func(k []byte) { matrixStrings = append(matrixStrings, string(k)) }
		}},
		{"anonymous private mmap", "", func(t *testing.T) func([]byte) {
			region := anonMapping(t, unix.MAP_PRIVATE)
			return func(k []byte) { copy(region, k) }
		}},
		{"anonymous shared mmap", "", func(t *testing.T) func([]byte) {
			region := anonMapping(t, unix.MAP_SHARED)
			return func(k []byte) { copy(region, k) }
		}},
		{"undestroyed second memory enclave", "", func(t *testing.T) func([]byte) {
			var held []enclave.ByteAccess
			t.Cleanup(func() {
				for _, m := range held {
					_ = m.Destroy()
				}
			})
			return func(k []byte) {
				m, err := enclave.NewMemorySized(len(k))
				if err != nil {
					t.Errorf("second enclave: %v", err)
					return
				}
				held = append(held, m)
				if err := m.WithBytes(func(b []byte) error { copy(b, k); return nil }); err != nil {
					t.Errorf("filling the second enclave: %v", err)
				}
			}
		}},
		{"first half of the key", "miss: the sweep looks only for the whole key", func(*testing.T) func([]byte) {
			return func(k []byte) { matrixSlice = append(matrixSlice, bytes.Clone(k[:half])) }
		}},
		{"last half of the key", "miss: the sweep looks only for the whole key", func(*testing.T) func([]byte) {
			return func(k []byte) { matrixSlice = append(matrixSlice, bytes.Clone(k[half:])) }
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.miss != "" {
				t.Skip(tc.miss)
			}
			wantResidueFinding(t, &leakyProvider{inner: software(), keep: tc.keep(t)})
		})
	}

	t.Run("clean provider", func(t *testing.T) {
		// The software provider serves both modes, so it claims both.
		err := TestProvider(t.Context(), Config{
			New:   func() (any, error) { return software(), nil },
			Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
			Logf:  t.Logf,
		})
		if err != nil {
			t.Fatalf("the suite failed the clean software provider:\n%v", err)
		}
	})
}
