// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// residueProperty is the property the residue sweep reports under.
const residueProperty = "no copy of the key is findable in the process after Unprotect returns"

// Retention sites with package scope: a provider keeping a key in a global
// is the commonest way to leak one. Each case clears its own site in
// t.Cleanup.
var (
	leakSlices  [][]byte
	leakMap     = map[int][]byte{}
	leakPool    sync.Pool
	leakStrings []string
)

// keepingProtector conforms in every visible way and hands each key it
// recovers to keep, which retains it somewhere. Only the residue sweep can
// see the retained copy.
type keepingProtector struct {
	inner  enclave.SoftwareProvider
	mu     sync.Mutex
	keep   func(key []byte)
	stored int
}

func (p *keepingProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *keepingProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keep(key)
	p.stored++
	return nil
}

// retentionOutcome is what the suite must report for a provider.
type retentionOutcome int

const (
	caught retentionOutcome = iota // a *FindingsError with the one residue finding
	passes                         // no error: nothing is retained
)

// anonMapping maps one anonymous page with flags and unmaps it in t.Cleanup.
func anonMapping(t *testing.T, flags int) []byte {
	t.Helper()
	b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, flags|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	t.Cleanup(func() {
		clear(b)
		_ = unix.Munmap(b)
	})
	return b
}

// keepInRegion copies each key into region, one after another, until it is
// full; later keys overwrite the first.
func keepInRegion(region []byte) func([]byte) {
	off := 0
	return func(key []byte) {
		if off+len(key) > len(region) {
			off = 0
		}
		off += copy(region[off:], key)
	}
}

// TestSuiteCatchesEachRetention runs the suite against one deliberately leaky
// provider per place a Go provider can keep a key, and against the clean
// provider, and asserts the exact outcome of each.
func TestSuiteCatchesEachRetention(t *testing.T) {
	tests := []struct {
		name string
		// keep returns the retention hook; it registers its own release.
		keep func(t *testing.T) func(key []byte)
		want retentionOutcome
	}{
		{"package-level slice", func(t *testing.T) func([]byte) {
			t.Cleanup(func() {
				for _, k := range leakSlices {
					clear(k)
				}
				leakSlices = nil
			})
			return func(key []byte) { leakSlices = append(leakSlices, append([]byte(nil), key...)) }
		}, caught},
		{"map value", func(t *testing.T) func([]byte) {
			t.Cleanup(func() {
				for i, k := range leakMap {
					clear(k)
					delete(leakMap, i)
				}
			})
			return func(key []byte) { leakMap[len(leakMap)] = append([]byte(nil), key...) }
		}, caught},
		{"sync.Pool", func(t *testing.T) func([]byte) {
			var held [][]byte // the pool may drop its entries at a GC; the bytes stay
			t.Cleanup(func() {
				for v := leakPool.Get(); v != nil; v = leakPool.Get() {
					if k, ok := v.(*[]byte); ok {
						clear(*k)
					}
				}
				for _, k := range held {
					clear(k)
				}
			})
			return func(key []byte) {
				k := append([]byte(nil), key...)
				held = append(held, k)
				leakPool.Put(&k)
			}
		}, caught},
		{"buffered channel", func(t *testing.T) func([]byte) {
			ch := make(chan [keyBytes]byte, 64)
			t.Cleanup(func() {
				for len(ch) > 0 {
					<-ch
				}
				close(ch)
			})
			return func(key []byte) {
				var k [keyBytes]byte
				copy(k[:], key)
				select {
				case ch <- k:
				default:
				}
			}
		}, caught},
		{"stack of a parked goroutine", func(t *testing.T) func([]byte) {
			done := make(chan struct{})
			var wg sync.WaitGroup
			t.Cleanup(func() {
				close(done)
				wg.Wait()
			})
			return func(key []byte) {
				ready := make(chan struct{})
				wg.Add(1)
				go func() {
					defer wg.Done()
					var k [keyBytes]byte // a non-escaping array: it lives on this goroutine's stack
					copy(k[:], key)
					close(ready)
					<-done
					clear(k[:])
				}()
				<-ready
			}
		}, caught},
		{"string conversion", func(t *testing.T) func([]byte) {
			t.Cleanup(func() { leakStrings = nil })
			return func(key []byte) { leakStrings = append(leakStrings, string(key)) }
		}, caught},
		{"anonymous private mmap", func(t *testing.T) func([]byte) {
			return keepInRegion(anonMapping(t, unix.MAP_PRIVATE))
		}, caught},
		{"anonymous shared mmap", func(t *testing.T) func([]byte) {
			return keepInRegion(anonMapping(t, unix.MAP_SHARED))
		}, caught},
		{"second memory enclave never destroyed", func(t *testing.T) func([]byte) {
			var held []enclave.ByteAccess
			t.Cleanup(func() {
				for _, h := range held {
					_ = h.Destroy()
				}
			})
			return func(key []byte) {
				m, err := enclave.NewMemorySized(len(key))
				if err != nil {
					t.Errorf("a second memory enclave: %v", err)
					return
				}
				held = append(held, m)
				_ = m.WithBytes(func(b []byte) error {
					copy(b, key)
					return nil
				})
			}
		}, caught},
		{"first half of the key", func(t *testing.T) func([]byte) {
			t.Cleanup(func() {
				for _, k := range leakSlices {
					clear(k)
				}
				leakSlices = nil
			})
			return func(key []byte) { leakSlices = append(leakSlices, append([]byte(nil), key[:len(key)/2]...)) }
		}, caught},
		{"last half of the key", func(t *testing.T) func([]byte) {
			t.Cleanup(func() {
				for _, k := range leakSlices {
					clear(k)
				}
				leakSlices = nil
			})
			return func(key []byte) { leakSlices = append(leakSlices, append([]byte(nil), key[len(key)/2:]...)) }
		}, caught},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &keepingProtector{inner: software(), keep: tc.keep(t)}
			err := TestProvider(t.Context(), Config{
				New:   func() (any, error) { return p, nil },
				Modes: []enclave.Mode{enclave.ModePerOperation},
				Logf:  t.Logf,
			})
			assertRetentionOutcome(t, err, tc.want)
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.stored == 0 {
				t.Fatal("the planted provider kept nothing; the case proved nothing")
			}
		})
	}
	t.Run("clean provider", func(t *testing.T) {
		err := TestProvider(t.Context(), Config{
			New:   func() (any, error) { return software(), nil },
			Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
			Logf:  t.Logf,
		})
		assertRetentionOutcome(t, err, passes)
	})
}

// assertRetentionOutcome fails t unless err is exactly want: no error, a
// *FindingsError whose only findings are residue findings, or a
// *NotMeasuredError for the residue property.
func assertRetentionOutcome(t *testing.T, err error, want retentionOutcome) {
	t.Helper()
	switch want {
	case passes:
		if err != nil {
			t.Fatalf("the suite failed a provider that retains nothing:\n%v", err)
		}
	case caught:
		if err == nil {
			t.Fatal("the suite PASSED a provider that keeps a copy of the key; the residue sweep missed it")
		}
		var findings *FindingsError
		if !errors.As(err, &findings) {
			t.Fatalf("got %T, want a *FindingsError:\n%v", err, err)
		}
		if len(findings.Findings) != 1 {
			t.Fatalf("want exactly the residue finding, got %d:\n%v", len(findings.Findings), err)
		}
		for _, f := range findings.Findings {
			var pe *PropertyError
			if !errors.As(f, &pe) || pe.Property != residueProperty {
				t.Fatalf("a finding other than the residue property: %v", f)
			}
			if !strings.Contains(pe.Detail, "RETAINED a copy") {
				t.Fatalf("the residue finding does not say the provider retained a copy: %v", f)
			}
		}
	}
}
