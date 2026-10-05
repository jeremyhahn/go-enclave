// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package providertest_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// mappedRetainer conforms in every visible way and copies every key it
// recovers into a mapping it owns, outside the anonymous heap.
type mappedRetainer struct {
	inner  *enclave.SoftwareProvider
	mu     sync.Mutex
	region []byte
	stored int
}

func (p *mappedRetainer) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *mappedRetainer) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	copy(p.region, key)
	p.stored++
	return nil
}

// TestSuiteCatchesAKeyRetainedInAMemfdOrFileMapping runs the residue sweep
// against the devcontainer's kernel with the key kept in a memfd and in a
// private writable file mapping; both must be caught.
func TestSuiteCatchesAKeyRetainedInAMemfdOrFileMapping(t *testing.T) {
	page := os.Getpagesize()
	mapped := func(t *testing.T, fd, flags int) []byte {
		t.Helper()
		t.Cleanup(func() { _ = unix.Close(fd) })
		if err := unix.Ftruncate(fd, int64(page)); err != nil {
			t.Fatalf("ftruncate: %v", err)
		}
		b, err := unix.Mmap(fd, 0, page, unix.PROT_READ|unix.PROT_WRITE, flags)
		if err != nil {
			t.Fatalf("mmap: %v", err)
		}
		t.Cleanup(func() { _ = unix.Munmap(b) })
		return b
	}
	tests := []struct {
		name   string
		region func(t *testing.T) []byte
	}{
		{"memfd", func(t *testing.T) []byte {
			fd, err := unix.MemfdCreate("providertest-retainer", unix.MFD_CLOEXEC)
			if err != nil {
				t.Fatalf("memfd_create: %v", err)
			}
			return mapped(t, fd, unix.MAP_SHARED)
		}},
		{"private file mapping", func(t *testing.T) []byte {
			fd, err := unix.Open(filepath.Join(t.TempDir(), "retained"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			return mapped(t, fd, unix.MAP_PRIVATE)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &mappedRetainer{inner: software(), region: tc.region(t)}
			wantFail(t, perOp(func() (any, error) { return p, nil }),
				"no copy of the key is findable in the process after Unprotect returns", "RETAINED a copy")
			if p.stored == 0 {
				t.Fatal("the planted provider stored nothing; the control proved nothing")
			}
		})
	}
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

// TestAResidueSweepWithoutLockedMemoryIsNotAPass drops RLIMIT_MEMLOCK to zero
// so the sweep cannot place its needle, and requires the run to report the
// property as ErrNotMeasured — unless SkipResidueSweep accepts that.
func TestAResidueSweepWithoutLockedMemoryIsNotAPass(t *testing.T) {
	const property = "no copy of the key is findable in the process after Unprotect returns"
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &old); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	none := unix.Rlimit{Cur: 0, Max: old.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &none); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &old); err != nil {
			t.Fatalf("restoring RLIMIT_MEMLOCK: %v", err)
		}
	}()

	cfg := perOp(func() (any, error) { return &heapProtector{keys: map[string][]byte{}}, nil })
	cfg.Logf = t.Logf
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
}
