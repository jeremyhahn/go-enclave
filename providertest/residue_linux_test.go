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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestSuiteCatchesAProviderThatRetainsACopy is the deliberate-leak control
// for retention by copy. It lives in the Linux file because the residue sweep
// exists only on Linux; TestResidueSweepReportsItselfNotRunOffLinux
// (residue_unsupported_test.go) pins the behavior elsewhere.
func TestSuiteCatchesAProviderThatRetainsACopy(t *testing.T) {
	kept := &retainingProtector{inner: software()}
	wantFail(t, perOp(func() (any, error) { return kept, nil }),
		"no copy of the key is findable in the process after Unprotect returns")
	// Hold the retained copies past the sweep so the failure cannot be
	// explained away as garbage the collector had not yet reached.
	if len(kept.kept) == 0 {
		t.Fatal("the planted provider retained nothing; the control proved nothing")
	}
}

// TestEqualBytes pins that a recovery of the wrong length is not the key,
// whatever its prefix holds.
func TestEqualBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("key-bytes"), []byte("key-bytes"), true},
		{"both empty", nil, []byte{}, true},
		{"one byte differs", []byte("key-bytes"), []byte("key-bytez"), false},
		{"a strict prefix", []byte("key-bytes"), []byte("key-byte"), false},
		{"longer", []byte("key-bytes"), []byte("key-bytes!"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := equalBytes(tc.a, tc.b); got != tc.want {
				t.Errorf("equalBytes = %v, want %v", got, tc.want)
			}
		})
	}
}

// mappedRetainer conforms in every visible way and copies every key it
// recovers into a mapping it owns, outside anonymous memory.
type mappedRetainer struct {
	inner  *enclave.SoftwareProvider
	mu     sync.Mutex
	region []byte // written through, when fd < 0
	fd     int    // written through with pwrite, when >= 0
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
	if p.fd >= 0 {
		if _, err := unix.Pwrite(p.fd, key, 0); err != nil {
			return err
		}
	} else {
		copy(p.region, key)
	}
	p.stored++
	return nil
}

// TestSuiteCatchesAKeyRetainedInAFileOrDeviceMapping plants the key in every
// kind of mapping /proc/self/maps names with a path, and requires the sweep to
// find it there.
func TestSuiteCatchesAKeyRetainedInAFileOrDeviceMapping(t *testing.T) {
	const property = "no copy of the key is findable in the process after Unprotect returns"
	page := os.Getpagesize()

	mapFd := func(t *testing.T, fd, prot, flags int) []byte {
		t.Helper()
		b, err := unix.Mmap(fd, 0, page, prot, flags)
		if err != nil {
			t.Fatalf("mmap: %v", err)
		}
		t.Cleanup(func() { _ = unix.Munmap(b) })
		return b
	}
	openFile := func(t *testing.T, path string, flag int) int {
		t.Helper()
		fd, err := unix.Open(path, flag|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	sizedFile := func(t *testing.T, fd int) {
		t.Helper()
		if err := unix.Ftruncate(fd, int64(page)); err != nil {
			t.Fatalf("ftruncate: %v", err)
		}
	}
	memfd := func(t *testing.T) int {
		t.Helper()
		fd, err := unix.MemfdCreate("providertest-retainer", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatalf("memfd_create: %v", err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		sizedFile(t, fd)
		return fd
	}
	tempFile := func(t *testing.T) int {
		t.Helper()
		fd := openFile(t, filepath.Join(t.TempDir(), "retained"), unix.O_RDWR|unix.O_CREAT)
		sizedFile(t, fd)
		return fd
	}
	rw := unix.PROT_READ | unix.PROT_WRITE

	tests := []struct {
		name  string
		setup func(t *testing.T) *mappedRetainer
	}{
		{"private /dev/zero mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, openFile(t, "/dev/zero", unix.O_RDWR), rw, unix.MAP_PRIVATE)}
		}},
		{"shared /dev/zero mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, openFile(t, "/dev/zero", unix.O_RDWR), rw, unix.MAP_SHARED)}
		}},
		{"writable memfd mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, memfd(t), rw, unix.MAP_SHARED)}
		}},
		{"read-only memfd mapping written through its descriptor", func(t *testing.T) *mappedRetainer {
			fd := memfd(t)
			mapFd(t, fd, unix.PROT_READ, unix.MAP_SHARED)
			return &mappedRetainer{fd: fd}
		}},
		{"private writable file mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, tempFile(t), rw, unix.MAP_PRIVATE)}
		}},
		{"shared writable file mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, tempFile(t), rw, unix.MAP_SHARED)}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.setup(t)
			p.inner = software()
			wantFail(t, perOp(func() (any, error) { return p, nil }), property+": ", "RETAINED a copy")
			if p.stored == 0 {
				t.Fatal("the planted provider stored nothing; the control proved nothing")
			}
		})
	}
}
