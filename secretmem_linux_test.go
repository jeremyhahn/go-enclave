// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux && (386 || amd64 || arm64 || loong64 || riscv64 || s390x)

package enclave

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// allZero reports whether every byte of p is zero.
func allZero(p []byte) bool {
	for _, c := range p {
		if c != 0 {
			return false
		}
	}
	return true
}

// withMemfdSecret replaces the memfd_secret seam for one test.
func withMemfdSecret(t *testing.T, fn func(flags int) (int, error)) {
	t.Helper()
	prev := memfdSecret
	memfdSecret = fn
	t.Cleanup(func() { memfdSecret = prev })
}

// refuseMemfdSecret makes memfd_secret fail with errno, as a disabled kernel
// (ENOSYS), a seccomp filter (EPERM) or memory pressure (ENOMEM) does.
func refuseMemfdSecret(t *testing.T, errno syscall.Errno) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	withMemfdSecret(t, func(int) (int, error) {
		calls.Add(1)
		return -1, errno
	})
	return &calls
}

// memfdStandIn makes memfd_secret an ordinary memfd, which ftruncate, a shared
// mmap and the first touch treat alike, so the backend's path runs on any
// Linux kernel and under any seccomp profile that allows memfd_create.
func memfdStandIn(t *testing.T, seals int) {
	t.Helper()
	withMemfdSecret(t, func(flags int) (int, error) {
		if flags != unix.O_CLOEXEC {
			t.Errorf("memfd_secret flags = %#x, want O_CLOEXEC", flags)
		}
		fd, err := unix.MemfdCreate("secretmem-stand-in", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if err != nil {
			return -1, err
		}
		if seals != 0 {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
				_ = unix.Close(fd)
				return -1, err
			}
		}
		return fd, nil
	})
}

func newSecretMemoryForTest(t *testing.T, budget int64) (*secretMemory, Allocator) {
	t.Helper()
	a, err := NewAllocator(budget)
	if err != nil {
		t.Fatalf("NewAllocator(%d) = %v", budget, err)
	}
	b, err := NewSecretMemory(a)
	if err != nil {
		t.Fatalf("NewSecretMemory = %v", err)
	}
	return b.(*secretMemory), a
}

// assertMemfdSecretRefusal checks err is the backend's typed refusal naming
// call and carrying errno, and not locked memory's error.
func assertMemfdSecretRefusal(t *testing.T, err error, call string, errno syscall.Errno) {
	t.Helper()
	var me *MemfdSecretError
	if !errors.As(err, &me) || !errors.Is(err, ErrMemfdSecretUnavailable) {
		t.Fatalf("err = %v, want a *MemfdSecretError", err)
	}
	var se *os.SyscallError
	if !errors.As(me.Cause, &se) || se.Syscall != call || !errors.Is(err, errno) {
		t.Fatalf("cause = %v, want %s failing with %v", me.Cause, call, errno)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("err = %v also matches ErrLockedMemoryUnavailable", err)
	}
}

func TestLinuxSecretmem_ConstructionNeedsAnAllocator(t *testing.T) {
	if _, err := NewSecretMemory(nil); !errors.Is(err, ErrNilAllocator) {
		t.Fatalf("NewSecretMemory(nil) = %v, want ErrNilAllocator", err)
	}
	var zero *budgetAllocator
	if _, err := NewSecretMemory(zero); !errors.Is(err, ErrNilAllocator) {
		t.Fatalf("NewSecretMemory(typed nil) = %v, want ErrNilAllocator", err)
	}
	if _, err := NewSecretMemory(&budgetAllocator{}); !errors.Is(err, ErrAllocatorNotConstructed) {
		t.Fatalf("NewSecretMemory(zero) = %v, want ErrAllocatorNotConstructed", err)
	}
}

func TestLinuxSecretmem_ConstructionMakesNoSystemCall(t *testing.T) {
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	newSecretMemoryForTest(t, 1<<20)
	if calls.Load() != 0 {
		t.Fatalf("NewSecretMemory called memfd_secret %d times; only Probe and Import may", calls.Load())
	}
}

func TestLinuxSecretmem_ProbeChecksCtxFirst(t *testing.T) {
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	b, _ := newSecretMemoryForTest(t, 1<<20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) = %v, want context.Canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatal("Probe called memfd_secret under a canceled ctx")
	}
	// A nil ctx never ends, per Prober.
	if err := b.Probe(nil); !errors.Is(err, unix.ENOSYS) {
		t.Fatalf("Probe(nil) = %v, want the injected ENOSYS", err)
	}
}

func TestLinuxSecretmem_ProbeRefusalsAreTyped(t *testing.T) {
	for _, errno := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.ENOMEM, unix.EMFILE} {
		t.Run(errno.Error(), func(t *testing.T) {
			refuseMemfdSecret(t, errno)
			b, _ := newSecretMemoryForTest(t, 1<<20)
			assertMemfdSecretRefusal(t, b.Probe(context.Background()), "memfd_secret", errno)
		})
	}
}

func TestLinuxSecretmem_ProbeNamesARefusedMmap(t *testing.T) {
	// A write-sealed memfd refuses a writable shared mapping with EPERM.
	memfdStandIn(t, unix.F_SEAL_WRITE)
	b, _ := newSecretMemoryForTest(t, 1<<20)
	assertMemfdSecretRefusal(t, b.Probe(context.Background()), "mmap", unix.EPERM)
}

func TestLinuxSecretmem_ProbeNamesARefusedFtruncate(t *testing.T) {
	memfdStandIn(t, unix.F_SEAL_GROW)
	b, _ := newSecretMemoryForTest(t, 1<<20)
	assertMemfdSecretRefusal(t, b.Probe(context.Background()), "ftruncate", unix.EPERM)
}

func TestLinuxSecretmem_DetectKeepsLockedMemoryOnRefusal(t *testing.T) {
	for _, errno := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			refuseMemfdSecret(t, errno)
			b, _ := newSecretMemoryForTest(t, 1<<20)
			registerForTest(t, b)
			got, results := Detect(context.Background())
			if got != DefaultBackend() {
				t.Fatalf("Detect selected %q, want locked memory", got.Name())
			}
			r := resultFor(t, results, SecretMemoryBackendName)
			if r.Rank != 1 || !errors.Is(r.Err, ErrBackendUnavailable) {
				t.Fatalf("result = %+v, want rank 1 and a *ProbeError", r)
			}
			var pe *ProbeError
			if !errors.As(r.Err, &pe) || pe.Backend != SecretMemoryBackendName {
				t.Fatalf("errors.As(%v, *ProbeError) = %+v", r.Err, pe)
			}
			assertMemfdSecretRefusal(t, pe.Cause, "memfd_secret", errno)
		})
	}
}

func TestLinuxSecretmem_DetectRanksAboveLockedMemoryAndBelowHardware(t *testing.T) {
	memfdStandIn(t, 0)
	b, _ := newSecretMemoryForTest(t, 1<<20)
	registerForTest(t, b)
	if got, _ := Detect(context.Background()); got != Backend(b) {
		t.Fatalf("Detect selected %q, want %q", got.Name(), SecretMemoryBackendName)
	}
	hw := &fakeProber{name: "test-secretmem-hardware", rank: 2}
	registerForTest(t, hw)
	if got, _ := Detect(context.Background()); got != Backend(hw) {
		t.Fatalf("Detect selected %q, want the hardware backend ranked 2", got.Name())
	}
}

func TestLinuxSecretmem_ImportRefusalIsTypedAndRefunded(t *testing.T) {
	for _, errno := range []syscall.Errno{unix.ENOSYS, unix.EPERM, unix.ENOMEM} {
		t.Run(errno.Error(), func(t *testing.T) {
			refuseMemfdSecret(t, errno)
			b, a := newSecretMemoryForTest(t, 1<<20)
			material := []byte("secretmem material")
			h, err := b.Import(context.Background(), material, WithPurpose(PurposeMaterial))
			if h != nil {
				t.Fatalf("Import returned a handle %v beside %v", h, err)
			}
			assertMemfdSecretRefusal(t, err, "memfd_secret", errno)
			if !allZero(material) {
				t.Fatal("Import left the caller's material unwiped")
			}
			if a.InUse() != 0 {
				t.Fatalf("InUse() = %d after a refused import, want 0", a.InUse())
			}
		})
	}
}

func TestLinuxSecretmem_ImportNamesARefusedMmap(t *testing.T) {
	memfdStandIn(t, unix.F_SEAL_WRITE)
	b, a := newSecretMemoryForTest(t, 1<<20)
	_, err := b.Import(context.Background(), []byte("material"), WithPurpose(PurposeMaterial))
	assertMemfdSecretRefusal(t, err, "mmap", unix.EPERM)
	if a.InUse() != 0 {
		t.Fatalf("InUse() = %d after a refused mmap, want 0", a.InUse())
	}
}

func TestLinuxSecretmem_ImportValidatesBeforeAnySystemCall(t *testing.T) {
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	b, _ := newSecretMemoryForTest(t, 1<<20)
	ctx := context.Background()
	if _, err := b.Import(ctx, []byte("short"), WithPurpose(PurposeDataKey), WithAlgorithm(AlgorithmAES256GCM)); !errors.Is(err, ErrInvalidImport) {
		t.Fatalf("Import(short AES key) = %v, want ErrInvalidImport", err)
	}
	if _, err := b.Import(ctx, nil, WithPurpose(PurposeMaterial)); !errors.Is(err, ErrEmptyEnclave) {
		t.Fatalf("Import(empty) = %v, want ErrEmptyEnclave", err)
	}
	if _, err := b.Import(ctx, []byte("x")); err == nil {
		t.Fatal("Import with no purpose succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Import(canceled, []byte("x"), WithPurpose(PurposeMaterial)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Import(canceled) = %v, want context.Canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("a refused import called memfd_secret %d times", calls.Load())
	}
}

func TestLinuxSecretmem_ImportBudgetRefusal(t *testing.T) {
	calls := refuseMemfdSecret(t, unix.ENOSYS)
	b, _ := newSecretMemoryForTest(t, pageSize)
	_, err := b.Import(context.Background(), make([]byte, 2*pageSize), WithPurpose(PurposeMaterial))
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("Import past the budget = %v, want a *BudgetError", err)
	}
	if calls.Load() != 0 {
		t.Fatal("an import the budget refused called memfd_secret")
	}
}

// checkSecretHandle runs a handle through its lifecycle: contents, the
// backend it names, frozen pages, the budget and release.
func checkSecretHandle(t *testing.T, b *secretMemory, a Allocator, want []byte) Handle {
	t.Helper()
	material := bytes.Clone(want)
	h, err := b.Import(context.Background(), material, WithPurpose(PurposeMaterial))
	if err != nil {
		t.Fatalf("Import = %v", err)
	}
	if !allZero(material) {
		t.Fatal("Import left the caller's material unwiped")
	}
	if h.Backend() != Backend(b) {
		t.Fatalf("Backend() = %v, want the secretmem backend", h.Backend())
	}
	ba, ok := h.(ByteAccess)
	if !ok {
		t.Fatalf("handle %T is no ByteAccess", h)
	}
	if _, ok := h.(Freezer); !ok {
		t.Fatalf("handle %T is no Freezer", h)
	}
	if eq, err := ba.EqualTo(want); !eq || err != nil {
		t.Fatalf("EqualTo = %t, %v", eq, err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse() = %d, want one page", a.InUse())
	}
	if err := h.(Freezer).Freeze(); err != nil {
		t.Fatalf("Freeze = %v", err)
	}
	return h
}

func TestLinuxSecretmem_HandleLifecycle(t *testing.T) {
	memfdStandIn(t, 0)
	b, a := newSecretMemoryForTest(t, 1<<20)
	h := checkSecretHandle(t, b, a, []byte("secretmem material"))
	if err := h.Destroy(); err != nil {
		t.Fatalf("Destroy = %v", err)
	}
	if h.IsAlive() || h.Size() != 0 || h.Backend() != Backend(b) {
		t.Fatalf("destroyed handle: alive %t, size %d, backend %v", h.IsAlive(), h.Size(), h.Backend())
	}
	if a.InUse() != 0 {
		t.Fatalf("InUse() = %d after Destroy, want 0", a.InUse())
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("second Destroy = %v", err)
	}
}

func TestLinuxSecretmem_WipeAllSweepsItsHandles(t *testing.T) {
	memfdStandIn(t, 0)
	b, a := newSecretMemoryForTest(t, 1<<20)
	h := checkSecretHandle(t, b, a, []byte("swept"))
	if held, err := WipeAll(context.Background()); held != 0 || err != nil {
		t.Fatalf("WipeAll = %d, %v", held, err)
	}
	if h.IsAlive() || a.InUse() != 0 {
		t.Fatalf("after WipeAll: alive %t, in use %d", h.IsAlive(), a.InUse())
	}
}

func TestLinuxSecretmem_TouchFaultIsTyped(t *testing.T) {
	// A shared mapping past the end of an empty memfd faults with SIGBUS on
	// first touch, as a secretmem page the kernel cannot allocate does.
	fd, err := unix.MemfdCreate("secretmem-fault", unix.MFD_CLOEXEC)
	if err != nil {
		t.Skipf("memfd_create refused (%v): the fault stand-in needs it", err)
	}
	defer unix.Close(fd)
	p, err := unix.Mmap(fd, 0, int(pageSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap = %v", err)
	}
	defer unix.Munmap(p)
	err = touchSecret(p)
	var me *MemfdSecretError
	var fault runtime.Error
	if !errors.As(err, &me) || !errors.As(me.Cause, &fault) {
		t.Fatalf("touchSecret over a faulting page = %v, want a *MemfdSecretError carrying the fault", err)
	}
}

// requireMemfdSecret skips where this host refuses memfd_secret, saying why.
func requireMemfdSecret(t *testing.T, b *secretMemory) {
	t.Helper()
	if err := b.Probe(context.Background()); err != nil {
		switch {
		case errors.Is(err, unix.ENOSYS):
			t.Skipf("memfd_secret is disabled, absent or filtered here (ENOSYS: secretmem.enable=0, a kernel before 5.14, or a seccomp profile): %v", err)
		case errors.Is(err, unix.EPERM):
			t.Skipf("memfd_secret is filtered here (EPERM: a seccomp profile or LSM): %v", err)
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.ENOMEM):
			t.Skipf("memfd_secret has no memory or lock headroom here: %v", err)
		}
		t.Fatalf("Probe = %v", err)
	}
}

func TestLinuxSecretmem_RealMemfdSecret(t *testing.T) {
	b, a := newSecretMemoryForTest(t, 1<<20)
	requireMemfdSecret(t, b)
	want := []byte("held in memfd_secret pages")
	h := checkSecretHandle(t, b, a, want)
	defer func() {
		if err := h.Destroy(); err != nil {
			t.Errorf("Destroy = %v", err)
		}
	}()

	// The pages refuse the kernel's access paths: /proc/self/mem cannot read
	// them, while the borrow can.
	var addr uintptr
	if err := h.(ByteAccess).WithBytes(func(p []byte) error {
		addr = uintptr(unsafe.Pointer(unsafe.SliceData(p)))
		if !bytes.Equal(p, want) {
			t.Error("WithBytes saw other bytes")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes = %v", err)
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Skipf("/proc/self/mem is not readable here (%v)", err)
	}
	defer mem.Close()
	got := make([]byte, len(want))
	if n, err := mem.ReadAt(got, int64(addr)); err == nil || bytes.Equal(got[:n], want) {
		t.Fatalf("/proc/self/mem read the material (%d bytes, err %v)", n, err)
	}
}
