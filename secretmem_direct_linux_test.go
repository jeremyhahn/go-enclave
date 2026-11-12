// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT

//go:build linux && (386 || amd64 || arm64 || loong64 || riscv64 || s390x)

package enclave

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openFDs counts the descriptors this process holds.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// requireSyscallCause checks err is a *MemfdSecretError whose cause is an
// os.SyscallError naming call.
func requireSyscallCause(t *testing.T, err error, call string) *os.SyscallError {
	t.Helper()
	var typed *MemfdSecretError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v (%T), want *MemfdSecretError", err, err)
	}
	if !errors.Is(err, ErrMemfdSecretUnavailable) {
		t.Errorf("error %v does not match ErrMemfdSecretUnavailable", err)
	}
	var sc *os.SyscallError
	if !errors.As(typed.Cause, &sc) {
		t.Fatalf("cause = %v (%T), want *os.SyscallError", typed.Cause, typed.Cause)
	}
	if sc.Syscall != call {
		t.Fatalf("cause names %q, want %q", sc.Syscall, call)
	}
	return sc
}

// memfdSeam makes memfdSecret hand out an ordinary memfd.
func memfdSeam(t *testing.T) {
	t.Helper()
	swapSeam(t, &memfdSecret, func(int) (int, error) {
		return unix.MemfdCreate("secretmem-direct", unix.MFD_CLOEXEC)
	})
}

func TestSecretmemDirect_CloseSecretOnClosedFD(t *testing.T) {
	fd, err := unix.MemfdCreate("secretmem-direct", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
	}
	err = closeSecret(fd)
	requireSyscallCause(t, err, "close")
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("error %v is not EBADF", err)
	}
}

func TestSecretmemDirect_CloseSecretOnOpenFD(t *testing.T) {
	before := openFDs(t)
	fd, err := unix.MemfdCreate("secretmem-direct", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	if err := closeSecret(fd); err != nil {
		t.Fatalf("closeSecret: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("open fds = %d, want %d", after, before)
	}
}

func TestSecretmemDirect_SecretFileSeamRefused(t *testing.T) {
	swapSeam(t, &memfdSecret, func(int) (int, error) { return -1, syscall.ENOSYS })
	fd, err := secretFile(int(pageSize))
	if fd != -1 {
		t.Errorf("fd = %d, want -1", fd)
	}
	requireSyscallCause(t, err, "memfd_secret")
	if !errors.Is(err, syscall.ENOSYS) {
		t.Fatalf("error %v is not ENOSYS", err)
	}
}

func TestSecretmemDirect_SecretFileFtruncateClosesFD(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[1]) })
	before := openFDs(t)
	swapSeam(t, &memfdSecret, func(int) (int, error) { return p[0], nil })
	fd, err := secretFile(int(pageSize))
	if fd != -1 {
		t.Errorf("fd = %d, want -1", fd)
	}
	requireSyscallCause(t, err, "ftruncate")
	if after := openFDs(t); after != before-1 {
		t.Fatalf("open fds = %d, want %d (the pipe's read end closed)", after, before-1)
	}
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_GETFD, 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("fcntl on the read end = %v, want EBADF", err)
	}
}

func TestSecretmemDirect_SecretFileSizesTheFile(t *testing.T) {
	memfdSeam(t)
	fd, err := secretFile(int(pageSize))
	if err != nil {
		t.Fatalf("secretFile: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if st.Size != int64(pageSize) {
		t.Fatalf("size = %d, want %d", st.Size, pageSize)
	}
}

func TestSecretmemDirect_MapSecretOverMemfd(t *testing.T) {
	memfdSeam(t)
	page, err := sysMap(int(pageSize))
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() { _ = sysUnmap(page) })
	page[0] = 0xAA
	before := openFDs(t)
	if err := mapSecret(page); err != nil {
		t.Fatalf("mapSecret: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("open fds = %d, want %d", after, before)
	}
	if page[0] != 0 {
		t.Fatalf("page[0] = %#x, want 0 from the fresh shared mapping", page[0])
	}
	page[len(page)-1] = 0x55
	if page[len(page)-1] != 0x55 {
		t.Fatal("mapped page is not writable")
	}
}

func TestSecretmemDirect_MapSecretSeamRefused(t *testing.T) {
	swapSeam(t, &memfdSecret, func(int) (int, error) { return -1, syscall.ENOSYS })
	page, err := sysMap(int(pageSize))
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() { _ = sysUnmap(page) })
	requireSyscallCause(t, mapSecret(page), "memfd_secret")
}

func TestSecretmemDirect_MapSecretUnalignedFails(t *testing.T) {
	memfdSeam(t)
	region, err := sysMap(2 * int(pageSize))
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() { _ = sysUnmap(region) })
	before := openFDs(t)
	err = mapSecret(region[1 : int(pageSize)+1])
	sc := requireSyscallCause(t, err, "mmap")
	if !errors.Is(sc, syscall.EINVAL) {
		t.Errorf("mmap cause = %v, want EINVAL", sc)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("open fds = %d, want %d", after, before)
	}
}

func TestSecretmemDirect_TouchSecretEmpty(t *testing.T) {
	if err := touchSecret(nil); err != nil {
		t.Fatalf("touchSecret(nil) = %v", err)
	}
	if err := touchSecret([]byte{}); err != nil {
		t.Fatalf("touchSecret(empty) = %v", err)
	}
}
