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
	"os"
	"runtime"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The architectures listed are those x/sys carries SYS_MEMFD_SECRET for; every
// other Linux one compiles secretmem_unsupported.go. x/sys has no wrapper, so
// the call is a raw syscall.

// memfdSecret is memfd_secret(2), returning the descriptor or the errno. It
// is a variable only so this package's tests can inject a refusal without
// depending on the host kernel.
var memfdSecret = sysMemfdSecret

// sysMemfdSecret is the raw memfd_secret(2) call.
func sysMemfdSecret(flags int) (int, error) {
	fd, _, errno := unix.Syscall(unix.SYS_MEMFD_SECRET, uintptr(flags), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// secretMemorySupported is nil: this build has memfd_secret. Whether the host
// allows it is the probe's question.
func secretMemorySupported() error { return nil }

// secretFile opens a close-on-exec secretmem file of n bytes. The caller
// closes it once it is mapped.
func secretFile(n int) (int, error) {
	fd, err := memfdSecret(unix.O_CLOEXEC)
	if err != nil {
		return -1, &MemfdSecretError{Cause: os.NewSyscallError("memfd_secret", err)}
	}
	if err := unix.Ftruncate(fd, int64(n)); err != nil {
		return -1, withCleanupFailure(&MemfdSecretError{Cause: os.NewSyscallError("ftruncate", err)}, closeSecret(fd))
	}
	return fd, nil
}

// closeSecret closes a secretmem file; a mapping of it outlives the close.
func closeSecret(fd int) error {
	if err := unix.Close(fd); err != nil {
		return &MemfdSecretError{Cause: os.NewSyscallError("close", err)}
	}
	return nil
}

// mapSecret maps a secretmem file of len(inner) bytes MAP_SHARED over inner's
// anonymous pages, closes it, and touches every page. inner is whole pages.
// It is mapBacked's back for the secretmem backend, so the mapping layer then
// applies MADV_DONTFORK, the canary and the guard pages as it does for locked
// memory.
func mapSecret(inner []byte) error {
	fd, err := secretFile(len(inner))
	if err != nil {
		return err
	}
	addr := unsafe.Pointer(unsafe.SliceData(inner)) // #nosec G103 -- the address of mmap'd pages MAP_FIXED replaces; not Go heap
	_, err = unix.MmapPtr(fd, 0, addr, uintptr(len(inner)),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FIXED)
	if err != nil {
		err = &MemfdSecretError{Cause: os.NewSyscallError("mmap", err)}
	}
	if failure := withCleanupFailure(err, closeSecret(fd)); failure != nil {
		return failure
	}
	return touchSecret(inner)
}

// probeSecret maps one secretmem page, touches it and releases it, leaving
// nothing behind: what [secretMemory.Probe] does once ctx allows.
func probeSecret() error {
	n := int(pageSize)
	fd, err := secretFile(n)
	if err != nil {
		return err
	}
	b, err := unix.Mmap(fd, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return withCleanupFailure(&MemfdSecretError{Cause: os.NewSyscallError("mmap", err)}, closeSecret(fd))
	}
	failure := closeSecret(fd)
	if failure == nil {
		failure = touchSecret(b)
	}
	if err := unix.Munmap(b); err != nil {
		return withCleanupFailure(failure, &MemfdSecretError{Cause: os.NewSyscallError("munmap", err)})
	}
	return failure
}

// touchSecret writes every page of p once, so the kernel allocates each and
// removes it from the direct map now. A failure there is a SIGBUS, not an
// error return; debug.SetPanicOnFault turns it into a panic this recovers.
// p's pages are fresh and zero, so writing zero changes nothing.
func touchSecret(p []byte) (err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		fault, ok := r.(runtime.Error)
		if !ok {
			panic(r)
		}
		err = &MemfdSecretError{Cause: fault}
	}()
	for i := 0; i < len(p); i += int(pageSize) {
		p[i] = 0
	}
	return nil
}
