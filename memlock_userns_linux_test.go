// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build userns

package enclave

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// This file is built only with -tags=userns, which `make
// integration-test-userns` passes inside the `userns` compose service: the
// default toolchain container refuses user namespaces (its seccomp profile
// denies clone(CLONE_NEWUSER) without CAP_SYS_ADMIN), so there `make test`
// could only fail this test. The tag selects where it runs; it does not make it
// optional. Where it runs and cannot create the namespace, it fails.

const (
	userNamespaceMarker        = "GO_ENCLAVE_USERNS_CHILD"
	userNamespaceNoCapability  = "userns child: no CAP_IPC_LOCK in the namespace"
	userNamespaceLimitEnforced = "userns child: the limit was reported and found enforced"
)

// TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace re-executes the
// test binary as root of a new user namespace, the equivalent of unshare -Ur:
// it holds CAP_IPC_LOCK there, and the kernel still applies RLIMIT_MEMLOCK
// because the capability is checked in the initial namespace. The child
// asserts both: this package reports the limit enforced, and mlock past it
// really fails.
//
// It fails when the host refuses unprivileged user namespaces, or grants one
// without capabilities (an AppArmor userns restriction): a run that verified
// nothing is not a pass.
func TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace(t *testing.T) {
	if os.Getenv(userNamespaceMarker) == "1" {
		userNamespaceChild(t)
		return
	}

	attr := &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	probe := exec.Command(os.Args[0], "-test.run=^$")
	probe.SysProcAttr = attr
	if err := probe.Run(); err != nil {
		for _, denied := range []error{unix.EPERM, unix.EACCES, unix.ENOSPC, unix.EINVAL, unix.ENOSYS} {
			if errors.Is(err, denied) {
				t.Fatalf("unprivileged user namespaces are unavailable here; run this test under a seccomp "+
					"profile that permits CLONE_NEWUSER (make integration-test-userns): %v", err)
			}
		}
		t.Fatalf("starting a child in a new user namespace: %v", err)
	}

	out, err := runTestChildWith(t, "TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace",
		userNamespaceMarker, "1", attr)
	if strings.Contains(out, userNamespaceNoCapability) {
		t.Fatalf("the user namespace carries no capabilities here (an AppArmor userns restriction?):\n%s", out)
	}
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, userNamespaceLimitEnforced) {
		t.Fatalf("subprocess did not confirm the enforced limit:\n%s", out)
	}
}

func userNamespaceChild(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()

	raw, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatalf("read uid_map: %v", err)
	}
	if fields := strings.Fields(string(raw)); len(fields) == 3 && fields[1] == "0" && fields[2] == "4294967295" {
		t.Fatalf("the child is in the initial user namespace (uid_map %q); nothing is under test", raw)
	}
	if !testHoldsIPCLock(t) {
		t.Log(userNamespaceNoCapability)
		return
	}

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	ceiling := uint64(4 * pageSize)
	if original.Max != rlimInfinity && original.Max < ceiling {
		ceiling = original.Max
	}
	// Past the ceiling by at least one whole page, whatever its size.
	over := int((ceiling/uint64(pageSize) + 1) * uint64(pageSize))
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: ceiling, Max: original.Max}); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Source != LimitRLimit || !limit.Bounded || limit.Bytes != int64(ceiling) {
		t.Fatalf("DiscoverLockedMemoryLimit = %+v, want a bounded LimitRLimit of %d: CAP_IPC_LOCK in a "+
			"child namespace does not lift the limit", limit, ceiling)
	}
	if _, err := NewAllocatorWithinRLimit(int64(over)); !errors.Is(err, ErrBudgetExceedsRLimit) {
		t.Fatalf("NewAllocatorWithinRLimit over the ceiling = %v, want ErrBudgetExceedsRLimit", err)
	}

	// The kernel agrees: a region larger than the ceiling cannot be locked.
	region, err := sysMap(over)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() { _ = sysUnmap(region) }()
	if err := unix.Mlock(region); !errors.Is(err, unix.ENOMEM) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("mlock past the ceiling = %v, want ENOMEM: the kernel did not enforce the limit, so "+
			"this host does not reproduce the case under test", err)
	}
	t.Log(userNamespaceLimitEnforced)
}
