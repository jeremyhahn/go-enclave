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
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-enclave/test/integration/internal/devcontainer"
)

// What every enclave's pages look like to the kernel (locked, undumpable,
// guarded, read-only once final), the process-wide RLIMIT_CORE hardening, and
// the recovery paths. Each Refused/Denied test runs in a child with the
// seccomp fault injector (seccomp_test.go), makes the kernel refuse one memory
// syscall, and checks the public outcome: what is returned, held and charged,
// and that a later Destroy or WipeAll finishes once the refusal lifts. Each
// first requires that the injector actually refused something.

// TestEnclaveMappingsAreLockedUndumpableAndGuarded creates an enclave by every
// public route and reads each mapping back from /proc/self/smaps: VmFlags has
// lo, dd and dc; the size is exactly LockedSize(n); permissions are r--p once
// final (rw-p only for an unfrozen sized enclave); the neighbors are unlocked
// ---p guard pages. Every locked mapping in the process, the sealer's
// included, is dd and together they make up VmLck; after WipeAll none remain.
func TestEnclaveMappingsAreLockedUndumpableAndGuarded(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		page := int(enclave.LockedSize(1))

		alloc, err := enclave.NewAllocator(64 * int64(page))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		sealer, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}

		type subject struct {
			name     string
			e        *enclave.MemoryEnclave
			size     int
			writable bool
		}
		var subjects []subject
		add := func(name string, size int, writable bool, e *enclave.MemoryEnclave, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			subjects = append(subjects, subject{name: name, e: e, size: size, writable: writable})
		}

		material := func(n int) []byte { b := make([]byte, n); b[0] = 1; return b }
		e, err := enclave.NewMemoryEnclave(material(32))
		add("NewMemoryEnclave", 32, false, e, err)
		e, err = enclave.NewMemoryEnclaveCopy(material(48))
		add("NewMemoryEnclaveCopy", 48, false, e, err)
		e, err = enclave.NewMemoryEnclaveSized(64)
		add("NewMemoryEnclaveSized (unfrozen)", 64, true, e, err)
		e, err = enclave.NewMemoryEnclaveSized(64)
		if err == nil {
			err = e.Freeze()
		}
		add("NewMemoryEnclaveSized + Freeze", 64, false, e, err)
		large := 3*page + 1
		e, err = enclave.NewMemoryEnclave(material(large))
		add("NewMemoryEnclave (multi-page)", large, false, e, err)
		e, err = alloc.New(material(16))
		add("Allocator.New", 16, false, e, err)
		e, err = alloc.NewSized(16)
		add("Allocator.NewSized (unfrozen)", 16, true, e, err)

		sealed, err := sealer.Seal(ctx, material(40))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		// Open's plaintext is final, so it is frozen read-only before Open returns.
		e, err = sealed.Open(ctx)
		add("SealedEnclave.Open", 40, false, e, err)
		e, err = sealed.OpenWith(ctx, alloc)
		add("SealedEnclave.OpenWith", 40, false, e, err)

		maps := readSmaps(t)
		var accounted int64
		for _, s := range subjects {
			addr := dataAddr(t, s.e)
			v, i, ok := vmaAt(maps, addr)
			if !ok {
				t.Errorf("%s: data address %#x is in no mapping", s.name, addr)
				continue
			}
			if !v.flags["lo"] {
				t.Errorf("%s: mapping is not locked (no VM_LOCKED \"lo\"): %s", s.name, v)
			}
			if !v.flags["dd"] {
				t.Errorf("%s: mapping is not excluded from core dumps (no VM_DONTDUMP \"dd\"): %s", s.name, v)
			}
			if !v.flags["dc"] {
				t.Errorf("%s: mapping is not excluded from fork (no VM_DONTCOPY \"dc\"): %s", s.name, v)
			}
			if want := enclave.LockedSize(s.size); v.size() != want {
				t.Errorf("%s: mapping is %d bytes, want LockedSize(%d) = %d: %s", s.name, v.size(), s.size, want, v)
			}
			wantPerms := "r--p"
			if s.writable {
				wantPerms = "rw-p"
			}
			if v.perms != wantPerms {
				t.Errorf("%s: permissions %s, want %s: %s", s.name, v.perms, wantPerms, v)
			}
			// The kernel may merge adjacent PROT_NONE VMAs, so a guard VMA can
			// exceed one page; only the immediate neighbors are checked.
			if i == 0 || i == len(maps)-1 {
				t.Errorf("%s: mapping has no neighbor on one side, so no guard page", s.name)
				continue
			}
			for _, g := range []struct {
				side string
				v    vma
				ok   bool
			}{
				{"below", maps[i-1], maps[i-1].hi == v.lo},
				{"above", maps[i+1], maps[i+1].lo == v.hi},
			} {
				if !g.ok {
					t.Errorf("%s: no mapping immediately %s the data (gap): %s", s.name, g.side, v)
					continue
				}
				if !g.v.flags["dc"] {
					t.Errorf("%s: the guard %s is not excluded from fork (no \"dc\"): %s", s.name, g.side, g.v)
				}
				if g.v.perms != "---p" {
					t.Errorf("%s: the mapping immediately %s is %s, want an inaccessible ---p guard: %s", s.name, g.side, g.v.perms, g.v)
				}
				if g.v.flags["lo"] {
					t.Errorf("%s: the guard %s is locked; guard pages must cost no locked memory: %s", s.name, g.side, g.v)
				}
			}
			accounted += v.size()
		}

		// Every locked mapping, the sealer's included, is dd, and together they
		// account for all of VmLck.
		locked := lockedVMAs(maps)
		var lockedBytes int64
		for _, v := range locked {
			lockedBytes += v.size()
			if !v.flags["dd"] {
				t.Errorf("locked mapping without VM_DONTDUMP: %s", v)
			}
		}
		if got := vmLck(t); got != lockedBytes {
			t.Errorf("VmLck = %d, but the VM_LOCKED mappings sum to %d: something is locked that smaps does not attribute", got, lockedBytes)
		}
		if lockedBytes <= accounted {
			t.Errorf("locked mappings total %d bytes, no more than the %d of the consumer's own enclaves: the sealer's key hierarchy is not among them, so this check did not cover it",
				lockedBytes, accounted)
		}
		t.Logf("%d consumer enclaves (%d bytes) and %d locked mappings in all (%d bytes, = VmLck), every one VM_LOCKED|VM_DONTDUMP",
			len(subjects), accounted, len(locked), lockedBytes)

		n, err := enclave.WipeAll(ctx)
		if n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
		if got := lockedVMAs(readSmaps(t)); len(got) != 0 {
			t.Errorf("after WipeAll %d locked mapping(s) remain, first: %s", len(got), got[0])
		}
		if got := vmLck(t); got != 0 {
			t.Errorf("after WipeAll VmLck = %d, want 0", got)
		}
		for _, s := range subjects {
			if s.e.IsAlive() {
				t.Errorf("%s: still alive after WipeAll", s.name)
			}
		}
	})
}

// TestCoreDumpLimitLoweredOnImport pins that importing go-enclave lowers
// RLIMIT_CORE to 0 soft and hard, CoreDumpsDisabled reports it, and the
// process cannot raise it again.
//
// It runs in the top-level process so its parent is the `go` command, which
// does not import go-enclave; the test requires that parent's limit to be the
// non-zero figure compose.yaml declares, or "lowered" would be unfalsifiable.
func TestCoreDumpLimitLoweredOnImport(t *testing.T) {
	if isChild() {
		t.Fatalf("must run in the top-level test process, whose parent is the go command")
	}
	want, err := devcontainer.EnvInt64(devcontainer.EnvCoreBytes)
	if err != nil {
		t.Fatal(err)
	}
	soft, hard, err := procLimit(fmt.Sprintf("/proc/%d/limits", os.Getppid()), "Max core file size")
	if err != nil {
		t.Fatalf("reading the parent's core limit: %v", err)
	}
	if soft != strconv.FormatInt(want, 10) || hard != strconv.FormatInt(want, 10) {
		t.Fatalf("the parent process (pid %d, the go command) has core limit %s/%s, want %d/%d from compose.yaml: without a non-zero starting limit this test cannot tell whether go-enclave lowered anything",
			os.Getppid(), soft, hard, want, want)
	}

	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Errorf("RLIMIT_CORE = %d/%d after importing go-enclave, want 0/0 (parent started at %d)", rl.Cur, rl.Max, want)
	}
	if err := enclave.CoreDumpsDisabled(); err != nil {
		t.Errorf("CoreDumpsDisabled() = %v, want nil: the lowering is in place, so the report must say so", err)
	}
	// Hard limit 0 without CAP_SYS_RESOURCE: cannot be raised.
	err = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: uint64(want), Max: uint64(want)})
	if !errors.Is(err, unix.EPERM) {
		t.Errorf("raising RLIMIT_CORE back to %d: err = %v, want EPERM", want, err)
	}
	t.Logf("core limit: parent (go command) %s/%s, this process %d/%d; raise refused: %v", soft, hard, rl.Cur, rl.Max, err)
}

// procLimit returns the soft and hard columns of one /proc/<pid>/limits row.
func procLimit(path, row string) (soft, hard string, err error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- a /proc path built by the caller
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, row); ok {
			f := strings.Fields(rest)
			if len(f) < 2 {
				return "", "", fmt.Errorf("%s: malformed %q row: %q", path, row, line)
			}
			return f[0], f[1], nil
		}
	}
	return "", "", fmt.Errorf("%s: no %q row", path, row)
}

// TestRefusedMlockRollsBackConstruction pins that a refused mlock fails every
// constructor with ErrLockedMemoryUnavailable, refunds the Allocator charge in
// full, leaves nothing on the ledger, and the next allocation succeeds.
func TestRefusedMlockRollsBackConstruction(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, 0)
		a, err := enclave.NewAllocator(16 * enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		f.refuse(unix.SYS_MLOCK, unix.ENOMEM, 0)
		if _, err := enclave.NewMemoryEnclave([]byte("refused")); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Errorf("NewMemoryEnclave with mlock refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		if _, err := a.NewSized(32); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Errorf("Allocator.NewSized with mlock refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		var lme *enclave.LockedMemoryError
		if _, err := a.New([]byte("refused")); !errors.As(err, &lme) || !errors.Is(err, unix.ENOMEM) {
			t.Errorf("Allocator.New with mlock refused = %v, want a *LockedMemoryError carrying ENOMEM", err)
		} else if msg := lme.Error(); !strings.Contains(msg, "locked memory") || !strings.Contains(msg, unix.ENOMEM.Error()) {
			t.Errorf("LockedMemoryError message %q names neither the condition nor the errno", msg)
		}
		requireRefused(t, f, unix.SYS_MLOCK)
		if used := a.InUse(); used != 0 {
			t.Errorf("InUse = %d after constructions whose lock was refused, want 0 (nothing was locked)", used)
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v): a refused construction left something on the ledger", n, err)
		}

		f.allow(unix.SYS_MLOCK)
		e, err := a.NewSized(32)
		if err != nil {
			t.Fatalf("NewSized after the refusal lifted: %v", err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
	})
}

// TestRefusedUnmapKeepsTheEnclaveForARetry pins that a refused munmap makes
// Destroy return the error, keeps the mapping and ledger entry, and a later
// Destroy finishes.
func TestRefusedUnmapKeepsTheEnclaveForARetry(t *testing.T) {
	const n = 48
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, mappingLen(n))
		e, err := enclave.NewMemoryEnclaveSized(n)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}

		f.refuse(unix.SYS_MUNMAP, unix.ENOMEM, 0)
		err = e.Destroy()
		requireRefused(t, f, unix.SYS_MUNMAP)
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) || errors.Is(err, enclave.ErrReleasedWithoutWipe) {
			t.Fatalf("Destroy with munmap refused = %v, want ErrLockedMemoryUnavailable (pages still held)", err)
		}
		if msg := err.Error(); !strings.Contains(msg, unix.ENOMEM.Error()) {
			t.Errorf("Destroy error %q does not name the refused munmap's errno", msg)
		}
		if c, err := enclave.WipeAll(context.Background()); c != 1 || err != nil {
			t.Errorf("WipeAll with the unmap still refused = (%d, %v), want (1, nil)", c, err)
		}

		f.allow(unix.SYS_MUNMAP)
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy after the refusal lifted = %v, want nil", err)
		}
		if c, err := enclave.WipeAll(context.Background()); c != 0 || err != nil {
			t.Errorf("WipeAll = (%d, %v), want (0, nil)", c, err)
		}
	})
}

// TestDeniedMprotectReleasesUnwiped pins that when mprotect is denied a frozen
// enclave is unmapped unwiped and reported as such: ErrReleasedWithoutWipe
// from Destroy, Unwiped in WipeAll's SweepError.
func TestDeniedMprotectReleasesUnwiped(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, 0)
		viaDestroy, err := enclave.NewMemoryEnclave([]byte("frozen at construction"))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		viaSweep, err := enclave.NewMemoryEnclave([]byte("frozen, reclaimed by the sweep"))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}

		f.refuseProt(unix.SYS_MPROTECT, unix.EPERM, unix.PROT_READ|unix.PROT_WRITE)
		err = viaDestroy.Destroy()
		requireRefused(t, f, unix.SYS_MPROTECT)
		if !errors.Is(err, enclave.ErrReleasedWithoutWipe) {
			t.Fatalf("Destroy with mprotect denied = %v, want ErrReleasedWithoutWipe", err)
		}
		var ure *enclave.UnwipedReleaseError
		if !errors.As(err, &ure) || !errors.Is(err, unix.EPERM) {
			t.Errorf("Destroy = %v, want an *UnwipedReleaseError carrying the EPERM", err)
		} else if msg := ure.Error(); !strings.Contains(msg, "without") || !strings.Contains(msg, unix.EPERM.Error()) {
			t.Errorf("UnwipedReleaseError message %q names neither the unwiped release nor the errno", msg)
		}
		if viaDestroy.IsAlive() {
			t.Error("the enclave reports itself alive after an unwiped release")
		}

		c, err := enclave.WipeAll(context.Background())
		var se *enclave.SweepError
		if c != 0 || !errors.As(err, &se) || se.Unwiped != 1 || !errors.Is(err, enclave.ErrReleasedWithoutWipe) {
			t.Fatalf("WipeAll with mprotect denied = (%d, %v), want (0, a SweepError with Unwiped=1)", c, err)
		}
		if msg := se.Error(); !strings.Contains(msg, "1") || !strings.Contains(msg, "without") {
			t.Errorf("SweepError message %q does not report the one unwiped release", msg)
		}
		if viaSweep.IsAlive() {
			t.Error("the swept enclave reports itself alive")
		}
	})
}

// TestRefusedGuardPageRollsBackALockedMapping refuses the guard page after
// the lock succeeded, and the rollback's munlock and munmap too: the mapping
// stays a counted, charged, locked orphan and is reclaimed once the kernel
// relents.
func TestRefusedGuardPageRollsBackALockedMapping(t *testing.T) {
	const n = 40
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, mappingLen(n))
		page := enclave.LockedSize(n)
		a, err := enclave.NewAllocator(16 * page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		f.refuseProt(unix.SYS_MPROTECT, unix.EPERM, unix.PROT_NONE)
		f.refuse(unix.SYS_MUNLOCK, unix.EPERM, 0)
		f.refuse(unix.SYS_MUNMAP, unix.ENOMEM, 0)
		if _, err := a.NewSized(n); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Fatalf("NewSized with the guard page refused = %v, want ErrLockedMemoryUnavailable", err)
		}
		requireRefused(t, f, unix.SYS_MPROTECT)
		requireRefused(t, f, unix.SYS_MUNLOCK)
		requireRefused(t, f, unix.SYS_MUNMAP)
		if used := a.InUse(); used != page {
			t.Errorf("InUse = %d with a locked orphan, want %d", used, page)
		}
		if c, err := enclave.WipeAll(context.Background()); c != 1 || err != nil {
			t.Errorf("WipeAll with the refusals standing = (%d, %v), want (1, nil)", c, err)
		}

		f.allow(unix.SYS_MPROTECT)
		f.allow(unix.SYS_MUNLOCK)
		f.allow(unix.SYS_MUNMAP)
		if c, err := enclave.WipeAll(context.Background()); c != 0 || err != nil {
			t.Fatalf("WipeAll once the refusals lifted = (%d, %v), want (0, nil)", c, err)
		}
		if used := a.InUse(); used != 0 {
			t.Errorf("InUse = %d after reclaim, want 0", used)
		}
	})
}

// TestConstructionFailsClosedWhenAnExclusionIsRefused pins that a refused
// MADV_DONTFORK or MADV_DONTDUMP fails construction with
// ErrLockedMemoryUnavailable and leaves nothing locked.
func TestConstructionFailsClosedWhenAnExclusionIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		advice uint32
	}{
		{"MADV_DONTFORK", unix.MADV_DONTFORK},
		{"MADV_DONTDUMP", unix.MADV_DONTDUMP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolated(t, childOpts{}, func(t *testing.T) {
				installErrnoFilter(t, unix.SYS_MADVISE, 2, tc.advice, unix.EPERM)

				e, err := enclave.NewMemoryEnclave([]byte("refused-exclusion"))
				if e != nil || !errors.Is(err, enclave.ErrLockedMemoryUnavailable) || !errors.Is(err, unix.EPERM) {
					t.Fatalf("NewMemoryEnclave with %s refused = %v, %v; want ErrLockedMemoryUnavailable wrapping EPERM", tc.name, e, err)
				}
				var se *os.SyscallError
				if !errors.As(err, &se) || se.Syscall != "madvise" {
					t.Errorf("err = %v, want the madvise *os.SyscallError reachable", err)
				}
				if locked := lockedVMAs(readSmaps(t)); len(locked) != 0 {
					t.Errorf("the failed construction left %d locked mappings: %v", len(locked), locked)
				}
			})
		})
	}
}
