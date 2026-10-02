// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && linux

package enclave_test

// REAL KERNEL REFUSALS, ON DEMAND.
//
// go-enclave's recovery paths — a refused mlock rolled back, a refused munlock
// or munmap leaving a mapping held, a constructor's orphan adopted and later
// reclaimed, a frozen enclave released unwiped because mprotect was denied —
// run only when the kernel says no. The unit tests reach them through
// in-package seams; an integration test must reach them through the public API,
// so the refusal has to come from the kernel itself.
//
// This is a seccomp user-notification supervisor. A child process (always one:
// a seccomp filter cannot be removed, so it must never be installed in the
// shared parent) installs a filter that routes exactly the library's memory
// syscalls — mlock, munlock, mprotect, and munmap of one chosen length — to a
// supervisor goroutine in the same process (mprotect only up to
// maxRoutedMprotect bytes; see below). The supervisor answers each from a
// policy the test changes at run time: let the call through
// (SECCOMP_USER_NOTIF_FLAG_CONTINUE, the kernel performs it exactly as it would
// have), or fail it with an errno. A refusal is therefore a real syscall
// returning a real error to the library's real code, and lifting it is a
// policy change, which is what lets a test drive "refused, then retried after
// the condition lifted" — the shape every reclaim path is about.
//
// Scope, stated precisely:
//   - Nothing the process needs in order to RUN the supervisor may be routed
//     to it, or the two wait on each other. The pure-Go runtime makes no
//     mlock, munlock or mprotect on linux, but a cgo build — every -race
//     build is one — creates threads with pthread_create, and musl's
//     pthread_create mprotects each new thread's stack read-write. Routed,
//     that deadlocks the moment the supervisor's goroutine needs a fresh
//     thread to run on (measured: three threads parked in
//     seccomp_do_user_notification, none in the supervisor's receive), and
//     refused it aborts the runtime (measured: "pthread_create failed").
//     So mprotect is routed only for lengths up to maxRoutedMprotect, which
//     covers every enclave region these tests create and no thread stack
//     (musl's smallest is 128 KiB). The munmap rule likewise matches one
//     length the test chooses (an enclave mapping's total size).
//   - The supervisor's goroutine is locked to its own thread and makes only
//     ioctl and futex-class calls, none of which the filter routes.
//   - Requires Linux >= 5.19 (WAIT_KILLABLE_RECV, so the Go runtime's own
//     preemption signals cannot withdraw a notification the supervisor is
//     answering; TSYNC_ESRCH alongside NEW_LISTENER), no_new_privs
//     (set here, unprivileged), and a container seccomp profile that permits
//     seccomp(2) — Docker's default does. Absence is a failure, not a skip.

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The kernel's notification structures (include/uapi/linux/seccomp.h). x/sys
// exports the ioctl numbers and flags but not these layouts.
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type seccompNotif struct {
	ID    uint64
	Pid   uint32
	Flags uint32
	Data  seccompData
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// syscallRule is the supervisor's answer for one syscall: refuse with errno
// when Refuse is set, otherwise let it through. Addr, when non-zero, limits a
// refusal to calls whose first argument is exactly that address — the way a
// test refuses ONE enclave's munlock while every other proceeds.
type syscallRule struct {
	Refuse bool
	Errno  unix.Errno
	Addr   uintptr
	// Prot, when HasProt is set, limits a refusal to calls whose third
	// argument is exactly Prot — mprotect's protection, which is how a test
	// refuses the freeze (PROT_READ) while guard-page setup (PROT_NONE) and
	// release (PROT_READ|PROT_WRITE) proceed.
	Prot    uint64
	HasProt bool
	// Skip lets that many matching calls through before the refusal starts,
	// which is how a test refuses the Nth lock of an operation — the KEK a
	// seal mints after its DEK and root, say — rather than the first.
	//
	// It counts DISTINCT addresses (args[0]), not notifications. A syscall
	// the kernel restarts — a signal landing after the supervisor's answer
	// was accepted but before the target consumed it, a race Linux closed
	// only in commit cce436aafc2a — is presented again with the same
	// arguments, and must not spend a second allowance. Within one refusal
	// sequence every allocation is a distinct live mapping, so its address
	// identifies it.
	Skip    uint64
	skipped map[uintptr]struct{}
}

// faultInjector is a running supervisor. Its rules are read on every
// notification, so a test changes the kernel's answers mid-run by calling
// set; refused and allowed count what it actually answered.
type faultInjector struct {
	mu      sync.Mutex
	rules   map[int32]syscallRule
	refused map[int32]*atomic.Int64
	allowed map[int32]*atomic.Int64
	fd      int
}

func syscallName(nr int32) string {
	switch nr {
	case unix.SYS_MLOCK:
		return "mlock"
	case unix.SYS_MUNLOCK:
		return "munlock"
	case unix.SYS_MPROTECT:
		return "mprotect"
	case unix.SYS_MUNMAP:
		return "munmap"
	}
	return fmt.Sprintf("syscall %d", nr)
}

func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	}
	return 0, fmt.Errorf("no seccomp audit arch for GOARCH=%s", runtime.GOARCH)
}

// installFaultInjector installs the filter and starts the supervisor. It must
// run inside an isolated child: the filter is permanent for the process.
// munmapLen is the one munmap length routed to the supervisor (0 routes none).
// maxRoutedMprotect is the largest mprotect the filter routes to the
// supervisor: well above any enclave region these tests create (a few pages),
// well below any thread stack (musl's smallest is 128 KiB), so the runtime's
// own thread creation is never routed; see the scope notes above.
const maxRoutedMprotect = 64 << 10

func installFaultInjector(t *testing.T, munmapLen uint64) *faultInjector {
	t.Helper()
	if !isChild() {
		t.Fatal("installFaultInjector outside an isolated child: a seccomp filter cannot be removed, so it would outlive this test")
	}
	arch, err := auditArch()
	if err != nil {
		t.Fatal(err)
	}

	const (
		ldW   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeqK  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jgtK  = unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K
		retK  = unix.BPF_RET | unix.BPF_K
		offNr = 0
		offAr = 4
		// args[1] of a little-endian seccomp_data: low word at 16+8, high at 28.
		offLenLo = 24
		offLenHi = 28
	)
	notify := uint32(unix.SECCOMP_RET_USER_NOTIF)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	// Layout (jump offsets are relative to the next instruction):
	//  0 ld arch            1 jeq arch ? 2 : ALLOW
	//  2 ld nr              3 jeq mlock    → NOTIFY
	//  4 jeq munlock → NOTIFY               5 jeq mprotect → 11
	//  6 jeq munmap ? 7 : ALLOW
	//  7 ld len.lo          8 jeq munmapLen.lo ? 9 : ALLOW
	//  9 ld len.hi         10 jeq munmapLen.hi ? NOTIFY : ALLOW
	// 11 ld len.hi         12 jeq 0 ? 13 : ALLOW
	// 13 ld len.lo         14 jgt maxRoutedMprotect ? ALLOW : NOTIFY
	// 15 NOTIFY            16 ALLOW
	prog := []unix.SockFilter{
		{Code: ldW, K: offAr},
		{Code: jeqK, Jt: 0, Jf: 14, K: arch},
		{Code: ldW, K: offNr},
		{Code: jeqK, Jt: 11, Jf: 0, K: uint32(unix.SYS_MLOCK)},
		{Code: jeqK, Jt: 10, Jf: 0, K: uint32(unix.SYS_MUNLOCK)},
		{Code: jeqK, Jt: 5, Jf: 0, K: uint32(unix.SYS_MPROTECT)},
		{Code: jeqK, Jt: 0, Jf: 9, K: uint32(unix.SYS_MUNMAP)},
		{Code: ldW, K: offLenLo},
		{Code: jeqK, Jt: 0, Jf: 7, K: uint32(munmapLen)},
		{Code: ldW, K: offLenHi},
		{Code: jeqK, Jt: 4, Jf: 5, K: uint32(munmapLen >> 32)},
		{Code: ldW, K: offLenHi},
		{Code: jeqK, Jt: 0, Jf: 3, K: 0},
		{Code: ldW, K: offLenLo},
		{Code: jgtK, Jt: 1, Jf: 0, K: maxRoutedMprotect},
		{Code: retK, K: notify},
		{Code: retK, K: allow},
	}
	if munmapLen == 0 {
		// No munmap is routed: make the munmap arm fall straight to ALLOW.
		prog[6] = unix.SockFilter{Code: jeqK, Jt: 9, Jf: 9, K: uint32(unix.SYS_MUNMAP)}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("prctl(PR_SET_NO_NEW_PRIVS): %v — needed to install a seccomp filter unprivileged", err)
	}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER|unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH|unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
		uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		t.Fatalf("seccomp(SET_MODE_FILTER, NEW_LISTENER|TSYNC|TSYNC_ESRCH|WAIT_KILLABLE_RECV): %v — the integration suite needs Linux >= 5.19 and a container seccomp profile that permits seccomp(2) (Docker's default does)", errno)
	}

	f := &faultInjector{
		rules:   map[int32]syscallRule{},
		refused: map[int32]*atomic.Int64{},
		allowed: map[int32]*atomic.Int64{},
		fd:      int(fd),
	}
	for _, nr := range []int32{unix.SYS_MLOCK, unix.SYS_MUNLOCK, unix.SYS_MPROTECT, unix.SYS_MUNMAP} {
		f.refused[nr] = new(atomic.Int64)
		f.allowed[nr] = new(atomic.Int64)
	}
	started := make(chan struct{})
	go f.supervise(started)
	<-started
	// The filter and its supervisor live until the process exits, but no
	// refusal may outlive the test that set it: the child still runs the
	// testing framework's teardown and the runtime's exit path afterwards, and
	// a stale mprotect refusal there fails cgo's pthread_create (measured:
	// SIGABRT after a passing test). Every rule is lifted at cleanup.
	t.Cleanup(func() {
		for nr := range f.refused {
			f.allow(nr)
		}
	})
	return f
}

// set replaces the rule for one syscall.
func (f *faultInjector) set(nr int32, r syscallRule) {
	f.mu.Lock()
	f.rules[nr] = r
	f.mu.Unlock()
}

// refuse makes every call of nr fail with errno (addr 0) or only the call on
// addr; allow lifts any refusal for nr.
func (f *faultInjector) refuse(nr int32, errno unix.Errno, addr uintptr) {
	f.set(nr, syscallRule{Refuse: true, Errno: errno, Addr: addr})
}

// refuseProt makes calls of nr whose third argument equals prot fail with errno.
func (f *faultInjector) refuseProt(nr int32, errno unix.Errno, prot uint64) {
	f.set(nr, syscallRule{Refuse: true, Errno: errno, Prot: prot, HasProt: true})
}

// refuseAfter lets the next skip calls of nr through, then refuses every
// later one with errno.
func (f *faultInjector) refuseAfter(nr int32, errno unix.Errno, skip uint64) {
	f.set(nr, syscallRule{Refuse: true, Errno: errno, Skip: skip, skipped: map[uintptr]struct{}{}})
}

func (f *faultInjector) allow(nr int32) { f.set(nr, syscallRule{}) }

func (f *faultInjector) refusals(nr int32) int64 { return f.refused[nr].Load() }

// respond decides the answer to one notification, sends it, and only once
// the kernel has ACCEPTED it commits what the answer consumed — a Skip
// allowance, a counter. A notification the kernel withdraws (ENOENT: the
// target was killed) consumes nothing, so it cannot shift which call of a
// sequence is refused. f.mu is held throughout, so a rule a test changes
// concurrently is never half-applied; the supervisor is the only responder,
// so notifications are answered one at a time in any case.
func (f *faultInjector) respond(n *seccompNotif) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.decideLocked(n)
	refuse := d.refuse
	resp := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	counter := f.allowed[n.Data.Nr]
	if refuse {
		resp = seccompNotifResp{ID: n.ID, Error: -int32(d.errno)}
		counter = f.refused[n.Data.Nr]
	}
	// Counted BEFORE the answer is sent: the target resumes the moment the
	// kernel accepts it, and a test that reads the counter right after its
	// syscall returns must already see it. Taken back if the answer is not
	// accepted.
	if counter != nil {
		counter.Add(1)
	}
	for {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(f.fd), uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND), uintptr(unsafe.Pointer(&resp)))
		if errno == unix.EINTR {
			continue
		}
		if errno == 0 {
			break
		}
		if counter != nil {
			counter.Add(-1)
		}
		if errno == unix.ENOENT {
			return nil // withdrawn: nothing was answered, nothing is consumed
		}
		return errno
	}
	f.commitLocked(n, d)
	return nil
}

// decision is what the supervisor will answer to one notification.
type decision struct {
	refuse    bool
	errno     unix.Errno
	skip      bool // let through on a Skip allowance
	restarted bool // ...one this address already spent
}

// decideLocked decides the answer to n from the current rule without
// changing anything; f.mu is held.
func (f *faultInjector) decideLocked(n *seccompNotif) decision {
	r := f.rules[n.Data.Nr]
	addr := uintptr(n.Data.Args[0])
	matches := r.Refuse && (r.Addr == 0 || addr == r.Addr) && (!r.HasProt || n.Data.Args[2] == r.Prot)
	_, restarted := r.skipped[addr]
	skip := matches && (restarted || r.Skip > 0)
	return decision{refuse: matches && !skip, errno: r.Errno, skip: skip, restarted: restarted}
}

// commitLocked records what an ACCEPTED answer consumed: a Skip allowance,
// once per address. The supervisor answers one notification at a time under
// f.mu, so no later call is decided before this commit.
func (f *faultInjector) commitLocked(n *seccompNotif, d decision) {
	if !d.skip || d.restarted {
		return
	}
	r := f.rules[n.Data.Nr]
	r.Skip--
	r.skipped[uintptr(n.Data.Args[0])] = struct{}{}
	f.rules[n.Data.Nr] = r
}

// supervise answers notifications for the life of the process. It is locked to
// its own thread so nothing else ever runs on the thread that must answer.
//
// The filter is installed with WAIT_KILLABLE_RECV, so once a notification has
// been received only a FATAL signal can cancel it; before that, a signal to
// the target withdraws it and the target restarts the syscall, which RECV may
// observe as ENOENT for a notification that is already gone. Both RECV errors
// are therefore "nothing to answer", never a reason to stop answering.
func (f *faultInjector) supervise(started chan<- struct{}) {
	runtime.LockOSThread()
	close(started)
	for {
		var n seccompNotif
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(f.fd), uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV), uintptr(unsafe.Pointer(&n))); errno != 0 {
			if errno == unix.EINTR || errno == unix.ENOENT {
				continue
			}
			// Any other failure means the listener itself is broken; nothing
			// can be answered from here on, and every routed syscall would
			// hang, so stop the process loudly instead.
			panic(fmt.Sprintf("seccomp supervisor: NOTIF_RECV: %v", errno))
		}
		if err := f.respond(&n); err != nil {
			panic(fmt.Sprintf("seccomp supervisor: NOTIF_SEND for %s: %v", syscallName(n.Data.Nr), err))
		}
	}
}

// TestFaultInjectorRefusesAndLifts proves the instrument before anything
// relies on it: a refused mlock really fails with the chosen errno, the same
// call succeeds once lifted, and the supervisor counted both answers. Without
// this, a filter that silently routed nothing would make every fault test
// below pass by never faulting.
func TestFaultInjectorRefusesAndLifts(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		f := installFaultInjector(t, 0)
		page := unix.Getpagesize()
		b, err := unix.Mmap(-1, 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if err != nil {
			t.Fatalf("mmap: %v", err)
		}
		defer func() { _ = unix.Munmap(b) }()

		f.refuse(unix.SYS_MLOCK, unix.EPERM, 0)
		if err := unix.Mlock(b); !errors.Is(err, unix.EPERM) {
			t.Fatalf("mlock under a refusing rule = %v, want EPERM from the supervisor", err)
		}
		// At least one: a kernel without the fast-reply fix can restart the
		// call after an accepted refusal, which is answered (and counted)
		// again; the result the caller sees is the same.
		if f.refusals(unix.SYS_MLOCK) < 1 {
			t.Fatalf("the supervisor counted %d mlock refusals, want at least 1", f.refusals(unix.SYS_MLOCK))
		}
		f.allow(unix.SYS_MLOCK)
		if err := unix.Mlock(b); err != nil {
			t.Fatalf("mlock after the refusal was lifted = %v, want success", err)
		}
		if err := unix.Munlock(b); err != nil {
			t.Fatalf("munlock: %v", err)
		}
		if f.allowed[unix.SYS_MLOCK].Load() < 1 || f.allowed[unix.SYS_MUNLOCK].Load() < 1 {
			t.Fatal("the supervisor never saw the allowed calls: the filter is not routing them")
		}
	})
}

// mappingLen is the total length of the mapping behind an n-byte enclave: its
// locked data pages plus the guard page on each side.
func mappingLen(n int) uint64 {
	return uint64(enclave.LockedSize(n)) + 2*uint64(unix.Getpagesize())
}

func requireRefused(t *testing.T, f *faultInjector, nr int32) {
	t.Helper()
	if f.refusals(nr) == 0 {
		t.Fatalf("the injector never refused %s: the fault this test is about did not happen", syscallName(nr))
	}
}

// TestFaultInjectorSkipSurvivesRestartedSyscalls replays the notifications a
// kernel produces when it restarts a syscall after the supervisor's answer
// was accepted (the fast-reply race, fixed upstream in cce436aafc2a): the same
// call, same arguments, presented again. It drives the decision and commit
// directly, so the replay is deterministic instead of depending on signal
// timing. A replayed call that was let through on an allowance is let through
// again without spending another; a replayed refusal is refused again; and
// the call the rule targets is still the one refused.
func TestFaultInjectorSkipSurvivesRestartedSyscalls(t *testing.T) {
	f := &faultInjector{rules: map[int32]syscallRule{}}
	f.rules[unix.SYS_MLOCK] = syscallRule{Refuse: true, Errno: unix.ENOMEM, Skip: 2, skipped: map[uintptr]struct{}{}}
	notif := func(addr uintptr) *seccompNotif {
		return &seccompNotif{Data: seccompData{Nr: unix.SYS_MLOCK, Args: [6]uint64{uint64(addr)}}}
	}
	answer := func(addr uintptr) bool {
		n := notif(addr)
		d := f.decideLocked(n)
		f.commitLocked(n, d) // as if the kernel accepted the answer
		return d.refuse
	}
	for i, step := range []struct {
		addr   uintptr
		refuse bool
	}{
		{0x1000, false}, // first allowance
		{0x1000, false}, // restarted: no second allowance spent
		{0x2000, false}, // second allowance
		{0x1000, false}, // restarted again, still free
		{0x3000, true},  // the third distinct call is the refused one
		{0x3000, true},  // restarted refusal: refused again
	} {
		if got := answer(step.addr); got != step.refuse {
			t.Fatalf("step %d (addr %#x): refused = %t, want %t", i, step.addr, got, step.refuse)
		}
	}
	if left := f.rules[unix.SYS_MLOCK].Skip; left != 0 {
		t.Fatalf("Skip left = %d, want 0: replays spent or failed to spend allowances", left)
	}
}
