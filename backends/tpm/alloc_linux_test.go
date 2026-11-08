//go:build linux && (amd64 || arm64)

package tpm

import (
	"bufio"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestLockedAllocator_ExcludesFromDumpAndFork reads the kernel's flags for a
// transient's mapping: locked ("lo"), left out of core dumps ("dd") and not
// copied into a forked child ("dc").
func TestLockedAllocator_ExcludesFromDumpAndFork(t *testing.T) {
	a := newAllocator()
	b, err := a.alloc(32)
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	defer a.free(b)
	flags, ok := vmFlags(t, addrOf(b))
	if !ok {
		t.Fatal("the transient is not in /proc/self/smaps")
	}
	for _, f := range []string{"lo", "dd", "dc"} {
		if !slices.Contains(flags, f) {
			t.Errorf("the transient's mapping lacks VmFlag %q: %v", f, flags)
		}
	}
}

// TestLockedAllocator_FailsClosedWhenAnExclusionIsRefused refuses each
// madvise(2) exclusion in turn: the allocation fails with ErrLockedMemory
// wrapping the refusal and leaves no mapping.
func TestLockedAllocator_FailsClosedWhenAnExclusionIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		advice int
	}{
		{"MADV_DONTDUMP", unix.MADV_DONTDUMP},
		{"MADV_DONTFORK", unix.MADV_DONTFORK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origAdvise, origUnmap := madvise, munmap
			t.Cleanup(func() { madvise, munmap = origAdvise, origUnmap })
			var mapped, unmapped []uintptr
			var mappedLen, unmappedLen []int
			var unmapErr error
			refused := false
			madvise = func(b []byte, advice int) error {
				mapped = append(mapped, addrOf(b))
				mappedLen = append(mappedLen, len(b))
				if advice == tc.advice {
					refused = true
					return unix.EPERM
				}
				return origAdvise(b, advice)
			}
			// The unmap is checked by what alloc hands to munmap and what
			// munmap returns, not by looking the address up afterwards: once
			// unmapped, any other mapping can take it.
			munmap = func(b []byte) error {
				unmapped = append(unmapped, addrOf(b))
				unmappedLen = append(unmappedLen, len(b))
				err := origUnmap(b)
				unmapErr = errors.Join(unmapErr, err)
				return err
			}
			a := newAllocator().(*lockedAllocator)
			b, err := a.alloc(32)
			if !errors.Is(err, ErrLockedMemory) || !errors.Is(err, unix.EPERM) || b != nil {
				t.Fatalf("got %d bytes, %v; want ErrLockedMemory wrapping EPERM", len(b), err)
			}
			if !refused {
				t.Fatalf("alloc did not ask for %s", tc.name)
			}
			if len(unmapped) != 1 {
				t.Fatalf("alloc unmapped %d times; want once", len(unmapped))
			}
			if unmapped[0] != mapped[0] || unmappedLen[0] != mappedLen[0] {
				t.Fatalf("alloc unmapped %d bytes at %#x; it mapped %d bytes at %#x",
					unmappedLen[0], unmapped[0], mappedLen[0], mapped[0])
			}
			for i := range mapped {
				if mapped[i] != mapped[0] || mappedLen[i] != mappedLen[0] {
					t.Fatalf("alloc advised %d bytes at %#x; it mapped %d bytes at %#x",
						mappedLen[i], mapped[i], mappedLen[0], mapped[0])
				}
			}
			if unmapErr != nil {
				t.Fatalf("the refused transient was not unmapped: %v", unmapErr)
			}
			if len(a.maps) != 0 {
				t.Fatalf("the allocator kept %d refused mappings", len(a.maps))
			}
		})
	}
}

// TestLockedAllocator_TransientNotInForkedChild forks children that probe
// whether a page is mapped: the child calls msync(2) on it and exits with the
// errno, ENOMEM where nothing is mapped. A plain anonymous page is the
// control: the child must see it mapped, and must not see the transient.
func TestLockedAllocator_TransientNotInForkedChild(t *testing.T) {
	a := newAllocator()
	b, err := a.alloc(32)
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	defer a.free(b)
	copy(b, canary(32))
	control, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() { _ = unix.Munmap(control) }()

	if got := probeInChild(t, addrOf(control)); got != 0 {
		t.Fatalf("the child's msync of the control page: %v, want it mapped", got)
	}
	if got := probeInChild(t, addrOf(b)); got != unix.ENOMEM {
		t.Fatalf("the child's msync of the transient: %v, want ENOMEM (not mapped)", got)
	}
}

func probeInChild(t *testing.T, p uintptr) syscall.Errno {
	t.Helper()
	pid, errno := forkProbe(p, uintptr(os.Getpagesize()))
	if errno != 0 {
		t.Fatalf("fork: %v", errno)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(int(pid), &ws, 0, nil); err != nil {
		t.Fatalf("wait4: %v", err)
	}
	if !ws.Exited() {
		t.Fatalf("the probe child did not exit: %#x", uint32(ws))
	}
	return syscall.Errno(ws.ExitStatus())
}

// forkProbe forks; the child calls msync(2) on [p, p+n) and exits with its
// errno. The child holds one thread of a copied runtime, so, as in the
// runtime's own fork, it makes only raw system calls. clone's arguments past
// the flags are zero, so their order, which differs by architecture, does not
// matter.
//
//go:norace
//go:nosplit
func forkProbe(p, n uintptr) (pid uintptr, errno syscall.Errno) {
	r, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e != 0 || r != 0 {
		return r, e
	}
	_, _, e = syscall.RawSyscall(syscall.SYS_MSYNC, p, n, syscall.MS_ASYNC)
	_, _, _ = syscall.RawSyscall(syscall.SYS_EXIT_GROUP, uintptr(e), 0, 0)
	return 0, 0
}

func addrOf(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[:1][0])) }

// vmFlags returns the VmFlags of the mapping holding p, and whether one does.
func vmFlags(t *testing.T, p uintptr) ([]string, bool) {
	t.Helper()
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		t.Fatalf("open smaps: %v", err)
	}
	defer f.Close()
	in := false
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if lo, hi, ok := mapRange(line); ok {
			in = lo <= p && p < hi
			continue
		}
		if v, ok := strings.CutPrefix(line, "VmFlags:"); ok && in {
			return strings.Fields(v), true
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("read smaps: %v", err)
	}
	return nil, false
}

// mapRange parses an smaps header line, "lo-hi perms ...".
func mapRange(line string) (lo, hi uintptr, ok bool) {
	r, _, _ := strings.Cut(line, " ")
	l, h, found := strings.Cut(r, "-")
	if !found {
		return 0, 0, false
	}
	a, err1 := strconv.ParseUint(l, 16, 64)
	b, err2 := strconv.ParseUint(h, 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uintptr(a), uintptr(b), true
}
