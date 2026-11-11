// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"crypto/rand"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestFindPlantsNoCopyOfTheNeedle sweeps for a 32-byte needle while signals
// land on the sweeping thread, then sweeps again. A search that holds the
// whole needle in registers (bytes.Contains does, for a needle this short)
// has the kernel save it, byte-exact, into each signal frame on the
// thread's signal stack, which lives in the Go heap and is never cleared:
// the sweep itself would plant the residue it is looking for.
func TestFindPlantsNoCopyOfTheNeedle(t *testing.T) {
	// 16 bytes fit one vector register, 32 bytes four general registers: the
	// lengths a short-needle search keeps whole in registers on amd64 and arm64.
	for _, n := range []int{16, 32} {
		t.Run("", func(t *testing.T) { testFindPlantsNoCopy(t, n) })
	}
}

func testFindPlantsNoCopy(t *testing.T, n int) {
	page := syscall.Getpagesize()
	region, err := syscall.Mmap(-1, 0, page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() {
		clear(region)
		_ = syscall.Munmap(region)
	}()
	needle := region[:n]
	if _, err := rand.Read(needle); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	needle[1] = needle[0] ^ 1                                 // the filler below must not match the needle's start
	home := uintptr(unsafe.Pointer(unsafe.SliceData(region))) // the needle's own mapping, excluded from the sweep

	for range 3 {
		if err := findUnderSignals(needle, home); err != nil {
			t.Fatalf("Find under signals: %v", err)
		}
	}
	hits, err := Find(needle, home)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(hits) > 0 {
		t.Fatalf("after sweeps under signals the needle is resident in %d mapping(s) outside its own: %q; "+
			"the sweep planted copies of what it looks for", len(hits), hits[0])
	}
}

// findUnderSignals runs Find on a locked thread and sends that thread
// SIGURG (which the Go runtime takes and ignores) until Find returns.
func findUnderSignals(needle []byte, home uintptr) error {
	tids := make(chan int, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- syscall.Gettid()
		// Memory dense with the needle's first byte is where a search
		// falls back from a byte scan to a whole-needle compare.
		_, err := mappingContains(firstByteReader(needle[0]), 0, 64<<20, needle, make([]byte, chunk+len(needle)-1))
		if err == nil {
			_, err = Find(needle, home)
		}
		done <- err
	}()
	pid, tid := syscall.Getpid(), <-tids
	for {
		select {
		case err := <-done:
			return err
		default:
			_ = syscall.Tgkill(pid, tid, syscall.SIGURG)
			time.Sleep(20 * time.Microsecond)
		}
	}
}

// firstByteReader is an io.ReaderAt over memory that holds only b.
type firstByteReader byte

func (r firstByteReader) ReadAt(p []byte, _ int64) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}
