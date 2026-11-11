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
	"fmt"
	"runtime"
	"sync/atomic"
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

	// The race detector changes what the thread holds when a signal lands,
	// so the run that catches a planted copy is the one without -race; the
	// race runs keep each round bounded rather than hide it.
	for range 3 {
		hits, err := findUnderSignals(needle, home)
		if err != nil {
			t.Fatalf("Find under signals: %v", err)
		}
		if len(hits) > 0 {
			t.Fatalf("a sweep right after signals finds the needle in %d mapping(s) outside its own: %q; "+
				"the sweep planted copies of what it looks for", len(hits), hits[0])
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

// TestSweepUnderSignalsJoinsItsWorkerOnTimeout holds the worker past the
// deadline. The sweep must fail, and must return only once its worker has
// stopped: the caller unmaps the needle's mapping as soon as it returns,
// and a worker still sweeping would read memory that is gone.
func TestSweepUnderSignalsJoinsItsWorkerOnTimeout(t *testing.T) {
	var released atomic.Bool
	hold := func() {
		time.Sleep(200 * time.Millisecond)
		released.Store(true)
	}
	needle := []byte{0x5a, 0x5b, 0x5c, 0x5d}
	_, err := sweepUnderSignals(needle, 0, 10*time.Millisecond, hold)
	if err == nil {
		t.Fatal("a worker held past the deadline: want the deadline's error, got nil")
	}
	if !released.Load() {
		t.Fatalf("the sweep returned %q while its worker was still running; the caller would release the needle under it", err)
	}
}

// findUnderSignals runs Find on a locked thread and sends that thread
// SIGURG (which the Go runtime takes and ignores) until Find returns.
func findUnderSignals(needle []byte, home uintptr) ([]string, error) {
	return sweepUnderSignals(needle, home, sweepDeadline, nil)
}

// sweepUnderSignals is findUnderSignals with its deadline as a parameter
// and hold, when not nil, run by the worker before it sweeps: the timeout
// path's test delays the worker with it.
func sweepUnderSignals(needle []byte, home uintptr, limit time.Duration, hold func()) ([]string, error) {
	type result struct {
		hits []string
		err  error
	}
	tids := make(chan int, 1)
	done := make(chan result, 1)
	var stop atomic.Bool
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- syscall.Gettid()
		if hold != nil {
			hold()
		}
		// Memory dense with the needle's first byte is where a search
		// falls back from a byte scan to a whole-needle compare: the sweep
		// stays on that path until the signals stop, so the last signal
		// lands mid-compare. Find then sweeps from the same thread, whose
		// signal stack still holds that frame.
		buf := make([]byte, chunk+len(needle)-1)
		for !stop.Load() {
			if _, err := mappingContains(firstByteReader(needle[0]), 0, denseFill, needle, buf); err != nil {
				done <- result{err: err}
				return
			}
		}
		hits, err := Find(needle, home)
		done <- result{hits, err}
	}()
	pid, tid := syscall.Getpid(), <-tids
	// The interval leaves the sweeping thread room to make progress: under
	// the race detector a signal every few microseconds starves it. The
	// phase is wall-clock, so a starved signaller (GOMAXPROCS=1) ends it too.
	tick := time.NewTicker(signalInterval)
	defer tick.Stop()
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	end := time.Now().Add(signalPhase)
	for {
		select {
		case r := <-done:
			return r.hits, r.err
		case <-deadline.C:
			stop.Store(true)
			return nil, fmt.Errorf("the sweep under signals did not finish within %v", limit)
		case <-tick.C:
			if stop.Load() {
				continue
			}
			if time.Now().After(end) {
				stop.Store(true)
				continue
			}
			_ = syscall.Tgkill(pid, tid, syscall.SIGURG)
		}
	}
}

const (
	denseFill      = chunk                  // memory dense with the needle's first byte
	signalPhase    = 50 * time.Millisecond  // of signals to the sweeping thread per round
	signalInterval = 200 * time.Microsecond // between signals to the sweeping thread
	sweepDeadline  = 30 * time.Second       // a round that takes longer fails, never hangs
)

// firstByteReader is an io.ReaderAt over memory that holds only b.
type firstByteReader byte

func (r firstByteReader) ReadAt(p []byte, _ int64) (int, error) {
	if len(p) > 0 && p[0] == byte(r) && p[len(p)-1] == byte(r) {
		return len(p), nil // still filled from the last read: only this caller writes p
	}
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}
