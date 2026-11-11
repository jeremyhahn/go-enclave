// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	// The rounds run in a child process that owns the needle's mapping: a
	// sweep cannot be cancelled, so the bound is the parent killing the
	// child, and the mapping goes with it.
	out, code, err := runSweepChild(childSweep, n, sweepDeadline)
	switch {
	case err != nil:
		t.Fatalf("%v\n%s", err, out)
	case code == exitResidue:
		t.Fatalf("the sweep planted copies of what it looks for:\n%s", out)
	case code == exitTooFewSignals:
		t.Fatalf("a round could not deliver its signals, so it proves nothing:\n%s", out)
	case code != 0:
		t.Fatalf("the sweep child exited %d:\n%s", code, out)
	}
}

// runSweepChild runs sweepChild(mode, n) in a copy of this test binary and
// kills it once limit passes. code is the child's exit status; err is set
// only when the child could not run or was killed.
func runSweepChild(mode string, n int, limit time.Duration) (out string, code int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSweepChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s %d", sweepChildEnv, mode, n))
	cmd.WaitDelay = time.Second
	b, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(b), -1, fmt.Errorf("the sweep under signals did not finish within %v; the child was killed", limit)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(b), exit.ExitCode(), nil
	}
	return string(b), 0, err
}

// TestSweepChild is the child process of runSweepChild; run on its own it
// skips.
func TestSweepChild(t *testing.T) {
	spec := os.Getenv(sweepChildEnv)
	if spec == "" {
		t.Skip("runs only as the child of a sweep-under-signals test")
	}
	var mode string
	var n int
	if _, err := fmt.Sscan(spec, &mode, &n); err != nil {
		fmt.Fprintf(os.Stderr, "bad %s=%q: %v\n", sweepChildEnv, spec, err)
		os.Exit(exitChildError)
	}
	os.Exit(sweepChild(mode, n))
}

// sweepChild maps an n-byte needle, sweeps for it under signals three
// times and once more after, and returns the exit status for the parent.
// In childStall mode it stops this process while its sweep runs instead,
// so the parent's deadline fires with Find in progress.
func sweepChild(mode string, n int) int {
	page := syscall.Getpagesize()
	region, err := syscall.Mmap(-1, 0, page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mmap: %v\n", err)
		return exitChildError
	}
	needle := region[:n]
	if _, err := rand.Read(needle); err != nil {
		fmt.Fprintf(os.Stderr, "rand.Read: %v\n", err)
		return exitChildError
	}
	needle[1] = needle[0] ^ 1                                 // the filler below must not match the needle's start
	home := uintptr(unsafe.Pointer(unsafe.SliceData(region))) // the needle's own mapping, excluded from the sweep

	if mode == childStall {
		fmt.Fprintln(os.Stderr, "sweep started")
		go func() {
			time.Sleep(time.Millisecond)
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
		}()
		_, _ = Find(needle, home)
		time.Sleep(time.Hour) // never exits on its own
		return exitChildError
	}

	// The race detector changes what the thread holds when a signal lands,
	// so the run that catches a planted copy is the one without -race; the
	// race runs keep each round bounded rather than hide it.
	for range 3 {
		hits, sent, err := sweepUnderSignals(needle, home, nil)
		if errors.Is(err, errTooFewSignals) {
			fmt.Fprintln(os.Stderr, err)
			return exitTooFewSignals
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Find under signals: %v\n", err)
			return exitChildError
		}
		if len(hits) > 0 {
			fmt.Fprintf(os.Stderr, "a sweep right after %d signals finds the needle in %d mapping(s) outside its own: %q\n", sent, len(hits), hits[0])
			return exitResidue
		}
	}
	hits, err := Find(needle, home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Find: %v\n", err)
		return exitChildError
	}
	if len(hits) > 0 {
		fmt.Fprintf(os.Stderr, "after sweeps under signals the needle is resident in %d mapping(s) outside its own: %q\n", len(hits), hits[0])
		return exitResidue
	}
	return 0
}

// TestSweepUnderSignalsSendsTheMinimum holds the worker past the signal
// window. A round counts only once the sweeping thread has taken at least
// minSignals signals: a window that runs out first proves nothing.
func TestSweepUnderSignalsSendsTheMinimum(t *testing.T) {
	// One P, and a worker that spins through the window: the signaller
	// runs only when the worker is preempted, as under -cpu=1. After the
	// window the Ps come back, and the round must go on signalling.
	if runtime.NumCPU() < 2 {
		t.Skip("needs two CPUs to give the signaller its P back")
	}
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	spin := func() {
		for end := time.Now().Add(2 * signalPhase); time.Now().Before(end); {
		}
		runtime.GOMAXPROCS(max(prev, 2))
	}
	needle := []byte{0x5a, 0x5b, 0x5c, 0x5d}
	_, sent, err := sweepUnderSignals(needle, 0, spin)
	if err != nil {
		t.Fatalf("sweep under signals: %v", err)
	}
	if sent < minSignals {
		t.Fatalf("the round ended after %d signal(s); want at least %d", sent, minSignals)
	}
}

// TestSweepUnderSignalsBoundsAStalledSweep stalls the sweep past its
// deadline. The sweep must fail within the bound, wherever it is stuck.
func TestSweepUnderSignalsBoundsAStalledSweep(t *testing.T) {
	const limit = 2 * time.Second
	start := time.Now()
	out, _, err := runSweepChild(childStall, 32, limit)
	if took := time.Since(start); took > limit+5*time.Second {
		t.Fatalf("a stalled sweep returned after %v; the deadline is %v", took, limit)
	}
	if err == nil {
		t.Fatalf("a stalled sweep: want the deadline's error, got nil; child output:\n%s", out)
	}
	if !strings.Contains(out, "sweep started") {
		t.Fatalf("the deadline fired before the sweep started; child output:\n%s", out)
	}
}

// sweepUnderSignals runs Find on a locked thread after sending that thread
// SIGURG (which the Go runtime takes and ignores) while it compares memory
// dense with the needle's first byte, and reports how many signals it
// sent. hold, when not nil, runs on that thread first. Nothing here bounds
// Find: the caller runs this in a child process it can kill.
func sweepUnderSignals(needle []byte, home uintptr, hold func()) (hits []string, sent int, err error) {
	type result struct {
		hits []string
		err  error
	}
	tids := make(chan int, 1)
	done := make(chan result, 1)
	var stop, abort atomic.Bool // stop ends the dense loop; abort skips Find too
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
		if abort.Load() {
			done <- result{}
			return
		}
		hits, err := Find(needle, home)
		done <- result{hits, err}
	}()
	pid, tid := syscall.Getpid(), <-tids
	// The interval leaves the sweeping thread room to make progress: under
	// the race detector a signal every few microseconds starves it. The
	// round ends once the window has passed and the thread has taken
	// minSignals signals; a signaller that cannot reach that many by
	// signalCap fails the round rather than let it pass unsignalled.
	tick := time.NewTicker(signalInterval)
	defer tick.Stop()
	start := time.Now()
	for {
		select {
		case r := <-done:
			if r.err == nil && abort.Load() {
				r.err = fmt.Errorf("%w: %d in %v, want %d", errTooFewSignals, sent, signalCap, minSignals)
			}
			return r.hits, sent, r.err
		case <-tick.C:
			if stop.Load() {
				continue
			}
			if took := time.Since(start); sent >= minSignals && took >= signalPhase {
				stop.Store(true)
				continue
			} else if took >= signalCap {
				abort.Store(true)
				stop.Store(true)
				continue
			}
			if syscall.Tgkill(pid, tid, syscall.SIGURG) == nil {
				sent++
			}
		}
	}
}

var errTooFewSignals = errors.New("too few signals reached the sweeping thread")

const (
	denseFill      = chunk                  // memory dense with the needle's first byte
	minSignals     = 50                     // a round counts only after this many
	signalPhase    = 50 * time.Millisecond  // of signals to the sweeping thread per round
	signalInterval = 200 * time.Microsecond // between signals to the sweeping thread
	signalCap      = 5 * time.Second        // a round that cannot reach minSignals by then fails
	sweepDeadline  = 30 * time.Second       // the sweep child is killed after this, never hangs

	sweepChildEnv     = "MEMSCAN_SWEEP_CHILD" // "<mode> <needle length>" for TestSweepChild
	childSweep        = "sweep"               // three rounds under signals, then a check sweep
	childStall        = "stall"               // stops itself while its sweep runs
	exitResidue       = 2                     // a sweep found the needle outside its mapping
	exitTooFewSignals = 3                     // a round could not reach minSignals
	exitChildError    = 4                     // the child could not run its sweep
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
