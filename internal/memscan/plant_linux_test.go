// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
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
	// sweep cannot be canceled, so the bound is the parent killing the
	// child, and the mapping goes with it.
	requireRunEvidence(t)
	out, _, code, err := runSweepChild(childSweep, n, sweepDeadline)
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
func runSweepChild(mode string, n int, limit time.Duration) (out string, rounds []int, code int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSweepChild$", "-test.count=1",
		"-test.cpu="+strconv.Itoa(runtime.GOMAXPROCS(0)))
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s %d", sweepChildEnv, mode, n))
	cmd.WaitDelay = time.Second
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", rounds, -1, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", rounds, -1, err
	}
	if err := cmd.Start(); err != nil {
		return "", rounds, -1, err
	}
	// The signals come from this process: a signal source inside the child
	// needs the child's scheduler, which its spinning worker starves at one
	// P. Each round the child names its sweeping thread; this process
	// signals that thread, bracketing each signal with a byte before and
	// after on the child's stdin. The child acknowledges the byte before
	// once it has looked at its compare pass, and reports each signal that
	// both looks found inside one comparison. Once enough are reported this
	// process tells the child to sweep, or else to give up.
	var short error
	var other strings.Builder
	lines := make(chan string)
	go func() {
		defer close(lines)
		scan := bufio.NewScanner(stdout)
		for scan.Scan() {
			lines <- scan.Text()
		}
		_, _ = io.Copy(io.Discard, stdout) // a line too long to scan must not block the child
	}()
	for line := range lines {
		tid, ok := strings.CutPrefix(line, roundTid)
		if !ok {
			other.WriteString(line + "\n")
			continue
		}
		id, err := strconv.Atoi(tid)
		if err != nil {
			short = fmt.Errorf("the child named no thread: %q", line)
			_ = cmd.Process.Kill()
			break
		}
		verdict := verdictSweep
		pid := cmd.Process.Pid
		reported, acked, befores := 0, 0, 0
		take := func(line string) {
			if n, isCount := strings.CutPrefix(line, roundSignaled); isCount {
				reported, _ = strconv.Atoi(n)
				return
			}
			if n, isAck := strings.CutPrefix(line, roundAck); isAck {
				acked, _ = strconv.Atoi(n)
				return
			}
			other.WriteString(line + "\n")
		}
		signaled := func() int {
			for {
				select {
				case line, open := <-lines:
					if !open {
						return reported
					}
					take(line)
				default:
					return reported
				}
			}
		}
		send := func() error {
			if _, err := io.WriteString(stdin, sendBefore); err != nil {
				return err
			}
			// The child takes the pass state at sendBefore; the signal
			// must go out after that, never before it.
			befores++
			wait := time.NewTimer(ackWait)
			defer wait.Stop()
			for acked < befores {
				select {
				case line, open := <-lines:
					if !open {
						return errors.New("the child ended before it took the pass state")
					}
					take(line)
				case <-wait.C:
					return errors.New("the child did not take the pass state")
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			// The child's pass state shows only that the marked pass has
			// not returned; a thread parked inside it shows the same. So
			// the signal counts only when this process saw the thread
			// running just before it and running, with more time on the
			// CPU, just after it, and saw the signal taken: no SIGURG
			// pending on the thread before it (a pending one would absorb
			// it) and none pending after it, so the kernel delivered this
			// one to the running thread. Otherwise the child is told to
			// drop it.
			after := sendIdle
			ran, running := runEvidence(pid, id, 0, false)
			if running && urgPending(pid, id) {
				running = false
			}
			if err := syscall.Tgkill(pid, id, syscall.SIGURG); err != nil {
				return err
			}
			if running {
				if _, ranOn := runEvidence(pid, id, ran, true); ranOn && urgDelivered(pid, id) {
					after = sendAfter
				}
			}
			_, err := io.WriteString(stdin, after)
			return err
		}
		sent, ok := signalRound(ctx, signaled, send)
		rounds = append(rounds, sent)
		if !ok {
			verdict = verdictAbort
			short = roundError(sent, ok)
		}
		if _, err := io.WriteString(stdin, verdict); err != nil {
			break
		}
	}
	for line := range lines { // until the child exits
		other.WriteString(line + "\n")
	}
	err = cmd.Wait()
	out = other.String() + errOut.String()
	if ctx.Err() != nil {
		return out, rounds, -1, fmt.Errorf("the sweep under signals did not finish within %v; the child was killed", limit)
	}
	if short != nil {
		return out, rounds, -1, short
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out, rounds, exit.ExitCode(), nil
	}
	return out, rounds, 0, err
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
	sweepNeedleStart(needle)
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
		hits, aborted, err := sweepRound(needle, home, mode)
		if aborted {
			fmt.Fprintln(os.Stderr, "the parent could not deliver the round's signals")
			return exitTooFewSignals
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Find under signals: %v\n", err)
			return exitChildError
		}
		if len(hits) > 0 {
			fmt.Fprintf(os.Stderr, "a sweep right after its signals finds the needle in %d mapping(s) outside its own: %q\n", len(hits), hits[0])
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

// sweepNeedleStart fixes up the first two bytes of a random needle. The
// first is never zero: zero bytes fill most of a process, and each one
// would send Find to a whole-needle compare. The second differs from the
// first, so memory dense with the first byte never matches the needle.
func sweepNeedleStart(needle []byte) {
	needle[0] = 1 + needle[0]%255
	needle[1] = needle[0] ^ 1
}

// TestSweepUnderSignalsSendsTheMinimum holds the worker past the signal
// window. A round counts only once the sweeping thread has taken at least
// minSignals signals: a window that runs out first proves nothing.
func TestSweepUnderSignalsSendsTheMinimum(t *testing.T) {
	// A 32-byte random needle: a short one can match unrelated memory and
	// fail the round as residue rather than on its signal count.
	requireRunEvidence(t)
	out, sent, code, err := runSweepChild(childSweep, 32, sweepDeadline)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != 0 {
		t.Fatalf("the sweep child exited %d:\n%s", code, out)
	}
	if len(sent) != 3 {
		t.Fatalf("the child ran %d round(s), want 3:\n%s", len(sent), out)
	}
	for i, s := range sent {
		if s < minSignals {
			t.Errorf("round %d took %d signal(s), want at least %d", i, s, minSignals)
		}
	}
}

func TestSignalRoundFailsAStarvedSender(t *testing.T) {
	// A sender that lands only a few signals before the window closes: the
	// round must fail rather than pass on the window alone.
	ctx, cancel := context.WithTimeout(context.Background(), controlDeadline)
	defer cancel()
	// The child stands in as one that counts every landed send.
	tries, landed := 0, 0
	sent, ok := signalRound(ctx, func() int { return landed }, func() error {
		if tries++; tries > 10 {
			return syscall.ESRCH
		}
		landed++
		return nil
	})
	if ok {
		t.Fatalf("a round with %d of %d signals passed", sent, minSignals)
	}
	if sent != 10 {
		t.Fatalf("the round counted %d signal(s), want the 10 that landed", sent)
	}
}

// TestSignalRoundFailsAChildThatNeverCompares names a thread that never
// reaches its compare loop: every send lands, but none interrupts a
// comparison, so the round must fail with nothing counted.
func TestSignalRoundFailsAChildThatNeverCompares(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), controlDeadline)
	defer cancel()
	sent, ok := signalRound(ctx, func() int { return 0 }, func() error { return nil })
	if ok {
		t.Fatalf("a round whose child never compared passed with %d signal(s) counted", sent)
	}
	if sent != 0 {
		t.Fatalf("the round counted %d signal(s) sent before the child compared, want 0", sent)
	}
	if err := roundError(sent, ok); !errors.Is(err, errTooFewSignals) {
		t.Fatalf("the round's error is %v, want %v", err, errTooFewSignals)
	}
}

// A round ends on its send budget, not on the clock: a child that never
// counts a signal fails after maxSends sends however long ctx still runs,
// so a slow runner sends as many signals as a fast one before the verdict.
func TestSignalRoundEndsOnItsSendBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sends := 0
	sent, ok := signalRound(ctx, func() int { return 0 }, func() error { sends++; return nil })
	if ok || sent != 0 {
		t.Fatalf("a round that counted nothing returned (%d, %v), want (0, false)", sent, ok)
	}
	if ctx.Err() != nil {
		t.Fatalf("the round ran until its context ended after %d sends; its budget is %d", sends, maxSends)
	}
	if sends != maxSends {
		t.Fatalf("the round made %d sends, want its budget of %d", sends, maxSends)
	}
}

// While a send is in flight, between its sendBefore and its sendAfter or
// sendIdle, the next read of a marked search keeps the compare window
// open: seq stays and inside stays set, so the window outlasts the
// parent's round trip however slow the runner. Once the send is judged the
// next read closes it, and a read at hi ends the search with no window.
func TestMarkedReaderHoldsTheWindowWhileASendIsInFlight(t *testing.T) {
	var st passState
	r := markedReader{b: 0xa5, st: &st, flag: true, hi: denseSpan}
	buf := make([]byte, denseFill+31)
	if n, err := r.ReadAt(buf, 0); n != len(buf) || err != nil || !st.inside.Load() {
		t.Fatalf("the first read: (%d, %v), inside %v; want a full read that opens a window", n, err, st.inside.Load())
	}
	at := st.seq.Load()
	st.hold.Store(at)
	for i := range 3 * denseSpan / denseFill { // past hi: the window must not close
		if _, err := r.ReadAt(buf, int64(i+1)*denseFill); err != nil {
			t.Fatalf("read %d with a send in flight: %v", i, err)
		}
		if st.seq.Load() != at || !st.inside.Load() {
			t.Fatalf("read %d with a send in flight closed the window (seq %d, want %d; inside %v)", i, st.seq.Load(), at, st.inside.Load())
		}
	}
	st.hold.Store(0)
	if _, err := r.ReadAt(buf, denseFill); err != nil || st.seq.Load() == at || !st.inside.Load() {
		t.Fatalf("the read after the send was judged: err %v, seq %d (was %d), inside %v; want a new window", err, st.seq.Load(), at, st.inside.Load())
	}
	if n, err := r.ReadAt(buf, denseSpan); n != 0 || !errors.Is(err, io.EOF) || st.inside.Load() {
		t.Fatalf("a read at hi: (%d, %v), inside %v; want (0, EOF) and no window", n, err, st.inside.Load())
	}
}

// TestSweepUnderSignalsFailsAPausedChild runs a child that compares once
// and then stops comparing, as a thread descheduled after its first pass
// would: it compares before its round's signals and never after, so its
// round must fail with nothing counted.
func TestSweepUnderSignalsFailsAPausedChild(t *testing.T) {
	requireRunEvidence(t)
	out, sent, _, err := runSweepChild(childPause, 32, controlDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose child stopped comparing: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose child stopped comparing counted %v signal(s), want [0]", sent)
	}
}

// TestSweepUnderSignalsFailsSignalsOutsideCompares runs a child that keeps
// comparing and runs the normal reader and counter, but never marks a
// pass as comparing and sleeps between passes, where most signals land:
// no signal is shown to have interrupted a comparison, so the round must
// count none and fail.
func TestSweepUnderSignalsFailsSignalsOutsideCompares(t *testing.T) {
	requireRunEvidence(t)
	out, sent, _, err := runSweepChild(childOutside, 32, controlDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose signals all landed between compare passes: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose signals all landed between compare passes counted %v signal(s), want [0]", sent)
	}
}

// A thread parked inside a marked pass keeps the pass state a comparing
// thread shows, but a signal to it interrupts the runtime, not a compare:
// the round must count none of them.
func TestSweepUnderSignalsFailsAParkedChild(t *testing.T) {
	requireRunEvidence(t)
	out, sent, _, err := runSweepChild(childParked, 32, controlDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose thread parked inside its pass: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose thread parked inside its pass counted %v signal(s), want [0]", sent)
	}
}

// A thread that runs and takes every signal in its marked passes but
// only fills its buffer and keeps its loop's books, never comparing:
// run and delivery evidence alone must not count, so the round counts
// none and fails.
func TestSweepUnderSignalsFailsABusyNonComparingChild(t *testing.T) {
	requireRunEvidence(t)
	out, sent, _, err := runSweepChild(childBusy, 32, controlDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose thread never compared: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose thread never compared counted %v signal(s), want [0]", sent)
	}
}

// TestSweepUnderSignalsFailsSignalsInTheBufferClear pins that a signal
// counts only inside the needle comparison: a child whose searches skip
// their compare and spend their time clearing the buffer, as
// mappingContains does before it returns, must count none.
func TestSweepUnderSignalsFailsSignalsInTheBufferClear(t *testing.T) {
	requireRunEvidence(t)
	out, sent, _, err := runSweepChild(childClear, 32, controlDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose signals all landed in a buffer clear: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose signals all landed in a buffer clear counted %v signal(s), want [0]", sent)
	}
}

// A signal the thread cannot take stays pending, and so must not count
// as delivered: block SIGURG on a locked thread, send it, and the
// delivery check must see it pending until the thread unblocks it.
func TestUrgDeliveredNeedsTheSignalTaken(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := os.Getpid(), syscall.Gettid()
	if urgPending(pid, tid) {
		t.Fatal("SIGURG is already pending on this locked thread, or /proc gives no SigPnd: the delivery check cannot start clean")
	}
	const sigBlock, sigSetmask = 0, 2
	set := uint64(1) << (uint(syscall.SIGURG) - 1)
	var old uint64
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigBlock,
		uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&old)), 8, 0, 0); e != 0 {
		t.Fatalf("rt_sigprocmask: %v", e)
	}
	restore := func() {
		_, _, _ = syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigSetmask,
			uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0)
	}
	if err := syscall.Tgkill(pid, tid, syscall.SIGURG); err != nil {
		restore()
		t.Fatalf("tgkill: %v", err)
	}
	blocked := urgDelivered(pid, tid)
	restore()
	if blocked {
		t.Fatal("a SIGURG the thread blocked counted as delivered")
	}
	if !urgDelivered(pid, tid) {
		t.Fatal("a SIGURG the thread unblocked still shows pending")
	}
}

// A busy child fills and closes its window with SIGURG blocked, so a
// signal sent meanwhile is not taken in the window: it stays pending
// until the step returns, and only then is delivered.
func TestWithUrgBlockedHoldsTheSignalPending(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := os.Getpid(), syscall.Gettid()
	if urgPending(pid, tid) {
		t.Fatal("SIGURG is already pending on this locked thread, or /proc gives no SigPnd: the check cannot start clean")
	}
	var sent, inside bool
	err := withUrgBlocked(func() {
		sent = syscall.Tgkill(pid, tid, syscall.SIGURG) == nil
		inside = urgDelivered(pid, tid)
	})
	if err != nil {
		t.Fatalf("withUrgBlocked: %v", err)
	}
	if !sent {
		t.Fatal("tgkill failed")
	}
	if inside {
		t.Fatal("a SIGURG sent inside withUrgBlocked was taken before the step returned")
	}
	if !urgDelivered(pid, tid) {
		t.Fatal("a SIGURG sent inside withUrgBlocked still shows pending after it returned")
	}
}

// TestSweepNeedleNeverStartsWithZero: a needle that starts with a zero
// byte sends Find's search to a whole-needle compare at every zero byte of
// the process, which under the race detector takes seconds per sweep and
// ran the sweep child into its deadline.
func TestSweepNeedleNeverStartsWithZero(t *testing.T) {
	for b := range 256 {
		needle := []byte{byte(b), 0, 0, 0}
		sweepNeedleStart(needle)
		if needle[0] == 0 {
			t.Fatalf("a needle drawn with first byte %#x still starts with zero", b)
		}
		if needle[1] != needle[0]^1 {
			t.Fatalf("needle[1] = %#x, want the first byte %#x with its low bit flipped", needle[1], needle[0])
		}
	}
}

// TestSweepUnderSignalsBoundsAStalledSweep stalls the sweep past its
// deadline. The sweep must fail within the bound, wherever it is stuck.
func TestSweepUnderSignalsBoundsAStalledSweep(t *testing.T) {
	const limit = 2 * time.Second
	start := time.Now()
	out, _, _, err := runSweepChild(childStall, 32, limit)
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

// sweepRound runs in the child. It names its locked thread to the parent,
// which sends
// that thread SIGURG (which the Go runtime takes and ignores) while it
// compares memory dense with the needle's first byte, then runs
// Find on that thread unless the parent gives up. Nothing here bounds
// Find: the parent kills the child at its deadline.
func sweepRound(needle []byte, home uintptr, mode string) (hits []string, aborted bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var st passState
	buf := make([]byte, denseFill+len(needle)-1)
	pass := func(flag bool) error {
		// Each search reads denseSpan a buffer at a time, and longer while
		// a send is in flight. The flag is set only from the end of a fill
		// to the start of the next read in the same search (see
		// markedReader), so a counted bracket spans compares of the filled
		// buffer: never a fill, the buffer clear before the search
		// returns, nor this loop's clock checks.
		r := markedReader{b: needle[0], st: &st, flag: flag, hi: denseSpan}
		for start := time.Now(); ; {
			_, err := mappingContains(r, 0, searchSpan, needle, buf)
			st.inside.Store(false)
			if errors.Is(err, io.EOF) {
				err = nil // the read at hi ended the search
			}
			if err != nil {
				return err
			}
			if time.Since(start) >= passSpan || st.verdict.Load() != 0 {
				return nil
			}
		}
	}
	if mode == childPause {
		// Its one pass ends before the parent learns the thread, so no
		// signal can land in it.
		if err := pass(true); err != nil {
			return nil, false, err
		}
	}
	fmt.Printf("%s%d\n", roundTid, syscall.Gettid())
	// Memory dense with the needle's first byte is where a search falls
	// back from a byte scan to a whole-needle compare: the sweep stays on
	// that path until the parent's verdict arrives, so the last signal
	// lands mid-compare. Find then sweeps from the same thread, whose
	// signal stack still holds that frame. This thread never reads stdin:
	// readParent does, on another goroutine, and judges each signal by the
	// pass state this thread publishes.
	done := make(chan error, 1)
	go readParent(&st, done)
	var wide []byte // childClear's buffer
	if mode == childClear {
		wide = make([]byte, clearSpan)
	}
	for st.verdict.Load() == 0 {
		switch mode {
		case childClear:
			// Each search reads nothing: it skips its compare, clears all
			// of wide and returns, so nearly every signal lands in the
			// clear. None may count.
			r := markedReader{b: needle[0], st: &st, flag: true, none: true}
			_, _ = mappingContains(r, 0, 2*clearSpan, needle, wide)
			st.inside.Store(false)
		case childPause:
			time.Sleep(time.Millisecond)
		case childParked:
			// The pass is marked but the thread never compares in it: the
			// goroutine blocks until the verdict, so its locked thread
			// parks in the runtime while every signal lands. None may
			// count.
			st.seq.Add(1)
			st.inside.Store(true)
			verdict := <-done
			st.inside.Store(false)
			done <- verdict // for the receive below
		case childBusy:
			// Running and busy in marked passes, but never comparing:
			// each fill opens a window that closes at once, as one does
			// after a search. None may count. SIGURG stays blocked from
			// the fill to the close: a signal taken there would preempt
			// the thread inside its open window, which the parent cannot
			// tell from a compare.
			r := markedReader{b: needle[0], st: &st, flag: true, hi: denseSpan}
			if err := withUrgBlocked(func() {
				_, _ = r.ReadAt(buf[:denseFill], 0)
				st.inside.Store(false)
			}); err != nil {
				return nil, false, err
			}
		case childOutside:
			// The pass compares with the flag clear and the sleep after it
			// takes most signals: none of them may count.
			if err := pass(false); err != nil {
				return nil, false, err
			}
			time.Sleep(time.Millisecond)
		default:
			if err := pass(true); err != nil {
				return nil, false, err
			}
		}
	}
	if err := <-done; err != nil {
		return nil, false, err
	}
	if st.verdict.Load() != uint32(verdictSweep[0]) {
		return nil, true, nil
	}
	hits, err = Find(needle, home)
	return hits, false, err
}

// passState is what the sweeping thread publishes about its compare
// passes. seq is the pass it is in or last ran, raised before the pass
// starts; inside is set only while that pass compares. hold is the seq of
// the window a send in flight keeps open, 0 for none. verdict is the
// parent's verdict byte, 0 until it arrives, or verdictFailed.
type passState struct {
	seq     atomic.Uint64
	inside  atomic.Bool
	hold    atomic.Uint64 // the window a send in flight holds open; 0, no window's seq, for none
	verdict atomic.Uint32
}

// readParent reads the parent's bytes from stdin for one round, on a
// goroutine other than the sweeping thread's. At each sendBefore it takes
// the pass state, seq first, and acknowledges it; the parent signals only
// after that acknowledgement, and writes sendAfter after the signal. At
// sendAfter it takes the state again, inside first. A signal counts only
// when both show the thread in the same compare window: seq never moved
// and inside was set at both looks, and only once a later look shows that
// window closed, so a thread parked in a window, which the signal itself
// wakes, never counts. A window runs from the end of one
// buffer fill to the start of the next fill of the same search (see
// markedReader), so the fills, the search's return, the buffer clear
// before it and the pass loop's clock checks lie outside every window.
// A sendBefore that finds a window open holds it (st.hold) until the send
// is judged, so whether a signal counts does not hang on the parent's
// round trip fitting in one compare. A window that already holds a
// counted signal is not held again: it closes, and the signal reports.
//
// What a counted signal proves: it was delivered to the running
// sweeping thread inside one marked compare window, that is while it ran
// contains over a filled buffer or the few instructions of offset
// arithmetic and the read's in-flight check between that compare and the
// next, which never touch the needle. It did not land in the buffer clear: the read after which a
// search returns opens no window. SIGURG was not pending on the thread
// before it was sent, so it did not coalesce with an earlier one; it was
// no longer pending after, so the thread took it; and the thread was
// running, with its on-CPU time advancing, before and after it. On the
// verdict byte readParent stores it in st and ends.
func readParent(st *passState, done chan<- error) {
	in := make([]byte, 512)
	acked, signaled := 0, 0
	var open bool // the last sendBefore found the thread comparing
	var at uint64 // in this pass
	var held int  // signals that landed in window heldAt, not yet counted
	var heldAt uint64
	for {
		n, err := syscall.Read(0, in)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			st.hold.Store(0)
			st.verdict.Store(verdictFailed)
			done <- fmt.Errorf("reading the parent: %d byte(s), %v", n, err)
			return
		}
		for _, b := range in[:n] {
			// A held signal counts once its window has closed: the thread
			// finished that compare and read on, or its search returned.
			// A thread parked in its window never closes it.
			if held > 0 && (st.seq.Load() != heldAt || !st.inside.Load()) {
				signaled += held
				held = 0
				fmt.Printf("%s%d\n", roundSignaled, signaled)
			}
			switch b {
			case sendBefore[0]:
				at = st.seq.Load()
				open = st.inside.Load()
				if open && held == 0 {
					// Hold this window open for this send. A window that
					// already holds a counted signal is not held again,
					// so it closes and that signal reports.
					st.hold.Store(at)
				}
				acked++
				fmt.Printf("%s%d\n", roundAck, acked)
			case sendAfter[0]:
				if open && st.inside.Load() && st.seq.Load() == at {
					heldAt = at // any held signal is in this same window
					held++
				}
				open = false
				st.hold.Store(0)
			case sendIdle[0]:
				open = false
				st.hold.Store(0)
			default:
				st.hold.Store(0)
				st.verdict.Store(uint32(b))
				done <- nil
				return
			}
		}
	}
}

// signalRound sends SIGURG to the child's sweeping thread every
// signalInterval. The interval leaves that thread room to make progress:
// under the race detector a signal every few microseconds starves it. The
// count is the child's own: signaled reports how many of its compare
// passes a send landed in, so a thread that is named but descheduled, or
// that stops comparing, adds nothing however many sends succeed. The round
// ends once that count reaches minSignals and signalPhase has passed since
// the first. Counts, not the clock, end the round: it fails once it has
// made maxSends sends short of minSignals, so a slow runner, as under the
// race detector and coverage, takes longer but is held to the same rule.
// ctx only bounds a child that stops answering: a round that sees it end
// reports false rather than pass unsignaled.
func signalRound(ctx context.Context, signaled func() int, send func() error) (count int, ok bool) {
	tick := time.NewTicker(signalInterval)
	defer tick.Stop()
	var first time.Time // when the child first reported a signaled pass
	for sends := 0; ; sends++ {
		select {
		case <-ctx.Done():
			return count, false
		case <-tick.C:
		}
		count = signaled()
		if count > 0 && first.IsZero() {
			first = time.Now()
		}
		if count >= minSignals && time.Since(first) >= signalPhase {
			return count, true
		}
		if count < minSignals && sends >= maxSends {
			return count, false
		}
		_ = send() // a send that fails lands in no pass, so it never counts
	}
}

// roundError is the error for a round signalRound reported as (sent, ok).
func roundError(sent int, ok bool) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%w: %d in %d sends, want %d", errTooFewSignals, sent, maxSends, minSignals)
}

// threadRun reads the scheduler state letter and the on-CPU nanoseconds
// of thread tid of process pid from /proc.
func threadRun(pid, tid int) (state byte, ran uint64, err error) {
	dir := fmt.Sprintf("/proc/%d/task/%d/", pid, tid)
	stat, err := os.ReadFile(dir + "stat")
	if err != nil {
		return 0, 0, err
	}
	i := bytes.LastIndexByte(stat, ')') // the command name may hold anything
	if i < 0 || i+2 >= len(stat) {
		return 0, 0, fmt.Errorf("unparsable %sstat: %q", dir, stat)
	}
	sched, err := os.ReadFile(dir + "schedstat")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(sched))
	if len(f) == 0 {
		return 0, 0, fmt.Errorf("empty %sschedstat", dir)
	}
	ran, err = strconv.ParseUint(f[0], 10, 64)
	return stat[i+2], ran, err
}

// runEvidence polls thread tid of process pid for up to runWait and
// returns its on-CPU time once the thread is running (state R) with more
// than since nanoseconds on the CPU. A parked thread is never R and gains
// nothing past the time its signal handler takes. When strict, a read
// that finds the thread not running ends the wait without evidence.
func runEvidence(pid, tid int, since uint64, strict bool) (uint64, bool) {
	deadline := time.Now().Add(runWait)
	for {
		state, ran, err := threadRun(pid, tid)
		if err != nil {
			return 0, false
		}
		if state == 'R' && ran > since {
			return ran, true
		}
		if (strict && state != 'R') || time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(runPoll)
	}
}

// urgPending reports whether SIGURG is pending on thread tid of process
// pid, by its SigPnd mask in /proc; a read that fails counts as pending,
// so it never lets a signal count.
func urgPending(pid, tid int) bool {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/status", pid, tid))
	if err != nil {
		return true
	}
	_, rest, found := bytes.Cut(status, []byte("\nSigPnd:"))
	if !found {
		return true
	}
	line, _, _ := bytes.Cut(rest, []byte("\n"))
	mask, err := strconv.ParseUint(strings.TrimSpace(string(line)), 16, 64)
	if err != nil {
		return true
	}
	return mask&(1<<(uint(syscall.SIGURG)-1)) != 0
}

// urgDelivered polls for up to runWait until SIGURG is no longer pending
// on thread tid of process pid: the kernel took the signal sent to it.
func urgDelivered(pid, tid int) bool {
	deadline := time.Now().Add(runWait)
	for {
		if !urgPending(pid, tid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(runPoll)
	}
}

// withUrgBlocked runs f on the calling thread, which must be locked to
// its goroutine, with SIGURG blocked. No SIGURG is taken while f runs, so
// none lands in f and none preempts it there; one sent meanwhile stays
// pending until f returns.
func withUrgBlocked(f func()) error {
	const sigBlock, sigSetmask = 0, 2
	set := uint64(1) << (uint(syscall.SIGURG) - 1)
	var old uint64
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigBlock,
		uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&old)), 8, 0, 0); e != 0 {
		return fmt.Errorf("rt_sigprocmask: %w", e)
	}
	defer func() {
		_, _, _ = syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigSetmask,
			uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0)
	}()
	f()
	return nil
}

// requireRunEvidence fails a test whose rounds need run evidence the
// kernel does not give: without schedstat no signal could count.
func requireRunEvidence(t *testing.T) {
	t.Helper()
	if _, _, err := threadRun(os.Getpid(), syscall.Gettid()); err != nil {
		t.Fatalf("a signal counts only with evidence its thread was running, and this kernel gives none (schedstat): %v", err)
	}
}

var errTooFewSignals = errors.New("too few signals reached the sweeping thread")

const (
	// denseFill is the buffer one compare of a pass reads, memory dense
	// with the needle's first byte. It is small so that a compare, and so
	// a window, ends within a send even under the race detector and
	// coverage: a held signal counts only once its window closes.
	denseFill      = 4 << 10
	denseSpan      = 16 * denseFill         // the region one search of a pass reads, a buffer at a time
	minSignals     = 50                     // a round counts only after this many
	maxSends       = 4 * minSignals         // a round fails once it has sent this many short of minSignals
	signalPhase    = 50 * time.Millisecond  // of signals to the sweeping thread per round
	signalInterval = 200 * time.Microsecond // between signals to the sweeping thread
	ackWait        = 250 * time.Millisecond // for the child to take the pass state at a sendBefore
	searchSpan     = ^uintptr(0) >> 1       // a marked search's span: its reader ends it at hi
	// sendBound is the most one send takes: the tick before it, the wait
	// for its ack and the two looks for run evidence around the signal.
	sendBound = signalInterval + ackWait + 2*runWait
	// roundBound is the most a round takes: its send budget, then sends
	// for signalPhase once the count is met, and the one in progress.
	roundBound = maxSends*sendBound + signalPhase + sendBound
	// childReserve covers the rest of a child's life: its start, the
	// verdicts, the check sweep and its exit.
	childReserve = 30 * time.Second
	// The deadlines follow from the rounds a child runs; each only kills a
	// child that stopped answering, the send budget fails a short round.
	sweepDeadline   = childReserve + 3*roundBound // three rounds under signals, then a check sweep
	controlDeadline = childReserve + roundBound   // a child whose one round must fail

	sweepChildEnv     = "MEMSCAN_SWEEP_CHILD" // "<mode> <needle length>" for TestSweepChild
	roundTid          = "sweep thread "       // the child's line naming a round's sweeping thread
	roundSignaled     = "sweep signaled "     // the child's count of compare passes a send landed in
	roundAck          = "sweep ack "          // the child's count of sendBefore bytes it took the pass state at
	sendBefore        = "b"                   // the parent's byte before each signal
	sendAfter         = "k"                   // the parent's byte after each signal it saw land on a running thread
	sendIdle          = "i"                   // the parent's byte after a signal it could not tie to a running thread
	runWait           = 50 * time.Millisecond // for the run evidence around each signal
	runPoll           = 100 * time.Microsecond
	passSpan          = 200 * time.Millisecond // a compare pass lasts at least this
	verdictSweep      = "s"                    // the parent's byte: the signals landed, sweep now
	verdictAbort      = "a"                    // the parent's byte: too few signals, give up
	childSweep        = "sweep"                // three rounds under signals, then a check sweep
	childStall        = "stall"                // stops itself while its sweep runs
	childPause        = "pause"                // compares once before its signals, then stops comparing
	childOutside      = "outside"              // compares outside its in-compare flag, sleeps between passes
	childBusy         = "busy"                 // spins through fills and bookkeeping in marked passes, never compares
	childParked       = "parked"               // marks a pass, then parks its thread in it until the verdict
	childClear        = "clear"                // searches that read nothing: each skips its compare and only clears its buffer
	clearSpan         = 64 << 20               // the buffer a childClear search clears, so the clear outlasts a signal's two looks
	exitResidue       = 2                      // a sweep found the needle outside its mapping
	exitTooFewSignals = 3                      // a round could not reach minSignals
	exitChildError    = 4                      // the child could not run its sweep
	verdictFailed     = 0x100                  // passState.verdict once stdin failed: no parent byte
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

// markedReader is a firstByteReader over [0, hi) that clears st's
// in-compare flag while it fills p. It then opens a new compare window,
// seq moving on and the flag set to flag, after a full read with no
// error, over memory dense with b, which cannot hold a needle that is not
// one repeated byte. mappingContains then compares the buffer and reads
// again, and that next read closes the window as it starts. So a window
// spans one contains call and the loop's offset arithmetic, never a fill,
// the return or the buffer clear before it. The search runs over a span
// wider than hi: a read at or past hi ends it with io.EOF and opens no
// window, so the buffer clear follows a closed window.
//
// While a send in flight holds the window (st.hold is its seq) the read
// after it keeps it open: it returns the buffer still filled, seq and the flag
// untouched, and the search compares it again. The window then outlasts
// the parent's round trip, however slow the runner, and spans compares
// and the few instructions of the hop between them.
//
// With none set it reads nothing and returns io.EOF, so the search skips
// its compare and returns at once, clearing its buffer.
type markedReader struct {
	b    byte
	st   *passState
	flag bool
	none bool
	hi   int64
}

func (r markedReader) ReadAt(p []byte, off int64) (int, error) {
	if r.flag && r.st.inside.Load() && r.st.hold.Load() == r.st.seq.Load() {
		return firstByteReader(r.b).ReadAt(p, off) // still filled: no fill in the window
	}
	r.st.inside.Store(false)
	n, err := 0, io.EOF
	if !r.none && off < r.hi {
		n, err = firstByteReader(r.b).ReadAt(p, off)
	}
	r.st.seq.Add(1)
	r.st.inside.Store(r.flag && err == nil && n == len(p))
	return n, err
}
