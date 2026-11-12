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
	ctx, cancel := context.WithTimeout(context.Background(), roundReserve+4*signalPhase)
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
	ctx, cancel := context.WithTimeout(context.Background(), roundReserve+4*signalPhase)
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

// A signal the thread cannot take stays pending, and so must not count
// as delivered: block SIGURG on a locked thread, send it, and the
// delivery check must see it pending until the thread unblocks it.
func TestUrgDeliveredNeedsTheSignalTaken(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := os.Getpid(), syscall.Gettid()
	if urgPending(pid, tid) {
		t.Skip("SIGURG is already pending on this thread, or /proc gives no SigPnd")
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
	buf := make([]byte, chunk+len(needle)-1)
	pass := func(flag bool) error {
		st.seq.Add(1)
		st.inside.Store(flag)
		defer st.inside.Store(false)
		// One pass compares for passSpan, so a whole bracket, its run
		// evidence and, at one P, the scheduler handing the P to the
		// reader and back, fits inside a single pass.
		for start := time.Now(); ; {
			if _, err := mappingContains(firstByteReader(needle[0]), 0, denseFill, needle, buf); err != nil {
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
	for st.verdict.Load() == 0 {
		switch mode {
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
// starts; inside is set only while that pass compares. verdict is the
// parent's verdict byte, 0 until it arrives, or verdictFailed.
type passState struct {
	seq     atomic.Uint64
	inside  atomic.Bool
	verdict atomic.Uint32
}

// readParent reads the parent's bytes from stdin for one round, on a
// goroutine other than the sweeping thread's. At each sendBefore it takes
// the pass state, seq first, and acknowledges it; the parent signals only
// after that acknowledgement, and writes sendAfter after the signal. At
// sendAfter it takes the state again, inside first. A signal counts only
// when both show the thread comparing in the same pass: seq never moved,
// and within one pass inside is set once, so the thread compared from
// the first look to the second, and the signal sent between them either
// interrupted that comparison or stayed pending until the thread returned
// to it. On the verdict byte it stores it in st and ends.
func readParent(st *passState, done chan<- error) {
	in := make([]byte, 512)
	acked, signaled := 0, 0
	var open bool // the last sendBefore found the thread comparing
	var at uint64 // in this pass
	for {
		n, err := syscall.Read(0, in)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			st.verdict.Store(verdictFailed)
			done <- fmt.Errorf("reading the parent: %d byte(s), %v", n, err)
			return
		}
		for _, b := range in[:n] {
			switch b {
			case sendBefore[0]:
				at = st.seq.Load()
				open = st.inside.Load()
				acked++
				fmt.Printf("%s%d\n", roundAck, acked)
			case sendAfter[0]:
				if open && st.inside.Load() && st.seq.Load() == at {
					signaled++
					fmt.Printf("%s%d\n", roundSignaled, signaled)
				}
				open = false
			case sendIdle[0]:
				open = false
			default:
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
// the first. The count, not a fixed window, ends the round: a slow
// thread, as under the race detector and coverage, takes longer to reach
// it but is held to the same rule. A round that cannot get there before
// roundReserve of ctx's deadline remains reports false rather than pass
// unsignaled, and leaves the child time to take its abort verdict.
func signalRound(ctx context.Context, signaled func() int, send func() error) (count int, ok bool) {
	tick := time.NewTicker(signalInterval)
	defer tick.Stop()
	stop, bounded := ctx.Deadline()
	stop = stop.Add(-roundReserve)
	var first time.Time // when the child first reported a signaled pass
	for {
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
		if bounded && !time.Now().Before(stop) {
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
	return fmt.Errorf("%w: %d before the deadline, want %d", errTooFewSignals, sent, minSignals)
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

// requireRunEvidence skips a test whose rounds need run evidence the
// kernel does not give: without schedstat no signal could count.
func requireRunEvidence(t *testing.T) {
	t.Helper()
	if _, _, err := threadRun(os.Getpid(), syscall.Gettid()); err != nil {
		t.Skipf("a signal counts only with evidence its thread was running, and this kernel gives none: %v", err)
	}
}

var errTooFewSignals = errors.New("too few signals reached the sweeping thread")

const (
	denseFill      = 64 << 10               // memory dense with the needle's first byte, per scan of a pass
	minSignals     = 50                     // a round counts only after this many
	signalPhase    = 50 * time.Millisecond  // of signals to the sweeping thread per round
	signalInterval = 200 * time.Microsecond // between signals to the sweeping thread
	ackWait        = 5 * time.Second        // for the child to take the pass state at a sendBefore
	roundReserve   = 2 * time.Second        // a round stops signaling this long before the child's deadline
	sweepDeadline  = 120 * time.Second      // the sweep child is killed after this, never hangs
	// controlDeadline bounds a child whose rounds must fail: it signals
	// for twice the old fixed window before its round gives up.
	controlDeadline = roundReserve + 10*time.Second

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
	childParked       = "parked"               // marks a pass, then parks its thread in it until the verdict
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
