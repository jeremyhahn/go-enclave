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
	// after on the child's stdin, and the child reports each compare pass
	// a whole bracket arrived in. Once enough passes are signaled this
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
		reported := 0
		signaled := func() int {
			for {
				select {
				case line, open := <-lines:
					if !open {
						return reported
					}
					if n, isCount := strings.CutPrefix(line, roundSignaled); isCount {
						reported, _ = strconv.Atoi(n)
						continue
					}
					other.WriteString(line + "\n")
				default:
					return reported
				}
			}
		}
		send := func() error {
			if _, err := io.WriteString(stdin, sendBefore); err != nil {
				return err
			}
			if err := syscall.Tgkill(pid, id, syscall.SIGURG); err != nil {
				return err
			}
			_, err := io.WriteString(stdin, sendAfter)
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
	if err := syscall.SetNonblock(0, true); err != nil {
		fmt.Fprintf(os.Stderr, "stdin: %v\n", err)
		return exitChildError
	}
	for range 3 {
		hits, aborted, err := sweepRound(needle, home, mode == childPause)
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*signalPhase)
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
	ctx, cancel := context.WithTimeout(context.Background(), 4*signalPhase)
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
// would: every send still lands, but none interrupts a comparison, so its
// round must fail with nothing counted.
func TestSweepUnderSignalsFailsAPausedChild(t *testing.T) {
	out, sent, _, err := runSweepChild(childPause, 32, sweepDeadline)
	if !errors.Is(err, errTooFewSignals) {
		t.Fatalf("a round whose child stopped comparing: want %v, got %v (signals %v)\n%s", errTooFewSignals, err, sent, out)
	}
	if len(sent) != 1 || sent[0] != 0 {
		t.Fatalf("a round whose child stopped comparing counted %v signal(s), want [0]", sent)
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

// sweepRound runs in the child. It names its locked thread to the parent
// and says so again once its first compare pass returns; the parent sends
// that thread SIGURG (which the Go runtime takes and ignores) while it
// compares memory dense with the needle's first byte, then runs
// Find on that thread unless the parent gives up. Nothing here bounds
// Find: the parent kills the child at its deadline.
func sweepRound(needle []byte, home uintptr, pause bool) (hits []string, aborted bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fmt.Printf("%s%d\n", roundTid, syscall.Gettid())
	// Memory dense with the needle's first byte is where a search falls
	// back from a byte scan to a whole-needle compare: the sweep stays on
	// that path until the parent's verdict arrives, so the last signal
	// lands mid-compare. Find then sweeps from the same thread, whose
	// signal stack still holds that frame. The parent's bytes are read on
	// this thread, without the scheduler, from a non-blocking stdin.
	buf := make([]byte, chunk+len(needle)-1)
	in := make([]byte, 512)
	// This read drains what the parent sent before the first pass, so no
	// send that came before it can count for that pass.
	_, verdict, err := readParent(in)
	signaled := 0
	for err == nil && verdict == 0 {
		if _, cerr := mappingContains(firstByteReader(needle[0]), 0, denseFill, needle, buf); cerr != nil {
			return nil, false, cerr
		}
		if pause {
			verdict, err = awaitVerdict(in)
			break
		}
		var landed bool
		landed, verdict, err = readParent(in)
		if landed {
			signaled++
			fmt.Printf("%s%d\n", roundSignaled, signaled)
		}
	}
	if err != nil {
		return nil, false, err
	}
	if verdict != verdictSweep[0] {
		return nil, true, nil
	}
	hits, err = Find(needle, home)
	return hits, false, err
}

// readParent reads what the parent has written to stdin so far. landed
// reports a whole send bracketed by this read: its sendBefore byte and its
// sendAfter byte both arrived here. The parent writes sendBefore before it
// signals and sendAfter after, so neither was there at the previous read:
// the signal went out between the two reads, while the one compare pass
// between them ran. verdict is the parent's verdict byte, or 0.
func readParent(in []byte) (landed bool, verdict byte, err error) {
	open := false
	for {
		n, err := syscall.Read(0, in)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) {
			return landed, 0, nil
		}
		if err != nil || n == 0 {
			return landed, 0, fmt.Errorf("reading the parent: %d byte(s), %v", n, err)
		}
		for _, b := range in[:n] {
			switch b {
			case sendBefore[0]:
				open = true
			case sendAfter[0]:
				landed = landed || open
				open = false
			default:
				return landed, b, nil
			}
		}
	}
}

// awaitVerdict stands for a sweeping thread descheduled after its first
// compare pass: it compares nothing more and polls for the parent's
// verdict every millisecond.
func awaitVerdict(in []byte) (byte, error) {
	for {
		time.Sleep(time.Millisecond)
		if _, verdict, err := readParent(in); err != nil || verdict != 0 {
			return verdict, err
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
// the first; a round that cannot get there by signalCap reports false
// rather than pass unsignaled.
func signalRound(ctx context.Context, signaled func() int, send func() error) (count int, ok bool) {
	tick := time.NewTicker(signalInterval)
	defer tick.Stop()
	start := time.Now()
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
		if time.Since(start) >= signalCap {
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
	return fmt.Errorf("%w: %d in %v, want %d", errTooFewSignals, sent, signalCap, minSignals)
}

var errTooFewSignals = errors.New("too few signals reached the sweeping thread")

const (
	denseFill      = 64 << 10               // memory dense with the needle's first byte, per compare pass
	minSignals     = 50                     // a round counts only after this many
	signalPhase    = 50 * time.Millisecond  // of signals to the sweeping thread per round
	signalInterval = 200 * time.Microsecond // between signals to the sweeping thread
	signalCap      = 5 * time.Second        // a round that cannot reach minSignals by then fails
	sweepDeadline  = 30 * time.Second       // the sweep child is killed after this, never hangs

	sweepChildEnv     = "MEMSCAN_SWEEP_CHILD" // "<mode> <needle length>" for TestSweepChild
	roundTid          = "sweep thread "       // the child's line naming a round's sweeping thread
	roundSignaled     = "sweep signaled "     // the child's count of compare passes a send landed in
	sendBefore        = "b"                   // the parent's byte before each signal
	sendAfter         = "k"                   // the parent's byte after each signal
	verdictSweep      = "s"                   // the parent's byte: the signals landed, sweep now
	verdictAbort      = "a"                   // the parent's byte: too few signals, give up
	childSweep        = "sweep"               // three rounds under signals, then a check sweep
	childStall        = "stall"               // stops itself while its sweep runs
	childPause        = "pause"               // compares once, then stops comparing while signaled
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
