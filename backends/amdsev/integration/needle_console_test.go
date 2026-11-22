package amdsev_test

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave/backends/amdsev/integration/guestcfg"
)

// needleIn reads the guest's console for the needle it holds: none once the
// console carries the release line.
func needleIn(serial string) (string, bool) {
	f, err := os.Open(serial)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	needle := ""
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == guestcfg.ReleasedLine {
			// The guest has destroyed the needle's enclave: there is no
			// needle left in its memory to scan for.
			return "", false
		}
		if rest, ok := strings.CutPrefix(line, guestcfg.NeedleMarker); ok && needle == "" {
			if _, err := hex.DecodeString(rest); err == nil && rest != "" {
				needle = rest
			}
		}
	}
	return needle, needle != ""
}

// heldThroughScan reports whether the guest still holds needle, unreleased,
// once a host scan has completed. A scan the guest's hold does not outlast
// read memory the guest had already wiped, so its "not found" proves nothing.
func heldThroughScan(serial, needle string) error {
	held, ok := needleIn(serial)
	switch {
	case !ok:
		return fmt.Errorf("the guest released its needle before the host scan completed, so the scan may have read wiped memory; raise amdsev.hold (console in %s)", serial)
	case held != needle:
		return fmt.Errorf("the guest's console holds needle %q, not the scanned %q (console in %s)", held, needle, serial)
	}
	return nil
}

// releaseNeedle ends the guest's hold: it announces the release on console,
// flushes it with flush, and only then destroys the needle's enclave with
// destroy.
func releaseNeedle(console io.Writer, flush, destroy func() error) error {
	// The announcement comes first and is flushed before the wipe: a host
	// scan that completes once the wipe may have begun then finds the
	// release line and is rejected.
	_, werr := fmt.Fprintln(console, guestcfg.ReleasedLine)
	if werr == nil {
		werr = flush()
	}
	// The needle is destroyed on every path, a failed announcement included.
	return errors.Join(destroy(), werr)
}

const testNeedle = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// writeConsole writes a guest console with the given lines.
func writeConsole(t *testing.T, lines ...string) string {
	t.Helper()
	serial := filepath.Join(t.TempDir(), "guest.log")
	if err := os.WriteFile(serial, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return serial
}

// appendConsole appends a line to the console, as the guest does.
func appendConsole(t *testing.T, serial, line string) {
	t.Helper()
	f, err := os.OpenFile(serial, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNeedleIn_HeldNeedle(t *testing.T) {
	serial := writeConsole(t, "boot", guestcfg.NeedleMarker+testNeedle)
	got, ok := needleIn(serial)
	if !ok || got != testNeedle {
		t.Fatalf("needleIn = %q, %v; want %q, true", got, ok, testNeedle)
	}
}

func TestNeedleIn_ReleasedNeedleIsNotReturned(t *testing.T) {
	serial := writeConsole(t, guestcfg.NeedleMarker+testNeedle, guestcfg.ReleasedLine)
	if got, ok := needleIn(serial); ok {
		t.Fatalf("needleIn = %q, true; want no needle once the console carries %q: the guest has wiped it", got, guestcfg.ReleasedLine)
	}
}

func TestNeedleIn_NoConsole(t *testing.T) {
	if got, ok := needleIn(filepath.Join(t.TempDir(), "absent.log")); ok {
		t.Fatalf("needleIn = %q, true; want no needle without a console", got)
	}
}

// A console line longer than the scanner's limit stops the scan before EOF,
// so a release line after it would go unseen: the read fails closed, and no
// needle counts as held.
func TestNeedleIn_OversizedLineFailsClosed(t *testing.T) {
	serial := writeConsole(t,
		guestcfg.NeedleMarker+testNeedle,
		strings.Repeat("x", 128<<10),
		guestcfg.ReleasedLine)
	if got, ok := needleIn(serial); ok {
		t.Fatalf("needleIn = %q, true; want no needle when the console cannot be read to its end", got)
	}
	if err := heldThroughScan(serial, testNeedle); err == nil {
		t.Fatal("heldThroughScan = nil for a console read that stopped before the release line; want an error")
	}
}

func TestHeldThroughScan_HeldNeedle(t *testing.T) {
	serial := writeConsole(t, guestcfg.NeedleMarker+testNeedle)
	if err := heldThroughScan(serial, testNeedle); err != nil {
		t.Fatalf("heldThroughScan with the needle still held: %v", err)
	}
}

// A scan that outlasts the guest's hold reads memory the guest has already
// wiped: its "not found" proves nothing, so the run must fail.
func TestHeldThroughScan_DelayedScanFails(t *testing.T) {
	serial := writeConsole(t, guestcfg.NeedleMarker+testNeedle)
	needle, ok := needleIn(serial)
	if !ok {
		t.Fatal("no needle in the console")
	}
	// The delayed scan: the guest's hold ends and it releases the needle
	// before the host scan completes.
	appendConsole(t, serial, guestcfg.ReleasedLine)
	if err := heldThroughScan(serial, needle); err == nil {
		t.Fatal("heldThroughScan = nil after the guest released its needle mid-scan; want an error")
	}
}

func TestHeldThroughScan_OtherNeedleFails(t *testing.T) {
	serial := writeConsole(t, guestcfg.NeedleMarker+testNeedle)
	if err := heldThroughScan(serial, "ff"+testNeedle[2:]); err == nil {
		t.Fatal("heldThroughScan = nil for a needle the console does not hold; want an error")
	}
}

func TestHeldThroughScan_NoConsoleFails(t *testing.T) {
	if err := heldThroughScan(filepath.Join(t.TempDir(), "absent.log"), testNeedle); err == nil {
		t.Fatal("heldThroughScan = nil without a console; want an error")
	}
}

// A host scan that completes while the guest is destroying the needle, after
// the wipe started but before any later step, read memory being wiped: the
// guest must have announced the release by then, so the scan is rejected.
func TestHeldThroughScan_ScanDuringDestroyFails(t *testing.T) {
	serial := writeConsole(t, guestcfg.NeedleMarker+testNeedle)
	console, err := os.OpenFile(serial, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = console.Close() }()
	destroyed := false
	var scanErr error
	destroy := func() error {
		destroyed = true
		// The host scan completes here, inside the destroy interval.
		scanErr = heldThroughScan(serial, testNeedle)
		return nil
	}
	if err := releaseNeedle(console, console.Sync, destroy); err != nil {
		t.Fatal(err)
	}
	if !destroyed {
		t.Fatal("releaseNeedle did not destroy the needle")
	}
	if scanErr == nil {
		t.Fatal("heldThroughScan = nil for a scan completing while the guest destroys its needle; want an error: the release must be on the console before the wipe")
	}
	if _, ok := needleIn(serial); ok {
		t.Fatal("needleIn returned a needle after the release")
	}
}

// A failed flush still destroys the needle, and reports the failure.
func TestReleaseNeedle_FlushFailureStillDestroys(t *testing.T) {
	var console strings.Builder
	destroyed := false
	flushErr := errors.New("flush failed")
	err := releaseNeedle(&console, func() error { return flushErr }, func() error { destroyed = true; return nil })
	if !errors.Is(err, flushErr) {
		t.Fatalf("releaseNeedle = %v; want the flush error", err)
	}
	if !destroyed {
		t.Fatal("releaseNeedle did not destroy the needle after a failed flush")
	}
	if !strings.Contains(console.String(), guestcfg.ReleasedLine) {
		t.Fatalf("console %q lacks %q", console.String(), guestcfg.ReleasedLine)
	}
}
