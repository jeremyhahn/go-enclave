package amdsev_test

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave/backends/amdsev/integration/guestcfg"
)

// needleIn reads the guest's console for the needle it holds: none once the
// console carries the release line.
func needleIn(serial string) (string, bool) {
	f, err := os.Open(serial) //nolint:gosec // the kit's console file
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
	f, err := os.OpenFile(serial, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // the test's own file
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
