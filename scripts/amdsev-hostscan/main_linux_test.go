//go:build linux

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	// holdEnv makes the test binary a holder: it decodes the hex needle in
	// it, holds the bytes, prints "ready" and waits for stdin to close.
	holdEnv = "AMDSEV_HOSTSCAN_HOLD"
	// helperEnv makes the test binary the helper itself, for the script.
	helperEnv = "AMDSEV_HOSTSCAN_AS_HELPER"
)

// held keeps the holder's needle reachable until it exits.
var held []byte

func TestMain(m *testing.M) {
	switch {
	case os.Getenv(holdEnv) != "":
		hold(os.Getenv(holdEnv))
	case os.Getenv(helperEnv) == "1":
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func hold(needle string) {
	// Under Yama's ptrace_scope 1 only an ancestor may read this process's
	// memory; the script's helper is not one, so let any process of this
	// user read it (PR_SET_PTRACER, PR_SET_PTRACER_ANY).
	const prSetPtracer, prSetPtracerAny = 0x59616d61, ^uintptr(0)
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetPtracer, prSetPtracerAny, 0)
	var err error
	held, err = hex.DecodeString(needle)
	if err != nil {
		os.Exit(3)
	}
	_, _ = os.Stdout.WriteString("ready\n")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	runtime.KeepAlive(held)
	os.Exit(0)
}

// holder starts a child holding needle (a hex string; the raw bytes exist
// only in the child) and returns its pid. The child exits with the test.
func holder(t *testing.T, needle string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), holdEnv+"="+needle)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Wait()
	})
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("holder did not start: %q, %v", line, err)
	}
	return cmd.Process.Pid
}

// freshHex is a random needle of n bytes as hex, drawn a digit at a time so
// its raw bytes never exist in this process either.
func freshHex(t *testing.T, n int) string {
	t.Helper()
	const digits = "0123456789abcdef"
	r := make([]byte, 2*n)
	if _, err := rand.Read(r); err != nil {
		t.Fatal(err)
	}
	for i := range r {
		r[i] = digits[r[i]&0xf]
	}
	return string(r)
}

func scanStatus(t *testing.T, pid int, needle string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	rc := run([]string{strconv.Itoa(pid), needle}, &out, &errOut)
	return rc, out.String() + errOut.String()
}

// The scan of another process finds the needle that process holds, and does
// not find a fresh one it never held.
func TestHostScan_FindsAHeldNeedleNotAFreshOne(t *testing.T) {
	needle := freshHex(t, 32)
	pid := holder(t, needle)
	if rc, out := scanStatus(t, pid, needle); rc != 1 || !strings.Contains(out, "found in pid") {
		t.Fatalf("scan for the held needle = %d, want 1 (found):\n%s", rc, out)
	}
	if rc, out := scanStatus(t, pid, freshHex(t, 32)); rc != 0 || !strings.Contains(out, "not found") {
		t.Fatalf("scan for a fresh needle = %d, want 0 (not found):\n%s", rc, out)
	}
}

func TestHostScan_RefusesWhatItMustRefuse(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"a pid that is not a number", []string{"qemu", "00"}},
		{"its own pid", []string{strconv.Itoa(os.Getpid()), "00"}},
		{"a needle that is not hex", []string{"1", "zz"}},
		{"an empty needle", []string{"1", ""}},
		{"no such process", []string{strconv.Itoa(1 << 30), "00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if rc := run(tc.args, &out, &out); rc != 2 {
				t.Fatalf("run(%q) = %d, want 2:\n%s", tc.args, rc, out.String())
			}
		})
	}
}

// A needle across a chunk boundary is found.
func TestHostScan_FindsANeedleAcrossAChunkBoundary(t *testing.T) {
	needle := []byte("across-the-boundary")
	mem := make([]byte, 3*chunk)
	copy(mem[chunk-5:], needle)
	found, err := contains(bytes.NewReader(mem), 0, uint64(len(mem)), needle, make([]byte, chunk+len(needle)-1))
	if err != nil || !found {
		t.Fatalf("contains = %v, %v; want found", found, err)
	}
}

// scripts/amdsev-host-scan.sh passes the helper's status through: 1 found,
// 0 not found, and 2 for its own refusals.
func TestHostScan_ScriptPassesTheStatusThrough(t *testing.T) {
	script, err := filepath.Abs("../amdsev-host-scan.sh")
	if err != nil {
		t.Fatal(err)
	}
	needle := freshHex(t, 32)
	pid := strconv.Itoa(holder(t, needle))
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"the held needle", []string{pid, needle}, 1},
		{"a fresh needle", []string{pid, freshHex(t, 32)}, 0},
		{"an odd needle", []string{pid, "abc"}, 2},
		{"no arguments", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", append([]string{script}, tc.args...)...)
			cmd.Env = append(os.Environ(), "AMDSEV_HOSTSCAN="+os.Args[0], helperEnv+"=1")
			out, err := cmd.CombinedOutput()
			rc := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				rc = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if rc != tc.want {
				t.Fatalf("amdsev-host-scan.sh %q = %d, want %d:\n%s", tc.args, rc, tc.want, out)
			}
		})
	}
}
