//go:build linux

// Command amdsev-hostscan scans another process's readable memory for a
// needle: step 5 of the amd-sev test plan on the real hardware
// (docs/backends/amd-sev.md), run on the host as root against the QEMU process
// of a guest that holds the needle in a handle.
//
// Usage: amdsev-hostscan <pid> <hex-needle>
//
// It reads every readable mapping in /proc/<pid>/maps through /proc/<pid>/mem,
// the scan internal/memscan does in-process, and exits 0 when the needle is
// not found, 1 when it is (naming each mapping that holds it), and 2 on an
// error, including when a readable mapping could not be read: that scan is
// incomplete, never "not found". scripts/amdsev-host-scan.sh builds
// and runs it.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// chunk is how much of a mapping one read takes.
const chunk = 1 << 20

var errNoProgress = errors.New("read made no progress")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the command: it returns the exit status.
func run(args []string, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "amdsev-hostscan: "+format+"\n", a...)
		return 2
	}
	if len(args) != 2 {
		return fail("usage: amdsev-hostscan <pid> <hex-needle>")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return fail("pid %q is not a process id", args[0])
	}
	if pid == os.Getpid() {
		return fail("pid %d is the scanner itself, which holds the needle", pid)
	}
	needle, err := hex.DecodeString(args[1])
	if err != nil || len(needle) == 0 {
		return fail("the needle is not a non-empty even-length hex string")
	}
	hits, err := scan(pid, needle)
	if err != nil {
		return fail("pid %d: %v", pid, err)
	}
	if len(hits) == 0 {
		_, _ = fmt.Fprintf(stdout, "not found in pid %d\n", pid)
		return 0
	}
	for _, h := range hits {
		_, _ = fmt.Fprintf(stdout, "found in pid %d: %s\n", pid, h)
	}
	return 1
}

// memFile is the target's /proc/<pid>/mem as the scan reads it.
type memFile interface {
	io.ReaderAt
	io.Closer
}

// openMem opens the target's memory; a variable so a test can make one
// mapping unreadable.
var openMem = func(name string) (memFile, error) {
	return os.Open(name) //nolint:gosec // /proc/<pid>/mem, pid a parsed integer
}

// scan returns the /proc/<pid>/maps lines of the readable mappings that hold
// needle. It fails, naming the mapping, when it cannot read one of them, and
// when it could read none.
func scan(pid int, needle []byte) ([]string, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	maps, err := os.ReadFile(dir + "/maps") //nolint:gosec // /proc/<pid>, pid a parsed integer
	if err != nil {
		return nil, err
	}
	mem, err := openMem(dir + "/mem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = mem.Close() }()
	buf := make([]byte, chunk+len(needle)-1)
	var hits []string
	read := 0
	for _, line := range strings.Split(string(maps), "\n") {
		lo, hi, ok := readable(line)
		if !ok {
			continue
		}
		found, err := contains(mem, lo, hi, needle, buf)
		if err != nil {
			// A mapping the scan could not read may hold the needle: the
			// scan is incomplete, never "not found".
			return nil, fmt.Errorf("incomplete scan: %s: %w", strings.TrimSpace(line), err)
		}
		read++
		if found {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	if read == 0 {
		return nil, errors.New("no mapping could be read")
	}
	return hits, nil
}

// readable parses a /proc/<pid>/maps line and reports the range of a mapping
// with read permission that /proc/<pid>/mem can serve: not the kernel's vvar
// and vsyscall pages, and not past the largest file offset.
func readable(line string) (lo, hi uint64, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || !strings.HasPrefix(fields[1], "r") {
		return 0, 0, false
	}
	if len(fields) > 5 && strings.HasPrefix(fields[5], "[v") {
		return 0, 0, false // [vvar], [vvar_vclock], [vsyscall]
	}
	a, b, found := strings.Cut(fields[0], "-")
	if !found {
		return 0, 0, false
	}
	lo, errLo := strconv.ParseUint(a, 16, 64)
	hi, errHi := strconv.ParseUint(b, 16, 64)
	if errLo != nil || errHi != nil || hi <= lo || hi > math.MaxInt64 {
		return 0, 0, false
	}
	return lo, hi, true
}

// contains reports whether mem holds needle in [lo, hi), reading a chunk at a
// time and keeping the last len(needle)-1 bytes of each, so a needle across a
// chunk boundary is found.
func contains(mem io.ReaderAt, lo, hi uint64, needle, buf []byte) (bool, error) {
	keep := 0
	for off := lo; off < hi; {
		n := min(uint64(len(buf)-keep), hi-off)
		got, err := mem.ReadAt(buf[keep:keep+int(n)], int64(off)) //nolint:gosec // off < hi <= MaxInt64 (readable)
		total := keep + got
		if bytes.Contains(buf[:total], needle) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if got == 0 {
			return false, errNoProgress
		}
		keep = min(len(needle)-1, total)
		copy(buf, buf[total-keep:total])
		off += uint64(got) //nolint:gosec // 0 < got <= len(buf)
	}
	return false, nil
}
