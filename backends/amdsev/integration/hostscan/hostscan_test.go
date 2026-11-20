package hostscan

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// childEnv makes the test binary a child that holds the hex needle it is
// given, decoded, until its stdin closes.
const childEnv = "HOSTSCAN_TEST_CHILD_NEEDLE"

func TestMain(m *testing.M) {
	if h := os.Getenv(childEnv); h != "" {
		held, err := hex.DecodeString(h)
		if err != nil {
			os.Exit(3)
		}
		_ = os.Unsetenv(childEnv)
		_, _ = os.Stdout.WriteString("ready\n")
		_, _ = io.Copy(io.Discard, os.Stdin)
		runtime.KeepAlive(held)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func needle(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// holder starts a child holding held and returns its pid.
func holder(t *testing.T, held []byte) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childEnv+"="+hex.EncodeToString(held))
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
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("child: %q, %v", line, err)
	}
	return cmd.Process.Pid
}

func TestAmdSev_ScanFindsTheNeedleAChildHolds(t *testing.T) {
	held := needle(t)
	pid := holder(t, held)
	res, err := Scan(pid, held)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Hits) == 0 {
		t.Fatalf("the needle the child holds was not found; %d mappings read, skipped %v", res.Read, res.Skipped)
	}
}

func TestAmdSev_ScanDoesNotFindANeedleTheChildNeverHeld(t *testing.T) {
	pid := holder(t, needle(t))
	res, err := Scan(pid, needle(t))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Hits) != 0 || res.Read == 0 {
		t.Fatalf("hits %v, read %d: want none found in a scan that read memory", res.Hits, res.Read)
	}
}

func TestAmdSev_ScanRefuses(t *testing.T) {
	if _, err := Scan(os.Getpid(), []byte{1}); !errors.Is(err, ErrSelf) {
		t.Errorf("self: %v", err)
	}
	if _, err := Scan(os.Getppid(), nil); !errors.Is(err, ErrEmptyNeedle) {
		t.Errorf("empty needle: %v", err)
	}
	if _, err := Scan(1<<30, []byte{1}); err == nil {
		t.Error("a pid that does not exist was scanned")
	}
}

func TestAmdSev_Readable(t *testing.T) {
	for _, tc := range []struct {
		line   string
		lo, hi uint64
		ok     bool
	}{
		{"00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/x", 0x400000, 0x452000, true},
		{"7ffd1000-7ffd3000 rw-p 00000000 00:00 0 [stack]", 0x7ffd1000, 0x7ffd3000, true},
		{"7ffd5000-7ffd7000 r--p 00000000 00:00 0 [vvar]", 0, 0, false},
		{"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]", 0, 0, false},
		{"00400000-00452000 ---p 00000000 08:02 173521", 0, 0, false},
		{"00452000-00400000 r--p 00000000 08:02 173521", 0, 0, false},
		{"zz-00400000 r--p 00000000 08:02 1", 0, 0, false},
		{"00400000 r--p 00000000 08:02 1", 0, 0, false},
		{"", 0, 0, false},
	} {
		lo, hi, ok := readable(tc.line)
		if lo != tc.lo || hi != tc.hi || ok != tc.ok {
			t.Errorf("readable(%q) = %#x, %#x, %v", tc.line, lo, hi, ok)
		}
	}
}

func TestAmdSev_ContainsAcrossTheChunkBoundary(t *testing.T) {
	n := []byte("needle")
	mem := bytes.Repeat([]byte{'.'}, 64)
	copy(mem[13:], n) // across the 16-byte reads below
	buf := make([]byte, 16)
	found, err := contains(bytes.NewReader(mem), 0, uint64(len(mem)), n, buf)
	if err != nil || !found {
		t.Fatalf("contains = %v, %v; want found", found, err)
	}
	found, err = contains(bytes.NewReader(mem), 20, uint64(len(mem)), n, buf)
	if err != nil || found {
		t.Fatalf("contains past it = %v, %v; want not found", found, err)
	}
}

type failingReader struct{ err error }

func (f failingReader) ReadAt([]byte, int64) (int, error) { return 0, f.err }

func TestAmdSev_ScanMapsSkipsWhatItCannotRead(t *testing.T) {
	maps := "00001000-00002000 r--p 00000000 00:00 0\n00003000-00004000 rw-p 00000000 00:00 0 [heap]\n"
	res := scanMaps(maps, failingReader{io.ErrUnexpectedEOF}, []byte("x"))
	if res.Read != 0 || len(res.Skipped) != 2 || !strings.Contains(res.Skipped[1], "[heap]") {
		t.Fatalf("got %+v; want both mappings skipped and named", res)
	}
	res = scanMaps(maps, failingReader{nil}, []byte("x"))
	if len(res.Skipped) != 2 || !strings.Contains(res.Skipped[0], errNoProgress.Error()) {
		t.Fatalf("got %+v; want no progress named", res)
	}
}

// partialReader reads zeros everywhere except [badLo, badHi), where it fails.
type partialReader struct{ badLo, badHi int64 }

func (p partialReader) ReadAt(b []byte, off int64) (int, error) {
	if off >= p.badLo && off < p.badHi {
		return 0, io.ErrUnexpectedEOF
	}
	clear(b)
	return len(b), nil
}

// A mapping the kernel refuses to read could hold the needle, so a scan that
// read some mappings but not all is incomplete, not a clean "not found".
func TestAmdSev_ScanIncompleteWhenAMappingIsUnreadable(t *testing.T) {
	maps := "00001000-00002000 r--p 00000000 00:00 0\n00003000-00004000 rw-p 00000000 00:00 0 [heap]\n"
	res := scanMaps(maps, partialReader{0x3000, 0x4000}, []byte("x"))
	if res.Read != 1 || len(res.Skipped) != 1 || len(res.Hits) != 0 {
		t.Fatalf("got %+v; want one mapping read, the heap skipped, no hit", res)
	}
	err := res.err()
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v; want ErrIncomplete", err)
	}
	var ie *IncompleteError
	if !errors.As(err, &ie) || ie.Read != 1 || len(ie.Skipped) != 1 || !strings.Contains(ie.Skipped[0], "[heap]") {
		t.Fatalf("err = %#v; want an *IncompleteError naming the heap", err)
	}
	if !strings.Contains(err.Error(), "[heap]") {
		t.Fatalf("err = %q; want the skipped mapping named", err)
	}
	if err := scanMaps(maps, failingReader{io.ErrUnexpectedEOF}, []byte("x")).err(); !errors.Is(err, ErrNothingRead) {
		t.Fatalf("nothing read: err = %v; want ErrNothingRead", err)
	}
	if err := scanMaps(maps, partialReader{0, 0}, []byte("x")).err(); err != nil {
		t.Fatalf("everything read: err = %v; want nil", err)
	}
}
