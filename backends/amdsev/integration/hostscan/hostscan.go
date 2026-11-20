// Package hostscan scans another process's readable memory for a needle, from
// outside it: every readable mapping in /proc/<pid>/maps, read through
// /proc/<pid>/mem. It is the scan internal/memscan does in-process, done
// across the process boundary, and the SEV-SNP kit runs it as root against a
// guest's QEMU process.
package hostscan

import (
	"bytes"
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

var (
	// ErrSelf refuses a scan of the scanning process, which holds the needle.
	ErrSelf = errors.New("hostscan: the pid is the scanner itself, which holds the needle")
	// ErrEmptyNeedle refuses an empty needle, found everywhere.
	ErrEmptyNeedle = errors.New("hostscan: empty needle")
	// ErrNothingRead is returned when no mapping could be read: a scan that
	// read nothing proves nothing.
	ErrNothingRead = errors.New("hostscan: no mapping could be read")
	// ErrIncomplete is the sentinel of *IncompleteError: some readable
	// mapping could not be read, so the needle may be where the scan could
	// not look.
	ErrIncomplete = errors.New("hostscan: scan incomplete")

	errNoProgress = errors.New("read made no progress")
)

// Result is one scan's outcome.
type Result struct {
	// Hits are the /proc/<pid>/maps lines of the mappings holding the needle.
	Hits []string
	// Read counts the mappings read in full.
	Read int
	// Skipped names each mapping the kernel refused to read, with the error.
	Skipped []string
}

// Scan reads every readable mapping of pid and reports those holding needle.
func Scan(pid int, needle []byte) (Result, error) {
	if pid == os.Getpid() {
		return Result{}, ErrSelf
	}
	if len(needle) == 0 {
		return Result{}, ErrEmptyNeedle
	}
	dir := "/proc/" + strconv.Itoa(pid)
	maps, err := os.ReadFile(dir + "/maps") //nolint:gosec // /proc/<int>/maps
	if err != nil {
		return Result{}, err
	}
	mem, err := os.Open(dir + "/mem") //nolint:gosec // /proc/<int>/mem
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = mem.Close() }()
	res := scanMaps(string(maps), mem, needle)
	return res, res.err()
}

// err is the scan's verdict on its own completeness: ErrNothingRead when no
// mapping could be read, an *IncompleteError when some could not, else nil.
// An unreadable mapping could hold the needle, so a scan that skipped one
// proves nothing about its absence.
func (r Result) err() error {
	if r.Read == 0 {
		return ErrNothingRead
	}
	if len(r.Skipped) > 0 {
		return &IncompleteError{Read: r.Read, Skipped: r.Skipped}
	}
	return nil
}

// IncompleteError reports a scan that read some mappings but not all. It is
// ErrIncomplete.
type IncompleteError struct {
	// Read counts the mappings read in full.
	Read int
	// Skipped names each mapping the kernel refused to read, with the error.
	Skipped []string
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("hostscan: scan incomplete: %d mappings read, %d unreadable (%s)", e.Read, len(e.Skipped), strings.Join(e.Skipped, "; "))
}

// Is reports whether target is ErrIncomplete.
func (e *IncompleteError) Is(target error) bool { return target == ErrIncomplete }

// scanMaps scans each readable range maps names through mem.
func scanMaps(maps string, mem io.ReaderAt, needle []byte) Result {
	buf := make([]byte, chunk+len(needle)-1)
	var res Result
	for _, line := range strings.Split(maps, "\n") {
		lo, hi, ok := readable(line)
		if !ok {
			continue
		}
		line = strings.TrimSpace(line)
		found, err := contains(mem, lo, hi, needle, buf)
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", line, err))
			continue
		}
		res.Read++
		if found {
			res.Hits = append(res.Hits, line)
		}
	}
	return res
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
// chunk boundary is found. buf is at least len(needle) bytes.
func contains(mem io.ReaderAt, lo, hi uint64, needle, buf []byte) (bool, error) {
	keep := 0
	for off := lo; off < hi; {
		n := min(uint64(len(buf)-keep), hi-off)
		got, err := mem.ReadAt(buf[keep:keep+int(n)], int64(off)) //nolint:gosec // off < hi <= MaxInt64 (readable)
		total := keep + got
		if bytes.Contains(buf[:total], needle) {
			return true, nil
		}
		if err != nil && (!errors.Is(err, io.EOF) || got != int(n)) { //nolint:gosec // n <= len(buf)
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
