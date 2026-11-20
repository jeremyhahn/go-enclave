// Command amdsev-hostscan scans another process's readable memory for a
// needle: the SEV-SNP kit's host scan, run as root against a guest's QEMU
// process by scripts/amd-sev-snp/host-scan.sh.
//
// Usage: amdsev-hostscan <pid> <hex-needle>
//
// It exits 0 when the needle is not found, 1 when it is (naming each mapping
// that holds it), and 2 on an error, including when no mapping could be read.
// A mapping the kernel refuses to read is named on stderr.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-enclave/test/integration/amdsev/hostscan"
)

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
	needle, err := hex.DecodeString(args[1])
	if err != nil || len(needle) == 0 {
		return fail("the needle is not a non-empty even-length hex string")
	}
	res, err := hostscan.Scan(pid, needle)
	for _, s := range res.Skipped {
		_, _ = fmt.Fprintf(stderr, "amdsev-hostscan: skipped %s\n", s)
	}
	if err != nil {
		return fail("pid %d: %v", pid, err)
	}
	if len(res.Hits) == 0 {
		_, _ = fmt.Fprintf(stdout, "not found in pid %d (%d mappings read)\n", pid, res.Read)
		return 0
	}
	for _, h := range res.Hits {
		_, _ = fmt.Fprintf(stdout, "found in pid %d: %s\n", pid, h)
	}
	return 1
}
