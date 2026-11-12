//go:build !linux

// Command amdsev-hostscan scans another process's memory through /proc, which
// only Linux has; elsewhere it refuses (exit 2).
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "amdsev-hostscan: needs Linux's /proc/<pid>/mem")
	os.Exit(2)
}
