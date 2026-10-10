//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package backendtest

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFrozenHead copies material into fresh pages and makes only the first of
// them read-only, the partial Freeze of the freezeHeadOnly fault. unmap
// releases the whole mapping.
func mapFrozenHead(material []byte) (view []byte, unmap func() error, err error) {
	page := os.Getpagesize()
	m, err := unix.Mmap(-1, 0, (len(material)+page-1)/page*page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, nil, err
	}
	copy(m, material)
	if err := unix.Mprotect(m[:page], unix.PROT_READ); err != nil {
		_ = unix.Munmap(m) // the Mprotect failure is the one to report
		return nil, nil, err
	}
	return m[:len(material)], func() error { return unix.Munmap(m) }, nil
}
