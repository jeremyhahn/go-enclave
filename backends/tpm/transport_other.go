//go:build !linux

package tpm

import "runtime"

// openDevice reports that only Linux has the kernel's TPM resource manager.
func openDevice(string, allocator) (device, error) {
	return nil, &PlatformError{GOOS: runtime.GOOS}
}

// heapAllocator serves the tests off Linux; Open never gets this far.
type heapAllocator struct{}

func newAllocator() allocator { return heapAllocator{} }

func (heapAllocator) alloc(n int) ([]byte, error) { return make([]byte, n), nil }

func (heapAllocator) free([]byte) {}
