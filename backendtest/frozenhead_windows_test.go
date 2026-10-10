package backendtest

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mapFrozenHead copies material into fresh pages and makes only the first of
// them read-only, the partial Freeze of the freezeHeadOnly fault. unmap
// releases the whole allocation. The uintptr-to-pointer conversion is safe
// because the pages are not Go heap and stay valid until unmap.
func mapFrozenHead(material []byte) (view []byte, unmap func() error, err error) {
	page := os.Getpagesize()
	n := (len(material) + page - 1) / page * page
	addr, err := windows.VirtualAlloc(0, uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return nil, nil, err
	}
	release := func() error { return windows.VirtualFree(addr, 0, windows.MEM_RELEASE) }
	base := *(*unsafe.Pointer)(unsafe.Pointer(&addr)) // #nosec G103 -- VirtualAlloc memory, not Go heap
	m := unsafe.Slice((*byte)(base), n)               // #nosec G103 -- n is exactly the length VirtualAlloc committed
	copy(m, material)
	var previous uint32
	if err := windows.VirtualProtect(addr, uintptr(page), windows.PAGE_READONLY, &previous); err != nil {
		_ = release() // the VirtualProtect failure is the one to report
		return nil, nil, err
	}
	return m[:len(material)], release, nil
}
