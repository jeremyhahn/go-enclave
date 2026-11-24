// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnreadableMapping is matched by the error Find returns when a mapping the
// sweep must read could not be read in full. A mapping that cannot be read is
// not a mapping that is clean, so the sweep fails closed. The only mappings
// excused are the kernel-provided regions that never hold process data (see
// kernelMapping), and the only pages excused inside a mapping are guard
// regions: a read that fails with EIO on a page /proc/self/pagemap marks
// PM_GUARD_REGION (see skipGuard). A caller must not swallow this error.
var ErrUnreadableMapping = errors.New("memscan: a mapping the sweep must read could not be read")

// ErrEmptySweep is matched by the error Find returns when the sweep read no
// mapping at all, so "no hits" would say nothing.
var ErrEmptySweep = errors.New("memscan: the sweep read no mapping")

// maxUnreadablePages bounds the pages an UnreadableMappingError names.
const maxUnreadablePages = 16

// UnreadablePage is a page of a mapping whose read failed and that is not a
// proven guard page: its address and its raw /proc/self/pagemap entry, or the
// failure to read that entry.
type UnreadablePage struct {
	Addr       uintptr
	Pagemap    uint64
	PagemapErr error
}

// UnreadableMappingError carries the /proc/self/maps line of the mapping that
// could not be read and the read failure, if the reader reported one. When the
// reader is /proc/self/mem it also carries the evidence of a page-by-page probe
// of the whole mapping: the first pages that failed and are not guard pages
// (at most 16, with their pagemap entries; never their contents), how many
// such pages there are, how many failing pages the pagemap marks as guard
// pages, and the release of the running kernel.
type UnreadableMappingError struct {
	Mapping         string
	Err             error
	Pages           []UnreadablePage
	UnreadablePages int
	GuardPages      int
	Kernel          string
}

func (e *UnreadableMappingError) Error() string {
	var b strings.Builder
	if e.Err == nil {
		fmt.Fprintf(&b, "%v: %s: the read made no progress", ErrUnreadableMapping, e.Mapping)
	} else {
		fmt.Fprintf(&b, "%v: %s: %v", ErrUnreadableMapping, e.Mapping, e.Err)
	}
	if e.Kernel != "" {
		fmt.Fprintf(&b, "; kernel %s", e.Kernel)
	}
	if e.UnreadablePages == 0 && e.GuardPages == 0 && len(e.Pages) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "; %d unreadable page(s) not marked as guard pages, %d guard page(s)", e.UnreadablePages, e.GuardPages)
	for i, p := range e.Pages {
		if i == 0 {
			b.WriteString("; first:")
		} else {
			b.WriteString(",")
		}
		if p.PagemapErr != nil {
			fmt.Fprintf(&b, " %#x pagemap unreadable: %v", p.Addr, p.PagemapErr)
		} else {
			fmt.Fprintf(&b, " %#x pagemap %#x", p.Addr, p.Pagemap)
		}
	}
	return b.String()
}

// Unwrap returns the read failure.
func (e *UnreadableMappingError) Unwrap() error { return e.Err }

// Is matches ErrUnreadableMapping.
func (e *UnreadableMappingError) Is(target error) bool { return target == ErrUnreadableMapping }
