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
)

// ErrUnreadableMapping is matched by the error Find returns when a mapping the
// sweep must read could not be read in full. A mapping that cannot be read is
// not a mapping that is clean, so the sweep fails closed. The only mappings
// excused are the kernel-provided regions that never hold process data (see
// kernelMapping); a caller must not swallow this error.
var ErrUnreadableMapping = errors.New("memscan: a mapping the sweep must read could not be read")

// ErrEmptySweep is matched by the error Find returns when the sweep read no
// mapping at all, so "no hits" would say nothing.
var ErrEmptySweep = errors.New("memscan: the sweep read no mapping")

// UnreadableMappingError carries the /proc/self/maps line of the mapping that
// could not be read and the read failure, if the reader reported one.
type UnreadableMappingError struct {
	Mapping string
	Err     error
}

func (e *UnreadableMappingError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%v: %s: the read made no progress", ErrUnreadableMapping, e.Mapping)
	}
	return fmt.Sprintf("%v: %s: %v", ErrUnreadableMapping, e.Mapping, e.Err)
}

// Unwrap returns the read failure.
func (e *UnreadableMappingError) Unwrap() error { return e.Err }

// Is matches ErrUnreadableMapping.
func (e *UnreadableMappingError) Is(target error) bool { return target == ErrUnreadableMapping }
