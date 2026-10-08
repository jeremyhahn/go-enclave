// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "sync"

// processSingleton is a process-wide value the binary may install once, before
// first use, and that is otherwise built lazily on first use. Once set it is
// never replaced outside tests: replacing it would strand whatever the old
// value holds.
type processSingleton[T any] struct {
	mu    sync.Mutex
	value *T

	// errNil refuses installing nil; errTaken refuses a second install.
	errNil, errTaken error

	// build makes the default on first use. A failed build installs nothing,
	// so a later call retries.
	build func() (*T, error)
}

// install sets v as the value. It is one-shot, and a default already built
// counts, so even a stray early get locks the configuration.
func (s *processSingleton[T]) install(v *T) error {
	if v == nil {
		return s.errNil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.value != nil {
		return s.errTaken
	}
	s.value = v
	return nil
}

// get returns the installed value, building the default if there is none.
func (s *processSingleton[T]) get() (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.value == nil {
		v, err := s.build()
		if err != nil {
			return nil, err
		}
		s.value = v
	}
	return s.value, nil
}
