// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"testing"
)

// The borrow benchmarks measure the cost a READER pays to hold an enclave's
// lock, which is the path a shutdown sweep has to be able to wait on (#88).
// Making a borrow observable to [WipeAll] must not cost a reader a lock or an
// allocation, and these are what settle what it does cost: run them before and
// after any change to withLocked, Size, IsAlive or the borrow bookkeeping, and
// compare with benchstat. No threshold is wired into CI, for the reason given
// on BenchmarkRefusalSerial.
//
// The callback does nothing on purpose. A real borrow does far more work than
// the bracket around it, and a benchmark whose body dwarfed the bracket would
// report noise as the answer.

// newBenchEnclave returns a small frozen enclave, destroyed at cleanup.
func newBenchEnclave(b *testing.B) *MemoryEnclave {
	b.Helper()
	e, err := NewMemoryEnclaveCopy(make([]byte, 32))
	if err != nil {
		b.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	b.Cleanup(func() {
		if err := e.Destroy(); err != nil {
			b.Errorf("Destroy: %v", err)
		}
	})
	return e
}

// noopBorrow is the callback every borrow benchmark runs. A package-level func
// value, so taking it does not allocate a closure per iteration.
func noopBorrow([]byte) error { return nil }

// BenchmarkBorrowSerial is one goroutine borrowing one enclave: the
// uncontended cost of the read-lock bracket.
func BenchmarkBorrowSerial(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.WithBytes(noopBorrow); err != nil {
			b.Fatalf("WithBytes: %v", err)
		}
	}
}

// BenchmarkBorrowParallelShared is GOMAXPROCS goroutines borrowing ONE enclave.
// Every borrow writes the enclave's lock word, so this is the arm in which a
// read-modify-write added to the bracket shows up at full amplitude: the line
// is already contended, and anything else written on it is contended with it.
func BenchmarkBorrowParallelShared(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := e.WithBytes(noopBorrow); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkBorrowParallelDistinct is GOMAXPROCS goroutines each borrowing its
// OWN enclave. Nothing per-enclave is shared, so the only cross-core cost left
// is whatever package-level state a borrow touches — which is what this arm
// exists to expose. A borrow that wrote a package-level word would collapse
// here even though it looked free in the serial arm.
func BenchmarkBorrowParallelDistinct(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		e, err := NewMemoryEnclaveCopy(make([]byte, 32))
		if err != nil {
			b.Error(err)
			return
		}
		defer func() {
			if err := e.Destroy(); err != nil {
				b.Error(err)
			}
		}()
		for pb.Next() {
			if err := e.WithBytes(noopBorrow); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkIsAliveParallel is the cheapest reader there is, polled from every
// core against one enclave — a health probe during shutdown, which is the
// reader the sweep most often meets.
func BenchmarkIsAliveParallel(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !e.IsAlive() {
				b.Error("IsAlive reported a live enclave destroyed")
				return
			}
		}
	})
}
