// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package enclave_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Existing material is moved into an enclave: the caller's slice is wiped,
// and the material is read only inside a WithBytes borrow.
func ExampleNewMemory() {
	secret := []byte("correct horse battery staple")
	e, err := enclave.NewMemory(secret) // secret is wiped, on every path
	if err != nil {
		log.Fatal(err)
	}
	defer e.Destroy()

	fmt.Println("caller's slice wiped:", secret[0] == 0)
	err = e.WithBytes(func(b []byte) error {
		fmt.Println("borrowed length:", len(b)) // never keep b past the callback
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	ok, err := e.EqualTo([]byte("correct horse battery staple"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("equal:", ok)
	// Output:
	// caller's slice wiped: true
	// borrowed length: 28
	// equal: true
}

// NewMemoryCopy leaves the source untouched, so the caller must wipe it.
func ExampleNewMemoryCopy() {
	src := []byte("not mine to wipe")
	e, err := enclave.NewMemoryCopy(src)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Destroy()

	fmt.Println("source kept:", string(src))
	enclave.Wipe(src) // the heap copy is outside every protection
	fmt.Println("enclave size:", e.Size())
	// Output:
	// source kept: not mine to wipe
	// enclave size: 16
}

// Material that is about to be created is generated in locked pages, then
// frozen read-only.
func ExampleNewMemorySized() {
	e, err := enclave.NewMemorySized(32)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Destroy()

	if err := e.WithBytes(func(key []byte) error {
		_, err := io.ReadFull(rand.Reader, key) // straight into locked pages
		return err
	}); err != nil {
		log.Fatal(err)
	}

	// A refused Freeze leaves the enclave WRITABLE, so check the error.
	var f enclave.Freezer
	if !enclave.As(e, &f) {
		log.Fatal("enclave cannot be frozen")
	}
	if err := f.Freeze(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("frozen key of", e.Size(), "bytes")
	// Output:
	// frozen key of 32 bytes
}

// Destroy wipes and releases the pages; it is idempotent, and every copy of
// the handle is the same enclave.
func ExampleHandle_destroy() {
	e, err := enclave.NewMemory([]byte("short-lived"))
	if err != nil {
		log.Fatal(err)
	}
	same := e
	if err := e.Destroy(); err != nil {
		switch {
		case errors.Is(err, enclave.ErrReleasedWithoutWipe):
			// Pages are gone; the environment denies mprotect.
		case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
			// Kernel refused the release; pages are still held.
			// Call Destroy again later; a shutdown WipeAll also retries it.
		}
		log.Fatal(err)
	}
	fmt.Println("alive:", same.IsAlive())
	fmt.Println("second Destroy:", same.Destroy())
	err = same.WithBytes(func([]byte) error { return nil })
	fmt.Println("borrow after Destroy:", errors.Is(err, enclave.ErrEnclaveDestroyed))
	// Output:
	// alive: false
	// second Destroy: <nil>
	// borrow after Destroy: true
}

// A budget admits whole pages: every enclave costs at least one, so size the
// budget with LockedSize.
func ExampleNewAllocator() {
	budget, err := enclave.NewAllocator(100 * enclave.LockedSize(32)) // 100 small credentials
	if err != nil {
		log.Fatal(err)
	}
	key, err := budget.NewSized(32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("one credential reserved:", budget.InUse() == enclave.LockedSize(32))
	fmt.Println("room for 99 more:", budget.Available() == 99*enclave.LockedSize(32))

	if err := key.Destroy(); err != nil { // returns the reservation
		log.Fatal(err)
	}
	fmt.Println("in use after Destroy:", budget.InUse())

	if err := budget.SetLimit(0); err != nil {
		log.Fatal(err)
	}
	_, err = budget.New([]byte("refused"))
	fmt.Println("over budget:", errors.Is(err, enclave.ErrBudgetExhausted))
	// Output:
	// one credential reserved: true
	// room for 99 more: true
	// in use after Destroy: 0
	// over budget: true
}

// The binary sizes and installs the process budget from main, before anything
// allocates locked memory; libraries ask for it with ProcessAllocator. This
// example has no Output block: the process allocator is installed once per
// process, so it is compiled but not run.
func ExampleSetAllocator() {
	budget, err := enclave.NewAllocatorWithinRLimit(64 << 20) // 64 MiB of locked pages
	if err != nil {
		log.Fatal(err) // e.g. ErrBudgetExceedsRLimit names both figures
	}
	if err := enclave.SetAllocator(budget); err != nil {
		log.Fatal(err) // ErrAllocatorInstalled: a ProcessAllocator call installed the default first
	}

	// In a library:
	a, err := enclave.ProcessAllocator()
	if err != nil {
		log.Fatal(err)
	}
	key, err := a.NewSized(32)
	if err != nil {
		log.Fatal(err) // ErrBudgetExhausted refuses this request, not the process
	}
	defer key.Destroy() // returns the reservation
}

// Detect always selects a backend: locked memory when nothing registered
// ranks above it. Which one it selects depends on the host and on what the
// binary registered, so this example prints only what holds everywhere.
func ExampleDetect() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	backend, results := enclave.Detect(ctx)
	fmt.Println("backend selected:", backend != nil && backend.Name() != "")
	for _, r := range results {
		if r.Backend == enclave.LockedMemoryBackendName {
			fmt.Println("locked memory usable:", r.Err == nil)
		}
	}
	// Output:
	// backend selected: true
	// locked memory usable: true
}

// WipeAll belongs to shutdown: take its deadline there, after the workers
// have stopped.
func ExampleWipeAll() {
	e, err := enclave.NewMemory([]byte("still open at exit"))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	n, err := enclave.WipeAll(ctx)
	var sweep *enclave.SweepError
	switch {
	case errors.As(err, &sweep):
		log.Printf("enclave: sweep found %d corrupted, %d unwiped, %d failed backends; %d still held",
			sweep.Corrupt, sweep.Unwiped, len(sweep.Backends), n)
	case errors.Is(err, enclave.ErrSweepInProgress):
		log.Printf("enclave: another sweep was running; %d still held", n)
	case n != 0:
		log.Printf("enclave: %d still held at exit", n)
	}
	fmt.Println("still held:", n)
	fmt.Println("enclave alive:", e.IsAlive())
	// Output:
	// still held: 0
	// enclave alive: false
}
