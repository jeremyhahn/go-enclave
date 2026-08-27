// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package enclave provides MemoryEnclave, a region of locked, zeroized memory
// for holding sensitive material — private keys, credentials, passphrases and
// tokens — for the whole of its lifetime in the process.
//
// The bytes live on pages this package maps itself: mlock'd, so they are never
// paged to swap; fenced on both sides by inaccessible guard pages, so an
// overflow faults instead of corrupting a neighbor; preceded by a random
// canary, so an underflow is detected on release; and wiped before the pages go
// back to the kernel.
//
// A core file would write those pages to disk in plaintext, so they are kept out
// of one at two levels: RLIMIT_CORE is lowered process-wide on import, which is
// best effort and reported by [CoreDumpsDisabled] rather than assumed, and every
// enclave's pages are additionally marked MADV_DONTDUMP as they are locked. The
// second one is checked rather than attempted-and-forgotten: its error fails the
// allocation. That the refusal is REPORTED at all is covered by a test; that the
// report is acted on at the call site is guaranteed by construction, being one
// branch in [newMapping] that no test can reach — the region it passes is always
// page-aligned, and an aligned madvise does not fail.
//
// Every failure is a returned error. The mapping, the lock and the guard
// protections can all be refused by the kernel — most often at the process's
// RLIMIT_MEMLOCK ceiling — and each one yields [ErrLockedMemoryUnavailable]
// having released whatever it had already taken. No failure anywhere in the
// process can touch an enclave it does not own. Until v0.3.0-alpha that second
// guarantee did not hold: the pages came
// from memguard, whose failure path unmaps every live locked buffer in the
// process before panicking, so an unrelated allocation failure destroyed live
// enclaves and holding a borrow across any call that allocated deadlocked
// against the lock that made the first hazard survivable (issue #2).
//
// # The one thing that is not an error
//
// [MemoryEnclave.Destroy] PANICS when the canary guarding an enclave did not
// verify, after wiping the material, releasing the pages and returning any
// [Allocator] reservation. Everything else in this package hands failures back;
// this one does not, and the distinction is deliberate rather than an oversight.
// A failed canary means memory the enclave did not own was written — the state a
// caller would use to handle the error is the state that is already wrong — and
// it is the class Go reserves panic for. It is also what this method always did:
// before v0.3.0-alpha the same check lived in memguard and called core.Panic,
// which additionally destroyed every other enclave in the process on its way out.
//
// The vocabulary is deliberate and portfolio-wide: the type describes its
// mechanism — a region of locked memory — and is never called a "secret",
// which in this codebase already means a config value, a secret reference, an
// ACME account secret or a Shamir share. Do not introduce Secret,
// SecureString, SecureBytes or ProtectedBuffer synonyms.
//
// Usage:
//
//	e, err := enclave.NewMemoryEnclave(keyPEM) // keyPEM is wiped
//	if err != nil {
//	    return err
//	}
//	defer e.Destroy()
//
//	var cert tls.Certificate
//	err = e.WithBytes(func(key []byte) error {
//	    var perr error
//	    cert, perr = tls.X509KeyPair(certPEM, key)
//	    return perr
//	})
//
// WithBytes is the idiom: it holds the enclave's read lock across the whole
// callback, so a concurrent Destroy blocks until the borrow returns instead of
// unmapping the pages mid-read. OpenString and EqualTo are locked the same way.
//
// Material that is about to be GENERATED never needs to touch the heap at all.
// NewMemoryEnclaveSized hands back locked, zeroed pages, and the same borrow
// window is where they are filled:
//
//	e, err := enclave.NewMemoryEnclaveSized(32)
//	if err != nil {
//	    return err
//	}
//	defer e.Destroy()
//
//	err = e.WithBytes(func(key []byte) error {
//	    _, err := io.ReadFull(rand.Reader, key)
//	    return err
//	})
//
// Reach for it wherever the alternative would be to draw the material into a
// make'd slice and move it in afterwards: the wipe that follows such a move
// cannot reach copies the compiler or the garbage collector already made, and
// the key was on swappable, core-dumpable memory in the meantime. Allocator has
// the admitted form, NewSized.
//
// Open also exists and returns the slice directly, but the slice aliases the
// locked pages and is NOT covered by the lock once Open returns: a concurrent
// Destroy unmaps it and a read through it then faults the process rather than
// returning an error. Nor is it a write path — a write faults on an enclave
// built from existing material, whose pages are frozen read-only, and silently
// corrupts a sized enclave, whose pages stay writable. Use Open only where no
// concurrent Destroy is possible, and never retain what it returns.
//
// # Shutdown
//
// WipeAll destroys every enclave the package has handed out and not yet
// reclaimed. It is for an ORDERLY EXIT — a signal handler, a defer in main —
// where locked memory still held is material that should not outlive the
// process. Nothing calls it for you.
//
// It is deliberately not a fault handler, which is what distinguishes it from
// the memguard purge this package removed in v0.3.0-alpha: that ran in response
// to any failed allocation, unmapped every live buffer in the process and then
// panicked. WipeAll is called on purpose, never panics, and never unmaps memory
// underneath a reader. An enclave being read when the sweep reaches it is
// retried on later passes, so a momentary reader costs a pass rather than the
// enclave; only one still held after every pass is counted.
//
// It returns two independent things. The COUNT is how many enclaves are still
// holding locked memory, so a non-zero value means workers outlived the
// shutdown. That is often an ordering problem in the caller and is not
// necessarily one, since a read outlasting the bounded retry budget (about
// 1.4ms) produces the same number — read it as "these were still in use,"
// not as a diagnosis. The ERROR reports detected canary
// corruption, matching ErrEnclaveCorrupted exactly as Destroy's panic value
// does. They are orthogonal: a corrupt enclave's pages ARE reclaimed, so it
// never appears in the count, and without a second return value the fact that
// something wrote into memory it did not own would vanish at exit behind a zero
// that looks like success. Destroy panics on that same condition because a
// single enclave's caller cannot act on state that is by definition wrong; a
// sweep must not abort, but non-fatal must not mean invisible either.
//
// One more thing follows for callers: WipeAll is a global destroyer. An enclave
// another component still holds is destroyed too, and a retained Open slice
// faults if it is read afterwards.
//
// So it belongs to the PROGRAM and never to a library. Call it from the code
// that owns the process — a signal handler, a defer in main. A library calling
// it destroys enclaves belonging to subsystems it knows nothing about, whose
// owners are still using them, and it has no way to know that is safe.
//
// # FIPS
//
// A MemoryEnclave performs no cryptography. It maps, locks and wipes memory,
// and the only cryptographic primitive anywhere near it is crypto/rand filling
// the canary — a FIPS-approved DRBG. It is safe under GODEBUG=fips140=only,
// which this repository's CI enforces.
//
// This is also why the package no longer depends on memguard, whose Enclave and
// Seal paths use NaCl secretbox: go-enclave never called them, but the
// dependency put a non-approved algorithm in the build graph of every consumer.
package enclave
