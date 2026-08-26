// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package enclave provides MemoryEnclave, a region of locked, zeroized memory
// for holding sensitive material — private keys, credentials, passphrases and
// tokens — for the whole of its lifetime in the process.
//
// A MemoryEnclave wraps a memguard LockedBuffer. The bytes live on guarded
// pages that are mlock'd (so they are never paged to swap), fenced by
// inaccessible guard pages, checked by a canary, and wiped on release. Core
// dumps are disabled process-wide by memguard on import.
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
// built from existing material, whose pages memguard freezes, and silently
// corrupts a sized enclave, whose pages stay writable. Use Open only where no
// concurrent Destroy is possible, and never retain what it returns.
//
// # FIPS
//
// A MemoryEnclave performs no cryptography. It uses only the memguard
// LockedBuffer path — never Enclave/Seal, whose sealing uses NaCl secretbox,
// an algorithm that is not FIPS 140-approved. Locked buffers are safe under
// GODEBUG=fips140=only, which this repository's CI enforces.
package enclave
