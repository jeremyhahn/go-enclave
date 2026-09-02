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
// The vocabulary is deliberate: the type describes its mechanism — a region of
// locked memory — rather than what a caller keeps in it. It is never called a
// "secret", because in most systems that word is already taken by a config
// value, a secret reference, an account secret or a key share, and a name that
// collides with three existing meanings makes every call site ambiguous. Avoid
// introducing Secret, SecureString, SecureBytes or ProtectedBuffer synonyms.
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
//	if err != nil {
//	    return err
//	}
//
//	// The fill is done. A refused Freeze leaves the enclave WRITABLE, so the
//	// fault-on-write property holds only if this error is checked.
//	if err := e.Freeze(); err != nil {
//	    return err
//	}
//
// Reach for it wherever the alternative would be to draw the material into a
// make'd slice and move it in afterwards: the wipe that follows such a move
// cannot reach copies the compiler or the garbage collector already made, and
// the key was on swappable, core-dumpable memory in the meantime. Allocator has
// the admitted form, NewSized.
//
// [MemoryEnclave.Freeze] is what leaves a sized enclave with the protection the
// other constructors give it for free. Pages that have to be filled cannot arrive
// read-only, so a sized enclave is writable while it is being filled; Freeze
// mprotects it read-only once the material is final, which bounds the window in
// which a retained slice could rewrite a key to the fill instead of the enclave's
// lifetime. It is idempotent, it is not reversible, and it waits out in-flight
// borrows.
//
// NewMemoryEnclaveCopy is the third constructor and the one to reach for last.
// It leaves its source intact, for callers that do not own the buffer they were
// handed, and the price is stated rather than hidden: an unprotected copy of the
// material stays on the heap for as long as that source lives, which is the
// thing this package exists to avoid. It is the right tool only when the source
// genuinely has to survive.
//
// Open also exists and returns the slice directly, but the slice aliases the
// locked pages and is NOT covered by the lock once Open returns: a concurrent
// Destroy unmaps it and a read through it then faults the process rather than
// returning an error. Nor is it a write path — a write faults wherever the
// pages are frozen, and silently corrupts a sized enclave that has not been
// frozen yet. Use Open only where no concurrent Destroy is possible, and never
// retain what it returns.
//
// # Sizing a budget against the host
//
// An Allocator's budget is in locked bytes, the unit RLIMIT_MEMLOCK is
// expressed in, so the two can be compared — and NewAllocatorWithinRLimit makes
// the comparison. It discovers the process's ceiling and REFUSES a budget above
// it, naming the discovered figure, so a budget that was never satisfiable
// fails at construction instead of at the first allocation under load. A
// library must never end its host's process over a resource limit, so this is a
// constructor error and the decision stays with the application.
//
// DiscoverLockedMemoryLimit exposes the same reading, for deriving a budget
// from the host rather than guessing one and for logging where the figure came
// from. Neither is a guarantee: the ceiling is process-wide and shared, a
// cgroup can bind well below it, and it can move afterwards, so the check is an
// early diagnostic and ErrLockedMemoryUnavailable remains the authority on what
// this process may actually lock. The ceiling is read on Linux and on the BSDs;
// where a platform exposes none — Windows bounds a working-set size instead —
// nothing is refused, and the reported source says the check did not run rather
// than that the host has no limit.
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
// # Sealing
//
// SealedEnclave is the counterpart type: material encrypted AT REST inside the
// process, decrypted into a fresh MemoryEnclave only for as long as a caller
// holds it open.
//
// # Choosing between MemoryEnclave and SealedEnclave
//
// The two types make DIFFERENT security promises, and choosing by name gets
// it wrong. What separates them is the residency window of the plaintext:
//
//   - A MemoryEnclave holds plaintext for the object's WHOLE LIFE — locked so
//     it cannot reach swap, guard-paged, canaried, kept out of core dumps,
//     wiped on destroy. Those protections keep the material off DISK; none of
//     them make it unreadable to something that can read this process's live
//     memory, at any moment of the object's lifetime.
//   - A SealedEnclave holds ciphertext; plaintext exists only for the
//     duration of an Open, inside the MemoryEnclave that Open returns.
//     Something that reads process memory BETWEEN opens finds ciphertext. A
//     MemoryEnclave is never unreadable that way; a SealedEnclave is,
//     whenever it is not open.
//
// Choose by ACCESS PATTERN. Material in hot or continuous use — a session key
// applied to every packet, anything handed to an API that needs a stable
// buffer for its lifetime — belongs in a MemoryEnclave: sealing it would buy
// nothing, because it would always be open. Material used INTERMITTENTLY — a
// credential opened once per request, a root key used a few times an hour, a
// share held across a ceremony that may never complete — belongs in a
// SealedEnclave, where the exposure window is the operation rather than the
// process lifetime. This is the classic secure-buffer versus secret split:
// the buffer shape converts to MemoryEnclave, the secret shape to
// SealedEnclave.
//
// The costs differ too, and they decide real choices:
//
//   - A MemoryEnclave charges at least one locked PAGE against
//     RLIMIT_MEMLOCK (and any Allocator budget) continuously, for its whole
//     life. A hundred long-lived 32-byte credentials cost a hundred pages.
//   - A SealedEnclave's envelope is ordinary heap ciphertext — near-free at
//     rest; the locked memory behind sealing is the Sealer's keys, shared by
//     every value. But every Open allocates a fresh locked page for the
//     plaintext (plus one, transiently, for the per-value key), and TODAY
//     that allocation is outside any Allocator budget — an admitted variant,
//     OpenWith, is tracked as issue #17. A service that opens a credential
//     per connection is allocating locked pages per connection and should
//     size RLIMIT_MEMLOCK accordingly.
//   - Sealing is not heap-free even though the MATERIAL is: the plaintext is
//     decrypted only into locked pages (verified by sweeping the process's
//     anonymous mappings), but the per-value KEY transits the Go heap on
//     every seal and open, because building the AEAD expands it into
//     aes.NewCipher's key schedule — a measured copy that persists past
//     collection until its span is reused. That is the accepted exposure at
//     the validated-primitive boundary, audited in full where it happens
//     (withAEAD); never read "encrypted at rest" as "no key bytes ever on
//     the heap".
//
// What a SealedEnclave does NOT give: protection against an attacker reading
// memory WHILE an Open is in flight, or against one who can drive Opens
// through the caller's own surface. It narrows the window to the operations;
// it does not close it. And how much the closed window is worth depends on
// the Sealer's mode — with the pure-software default or ModeRootKey, an
// adversary reading live process memory can recover the sealing keys and
// open everything anyway (see Mode for the honest comparison); per-operation
// hardware is what makes "sealed" mean "not recoverable from this process
// alone".
//
// One trap to know when holding both types: IsAlive is a DIFFERENT predicate
// on each. MemoryEnclave.IsAlive means "usable" — it reports false once the
// material is gone, however it went. SealedEnclave.IsAlive reports that the
// CIPHERTEXT is still held, and can be true for a value that can no longer
// be opened — after a shutdown sweep destroyed the sealing keys, the honest
// answer arrives as ErrSealerWiped from Open rather than as false from
// IsAlive. An explicit openability probe (Openable) is tracked as issue #33.
//
// Sealing is built on a hardware-rootable provider seam. go-enclave itself is
// PURE SOFTWARE — it defines the KeyProtector and RootUnsealer interfaces,
// ships the software default, and calls whatever a higher layer injects; TPM,
// HSM and cloud-KMS providers live above this package and are passed in
// through NewSealer or SetSealer. Providers must supply confidentiality AND
// authenticity — a sealed value is unforgeable as well as unreadable, and a
// confidentiality-only provider does not satisfy the seam (see KeyProtector;
// a bare decryption key qualifies only composed with a signing key, a
// composition tracked as issue #50).
// Two modes select how often the provider is invoked, trading device traffic
// against what a memory-reading adversary obtains; the honest comparison is
// on Mode. Out of the box — no provider, no configuration — NewSealed is
// plain software sealing.
//
// # FIPS
//
// A MemoryEnclave performs no cryptography: it maps, locks and wipes memory,
// and the only primitive near it is crypto/rand filling the canary. Sealing
// DOES perform cryptography — all of it AES-256-GCM via
// cipher.NewGCMWithRandomNonce, FIPS-approved through the standard
// library. The whole suite builds and passes under
// GODEBUG=fips140=only, which this repository's CI enforces. (memguard was
// removed in v0.3.0-alpha partly for this reason: its Enclave seals with NaCl
// secretbox, a non-approved algorithm, in every consumer's build graph.)
//
// # GOEXPERIMENT=boringcrypto builds cannot seal, deliberately
//
// On such a build every NewSealed fails with ErrSealFailed wrapping "cipher:
// NewGCMWithRandomNonce requires aes.Block": that constructor accepts only the
// standard library's own AES block type, and boringcrypto's aes.NewCipher
// returns BoringSSL's instead. MemoryEnclave, Allocator and WipeAll are
// unaffected — they perform no cryptography.
//
// This is a REFUSAL, not a gap, and it will not be "fixed" (#34). The only
// route to sealing under boringcrypto is cipher.NewGCM with a caller-supplied
// nonce — abandoning the construction that makes nonce misuse structurally
// impossible, on every build, to serve a mechanism superseded since Go 1.24 by
// the native FIPS 140-3 module this package targets. A consumer that needs
// certified crypto uses that module (GOFIPS140=latest), not boringcrypto.
package enclave
