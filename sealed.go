// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sync"
)

var (
	// ErrSealFailed reports that material could not be encrypted. It means the
	// AEAD, the CSPRNG or the provider failed, not that the caller did anything
	// wrong; the cause is joined and reachable with errors.Is and errors.As.
	ErrSealFailed = errors.New("enclave: could not seal material")

	// ErrSealedAuthentication reports that sealed material did not
	// authenticate: the ciphertext or the wrapped-key blob was altered,
	// truncated or forged, the two were re-paired across values, or the blob
	// was produced by a different provider. It is also the error the
	// [KeyProtector] contract requires of a provider refusing a blob its own
	// Protect did not produce.
	//
	// It is deliberately indistinguishable between those causes: an
	// authenticated construction that explains WHY authentication failed is an
	// oracle.
	ErrSealedAuthentication = errors.New("enclave: sealed material failed authentication")

	// ErrPlaintextEscaped reports that the AEAD wrote recovered plaintext
	// somewhere other than the locked destination prepared for it, which would
	// put it on the ordinary heap and void the property this type exists for.
	//
	// It cannot happen: every decryption in this package hands crypto/cipher a
	// destination whose capacity is exactly the plaintext length, so its
	// append cannot reallocate. It is checked anyway because the alternative
	// to checking is trusting an implementation detail of another package with
	// the one guarantee this type sells, and because a silent recovery —
	// copying the stray plaintext in and wiping it — would still have left it
	// on the heap for a window that no wipe can undo.
	ErrPlaintextEscaped = errors.New("enclave: recovered plaintext did not land in locked memory")

	// ErrMaterialTooLarge reports material longer than AES-GCM will seal in
	// one message: (2^32-2) blocks of 16 bytes, about 64 GiB.
	//
	// It exists so that bound arrives as an error rather than as a panic.
	// crypto/cipher enforces it by panicking — reasonable for a primitive
	// whose caller is expected to know the construction, and wrong for a
	// constructor that documents its failures as typed errors. A library that
	// takes a caller's slice and panics on a legal length has made an input
	// mistake into a process-level fault.
	//
	// It is close to unreachable in practice and deliberately checked anyway:
	// nothing on a 32-bit platform can hold a slice this long, and on 64-bit
	// it takes a deliberate 64 GiB allocation. Unreachable-in-practice is the
	// property that changes when someone streams a file into this constructor.
	ErrMaterialTooLarge = errors.New("enclave: material is too large to seal")
)

// dekBytes selects AES-256 for the per-value data key. Every DEK is generated
// directly into a [MemoryEnclave] and destroyed before the seal or open that
// used it returns.
const dekBytes = 32

// maxSealedPlaintext is the per-message plaintext ceiling AES-GCM imposes:
// (2^32-2) blocks of 16 bytes. crypto/internal/fips140/aes/gcm panics above it.
//
// Typed uint64 rather than untyped: the value does not fit in a 32-bit int,
// and an untyped constant would fail to compile the moment anything assigned
// it to one.
const maxSealedPlaintext uint64 = (1<<32 - 2) * 16

// sealableLength reports whether n bytes can be sealed in one message.
//
// It is a function taking a LENGTH rather than an inline check on a slice so
// that the bound is testable without allocating 64 GiB — the test passes the
// number. That keeps the guard covered without a fault-injection seam in
// production code, which is the trade the alternative would have demanded.
//
// It takes uint64 rather than int because the ceiling does not fit in a
// 32-bit int: converting the constant down would not compile there, and
// converting a signed length up is the kind of widening a security linter is
// right to question. Callers pass a len, which cannot be negative.
func sealableLength(n uint64) error {
	if n > maxSealedPlaintext {
		return ErrMaterialTooLarge
	}
	return nil
}

// sealedOverhead is what AES-GCM with a random nonce adds to every sealed
// message: a 12-byte nonce prepended at Seal, and a 16-byte authentication
// tag. A sealed message of this length or shorter carries no plaintext and
// cannot authenticate.
const sealedOverhead = 12 + 16

// withAEAD runs fn with an AES-GCM AEAD built from a key held in a
// [MemoryEnclave], holding the key inside a borrow for exactly the duration
// of the call. Every AES-GCM operation in this package — the value under its
// DEK, a DEK under a KEK, a KEK under the root, the software provider's
// wrapping — goes through here, so this is the one place the key leaves
// locked memory and the audit of that exposure lives at the call site rather
// than only in the type documentation:
//
// # WHAT IS EXPOSED
//
// aes.NewCipher returns a heap-allocated AES Block — 488 bytes on
// go1.27/linux-amd64. It cannot be stack-allocated: it is returned through
// the cipher.Block interface, so it escapes.
//
// AES-256 expands into fifteen round keys, and the FIRST ROUND KEY IS THE
// MASTER KEY — the expansion copies the caller's 32 bytes in before deriving
// anything. Measured, the key sits at offset 8 of that Block:
//
//   - BYTE-EXACT on the hardware-AES path (AES-NI, Armv8 crypto extensions),
//     which is also the path taken under GOFIPS140=latest GODEBUG=fips140=only;
//   - as eight BIG-ENDIAN uint32 words on the generic path (reachable with
//     GODEBUG=cpu.aes=off) — the same bytes swapped within each four-byte
//     group on a little-endian host.
//
// Both forms recover the key outright. Neither pure-Go path exposes only
// derived material. The size and the offset are this host's; they follow the
// Block layout and move with word size, and nothing here depends on them. The
// PRESENCE is what the threat model rests on, and it is what
// TestSealedEnclave_KeyScheduleReachesTheHeapAsDocumented pins: that test
// fails if the key stops appearing in the schedule in either form, or if
// NewCipher stops allocating. Either failure means this comment has gone
// stale and the exposure needs re-measuring — not that the package is broken.
//
// What this means per key CLASS, because they differ in what a recovered copy
// is worth: a DEK opens exactly one value and its Block becomes garbage
// within one call; a KEK opens every DEK of its generation; the ROOT opens
// everything, and in [ModeRootKey] its schedule transits the heap on every
// retired-generation unwrap. [ModePerOperation] exists precisely so the key
// that opens everything never enters the process and never reaches this
// function at all.
//
// # FOR HOW LONG
//
// One Block per call: 1000 seals allocate 1000 of them (measured, 512 KiB
// total — the 512-byte size class). Each becomes garbage the instant this
// function returns, because nothing else references it.
//
// Go does not zero or finalize it. The bytes therefore stay legible in the
// freed span until the allocator reuses that span for something that
// overwrites them. The window is NOT bounded by this function's runtime; it
// is bounded by heap reuse, which in a quiet process is unbounded in
// practice. Reason about it as "until the process exits".
//
// # WHAT AN ATTACKER WOULD NEED
//
// Read access to this process's ANONYMOUS memory — /proc/<pid>/mem or ptrace
// at the same uid (or CAP_SYS_PTRACE), a swap device the heap page was paged
// out to, or a cold-boot capture of RAM. Notably NOT any ability to read
// locked memory: mlock and MADV_DONTDUMP cover enclave pages and not the
// heap, so the protections this package applies to the key's home do not
// reach this copy. And core-dump suppression is best-effort: this package
// lowers RLIMIT_CORE to zero on import, but if that was denied, a dump
// carries the heap and therefore carries this copy.
//
// # WHY THIS IS DOCUMENTED RATHER THAN FIXED
//
// Two routes out exist and both are worse than the exposure:
//
//   - USE AN AEAD WITH NO KEY SCHEDULE. XSalsa20-Poly1305 and
//     ChaCha20-Poly1305 take the key by pointer and expand nothing, which is
//     the only reason a library built on them can hold a key in locked memory
//     end to end. That is a property of the cipher, not of careful coding.
//     Neither is FIPS-approved, so this route trades a bounded heap copy for
//     a primitive that cannot be deployed where this one has to be.
//   - REIMPLEMENT AES so the schedule lands in locked memory. That is
//     hand-rolled cryptography, and it stays hand-rolled however good the
//     sub-primitives underneath it are. A bespoke AES carries no validation,
//     no constant-time review and no third-party testing, and would trade a
//     heap-residency window for a class of defect that is strictly worse and
//     much harder to see.
//
// So the conflict is resolved the way this class of conflict is generally
// resolved: where a validated implementation's INTERNALS collide with a
// memory-hygiene rule, the validated implementation wins and the hygiene rule
// yields at that boundary — with the boundary written down, as above, rather
// than coded around. Closing it for real needs a key that never enters the
// process at all, which is exactly what a hardware [KeyProtector] in
// [ModePerOperation] provides.
func withAEAD(key *MemoryEnclave, fn func(cipher.AEAD) error) error {
	return key.WithBytes(func(k []byte) error {
		// The key leaves locked memory HERE, and only here. See this
		// function's documentation for the measured extent of it.
		block, err := aes.NewCipher(k)
		if err != nil {
			return errors.Join(ErrSealFailed, err)
		}
		// NewGCMWithRandomNonce, not NewGCM — and there is deliberately no
		// fallback to NewGCM anywhere in this package, however a build is
		// configured. Two reasons, either sufficient:
		//
		// FIPS 140-only mode REFUSES a GCM that accepts caller-supplied IVs
		// ("use of GCM with arbitrary IVs is not allowed in FIPS 140-only
		// mode"), and this primitive exists to be deployable there.
		//
		// And it removes the sharpest edge in using GCM at all — a repeated
		// nonce is not a weakness but a break — by taking nonce generation
		// away from the caller entirely. It draws a random nonce per Seal and
		// prepends it to the ciphertext, so NonceSize is 0 and the nonce
		// argument to Seal and Open must be nil.
		//
		// The consequence for GOEXPERIMENT=boringcrypto builds is a REFUSAL,
		// not a gap: NewGCMWithRandomNonce accepts only the standard
		// library's own AES block type, and boringcrypto's aes.NewCipher
		// returns BoringSSL's instead, so this call fails on every seal
		// (#34, closed). Restoring boringcrypto would require NewGCM with a
		// caller-supplied nonce — weakening every build to serve a mode this
		// portfolio does not use, superseded since Go 1.24 by the native
		// FIPS 140-3 module this package is built against. Do not "fix" that
		// error by reaching for NewGCM; see the package documentation.
		gcm, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return errors.Join(ErrSealFailed, err)
		}
		return fn(gcm)
	})
}

// sealWithKey encrypts plaintext under the key held in ke, binding aad, and
// returns nonce || ciphertext || tag as an ordinary heap slice — which is
// safe by construction, because everything this package stores on the heap is
// ciphertext.
func sealWithKey(ke *MemoryEnclave, plaintext, aad []byte) ([]byte, error) {
	if err := sealableLength(uint64(len(plaintext))); err != nil {
		return nil, err
	}

	var sealed []byte
	if err := withAEAD(ke, func(gcm cipher.AEAD) error {
		// nil nonce: the AEAD draws its own and prepends it, so the result is
		// nonce || ciphertext || tag and the nonce travels with what it seals.
		//
		// gosec reads the literal nil as a hardcoded nonce (G407). It is not,
		// and it CANNOT become one: a nil nonce is only legal for an AEAD
		// whose NonceSize is zero, which is NewGCMWithRandomNonce and nothing
		// else. Measured — cipher.NewGCM's Seal panics on a nil nonce with
		// "incorrect nonce length given to GCM" rather than accepting it as
		// twelve zero bytes. So a change of AEAD fails loudly at the first
		// Seal, and the one remaining way to reach a fixed nonce, passing an
		// explicit zeroed slice, is caught by
		// TestSealedEnclave_SealIsNonDeterministic. The suppression rests on
		// a fact the code enforces and a test that fails if it stops holding,
		// which is the only kind worth writing.
		/* #nosec G407 -- nil is required by NewGCMWithRandomNonce, which generates the nonce itself; see above */
		sealed = gcm.Seal(nil, nil, plaintext, aad)
		return nil
	}); err != nil {
		return nil, err
	}
	return sealed, nil
}

// openWithKeyInto decrypts sealed under the key held in ke, verifying aad,
// writing the plaintext into dst and nowhere else. dst is the caller's
// destination — locked pages, whenever what is being recovered is sensitive —
// and its LENGTH is a claim about the plaintext: a sealed message whose
// plaintext would not be exactly len(dst) bytes is refused as an
// authentication failure.
//
// The refusal happens BEFORE decrypting, and the order is the point. The
// destination handed to the AEAD has capacity exactly len(dst), so a longer
// plaintext would make crypto/cipher's append REALLOCATE — writing the
// recovered material into an ordinary heap buffer, in memory this package
// neither locked nor marked MADV_DONTDUMP. Catching that afterwards is not
// equivalent: the copy would already exist, and no wipe undoes a window. So
// the mismatch is a refusal here rather than a diagnosis below, and the
// checks below stay as the guard against being wrong about that.
func openWithKeyInto(ke *MemoryEnclave, sealed, aad, dst []byte) error {
	return withAEAD(ke, func(gcm cipher.AEAD) error {
		if len(sealed) <= sealedOverhead || len(sealed)-sealedOverhead != len(dst) {
			return ErrSealedAuthentication
		}

		// dst[:0:len(dst)] pins the capacity even if the caller's slice has
		// slack, so the AEAD's append writes in place and cannot reallocate.
		// nil nonce: the AEAD reads the one it prepended at seal time.
		got, oerr := gcm.Open(dst[:0:len(dst)], nil, sealed, aad)
		if oerr != nil {
			// crypto/cipher zeroes its output before reporting a failed tag,
			// so nothing partial is left in the destination.
			//
			// Deleting this branch changes no behavior — a failed Open
			// returns a nil slice, so the length check below refuses the same
			// values with the same error, and the mutation is invisible. It
			// stays because that is an implementation detail of another
			// package and this is the contract: an AEAD that reported failure
			// is not to be trusted for anything, whatever shape its output
			// happens to take.
			return ErrSealedAuthentication
		}
		// ESCAPE FIRST, LENGTH SECOND. The other order has a hole: a result
		// that both escaped and came back the wrong length would return on
		// the length check and leave the heap copy unwiped, which is the
		// failure this whole ordering exists to avoid. Checking residency
		// first means every path that can see heap plaintext wipes it.
		if len(got) > 0 && &got[0] != &dst[0] {
			// Unreachable while the capacity is exact and the length check
			// above holds; see [ErrPlaintextEscaped] for why it is checked
			// rather than assumed, and why this fails instead of copying.
			wipe(got)
			return ErrPlaintextEscaped
		}
		if len(got) != len(dst) {
			return ErrSealedAuthentication
		}
		return nil
	})
}

// newKeyEnclave returns a [MemoryEnclave] holding n bytes drawn from the
// CSPRNG — generated straight into locked memory, never through a heap
// buffer, which is the whole reason [NewMemoryEnclaveSized] exists.
//
//nolint:unparam // n is always 32 today because dekBytes, kekBytes and RootKeyBytes are three independent decisions that happen to agree; folding them into one constant here would couple them.
func newKeyEnclave(n int) (*MemoryEnclave, error) {
	e, err := NewMemoryEnclaveSized(n)
	if err != nil {
		return nil, err
	}
	if err := e.WithBytes(fillRandom); err != nil {
		e.Destroy()
		return nil, errors.Join(ErrSealFailed, err)
	}
	return e, nil
}

// SealedEnclave holds material ENCRYPTED AT REST, decrypting it only for as
// long as a caller holds it open.
//
// It is the counterpart to [MemoryEnclave], not a replacement for it. A
// MemoryEnclave holds plaintext in locked memory for its entire lifetime; a
// SealedEnclave holds ciphertext and produces plaintext only inside a
// [SealedEnclave.Open]. Use a SealedEnclave for material that is needed
// occasionally and held for a long time — a credential used once per
// connection, a key wrapped for storage. Use a MemoryEnclave for material in
// continuous use, where the decryption would be perpetual and the sealing
// would buy nothing.
//
// # The envelope
//
// Every sealed value is an envelope with two halves, and both live on the
// ordinary heap ON PURPOSE — they are ciphertext, and locking ciphertext
// would consume the resource this type exists to conserve:
//
//   - a fresh 32-byte data key (DEK), generated into locked memory, seals the
//     material with AES-256-GCM and is destroyed before the constructor
//     returns;
//   - a wrapped-DEK BLOB — the DEK protected by the [Sealer]'s provider
//     ([ModePerOperation]) or wrapped under its in-memory key hierarchy
//     ([ModeRootKey]).
//
// The blob is fed to the AEAD as ADDITIONAL AUTHENTICATED DATA when the
// material is sealed, and that binding is load-bearing rather than
// decorative: without it, an attacker who can forge nothing can still
// SUBSTITUTE — pair one value's blob with another value's ciphertext, both
// halves individually authentic, and nothing would notice. Bound, a re-paired
// envelope fails the GCM tag.
//
// # What this protects against — decided by the Sealer's mode, not this type
//
// The plaintext never reaches the ordinary heap: [NewSealed] wipes the
// caller's slice, and [SealedEnclave.Open] decrypts directly into locked
// pages whose capacity is exactly the plaintext length, so the AEAD cannot
// allocate. That is verified by a sweep of every anonymous mapping in the
// process. What an adversary who can read this process's LIVE memory obtains
// is a different question, and it is answered by the [Mode] the value was
// sealed under — per-operation hardware bounds the compromise to values
// actually open during the adversary's window; a root-key hierarchy, and the
// pure-software default, do not. Read [Mode] before choosing; the honest
// statement of what each buys lives there.
//
// One caveat belongs in the same breath as "the plaintext never reaches the
// heap": the per-value DEK transits it, transiently, on every operation —
// building the AEAD expands the key into a heap allocation (the full audit is
// on [withAEAD]). The correct claim is narrower and still worth having: the
// long-lived key that opens every value never enters the process in
// [ModePerOperation]; only per-value keys do, and only for the duration of
// one operation.
//
// # Foreign sealed bytes are out of contract
//
// There is NO constructor that accepts sealed bytes — no unmarshaller, no
// encoding.BinaryUnmarshaler, nothing that turns foreign bytes into an
// openable value — and that absence is deliberate and load-bearing, pinned by
// an AST guard test. Not because a forged envelope would open (the provider
// authenticates; it would not): because this package makes NO persistence
// contract. The envelope layout is internal, unversioned across releases,
// and keyed to a Sealer whose hierarchy lives and dies with the process.
// Accepting foreign bytes would make that format accidentally permanent. If
// persistence or transport is ever wanted, it is a new requirement designed
// then — versioning, format stability and a migration story are the work, not
// an UnmarshalBinary.
//
// # What a shutdown sweep does to sealed values
//
// [WipeAll] destroys every registered [MemoryEnclave], and a Sealer's root
// and KEK hierarchy are registered enclaves — swept like any other, which is
// correct: leaving the key that opens everything mapped at exit is precisely
// what the sweep exists to prevent. A SealedEnclave itself owns no locked
// pages and is NOT swept; after a sweep it still reports
// [SealedEnclave.IsAlive] while [SealedEnclave.Open] fails. The sealer FAILS
// CLOSED from that point — [ErrSealerWiped], never silent re-keying — and the
// two modes differ in whether sealed values survive; see [ErrSealerWiped] and
// [WipeAll].
//
// The sweep does not and will not cover this type (#33, decided): its count
// means "still holding locked memory", and a sealed value holds none, so
// covering it would either corrupt that number or need a second one. More
// than costly, it would be WRONG — a per-operation hardware value stays
// legitimately openable after a sweep, and destroying it would destroy
// recoverable application data that this process's memory never protected,
// under a call documented for sweep-and-keep-running callers. What the sweep
// leaves behind is answered instead by [SealedEnclave.Openable], which
// reports [ErrSealerWiped] where a destroyed handle reports
// [ErrEnclaveDestroyed]; a swept-then-destroyed value would have reported the
// wrong one of those.
//
// The zero value is not usable; construct one with [NewSealed] or
// [Sealer.Seal]. A nil *SealedEnclave is a valid receiver for every method.
// A SealedEnclave is safe for concurrent use.
type SealedEnclave struct {
	mu sync.RWMutex

	// sealer produced this value and is the only thing that can open it: the
	// blob below is meaningful only to its provider or key hierarchy. Held so
	// Open needs no process-global lookup, and nil'd on Destroy so a
	// destroyed value does not pin a Sealer.
	sealer *Sealer

	// sealed is nonce || ciphertext || tag for the material, under the DEK.
	// nil once destroyed, which is what every method tests for.
	sealed []byte

	// blob is the wrapped DEK — produced by the provider in ModePerOperation,
	// or by the KEK hierarchy in ModeRootKey — and is also the AAD the sealed
	// bytes were bound to.
	blob []byte

	// size is the plaintext length, kept so Open can size its destination
	// exactly — an exact capacity is what keeps the AEAD from allocating and
	// putting the plaintext on the heap.
	size int

	// sealedAtGen is the sweep generation current when this value was sealed.
	// WRITTEN ONCE, at construction, and never again — which is what lets
	// Openable compare it with a single atomic load and no lock. If a later
	// change ever makes it mutable, that comparison needs revisiting.
	//
	// It exists so a value can tell whether a [WipeAll] has run during its
	// lifetime, which is the only thing this package can honestly say about a
	// provider that reports nothing; see [ErrOpenabilityUnknown].
	sealedAtGen uint64
}

// NewSealed encrypts data under the PROCESS Sealer and returns the sealed
// enclave holding it.
//
// The process Sealer is whatever [SetSealer] installed, or — if nothing did
// before the first seal — the pure-software default: a [SoftwareProvider] in
// [ModeRootKey], which needs no hardware and no configuration. Callers that
// want an explicitly configured or additional sealer construct one with
// [NewSealer] and use [Sealer.Seal]; the semantics are identical.
//
// It TAKES OWNERSHIP of data exactly as [NewMemoryEnclave] does: the caller's
// slice is wiped before this returns, on every path including failure, so
// there is no unprotected copy left behind. Callers that need to keep the
// original bytes must copy them first — and by doing so accept an unprotected
// copy, which is what this type exists to avoid.
//
// It returns ErrEmptyEnclave when data is empty, ErrMaterialTooLarge above
// AES-GCM's per-message ceiling, ErrSealFailed when the AEAD, the CSPRNG or
// the provider fails, ErrLockedMemoryUnavailable when the kernel refuses to
// lock the pages the seal transiently needs, and ErrSealerWiped after a
// shutdown sweep has destroyed the process Sealer's keys.
//
// ON A GOEXPERIMENT=boringcrypto BUILD IT ALWAYS RETURNS ErrSealFailed
// (wrapping "cipher: NewGCMWithRandomNonce requires aes.Block"). That is a
// refusal, not a defect, and there is deliberately no fallback — see the
// package documentation.
func NewSealed(data []byte) (*SealedEnclave, error) {
	s, err := processSealer()
	if err != nil {
		Wipe(data)
		return nil, err
	}
	return s.Seal(data)
}

// Open decrypts the material into a NEW [MemoryEnclave] and returns it.
//
// The plaintext is written directly into locked pages and exists nowhere
// else: the destination is allocated first and the AEAD decrypts into it in
// place. It never passes through an ordinary heap buffer, not even
// transiently. (The DEK's key schedule does transit the heap; see
// [SealedEnclave] and [withAEAD].)
//
// The CALLER OWNS the returned enclave and must Destroy it. Open is what
// makes the material readable, so holding the result defeats the sealing
// exactly as surely as never sealing at all — open late, destroy early, and
// let the SealedEnclave be what survives in between.
//
// Each call returns an independent enclave; opening twice yields two, and
// destroying one does not affect the other or the SealedEnclave.
//
// It allocates OUTSIDE any [Allocator] budget: the destination, and the key
// pages the recovery needs on the way, come from the unadmitted constructors.
// That is the right default for the caller who has no budget, and the wrong
// one for the caller who does — an Open per connection is a locked page per
// connection, and none of them are visible to the Allocator that path thought
// it was bounded by. Callers holding a budget use [SealedEnclave.OpenWith].
//
// It returns ErrEnclaveDestroyed once Destroy has run, ErrSealedAuthentication
// if the envelope does not authenticate, ErrLockedMemoryUnavailable when the
// kernel refuses to lock the destination — the sealed value SURVIVES that
// intact, so a transient ceiling is retryable rather than a lost credential —
// and ErrSealerWiped when a shutdown sweep has destroyed the sealing Sealer's
// keys. In [ModePerOperation] a provider's own infrastructure failures (a
// device unreachable, say) surface unchanged, per the [KeyProtector]
// contract.
func (s *SealedEnclave) Open() (*MemoryEnclave, error) {
	// nil is how the open path spells "unadmitted"; see allocSized.
	return s.openWith(nil)
}

// OpenWith is [SealedEnclave.Open] with the recovered material ADMITTED
// AGAINST a — the destination is reserved from a's budget before any locked
// memory is requested, and the reservation is returned to a when the caller
// Destroys the returned enclave.
//
// It exists because of WHEN this type allocates. [NewSealed] takes locked
// memory once, for keys; Open takes a fresh locked page on EVERY call, and
// Open is the hot path — once per use of the credential. A service that opens
// a Secret per connection allocates a locked page per connection, and through
// Open every one of them is outside whatever budget that service configured.
// Locked memory is a process-wide ceiling, so that is not merely unaccounted:
// it is the unbounded, request-rate-driven consumption an [Allocator] exists
// to convert into a typed refusal on the abusive path.
//
// # A nil Allocator is refused
//
// OpenWith(nil) returns [ErrNilAllocator] and allocates nothing. It does NOT
// fall back to an unbudgeted open: a caller reached for this method to bound
// something, and quietly allocating outside the budget would deliver exactly
// the outcome the call was written to prevent, while continuing to look
// bounded. The unbudgeted open is still available and spelled differently —
// call Open. The refusal precedes the destroyed check, so a lost allocator is
// reported as a lost allocator whatever the value's lifecycle happens to be.
//
// # What is admitted: the destination, in ONE reservation, taken FIRST
//
// The destination is the only admitted allocation, and it is taken before any
// other work. An open the budget refuses therefore costs nothing at all — no
// locked page, no key touched — and the budget is a bound on the material a
// caller HOLDS, which is the quantity that accumulates.
//
// The transient key pages an open needs on the way are NOT charged: the
// per-value DEK, and — only for a value sealed under a retired KEK generation
// in [ModeRootKey] — that generation's key. So the process's actual peak can
// exceed the budget, by at most one page (two across a retired unwrap) per
// open IN FLIGHT. That excess is bounded rather than open-ended, precisely
// because the destination reservation gates it: nothing transient is
// allocated until a reservation has been granted, so an open the budget
// refuses adds nothing to the peak. Size a budget with headroom of a page per
// concurrent open if the comparison against RLIMIT_MEMLOCK has to be tight.
//
// # Why the transients are not admitted, which was tried first
//
// Charging them is more accurate and it BREAKS UNDER LOAD, which is the
// condition an Allocator exists for. Two reservations per open let concurrent
// callers fragment the budget against themselves: under a budget sized for
// one open, two callers can each take a key page, and then BOTH be refused
// for a destination the budget could have covered for one of them. A flood
// then makes every open fail — including the legitimate ones — which is the
// outcome an Allocator is supposed to prevent, arriving by a new road.
//
// One reservation per open cannot do that. Admission for a whole open is a
// single atomic decision, so contention refuses only the excess and the
// callers that were admitted make progress.
//
// It returns everything Open returns, plus ErrNilAllocator for a nil
// Allocator and ErrBudgetExhausted (as a [BudgetError]) when the open would
// exceed a's budget. A budget refusal leaves the sealed value untouched and
// is retryable, exactly as ErrLockedMemoryUnavailable is.
//
// The SEAL path is not budgeted at all: there is no SealWith, so [NewSealed],
// [Sealer.Seal] and the one-time hierarchy setup take their locked pages
// unadmitted. That is a real gap and a deliberate boundary for this change —
// sealing allocates once per value rather than once per use, so it does not
// scale with request rate the way opening does.
func (s *SealedEnclave) OpenWith(a *Allocator) (*MemoryEnclave, error) {
	if s == nil {
		return nil, ErrEnclaveDestroyed
	}
	if a == nil {
		return nil, ErrNilAllocator
	}
	return s.openWith(a)
}

// openWith is the shared body of Open and OpenWith. a is nil for an
// unadmitted open and non-nil for a budgeted one; nothing below branches on
// it, which is what keeps the two entry points from drifting apart.
func (s *SealedEnclave) openWith(a *Allocator) (*MemoryEnclave, error) {
	if s == nil {
		return nil, ErrEnclaveDestroyed
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed == nil {
		return nil, ErrEnclaveDestroyed
	}

	return s.sealer.open(a, s.blob, s.sealed, s.size)
}

// IsAlive reports whether this value still HOLDS ITS CIPHERTEXT — that
// [SealedEnclave.Destroy] has not run. It is a local, lock-cheap fact about
// this handle and nothing else.
//
// It is NOT the question "can this be opened", and the two genuinely differ:
// a shutdown [WipeAll] destroys the sealing keys without touching this value,
// so a swept sealer leaves every value it sealed reporting IsAlive while
// [SealedEnclave.Open] fails with [ErrSealerWiped]. Ask
// [SealedEnclave.Openable] for openability; it consults the sealer, which
// IsAlive deliberately does not.
//
// The distinction is worth stating because the name reads the other way
// elsewhere in this package: [MemoryEnclave.IsAlive] reports false once its
// material is wiped, so there it does answer "usable". A SealedEnclave's
// usability lives in a sealer this value does not own and cannot cheaply
// speak for, so the two methods split rather than one of them lying.
func (s *SealedEnclave) IsAlive() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed != nil
}

// Openable reports whether an [SealedEnclave.Open] could still recover this
// material, without recovering it: nil if nothing known prevents it,
// [ErrEnclaveDestroyed] if this value was destroyed (or is nil),
// [ErrSealerWiped] if a shutdown [WipeAll] destroyed the in-process keys the
// sealer needs, and [ErrOpenabilityUnknown] if a sweep has run since this
// value was sealed and the provider can report nothing about its own sealing
// state.
//
// # The four answers are four different facts
//
// nil and ErrOpenabilityUnknown are NOT variations of each other. nil is a
// positive claim that nothing known prevents an open; the sentinel says this
// package cannot see far enough to make that claim. Collapsing the second
// into the first is a fail-open, and it is what this method did before
// providers could report their own health: an out-of-package [KeyProtector]
// cannot implement an unexported interface, so one keeping its key in this
// process's locked memory was silently assumed healthy, reported nil, and
// then failed to Open. Supply [WithProviderHealth] and the answer becomes
// precise again.
//
// It exists because [SealedEnclave.IsAlive] cannot answer this and must not
// try. IsAlive reports on the ciphertext, which survives a sweep; the keys do
// not. Without Openable, code holding a swept value sees a live-looking
// handle and learns otherwise only by opening it — a live-looking handle to
// material that yields nothing.
//
// # It is a snapshot, not a promise
//
// A nil return does not reserve anything: a sweep between this call and the
// Open makes the answer stale, and Open is the operation that decides. Use it
// for diagnostics — a health endpoint, a shutdown-ordering assertion, a log
// line that says WHICH failure a caller is about to hit — not as a gate in
// front of every Open, which would double the sealer lock traffic to
// re-answer a question Open answers anyway.
//
// # nil is narrower than "will succeed"
//
// It reports the states that are knowable cheaply and locally. It does
// NOT predict [ErrSealedAuthentication] (which needs the crypto),
// ErrLockedMemoryUnavailable (a kernel condition at the moment of the call),
// or a hardware provider's own failures (a device unreachable — which is a
// device liveness question, not a question about this process's memory, and
// deliberately not answered here). In [ModePerOperation] with a real
// hardware provider, nil is the correct answer: the device holds the key, a
// sweep of this process's memory does not invalidate it, and values stay
// openable. Say so with [WithProviderHealth] — a provider that reports its
// health is BELIEVED, and its answer is terminal. Without it, this package
// falls back to whether a sweep has happened at all and returns
// ErrOpenabilityUnknown, because it has no way to tell that provider apart
// from one keeping its key in memory the sweep just destroyed.
//
// The pure-software provider is the exception in that mode, since its root IS
// an in-process enclave, and it reports the sweep directly.
//
// A sweep is deliberately NOT reported as ErrEnclaveDestroyed. The two say
// different things to whoever reads the log — "you destroyed this" against "a
// sweep did" — and conflating them sends an operator to the wrong code.
func (s *SealedEnclave) Openable() error {
	if s == nil {
		return ErrEnclaveDestroyed
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Both conditions are the destroyed state: Destroy clears them together
	// under this same lock. Testing the sealer too is what keeps the
	// documented return set exact — a nil sealer can never reach openable
	// below, so ErrNilSealer is not among the errors this can return.
	if s.sealed == nil || s.sealer == nil {
		return ErrEnclaveDestroyed
	}

	return s.sealer.openable(s.sealedAtGen)
}

// Destroy wipes the sealed material and releases it. It is idempotent and
// safe on a nil enclave, so it can always be deferred.
//
// It does NOT affect enclaves already handed out by [SealedEnclave.Open];
// those are the caller's and outlive this. It takes the write lock, so it
// waits out any Open in flight rather than clearing the envelope underneath
// one.
//
// Wiping ciphertext is belt and braces — without its keys it reveals nothing
// — but it costs one pass over two heap slices and removes the question.
func (s *SealedEnclave) Destroy() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return
	}

	wipe(s.sealed)
	wipe(s.blob)
	s.sealed = nil
	s.blob = nil
	s.size = 0
	// Drop the Sealer reference so a destroyed value does not pin a sealer —
	// and, in ModeRootKey, the retired-generation blobs it retains — for as
	// long as the handle happens to live.
	s.sealer = nil
}

// String masks the contents. It exists so that a sealed enclave reached by an
// accidental %v or %s — a log line, a struct dump — cannot spill even its
// ciphertext, which would otherwise print as a wall of bytes that looks like
// nothing and is in fact the protected material.
func (s *SealedEnclave) String() string {
	if !s.IsAlive() {
		return "SealedEnclave(destroyed)"
	}
	return "SealedEnclave(sealed)"
}
