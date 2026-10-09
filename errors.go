// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"errors"
	"strconv"
)

// Every sentinel and error type of this package is declared here. Callers
// match a sentinel with errors.Is and read a type's fields with errors.As; a
// type is never the contract its sentinel is.

// Locked memory.
var (
	// ErrEmptyEnclave is returned when an enclave is requested for zero bytes
	// of material.
	ErrEmptyEnclave = errors.New("enclave: refusing to create an enclave over empty material")

	// ErrEnclaveDestroyed is returned when a destroyed enclave is opened or
	// read. The locked pages have already been wiped and released.
	ErrEnclaveDestroyed = errors.New("enclave: enclave has been destroyed")

	// ErrInvalidSize is returned by [NewMemoryEnclaveSized] and
	// [Allocator.NewSized], before anything is mapped, for a size that is
	// non-positive or too large to map (the sizes [LockedSize] reports as 0).
	ErrInvalidSize = errors.New("enclave: enclave size must be positive and small enough to map")

	// ErrLockedMemoryUnavailable reports that the kernel refused to map, lock,
	// protect or release an enclave's pages (often the RLIMIT_MEMLOCK ceiling).
	// Every [LockedMemoryError] matches it.
	ErrLockedMemoryUnavailable = errors.New("enclave: could not allocate locked memory")

	// ErrReleasedWithoutWipe reports that an enclave's pages were unmapped
	// without the in-process wipe because mprotect was denied (a seccomp
	// filter, a sandbox). Nothing leaked: the pages were mlock'd throughout and
	// the kernel zeroes them before reuse. Every [UnwipedReleaseError] matches
	// it, and never also matches [ErrLockedMemoryUnavailable].
	ErrReleasedWithoutWipe = errors.New("enclave: pages unmapped without an in-process wipe; mprotect was denied")

	// ErrEnclaveCorrupted reports that an enclave's canary or guard pages were
	// overwritten, detected at release. See [MemoryEnclave.Destroy].
	ErrEnclaveCorrupted = errors.New("enclave: canary verification failed; memory ahead of the enclave was overwritten")

	// ErrCoreDumpLimitUnsupported is what [CoreDumpsDisabled] reports on
	// Windows, which has no process-wide core-dump limit; dump exposure there
	// must be governed by host policy.
	ErrCoreDumpLimitUnsupported = errors.New("enclave: this platform has no process-wide core-dump limit to lower")

	// errInvalidProtection reports a protection outside the defined values, so
	// the zero value is refused rather than guessed.
	errInvalidProtection = errors.New("enclave: invalid page protection")
)

// LockedMemoryError is the error behind [ErrLockedMemoryUnavailable], which
// errors.Is reports for every LockedMemoryError. Its Cause, the failing system
// call's error or nil, is diagnostic; Unwrap returns it.
type LockedMemoryError = causeError[lockedMemoryUnavailable]

// UnwipedReleaseError is the error behind [ErrReleasedWithoutWipe], which
// errors.Is reports for every UnwipedReleaseError. Its Cause is the refused
// mprotect's *os.SyscallError, deliberately not a [LockedMemoryError]; Unwrap
// returns it.
type UnwipedReleaseError = causeError[releasedWithoutWipe]

// pagesHeldError marks, transparently, a failure that left the pages mapped.
// locked says they are still mlock'd, so a failed constructor keeps its
// Allocator charge; orphan is the mapping a failed construction gives up.
type pagesHeldError struct {
	err    error
	locked bool
	orphan *mapping
}

// Error implements error, unchanged from the wrapped failure.
func (e *pagesHeldError) Error() string { return e.err.Error() }

// Unwrap returns the wrapped failure, so the sentinels it matches still match.
func (e *pagesHeldError) Unwrap() error { return e.err }

// Locked-memory budget.
var (
	// ErrBudgetExhausted is returned by [Allocator.New] and
	// [Allocator.NewSized] when an allocation would exceed the budget. Every
	// [BudgetError] matches it. It is returned before any locked memory is
	// requested.
	ErrBudgetExhausted = errors.New("enclave: locked-memory budget exhausted")

	// ErrInvalidBudget is returned by [NewAllocator] for a non-positive budget,
	// by [Allocator.SetLimit] and [Allocator.ForceLimit] for a negative one
	// (zero is legal there), and by [Allocator.TransferTo] when the
	// destination's budget would overflow int64.
	ErrInvalidBudget = errors.New("enclave: allocator budget must be positive")

	// ErrBudgetInUse is returned when lowering a budget would put it below the
	// locked bytes already reserved; nothing is changed. Every
	// [BudgetInUseError] matches it. [Allocator.ForceLimit] lowers regardless.
	ErrBudgetInUse = errors.New("enclave: budget would fall below the locked memory already reserved")

	// ErrInvalidTransfer is returned by [Allocator.TransferTo] for a malformed
	// transfer: a non-positive amount, a nil destination, or a destination
	// that is the source.
	ErrInvalidTransfer = errors.New("enclave: invalid headroom transfer")

	// ErrNilAllocator is returned for a nil *Allocator by [SetAllocator],
	// [SealedEnclave.OpenWith] (which never falls back to the unbudgeted
	// [SealedEnclave.Open]), and the Allocator methods that can fail. New
	// still wipes the data it was handed.
	ErrNilAllocator = errors.New("enclave: allocator is nil")

	// ErrAllocatorInstalled is returned by [SetAllocator] when the process
	// allocator is already set, by an earlier SetAllocator or by the first
	// [ProcessAllocator] call installing the default.
	ErrAllocatorInstalled = errors.New("enclave: a process allocator is already installed")

	// ErrBudgetExceedsRLimit is returned by [NewAllocatorWithinRLimit],
	// [Allocator.SetLimit] and [Allocator.TransferTo] when a budget is larger
	// than the locked memory this process may hold. Every [RLimitError]
	// matches it.
	//
	// It differs from [ErrInvalidBudget] (a non-positive budget, checked
	// before the ceiling is read), [ErrBudgetExhausted] (a live allocator's
	// own budget is full) and [ErrLockedMemoryUnavailable] (the kernel refused
	// to lock pages; the authority on what may be locked, where this reports
	// only what the ceiling said when read).
	ErrBudgetExceedsRLimit = errors.New("enclave: allocator budget exceeds the process's locked-memory limit")

	// ErrLimitDiscoveryFailed reports that the ceiling could not be read (a
	// getrlimit that did not answer). Every [LimitDiscoveryError] matches it.
	// Nothing was compared, so it is neither a budget problem nor a shortage;
	// a caller that can proceed may fall back to [NewAllocator] with a
	// configured budget and log that the budget went unchecked.
	ErrLimitDiscoveryFailed = errors.New("enclave: could not read the process's locked-memory limit")
)

// BudgetError reports that an allocation was refused because it would exceed
// an [Allocator]'s budget. Its fields are diagnostic; match on
// [ErrBudgetExhausted].
type BudgetError struct {
	// Requested is the page-rounded charge of the refused allocation
	// ([LockedSize]).
	Requested int64
	// InUse is a snapshot of the bytes reserved. It is never negative, and
	// exceeds Limit only after [Allocator.ForceLimit].
	InUse int64
	// Limit is the allocator's total budget in locked bytes.
	Limit int64
}

// Error implements error.
func (e *BudgetError) Error() string {
	return budgetText(ErrBudgetExhausted, e.Requested, inUseOf(e.InUse, e.Limit))
}

// Is reports every BudgetError as ErrBudgetExhausted.
func (e *BudgetError) Is(target error) bool { return target == ErrBudgetExhausted }

// BudgetInUseError reports that a budget change was refused because the
// requested budget is below the locked memory already reserved; the allocator
// is unchanged. Match on [ErrBudgetInUse].
type BudgetInUseError struct {
	// Requested is the budget asked for; for [Allocator.TransferTo], what the
	// source would have been left with.
	Requested int64
	InUse     int64 // snapshot of the bytes reserved
	Limit     int64 // the unchanged budget
}

// newBudgetInUseError refuses a budget of requested against an allocator whose
// unchanged limit has free bytes unreserved.
func newBudgetInUseError(requested, limit, free int64) *BudgetInUseError {
	return &BudgetInUseError{Requested: requested, InUse: limit - free, Limit: limit}
}

// Error implements error.
func (e *BudgetInUseError) Error() string {
	return budgetText(ErrBudgetInUse, e.Requested, inUseOf(e.InUse, e.Limit))
}

// Is reports every BudgetInUseError as ErrBudgetInUse.
func (e *BudgetInUseError) Is(target error) bool { return target == ErrBudgetInUse }

// RLimitError reports that an [Allocator] budget was refused because it
// exceeds the locked memory the process may hold, carrying both figures.
// Match on [ErrBudgetExceedsRLimit].
type RLimitError struct {
	// Requested is the budget the caller asked for, in locked bytes.
	Requested int64
	// Limit is the ceiling as discovered; Limit.Bounded is always true.
	Limit LockedMemoryLimit
}

// Error implements error.
func (e *RLimitError) Error() string {
	return budgetText(ErrBudgetExceedsRLimit, e.Requested,
		e.Limit.Source.String()+" is "+strconv.FormatInt(e.Limit.Bytes, 10)+" bytes")
}

// Is reports every RLimitError as [ErrBudgetExceedsRLimit].
func (e *RLimitError) Is(target error) bool { return target == ErrBudgetExceedsRLimit }

// LimitDiscoveryError reports that the process's locked-memory ceiling could
// not be read. Match on [ErrLimitDiscoveryFailed]. Its Cause, the getrlimit
// failure, is never nil in an error this package constructs; Unwrap returns
// it, as diagnostic rather than contract.
type LimitDiscoveryError = causeError[limitDiscoveryFailed]

// budgetText renders a refused budget figure: the sentinel's text, the bytes
// requested, and what they were refused against.
func budgetText(sentinel error, requested int64, against string) string {
	return sentinel.Error() + ": " + strconv.FormatInt(requested, 10) + " bytes requested, " + against
}

// inUseOf is what an allocator refuses against: its reservations and limit.
func inUseOf(inUse, limit int64) string {
	return strconv.FormatInt(inUse, 10) + " of " + strconv.FormatInt(limit, 10) + " bytes in use"
}

// Process hardening.
var (
	// ErrProcessHardeningUnsupported is what [HardenProcess] reports on a
	// platform where this package has no process-wide hardening to apply.
	ErrProcessHardeningUnsupported = errors.New("enclave: this platform has no process hardening this package can apply")

	// ErrProcessHardeningFailed reports a hardening step the kernel refused or
	// that did not take effect. Every [ProcessHardeningError] matches it.
	ErrProcessHardeningFailed = errors.New("enclave: process hardening failed")

	// errDumpableNotCleared reports a PR_SET_DUMPABLE that succeeded but did
	// not read back as cleared.
	errDumpableNotCleared = errors.New("enclave: the process is still dumpable after PR_SET_DUMPABLE 0")
)

// ProcessHardeningError is the error behind [ErrProcessHardeningFailed]. Its
// Cause is the refused system call, or the read-back that disagreed; Unwrap
// returns it.
type ProcessHardeningError = causeError[processHardeningFailed]

// Sealing.
var (
	// ErrSealFailed reports that material could not be encrypted because the
	// AEAD, the CSPRNG or the provider failed, or because the caller's context
	// ended. Every [SealError] matches it, and its cause is reachable with
	// errors.Is and errors.As.
	ErrSealFailed = errors.New("enclave: could not seal material")

	// ErrOpenFailed reports that sealed material could not be recovered for a
	// reason that says nothing about the material: the caller's context ended
	// before or during the open, or a [ModePerOperation] provider failed with
	// its own infrastructure error. Every [OpenError] matches it, and its
	// cause is reachable with errors.Is and errors.As, so a canceled open
	// also matches context.Canceled or context.DeadlineExceeded. The value is
	// intact.
	//
	// [ErrSealedAuthentication], [ErrSealerWiped], [ErrLockedMemoryUnavailable]
	// and the budget refusals are not wrapped in an OpenError, except that
	// when a provider returns one of the first three after the caller's
	// context has ended, the OpenError carries ctx.Err() and the provider's
	// error, and matches all of them.
	ErrOpenFailed = errors.New("enclave: could not open sealed material")

	// ErrSealedAuthentication reports that sealed material did not
	// authenticate: the ciphertext or the wrapped-key blob was altered,
	// truncated or forged, the two were re-paired across values, or the blob
	// was produced by a different provider. A [KeyProtector] returns it for a
	// blob its own Protect did not produce. The causes are deliberately
	// indistinguishable.
	ErrSealedAuthentication = errors.New("enclave: sealed material failed authentication")

	// ErrPlaintextEscaped reports that the AEAD wrote recovered plaintext
	// somewhere other than the locked destination. It is unreachable while
	// every decryption hands crypto/cipher a destination of exact capacity,
	// and is checked rather than assumed; the stray copy is wiped, not used.
	ErrPlaintextEscaped = errors.New("enclave: recovered plaintext did not land in locked memory")

	// ErrMaterialTooLarge reports material longer than AES-GCM will seal in
	// one message, (2^32-2) blocks of 16 bytes (about 64 GiB), or whose
	// sealed form (plaintext plus 28 bytes of nonce and tag) would not fit in
	// an int, about 2 GiB on 32-bit platforms. crypto/cipher would panic on
	// either.
	ErrMaterialTooLarge = errors.New("enclave: material is too large to seal")

	// ErrSealerWiped reports that a shutdown sweep ([WipeAll]) destroyed this
	// sealer's keys. Everything sealed through it is permanently unopenable,
	// and the sealer fails closed: it never generates fresh keys. Recovery is
	// constructing a new [Sealer]. Every [SealerWipedError] matches it.
	//
	// It is distinct from [ErrSealedAuthentication] so that a lifecycle event
	// is never reported as tampering.
	//
	// In [ModeRootKey] the sweep destroys the root and KEK hierarchy and this
	// error follows. In [ModePerOperation] the device still holds the key, so
	// a sweep does not invalidate sealed values; the exception is the
	// [SoftwareProvider], whose root is an in-process enclave and which
	// reports this error after a sweep.
	ErrSealerWiped = errors.New("enclave: this sealer's keys were destroyed by a shutdown sweep; sealed values are unrecoverable and re-initializing requires constructing a new Sealer")

	// ErrOpenabilityUnknown is returned by [SealedEnclave.Openable] when a
	// shutdown sweep has run since this value was sealed (or during the seal)
	// and the sealer's provider can report nothing about its own sealing
	// state. It occurs only in [ModePerOperation], only after a [WipeAll],
	// and only with a provider that does not implement [HealthReporter].
	//
	// It is neither [ErrSealerWiped] (nothing is known to be destroyed) nor
	// nil. Open the value to find out.
	ErrOpenabilityUnknown = errors.New("enclave: a shutdown sweep has run since this value was sealed and its provider reports no sealing-state health, so openability cannot be determined; open the value to find out")

	// ErrInvalidProvider is returned by [NewSealer] when a provider option is
	// given a nil or typed-nil provider, or when both [WithKeyProtector] and
	// [WithRootUnsealer] are given. A nil provider is a lost configuration
	// step, not a request for the software default.
	ErrInvalidProvider = errors.New("enclave: a sealer takes exactly one non-nil provider, from WithKeyProtector or WithRootUnsealer")

	// ErrSealerExhausted is the cause of the [SealError] a seal returns on a
	// [ModeRootKey] sealer that would need a KEK generation past 2^31, the GCM
	// usage bound of the sealer's own wrapping key. Nothing is minted and
	// every value already sealed keeps opening. Only a very small
	// [WithKEKRotationLimit] reaches it in practice; the remedy is a new
	// Sealer.
	ErrSealerExhausted = errors.New("enclave: this sealer has used every KEK generation its wrapping key may wrap; existing values still open, but new seals require constructing a new Sealer")

	// ErrInvalidRotationLimit is returned by [NewSealer] for a
	// [WithKEKRotationLimit] of zero, above 2^31, or given for
	// [ModePerOperation], which has no KEK to rotate.
	ErrInvalidRotationLimit = errors.New("enclave: KEK rotation limit must be between 1 and 2^31 and applies only to ModeRootKey")

	// ErrSealerInstalled is returned by [SetSealer] when the process sealer is
	// already set, by an earlier SetSealer or by the first seal lazily
	// installing the software default.
	ErrSealerInstalled = errors.New("enclave: a process sealer is already installed")

	// ErrNilSealer is returned by [SetSealer] for a nil *Sealer, and by
	// [Sealer.Seal] on a nil receiver.
	ErrNilSealer = errors.New("enclave: sealer is nil")

	// ErrSealerDestroyed is returned by every Seal and Open, and by
	// [SealedEnclave.Openable], once [Sealer.Destroy] has run; and by a
	// [SoftwareProvider] once its own Destroy has run. The sealer fails closed
	// and never re-keys.
	ErrSealerDestroyed = errors.New("enclave: sealer was destroyed; sealed values are unrecoverable and sealing requires constructing a new Sealer")

	// ErrSealerNotConstructed is returned by Seal and Open on a Sealer that
	// was not built by [NewSealer], such as the zero value. The caller's
	// material is wiped as on every other failure.
	ErrSealerNotConstructed = errors.New("enclave: sealer was not constructed with NewSealer")

	// ErrProviderMessageLimit reports that a [SoftwareProvider] in
	// [ModePerOperation] has performed as many Protect operations (2^31) as
	// its single root key may safely encrypt, and refuses further ones. The
	// provider does not rotate; use [ModeRootKey], which does, or a hardware
	// [KeyProtector].
	ErrProviderMessageLimit = errors.New("enclave: software provider reached its per-key message bound; use ModeRootKey or a hardware provider")

	// errHierarchyUninitialized marks a ModeRootKey hierarchy not yet built:
	// distinct from wiped, because uninitialized may initialize and wiped
	// must never.
	errHierarchyUninitialized = errors.New("enclave: sealer key hierarchy not yet initialized")

	// errProviderEmptyBlob is the cause of the SealError for a provider whose
	// Protect returned no blob.
	errProviderEmptyBlob = errors.New("enclave: provider returned an empty blob from Protect")
)

// SealError is the error behind [ErrSealFailed], which errors.Is reports for
// every SealError. Its Cause is what failed: the AEAD, the CSPRNG, the
// provider, or the caller's ended context; Unwrap returns it.
type SealError = causeError[sealFailed]

// OpenError is the error behind [ErrOpenFailed], which errors.Is reports for
// every OpenError. Its Cause is the caller's ended context or the provider's
// infrastructure failure; Unwrap returns it.
type OpenError = causeError[openFailed]

// SealerWipedError is [ErrSealerWiped] with the failure that left the sealer
// wiped, such as a key derivation that failed after a root unseal that may
// not be repeated. errors.Is reports ErrSealerWiped for every
// SealerWipedError; Unwrap returns the Cause.
type SealerWipedError = causeError[sealerWiped]

// contextError reports that the caller's context ended before or during an
// operation. It unwraps to each of its non-nil fields, so the error matches
// ctx.Err(), a distinct [context.Cause], and a provider failure that arrived
// after the context ended.
type contextError struct {
	ended    error // ctx.Err(), or the provider's error that already matches it
	cause    error // context.Cause when distinct from ctx.Err(), or nil
	provider error // a provider failure that does not match ctx.Err(), or nil
}

// Error implements error.
func (e *contextError) Error() string {
	msg := e.ended.Error()
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	if e.provider != nil {
		msg += "; provider: " + e.provider.Error()
	}
	return msg
}

// Unwrap returns the non-nil fields.
func (e *contextError) Unwrap() []error {
	errs := make([]error, 0, 3)
	for _, err := range []error{e.ended, e.cause, e.provider} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Backends.
var (
	// ErrBackendNotRegistered is returned by [Lookup] for a name no backend is
	// registered under. Every [BackendNotRegisteredError] matches it.
	ErrBackendNotRegistered = errors.New("enclave: no backend is registered under this name")

	// ErrBackendExists is returned by [Register] for a name already taken, by
	// an earlier Register or by the default backend. Every
	// [BackendExistsError] matches it.
	ErrBackendExists = errors.New("enclave: a backend is already registered under this name")

	// ErrInvalidBackend is returned by [Register] for a nil or typed-nil
	// backend, or one whose name breaks the rule on [Backend.Name]. Like a nil
	// provider, it is a lost configuration step, never a request for the
	// default.
	ErrInvalidBackend = errors.New("enclave: backend is nil or its name is not a valid backend name")

	// ErrCapabilityUnsupported reports that an operation needs a capability
	// the handle or backend it was given does not provide, such as byte access
	// to material that never leaves its device. Nothing was attempted: a
	// missing capability is never a panic and never a fallback to another
	// backend. Every [CapabilityError] matches it.
	ErrCapabilityUnsupported = errors.New("enclave: the backend does not provide a capability this operation needs")

	// ErrInvalidImport is returned by [NewImportSpec], and so by every
	// [Importer], for a nil option, a missing or unknown purpose, or an
	// algorithm the purpose does not take; and by an Importer for material
	// whose length the algorithm does not take. Like a nil provider, it is a
	// lost configuration step, never a request for a default.
	ErrInvalidImport = errors.New("enclave: import options or material do not describe a valid import")

	// ErrInvalidNonce is returned by an [AEAD]'s Seal and Open for a nonce
	// that is not NonceSize bytes.
	ErrInvalidNonce = errors.New("enclave: AEAD nonce is not the cipher's nonce size")

	// ErrAEADAuthentication is returned by an [AEAD]'s Open when the
	// ciphertext or additional data fails authentication. No plaintext is
	// returned.
	ErrAEADAuthentication = errors.New("enclave: AEAD ciphertext failed authentication")
)

// BackendNotRegisteredError reports the name [Lookup] found nothing under.
// Match on [ErrBackendNotRegistered].
type BackendNotRegisteredError = nameError[backendNotRegistered]

// BackendExistsError reports the name [Register] found taken. Match on
// [ErrBackendExists].
type BackendExistsError = nameError[backendExists]

// CapabilityError reports which capability an operation needed and which
// backend's handle or backend lacked it. Match on [ErrCapabilityUnsupported].
type CapabilityError struct {
	// Backend is the name of the backend that lacks the capability.
	Backend string
	// Capability is the capability the operation needed.
	Capability Capability
}

// Error implements error.
func (e *CapabilityError) Error() string {
	return ErrCapabilityUnsupported.Error() + ": backend " + strconv.Quote(e.Backend) +
		" does not provide " + strconv.Quote(string(e.Capability))
}

// Is reports every CapabilityError as [ErrCapabilityUnsupported].
func (e *CapabilityError) Is(target error) bool { return target == ErrCapabilityUnsupported }

// Shutdown sweep.

// ErrSweepInProgress is returned by [WipeAll] when it was never admitted:
// another sweep held the process's single sweep slot and this call stopped
// waiting for it, when its ctx ended or at once for a nil ctx. It is not a
// [SweepError] and says nothing about the memory: the call reclaimed nothing,
// and the count returned with it is the current ledger count.
var ErrSweepInProgress = errors.New("enclave: another WipeAll is in progress; nothing was swept")

// SweepError reports what an admitted [WipeAll] sweep found that is not a held
// page: canary corruption, unwiped unmaps, or both. Neither leaves pages held,
// so the count cannot carry them.
//
// Match it with errors.Is against [ErrEnclaveCorrupted] (Corrupt non-zero) and
// [ErrReleasedWithoutWipe] (Unwiped non-zero); read the numbers with errors.As.
// WipeAll returns one only when a field is non-zero, and never a nil
// *SweepError behind a non-nil error.
type SweepError struct {
	// Corrupt is how many entries this sweep found with a failed canary
	// (enclaves, and orphaned mappings that had material copied in), plus
	// every enclave whose [MemoryEnclave.Destroy] reported [ErrEnclaveCorrupted]
	// since the previous admitted sweep. Each is counted once per sweep. A
	// corrupt entry whose pages the kernel would not release is also in the
	// count WipeAll returns.
	Corrupt int

	// Unwiped is how many entries this sweep unmapped without the in-process
	// overwrite because the mprotect that makes a frozen region writable was
	// denied. Their pages are gone, so they are never in the count.
	Unwiped int
}

// Error implements error. Each non-zero condition is one line naming its
// count and ending in its sentinel's text; both lines appear when both hold.
func (e *SweepError) Error() string {
	var lines []string
	if e.Corrupt > 0 {
		lines = append(lines, "enclave: "+strconv.Itoa(e.Corrupt)+
			" of the swept enclaves failed canary verification: "+ErrEnclaveCorrupted.Error())
	}
	if e.Unwiped > 0 {
		lines = append(lines, "enclave: "+strconv.Itoa(e.Unwiped)+
			" of the swept enclaves were unmapped without an in-process wipe because mprotect was denied: "+
			ErrReleasedWithoutWipe.Error())
	}
	switch len(lines) {
	case 0:
		// Only a hand-built SweepError gets here.
		return "enclave: sweep reported nothing"
	case 1:
		return lines[0]
	}
	return lines[0] + "\n" + lines[1]
}

// Is reports whether e carries the condition target names:
// [ErrEnclaveCorrupted] when Corrupt is non-zero, [ErrReleasedWithoutWipe]
// when Unwiped is. A zero field never matches its sentinel.
func (e *SweepError) Is(target error) bool {
	switch target {
	case ErrEnclaveCorrupted:
		return e.Corrupt > 0
	case ErrReleasedWithoutWipe:
		return e.Unwiped > 0
	}
	return false
}

// The shared shape.

// kind names the sentinel a causeError matches. Each kind is an empty struct,
// so the sentinel is fixed by the error's type and holds for its zero value.
type kind interface{ sentinel() error }

type (
	lockedMemoryUnavailable struct{}
	releasedWithoutWipe     struct{}
	limitDiscoveryFailed    struct{}
	processHardeningFailed  struct{}
	sealFailed              struct{}
	openFailed              struct{}
	sealerWiped             struct{}
	backendNotRegistered    struct{}
	backendExists           struct{}
)

func (lockedMemoryUnavailable) sentinel() error { return ErrLockedMemoryUnavailable }
func (releasedWithoutWipe) sentinel() error     { return ErrReleasedWithoutWipe }
func (limitDiscoveryFailed) sentinel() error    { return ErrLimitDiscoveryFailed }
func (processHardeningFailed) sentinel() error  { return ErrProcessHardeningFailed }
func (sealFailed) sentinel() error              { return ErrSealFailed }
func (openFailed) sentinel() error              { return ErrOpenFailed }
func (sealerWiped) sentinel() error             { return ErrSealerWiped }
func (backendNotRegistered) sentinel() error    { return ErrBackendNotRegistered }
func (backendExists) sentinel() error           { return ErrBackendExists }

// causeError is the shape of every error type that is its kind's sentinel
// plus a diagnostic cause.
type causeError[K kind] struct {
	// Cause is the underlying failure, or nil.
	Cause error
}

// Error is the sentinel's text, followed by the cause's when there is one.
func (e *causeError[K]) Error() string {
	var k K
	if e.Cause == nil {
		return k.sentinel().Error()
	}
	return k.sentinel().Error() + ": " + e.Cause.Error()
}

// Is reports every error of kind K as K's sentinel.
func (e *causeError[K]) Is(target error) bool {
	var k K
	return target == k.sentinel()
}

// Unwrap returns the cause.
func (e *causeError[K]) Unwrap() error { return e.Cause }

// nameError is the shape of every error type that is its kind's sentinel
// plus the backend name it concerns.
type nameError[K kind] struct {
	// Name is the backend name the failure concerns.
	Name string
}

// Error is the sentinel's text followed by the quoted name.
func (e *nameError[K]) Error() string {
	var k K
	return k.sentinel().Error() + ": " + strconv.Quote(e.Name)
}

// Is reports every error of kind K as K's sentinel.
func (e *nameError[K]) Is(target error) bool {
	var k K
	return target == k.sentinel()
}

// withCause returns K's sentinel itself when cause is nil, and the causeError
// carrying cause otherwise.
func withCause[K kind](cause error) error {
	if cause == nil {
		var k K
		return k.sentinel()
	}
	return &causeError[K]{Cause: cause}
}

// withCleanupFailure reports failure together with an independent cleanup
// failure that followed it, such as a refused release after a failed
// operation; both stay reachable with errors.Is and errors.As. Either may be
// nil, and the other is then returned unchanged. It is this package's only
// errors.Join.
func withCleanupFailure(failure, cleanup error) error {
	switch {
	case cleanup == nil:
		return failure
	case failure == nil:
		return cleanup
	}
	return errors.Join(failure, cleanup)
}

// destroyOnFailure destroys e, which a failed operation leaves unwanted, and
// returns failure with any release the kernel refused, which destroyTransient
// would drop.
func destroyOnFailure(failure error, e *MemoryEnclave) error {
	return withCleanupFailure(failure, e.Destroy())
}

// destroyAll destroys every key, nil ones included, and returns every release
// the kernel refused. A refused key is already wiped and stays on the
// [WipeAll] ledger; destroying it again retries the release, and destroying a
// released one again is a no-op.
func destroyAll(keys ...*MemoryEnclave) error {
	var errs error
	for _, k := range keys {
		errs = withCleanupFailure(errs, k.Destroy())
	}
	return errs
}

// contextFailure returns nil while ctx is live; otherwise the operation's
// error (kind K) carrying a contextError. A provider error cause is kept: it
// replaces the bare context error when it already matches it, and is carried
// alongside otherwise. A distinct [context.Cause] is carried too.
func contextFailure[K kind](ctx context.Context, cause error) error {
	ended := ctx.Err()
	if ended == nil {
		return nil
	}

	ce := &contextError{ended: ended}
	switch {
	case cause == nil:
	case errors.Is(cause, ended):
		ce.ended = cause
	default:
		ce.provider = cause
	}
	if why := context.Cause(ctx); why != nil && !errors.Is(why, ended) {
		ce.cause = why
	}
	return &causeError[K]{Cause: ce}
}

// providerVerdicts lists, by operation sentinel, the errors providerFailure
// passes through: this package's own sentinels, and for an open the
// authentication verdict.
var providerVerdicts = map[error][]error{
	ErrSealFailed: {
		ErrSealerWiped, ErrSealerDestroyed, ErrSealFailed, ErrLockedMemoryUnavailable, ErrProviderMessageLimit, ErrEnclaveDestroyed,
	},
	ErrOpenFailed: {
		ErrSealedAuthentication, ErrSealerWiped, ErrSealerDestroyed, ErrOpenFailed, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed,
	},
}

// providerFailure shapes a provider's failure as operation K's: one of its
// providerVerdicts passes through, and anything else is wrapped in a
// [SealError] or [OpenError], so an open failure that is not a verdict cannot
// be mistaken for one.
func providerFailure[K kind](err error) error {
	if err == nil {
		return nil
	}
	var k K
	for _, verdict := range providerVerdicts[k.sentinel()] {
		if errors.Is(err, verdict) {
			return err
		}
	}
	return &causeError[K]{Cause: err}
}
