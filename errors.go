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

	// ErrInvalidSize is returned by [NewMemorySized] and
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
	// overwritten, detected at release. See [Memory.Destroy].
	ErrEnclaveCorrupted = errors.New("enclave: canary verification failed; memory ahead of the enclave was overwritten")

	// ErrNilFunc is returned by [Memory.WithBytes] for a nil function, which
	// it never calls; the enclave is unchanged.
	ErrNilFunc = errors.New("enclave: WithBytes was given a nil function")

	// ErrCoreDumpLimitUnsupported is what [CoreDumpsDisabled] reports on
	// Windows, which has no process-wide core-dump limit, whether or not
	// [HardenProcess] ran; dump exposure there must be governed by host policy.
	ErrCoreDumpLimitUnsupported = errors.New("enclave: this platform has no process-wide core-dump limit to lower")

	// errInvalidProtection reports a protection outside the defined values, so
	// the zero value is refused rather than guessed.
	errInvalidProtection = errors.New("enclave: invalid page protection")
)

// LockedMemoryError is the error behind [ErrLockedMemoryUnavailable], which
// errors.Is reports for every LockedMemoryError. Its Cause, the failing system
// call's error or nil, is diagnostic; Unwrap returns it.
type LockedMemoryError struct {
	// Cause is the failing system call's error, or nil.
	Cause error
}

// Error is [ErrLockedMemoryUnavailable]'s text, followed by the cause's when
// there is one.
func (e *LockedMemoryError) Error() string { return causeText(ErrLockedMemoryUnavailable, e.Cause) }

// Is reports every LockedMemoryError as [ErrLockedMemoryUnavailable].
func (e *LockedMemoryError) Is(target error) bool { return target == ErrLockedMemoryUnavailable }

// Unwrap returns the cause.
func (e *LockedMemoryError) Unwrap() error { return e.Cause }

// UnwipedReleaseError is the error behind [ErrReleasedWithoutWipe], which
// errors.Is reports for every UnwipedReleaseError. Its Cause is the refused
// mprotect's *os.SyscallError, deliberately not a [LockedMemoryError]; Unwrap
// returns it.
type UnwipedReleaseError struct {
	// Cause is the refused mprotect's error.
	Cause error
}

// Error is [ErrReleasedWithoutWipe]'s text, followed by the cause's when there
// is one.
func (e *UnwipedReleaseError) Error() string { return causeText(ErrReleasedWithoutWipe, e.Cause) }

// Is reports every UnwipedReleaseError as [ErrReleasedWithoutWipe].
func (e *UnwipedReleaseError) Is(target error) bool { return target == ErrReleasedWithoutWipe }

// Unwrap returns the cause.
func (e *UnwipedReleaseError) Unwrap() error { return e.Cause }

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
	// [Sealed.OpenIn] (which never falls back to the unbudgeted
	// [Sealed.Open]), and the Allocator methods that can fail. New
	// still wipes the data it was handed.
	ErrNilAllocator = errors.New("enclave: allocator is nil")

	// ErrAllocatorNotConstructed is returned for an [Allocator] that was not
	// built by [NewAllocator] or [NewAllocatorWithinRLimit], such as the zero
	// value, by [SetAllocator] (which installs nothing), by [Sealed.OpenIn],
	// and by the Allocator methods that can fail, as either side of
	// [Allocator.TransferTo]. Nothing is admitted or changed; New and Import
	// still wipe the data they were handed.
	ErrAllocatorNotConstructed = errors.New("enclave: allocator was not constructed with NewAllocator or NewAllocatorWithinRLimit")

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
type LimitDiscoveryError struct {
	// Cause is the getrlimit failure.
	Cause error
}

// Error is [ErrLimitDiscoveryFailed]'s text, followed by the cause's when
// there is one.
func (e *LimitDiscoveryError) Error() string { return causeText(ErrLimitDiscoveryFailed, e.Cause) }

// Is reports every LimitDiscoveryError as [ErrLimitDiscoveryFailed].
func (e *LimitDiscoveryError) Is(target error) bool { return target == ErrLimitDiscoveryFailed }

// Unwrap returns the cause.
func (e *LimitDiscoveryError) Unwrap() error { return e.Cause }

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

	// ErrCoreDumpLimitFailed reports that [HardenProcess] could not lower
	// RLIMIT_CORE to zero, soft and hard: setrlimit or its read-back was
	// refused, or the read-back disagreed. Every [CoreDumpLimitError] matches
	// it; [CoreDumpsDisabled] keeps reporting it until a later HardenProcess
	// succeeds.
	ErrCoreDumpLimitFailed = errors.New("enclave: lowering the core-dump limit to zero failed")

	// ErrCoreDumpLimitNotApplied is what [CoreDumpsDisabled] reports before
	// [HardenProcess] has run: importing the package leaves RLIMIT_CORE as the
	// process found it.
	ErrCoreDumpLimitNotApplied = errors.New("enclave: the core-dump limit was not lowered; HardenProcess has not run")

	// errCoreLimitNotCleared reports a setrlimit(RLIMIT_CORE) that succeeded
	// but did not read back as zero, soft and hard.
	errCoreLimitNotCleared = errors.New("enclave: RLIMIT_CORE is not zero after setrlimit")
)

// ProcessHardeningError is the error behind [ErrProcessHardeningFailed]. Its
// Cause is the refused system call, the read-back that disagreed, or a
// [CoreDumpLimitError]; Unwrap returns it.
type ProcessHardeningError struct {
	// Cause is the refused system call, the read-back that disagreed, or a
	// [CoreDumpLimitError].
	Cause error
}

// Error is [ErrProcessHardeningFailed]'s text, followed by the cause's when
// there is one.
func (e *ProcessHardeningError) Error() string { return causeText(ErrProcessHardeningFailed, e.Cause) }

// Is reports every ProcessHardeningError as [ErrProcessHardeningFailed].
func (e *ProcessHardeningError) Is(target error) bool { return target == ErrProcessHardeningFailed }

// Unwrap returns the cause.
func (e *ProcessHardeningError) Unwrap() error { return e.Cause }

// CoreDumpLimitError is the error behind [ErrCoreDumpLimitFailed], which
// errors.Is reports for every CoreDumpLimitError. Its Cause is the refused
// setrlimit or getrlimit's *os.SyscallError, or the read-back that disagreed;
// Unwrap returns it.
type CoreDumpLimitError struct {
	// Cause is the refused system call or the read-back that disagreed.
	Cause error
}

// Error is [ErrCoreDumpLimitFailed]'s text, followed by the cause's when there
// is one.
func (e *CoreDumpLimitError) Error() string { return causeText(ErrCoreDumpLimitFailed, e.Cause) }

// Is reports every CoreDumpLimitError as [ErrCoreDumpLimitFailed].
func (e *CoreDumpLimitError) Is(target error) bool { return target == ErrCoreDumpLimitFailed }

// Unwrap returns the cause.
func (e *CoreDumpLimitError) Unwrap() error { return e.Cause }

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

	// ErrOpenabilityUnknown is returned by [Sealed.Openable] when a
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
	// [Sealed.Openable], once [Sealer.Destroy] has run; and by a
	// [SoftwareProvider] once its own Destroy has run. The sealer fails closed
	// and never re-keys.
	ErrSealerDestroyed = errors.New("enclave: sealer was destroyed; sealed values are unrecoverable and sealing requires constructing a new Sealer")

	// ErrSealerNotConstructed is returned by [Sealer.Seal], [Sealer.SealFrom]
	// and [SetSealer] for a Sealer that was not built by [NewSealer], such as
	// the zero value. The caller's material is wiped as on every other failure.
	ErrSealerNotConstructed = errors.New("enclave: sealer was not constructed with NewSealer")

	// ErrInvalidSealerOption is returned by [NewSealer] for a nil
	// [SealerOption].
	ErrInvalidSealerOption = errors.New("enclave: a sealer option is nil")

	// ErrSealSourceReadOnly is returned by [Sealer.Seal] and [NewSealed] for
	// data this process cannot write, such as a view into a frozen [Memory]
	// passed from inside its WithBytes. Seal wipes its input, and a write to a
	// read-only page kills the process, so the value is refused before any key
	// is touched and data is left as it was. Seal the enclave itself with
	// [Sealer.SealFrom] or [NewSealedFrom], which borrow it and never wipe it.
	ErrSealSourceReadOnly = errors.New("enclave: material to seal is read-only and cannot be wiped; seal its enclave with SealFrom")

	// ErrKeyScheduleExposed is returned by [NewSealer] with
	// [WithRequireKeyScheduleErasure] when a class of the sealer's keys would
	// leave its AES key schedule on the heap: neither does the build erase it
	// ([KeyScheduleErasure]) nor does the sealer's backend confine the process
	// ([Confiner]). Every [KeyScheduleExposedError] matches it.
	ErrKeyScheduleExposed = errors.New("enclave: a sealing key's AES key schedule would reach the heap without being erased")

	// ErrProviderMessageLimit reports that a [SoftwareProvider] in
	// [ModePerOperation] has performed as many Protect operations (2^31) as
	// its single root key may safely encrypt, and refuses further ones. The
	// provider does not rotate; use [ModeRootKey], which does, or a hardware
	// [KeyProtector].
	ErrProviderMessageLimit = errors.New("enclave: software provider reached its per-key message bound; use ModeRootKey or a hardware provider")

	// ErrProviderNotConstructed reports a [SoftwareProvider] that was not
	// built by [NewSoftwareProvider], such as the zero value.
	ErrProviderNotConstructed = errors.New("enclave: software provider was not constructed with NewSoftwareProvider")

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
type SealError struct {
	// Cause is what failed, or nil.
	Cause error
}

// Error is [ErrSealFailed]'s text, followed by the cause's when there is one.
func (e *SealError) Error() string { return causeText(ErrSealFailed, e.Cause) }

// Is reports every SealError as [ErrSealFailed].
func (e *SealError) Is(target error) bool { return target == ErrSealFailed }

// Unwrap returns the cause.
func (e *SealError) Unwrap() error { return e.Cause }

// OpenError is the error behind [ErrOpenFailed], which errors.Is reports for
// every OpenError. Its Cause is the caller's ended context or the provider's
// infrastructure failure; Unwrap returns it.
type OpenError struct {
	// Cause is what failed, or nil.
	Cause error
}

// Error is [ErrOpenFailed]'s text, followed by the cause's when there is one.
func (e *OpenError) Error() string { return causeText(ErrOpenFailed, e.Cause) }

// Is reports every OpenError as [ErrOpenFailed].
func (e *OpenError) Is(target error) bool { return target == ErrOpenFailed }

// Unwrap returns the cause.
func (e *OpenError) Unwrap() error { return e.Cause }

// SealerWipedError is [ErrSealerWiped] with the failure that left the sealer
// wiped, such as a key derivation that failed after a root unseal that may
// not be repeated. errors.Is reports ErrSealerWiped for every
// SealerWipedError; Unwrap returns the Cause.
type SealerWipedError struct {
	// Cause is the failure that left the sealer wiped.
	Cause error
}

// Error is [ErrSealerWiped]'s text, followed by the cause's when there is one.
func (e *SealerWipedError) Error() string { return causeText(ErrSealerWiped, e.Cause) }

// Is reports every SealerWipedError as [ErrSealerWiped].
func (e *SealerWipedError) Is(target error) bool { return target == ErrSealerWiped }

// Unwrap returns the cause.
func (e *SealerWipedError) Unwrap() error { return e.Cause }

// KeyScheduleExposedError is the error behind [ErrKeyScheduleExposed], which
// errors.Is reports for every KeyScheduleExposedError. Its Name is the first
// key class found exposed: "wrapping-key" or "dek".
type KeyScheduleExposedError struct {
	// Name is the key class found exposed.
	Name string
}

// Error is [ErrKeyScheduleExposed]'s text followed by the quoted name.
func (e *KeyScheduleExposedError) Error() string { return nameText(ErrKeyScheduleExposed, e.Name) }

// Is reports every KeyScheduleExposedError as [ErrKeyScheduleExposed].
func (e *KeyScheduleExposedError) Is(target error) bool { return target == ErrKeyScheduleExposed }

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
type BackendNotRegisteredError struct {
	// Name is the name looked up.
	Name string
}

// Error is [ErrBackendNotRegistered]'s text followed by the quoted name.
func (e *BackendNotRegisteredError) Error() string { return nameText(ErrBackendNotRegistered, e.Name) }

// Is reports every BackendNotRegisteredError as [ErrBackendNotRegistered].
func (e *BackendNotRegisteredError) Is(target error) bool { return target == ErrBackendNotRegistered }

// BackendExistsError reports the name [Register] found taken. Match on
// [ErrBackendExists].
type BackendExistsError struct {
	// Name is the name found taken.
	Name string
}

// Error is [ErrBackendExists]'s text followed by the quoted name.
func (e *BackendExistsError) Error() string { return nameText(ErrBackendExists, e.Name) }

// Is reports every BackendExistsError as [ErrBackendExists].
func (e *BackendExistsError) Is(target error) bool { return target == ErrBackendExists }

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

// Handle cleanup.

// ErrCleanupFailed reports that cleanup an operation did failed alongside
// another failure: a [Handle] the operation no longer needed, such as a
// sealer's outgoing KEK or a plaintext handle an open did not return, refused
// its Destroy and still holds its material, or a release of locked memory was
// refused after the operation had already failed. Every [CleanupError]
// matches it.
var ErrCleanupFailed = errors.New("enclave: cleanup failed; what it released may still hold its material")

// CleanupError reports cleanup that failed: the operation's own failure, if
// any, and every cleanup failure that followed it. A [Handle] that refused its
// Destroy is kept by the [Sealer] the operation ran under, which retries it on
// every [Sealer.Destroy], so the material stays reachable until it is
// released; a release of locked memory the kernel refused stays on the
// [WipeAll] ledger.
//
// Match it with errors.Is against [ErrCleanupFailed], and against the
// operation's failure and each cause, which Unwrap returns; read them with
// errors.As.
type CleanupError struct {
	// Failure is the operation's own error, or nil when the operation did its
	// work and failed only for its cleanup.
	Failure error
	// Causes holds each cleanup failure, in the order they happened: what a
	// handle's Destroy, or a release of locked memory, returned.
	Causes []error
}

// Error is the operation's failure, when there is one, followed by
// [ErrCleanupFailed]'s text and each cause's.
func (e *CleanupError) Error() string {
	msg := ErrCleanupFailed.Error()
	sep := ": "
	for _, cause := range e.Causes {
		if cause != nil {
			msg += sep + cause.Error()
			sep = "; "
		}
	}
	if e.Failure != nil {
		msg = e.Failure.Error() + "; " + msg
	}
	return msg
}

// Is reports every CleanupError as [ErrCleanupFailed].
func (e *CleanupError) Is(target error) bool { return target == ErrCleanupFailed }

// Unwrap returns the operation's failure and each cause, skipping nil ones.
func (e *CleanupError) Unwrap() []error {
	errs := make([]error, 0, 1+len(e.Causes))
	for _, err := range append([]error{e.Failure}, e.Causes...) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Shutdown sweep.

// ErrSweepInProgress is returned by [WipeAll] when it was never admitted:
// another sweep held the process's single sweep slot and this call stopped
// waiting for it, when its ctx ended or at once for a nil ctx. It is not a
// [SweepError] and says nothing about the memory: the call reclaimed nothing,
// and the count returned with it is the current ledger count.
var ErrSweepInProgress = errors.New("enclave: another WipeAll is in progress; nothing was swept")

// SweepError reports what an admitted [WipeAll] sweep found that is not a held
// page: canary corruption, unwiped unmaps, a registered [Sweeper] that failed,
// or any mix. None leaves locked-memory pages held, so the count cannot carry
// them.
//
// Match it with errors.Is against [ErrEnclaveCorrupted] (Corrupt non-zero) and
// [ErrReleasedWithoutWipe] (Unwiped non-zero), and against each failed
// backend's own errors, which Unwrap returns; read the numbers and the failures
// with errors.As. WipeAll returns one only when a field is non-zero or
// non-empty, and never a nil *SweepError behind a non-nil error.
type SweepError struct {
	// Corrupt is how many entries this sweep found with a failed canary
	// (enclaves, and orphaned mappings that had material copied in), plus
	// every enclave whose [Memory.Destroy] reported [ErrEnclaveCorrupted]
	// since the previous admitted sweep. Each is counted once per sweep. A
	// corrupt entry whose pages the kernel would not release is also in the
	// count WipeAll returns.
	Corrupt int

	// Unwiped is how many entries this sweep unmapped without the in-process
	// overwrite because the mprotect that makes a frozen region writable was
	// denied. Their pages are gone, so they are never in the count.
	Unwiped int

	// Backends has one entry per registered backend whose Sweep returned an
	// error, in name order. What such a backend still holds is in the count.
	Backends []BackendSweepFailure
}

// BackendSweepFailure records one failed [Sweeper.Sweep] in a [SweepError]. It
// is a record, not an error type.
type BackendSweepFailure struct {
	// Backend is the name the backend is registered under.
	Backend string
	// Err is what its Sweep returned.
	Err error
}

// Error implements error. Each non-zero count is one line naming it and ending
// in its sentinel's text, followed by one line per failed backend, its name
// quoted.
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
	for _, f := range e.Backends {
		cause := "<nil>"
		if f.Err != nil {
			cause = f.Err.Error()
		}
		lines = append(lines, "enclave: backend "+strconv.Quote(f.Backend)+" failed its sweep: "+cause)
	}
	if len(lines) == 0 {
		// Only a hand-built SweepError gets here.
		return "enclave: sweep reported nothing"
	}
	msg := lines[0]
	for _, line := range lines[1:] {
		msg += "\n" + line
	}
	return msg
}

// Unwrap returns every failed backend's error, in name order, so errors.Is and
// errors.As reach each backend's own typed error.
func (e *SweepError) Unwrap() []error {
	errs := make([]error, 0, len(e.Backends))
	for _, f := range e.Backends {
		if f.Err != nil {
			errs = append(errs, f.Err)
		}
	}
	return errs
}

// Is reports whether e carries the condition target names:
// [ErrEnclaveCorrupted] when Corrupt is non-zero, [ErrReleasedWithoutWipe]
// when Unwiped is. A zero count never matches its sentinel here; a backend's
// own error can still match through Unwrap.
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

// causeText is the text of every error type that is a sentinel plus a
// diagnostic cause: the sentinel's text, followed by the cause's when there is
// one.
func causeText(sentinel, cause error) string {
	if cause == nil {
		return sentinel.Error()
	}
	return sentinel.Error() + ": " + cause.Error()
}

// nameText is the text of every error type that is a sentinel plus the name
// it concerns: the sentinel's text followed by the quoted name.
func nameText(sentinel error, name string) string {
	return sentinel.Error() + ": " + strconv.Quote(name)
}

// causeShape is the struct every cause error type is defined as.
type causeShape interface{ ~struct{ Cause error } }

// causeError constrains the generic helpers to a cause error type: P is *E,
// an error, and names the sentinel it matches.
type causeError[E causeShape] interface {
	*E
	error
	sentinel() error
}

func (*SealError) sentinel() error        { return ErrSealFailed }
func (*OpenError) sentinel() error        { return ErrOpenFailed }
func (*SealerWipedError) sentinel() error { return ErrSealerWiped }

// newCause returns the E carrying cause.
func newCause[E causeShape, P causeError[E]](cause error) error {
	return P(&E{Cause: cause})
}

// withCause returns E's sentinel itself when cause is nil, and the E carrying
// cause otherwise.
func withCause[E causeShape, P causeError[E]](cause error) error {
	if cause == nil {
		var p P
		return p.sentinel()
	}
	return newCause[E, P](cause)
}

// withCleanupFailure reports failure together with the cleanup failures that
// followed it, such as a refused release after a failed operation, as one
// [CleanupError]; every one stays reachable with errors.Is and errors.As. Nil
// cleanups are skipped, and a CleanupError among them contributes its own
// failure and causes, so the report stays flat; so does a failure that is
// already a CleanupError, which is extended. With no cleanup failure, failure
// is returned unchanged; with one and a nil failure, so is that one.
func withCleanupFailure(failure error, cleanups ...error) error {
	var causes []error
	var last error
	n := 0
	for _, c := range cleanups {
		if c == nil {
			continue
		}
		n, last = n+1, c
		var ce *CleanupError
		if !asCleanupError(c, &ce) {
			causes = append(causes, c)
			continue
		}
		if ce.Failure != nil {
			causes = append(causes, ce.Failure)
		}
		causes = append(causes, ce.Causes...)
	}
	switch {
	case n == 0:
		return failure
	case failure == nil && n == 1:
		return last
	}
	var ce *CleanupError
	if asCleanupError(failure, &ce) {
		return &CleanupError{Failure: ce.Failure, Causes: append(append([]error(nil), ce.Causes...), causes...)}
	}
	return &CleanupError{Failure: failure, Causes: causes}
}

// asCleanupError sets *ce when err itself, not an error it wraps, is a
// *CleanupError: only those are merged.
func asCleanupError(err error, ce **CleanupError) bool {
	var ok bool
	*ce, ok = err.(*CleanupError) //nolint:errorlint // only a top-level CleanupError is merged
	return ok
}

// destroyOnFailure destroys e, which a failed operation leaves unwanted, and
// returns failure with any release the kernel refused, which destroyTransient
// would drop.
func destroyOnFailure(failure error, e *Memory) error {
	return withCleanupFailure(failure, e.Destroy())
}

// contextFailure returns nil while ctx is live; otherwise the operation's
// error (an E) carrying a contextError. A provider error cause is kept: it
// replaces the bare context error when it already matches it, and is carried
// alongside otherwise. A distinct [context.Cause] is carried too.
func contextFailure[E causeShape, P causeError[E]](ctx context.Context, cause error) error {
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
	return newCause[E, P](ce)
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

// providerFailure shapes a provider's failure as an E: one of its
// providerVerdicts passes through, and anything else is wrapped in a
// [SealError] or [OpenError], so an open failure that is not a verdict cannot
// be mistaken for one.
func providerFailure[E causeShape, P causeError[E]](err error) error {
	if err == nil {
		return nil
	}
	var p P
	for _, verdict := range providerVerdicts[p.sentinel()] {
		if errors.Is(err, verdict) {
			return err
		}
	}
	return newCause[E, P](err)
}
