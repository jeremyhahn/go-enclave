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

	// ErrReleasedWithoutWipe reports pages unmapped without the in-process wipe because mprotect was denied.
	ErrReleasedWithoutWipe = errors.New("enclave: pages unmapped without an in-process wipe; mprotect was denied")

	// ErrEnclaveCorrupted reports that an enclave's canary or guard pages were
	// overwritten, detected at release. See Destroy in [NewMemory].
	ErrEnclaveCorrupted = errors.New("enclave: canary verification failed; memory ahead of the enclave was overwritten")

	// ErrNilFunc is returned by a memory enclave's [ByteAccess.WithBytes] for
	// a nil function, which
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

// UnwipedReleaseError is the error behind [ErrReleasedWithoutWipe]; it unwraps to the refused mprotect.
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
	// ErrBudgetExhausted is returned before any locked memory is requested when an allocation would exceed the budget.
	ErrBudgetExhausted = errors.New("enclave: locked-memory budget exhausted")

	// ErrInvalidBudget is returned for a non-positive budget, a negative limit, or a transfer that would overflow int64.
	ErrInvalidBudget = errors.New("enclave: allocator budget must be positive")

	// ErrBudgetInUse is returned when lowering a budget would put it below the
	// locked bytes already reserved; nothing is changed. Every
	// [BudgetInUseError] matches it. [Allocator.ForceLimit] lowers regardless.
	ErrBudgetInUse = errors.New("enclave: budget would fall below the locked memory already reserved")

	// ErrInvalidTransfer is returned by [Allocator.TransferTo] for a malformed
	// transfer: a non-positive amount, a nil destination, or a destination
	// that is the source.
	ErrInvalidTransfer = errors.New("enclave: invalid headroom transfer")

	// ErrNilAllocator is returned for a nil [Allocator].
	ErrNilAllocator = errors.New("enclave: allocator is nil")

	// ErrAllocatorNotConstructed is returned for an [Allocator] this package did not build.
	ErrAllocatorNotConstructed = errors.New("enclave: allocator was not constructed with NewAllocator or NewAllocatorWithinRLimit")

	// ErrAllocatorInstalled is returned by [SetAllocator] when the process
	// allocator is already set, by an earlier SetAllocator or by the first
	// [ProcessAllocator] call installing the default.
	ErrAllocatorInstalled = errors.New("enclave: a process allocator is already installed")

	// ErrBudgetExceedsRLimit is returned when a budget exceeds the process's locked-memory ceiling.
	ErrBudgetExceedsRLimit = errors.New("enclave: allocator budget exceeds the process's locked-memory limit")

	// ErrLimitDiscoveryFailed reports that the locked-memory ceiling could not be read.
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

// LimitDiscoveryError reports the locked-memory ceiling could not be read; it unwraps to the getrlimit failure.
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

	// ErrCoreDumpLimitFailed reports that [HardenProcess] could not lower RLIMIT_CORE to zero.
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

// CoreDumpLimitError is the error behind [ErrCoreDumpLimitFailed]; it unwraps to the refused call.
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
	// ErrSealFailed reports that material could not be encrypted.
	ErrSealFailed = errors.New("enclave: could not seal material")

	// ErrOpenFailed reports an open failure that says nothing about the material, such as an ended context; the value is intact.
	ErrOpenFailed = errors.New("enclave: could not open sealed material")

	// ErrSealedAuthentication reports that sealed material did not authenticate; the causes are indistinguishable.
	ErrSealedAuthentication = errors.New("enclave: sealed material failed authentication")

	// ErrUnknownSealedVersion reports a [Sealed] envelope whose version this
	// package does not read: neither contract v1 (version 0) nor version 2.
	// It is refused before any key is touched or anything is decrypted.
	ErrUnknownSealedVersion = errors.New("enclave: sealed envelope version is unknown")

	// ErrPlaintextEscaped reports that the AEAD wrote plaintext outside the locked destination.
	ErrPlaintextEscaped = errors.New("enclave: recovered plaintext did not land in locked memory")

	// ErrMaterialTooLarge reports material too long for one AES-GCM message or an int.
	ErrMaterialTooLarge = errors.New("enclave: material is too large to seal")

	// ErrSealerWiped reports that a shutdown sweep destroyed this sealer's keys; the sealer fails closed.
	ErrSealerWiped = errors.New("enclave: this sealer's keys were destroyed by a shutdown sweep; sealed values are unrecoverable and re-initializing requires constructing a new Sealer")

	// ErrOpenabilityUnknown is returned by [Sealed.Openable] when a sweep has run and the provider cannot report its state.
	ErrOpenabilityUnknown = errors.New("enclave: a shutdown sweep has run since this value was sealed and its provider reports no sealing-state health, so openability cannot be determined; open the value to find out")

	// ErrInvalidProvider is returned by [NewSealer] for a nil provider or both provider options.
	ErrInvalidProvider = errors.New("enclave: a sealer takes exactly one non-nil provider, from WithKeyProtector or WithRootUnsealer")

	// ErrSealerExhausted is the cause of a seal that would need a KEK generation past 2^31.
	ErrSealerExhausted = errors.New("enclave: this sealer has used every KEK generation its wrapping key may wrap; existing values still open, but new seals require constructing a new Sealer")

	// ErrInvalidRotationLimit is returned by [NewSealer] for a
	// [WithKEKRotationLimit] of zero, above 2^31, or given for
	// [ModePerOperation], which has no KEK to rotate.
	ErrInvalidRotationLimit = errors.New("enclave: KEK rotation limit must be between 1 and 2^31 and applies only to ModeRootKey")

	// ErrSealerInstalled is returned by [SetSealer] when the process sealer is
	// already set, by an earlier SetSealer or by the first seal lazily
	// installing the software default.
	ErrSealerInstalled = errors.New("enclave: a process sealer is already installed")

	// ErrNilSealer is returned by [SetSealer] for a nil [Sealer], a typed-nil
	// implementation included, which installs nothing.
	ErrNilSealer = errors.New("enclave: sealer is nil")

	// ErrSealerDestroyed is returned by every Seal and Open once [Sealer.Destroy] has run.
	ErrSealerDestroyed = errors.New("enclave: sealer was destroyed; sealed values are unrecoverable and sealing requires constructing a new Sealer")

	// ErrSealerNotConstructed is returned by [SetSealer] for a [Sealer] that
	// was not built by [NewSealer] (another implementation of the interface),
	// which installs nothing and takes no material.
	ErrSealerNotConstructed = errors.New("enclave: sealer was not constructed with NewSealer")

	// ErrInvalidSealerOption is returned by [NewSealer] for a nil
	// [SealerOption].
	ErrInvalidSealerOption = errors.New("enclave: a sealer option is nil")

	// ErrSealSourceReadOnly is returned for data this process cannot write; seal the enclave with [Sealer.SealFrom] instead.
	ErrSealSourceReadOnly = errors.New("enclave: material to seal is read-only and cannot be wiped; seal its enclave with SealFrom")

	// ErrKeyScheduleExposed is returned by [NewSealer] with [WithRequireKeyScheduleErasure] when a key schedule would stay on the heap.
	ErrKeyScheduleExposed = errors.New("enclave: a sealing key's AES key schedule would reach the heap without being erased")

	// ErrProviderMessageLimit reports a [SoftwareProvider] in [ModePerOperation] reached 2^31 Protect operations.
	ErrProviderMessageLimit = errors.New("enclave: software provider reached its per-key message bound; use ModeRootKey or a hardware provider")

	// ErrProviderNotConstructed reports a software provider not built by [NewSoftwareProvider].
	ErrProviderNotConstructed = errors.New("enclave: software provider was not constructed with NewSoftwareProvider")

	// errHierarchyUninitialized marks a ModeRootKey hierarchy not yet built:
	// distinct from wiped, because uninitialized may initialize and wiped
	// must never.
	errHierarchyUninitialized = errors.New("enclave: sealer key hierarchy not yet initialized")

	// errProviderEmptyBlob is the cause of the SealError for a provider whose
	// Protect returned no blob.
	errProviderEmptyBlob = errors.New("enclave: provider returned an empty blob from Protect")
)

// SealError is the error behind [ErrSealFailed]; it unwraps to what failed.
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

// SealerWipedError is [ErrSealerWiped] with the failure that left the sealer wiped.
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

// contextError reports that the caller's context ended; it unwraps to each non-nil field.
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

	// ErrInvalidBackend is returned by [Register] for a nil backend or an invalid name.
	ErrInvalidBackend = errors.New("enclave: backend is nil or its name is not a valid backend name")

	// ErrCapabilityUnsupported reports that an operation needs a capability the handle or backend lacks.
	ErrCapabilityUnsupported = errors.New("enclave: the backend does not provide a capability this operation needs")

	// ErrInvalidImport is returned for invalid import options or a material length the algorithm does not take.
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

// Backend detection.

// ErrBackendUnavailable reports that a registered backend's [Prober.Probe]
// found it not usable on this host, so [Detect] passed it over. Every
// [ProbeError] matches it.
var ErrBackendUnavailable = errors.New("enclave: the backend is not usable on this host")

// ProbeError reports a registered backend whose [Prober.Probe] failed: why
// [Detect] passed it over. Match on [ErrBackendUnavailable]; Unwrap returns
// what the backend's Probe returned, so its own typed errors match too.
type ProbeError struct {
	// Backend is the name the backend is registered under.
	Backend string
	// Cause is what its Probe returned.
	Cause error
}

// Error is [ErrBackendUnavailable]'s text, the quoted name, then the cause.
func (e *ProbeError) Error() string {
	text := nameText(ErrBackendUnavailable, e.Backend)
	if e.Cause == nil {
		return text
	}
	return text + ": " + e.Cause.Error()
}

// Is reports every ProbeError as [ErrBackendUnavailable].
func (e *ProbeError) Is(target error) bool { return target == ErrBackendUnavailable }

// Unwrap returns what the backend's Probe returned.
func (e *ProbeError) Unwrap() error { return e.Cause }

// The secretmem backend.

// ErrMemfdSecretUnavailable reports that the host refused secretmem memory ([NewSecretMemory]).
var ErrMemfdSecretUnavailable = errors.New("enclave: memfd_secret memory is unavailable")

// MemfdSecretError is the error behind [ErrMemfdSecretUnavailable]; it unwraps to the refused call.
type MemfdSecretError struct {
	// Cause is the refused call's error or the recovered fault.
	Cause error
}

// Error is [ErrMemfdSecretUnavailable]'s text, followed by the cause's when
// there is one.
func (e *MemfdSecretError) Error() string { return causeText(ErrMemfdSecretUnavailable, e.Cause) }

// Is reports every MemfdSecretError as [ErrMemfdSecretUnavailable].
func (e *MemfdSecretError) Is(target error) bool { return target == ErrMemfdSecretUnavailable }

// Unwrap returns the cause.
func (e *MemfdSecretError) Unwrap() error { return e.Cause }

// Handle cleanup.

// ErrCleanupFailed reports cleanup that failed alongside another failure.
var ErrCleanupFailed = errors.New("enclave: cleanup failed; what it released may still hold its material")

// CleanupError reports an operation's failure and every cleanup failure that followed; match with errors.Is and errors.As.
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

// ErrSweepInProgress is returned by [WipeAll] when another sweep held the sweep slot until ctx ended; nothing was reclaimed.
var ErrSweepInProgress = errors.New("enclave: another WipeAll is in progress; nothing was swept")

// SweepError reports what an admitted [WipeAll] sweep found besides held pages: corruption, unwiped unmaps, failed sweepers.
type SweepError struct {
	// Corrupt counts entries with a failed canary found by this sweep or reported by Destroy since the last one.
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

// Is matches [ErrEnclaveCorrupted] when Corrupt is non-zero and [ErrReleasedWithoutWipe] when Unwiped is.
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

// withCleanupFailure joins failure and the cleanup failures after it into one flat [CleanupError].
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
func destroyOnFailure(failure error, e *lockedRegion) error {
	return withCleanupFailure(failure, e.Destroy())
}

// contextFailure returns nil while ctx is live, else the operation's error carrying a contextError.
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

// providerFailure passes a provider verdict through and wraps anything else in a [SealError] or [OpenError].
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
