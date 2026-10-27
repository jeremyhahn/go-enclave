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
	"reflect"
	"slices"
	"strings"
	"sync"
)

// The backend seam: what a hardware enclave module (a TEE, a secure element,
// a TPM, GPU confidential computing) implements so its enclaves stand where a
// memory enclave ([NewMemory]) stands. Locked memory is the default backend; every other
// backend ships as its own module. The design is docs/backends/architecture.md.

// Handle is the core every backend's enclave provides: a reference to
// material a [Backend] holds. Everything else an enclave can do is an optional
// capability, found by type assertion ([ByteAccess], [Freezer], [Deriver],
// [AEAD], [Attester], and the standard library's crypto.Signer and
// crypto.Decrypter); an operation that needs one a handle lacks fails with a
// [*CapabilityError], never a panic and never a silent fallback.
//
// A Handle's dynamic type is a pointer to shared state, so every copy of the
// handle refers to the same material and one Destroy reaches all of them.
// Every method, the capabilities' included, is safe for concurrent use and
// never panics on a live or destroyed handle. A nil receiver is outside the
// contract: a backend whose type supports one documents it.
//
// After Destroy, every capability method that returns an error returns
// [ErrEnclaveDestroyed], one sentinel for every backend. A method with no
// error result reports a non-secret constant and keeps reporting it: [AEAD]'s
// NonceSize and Overhead, and the public key from crypto.Signer's and
// crypto.Decrypter's Public.
type Handle interface {
	// Size reports the length in bytes of the material held, or 0 once it is
	// destroyed. For material that never leaves its device it is the key's
	// length as the backend defines it.
	Size() int

	// IsAlive reports whether the handle still holds its material.
	IsAlive() bool

	// Destroy releases the material: wiped, erased or deleted, as the backend
	// does it. It is idempotent, waits out in-flight borrows and operations,
	// and returns nil or a typed error. A nil error means the material is gone;
	// a backend documents which errors leave it held and whether calling
	// Destroy again resumes the release.
	Destroy() error

	// Backend returns the backend that made the handle, also once it is
	// destroyed. It never returns nil.
	Backend() Backend
}

// Backend makes and holds the material behind handles. The core is its name;
// everything else is an optional capability found by type assertion
// ([Importer], [Sweeper], [Confiner], [Attester], [Prober]). A backend reaches this package by
// explicit injection or by [Register]; none registers itself at import.
//
// A backend's concrete type is its native interface. Callers reach it with a
// type assertion, or with [As] when the backend wraps another.
type Backend interface {
	// Name is the label the backend is registered and configured under: 1 to
	// 64 bytes of lowercase ASCII letters, digits, '-' and '.', starting and
	// ending with a letter or digit, such as "tdx" or "sev-snp". It must return
	// the same value for the backend's whole life.
	//
	// It names a kind of backend, not an instance: two devices of one module,
	// or a budgeted [Allocator] and the default, report the same name, and at
	// most one of them is registered. Identity is the value h.Backend()
	// returns, never a lookup by name.
	Name() string
}

// ByteAccess is the capability of a handle whose material this process may
// read: locked memory, and the memory of a TEE the process runs inside.
// [NewMemory] documents how a memory enclave keeps each method's contract.
type ByteAccess interface {
	Handle

	// WithBytes calls fn with a view of the material and returns fn's error,
	// or [ErrEnclaveDestroyed]. The view is valid only during fn: fn must not
	// retain it or call a method on the same handle.
	WithBytes(fn func([]byte) error) error

	// EqualTo reports whether the handle holds exactly other, in time that
	// does not depend on the contents, or [ErrEnclaveDestroyed].
	EqualTo(other []byte) (bool, error)
}

// Freezer is the capability of a handle that can be made read-only, so a
// stray write faults. Freeze is idempotent and irreversible. A handle without
// it is either read-only from birth (material that never leaves its device)
// or cannot be protected; [ByteAccess] alone promises neither.
type Freezer interface {
	Handle

	// Freeze makes the material read-only. It waits out in-flight borrows and
	// returns [ErrEnclaveDestroyed] for a destroyed handle; a refusal leaves
	// the handle alive and writable.
	Freeze() error
}

// Deriver is the capability of a handle that derives new key material without
// the material leaving its backend, such as a secure element's KDF.
type Deriver interface {
	Handle

	// Derive returns a new handle, from the same backend, holding n bytes
	// derived from this handle's material and bound to info. The backend
	// defines the function and documents it; ctx bounds the device work as
	// [RootUnsealer] describes.
	Derive(ctx context.Context, info []byte, n int) (Handle, error)
}

// AEAD is the capability of a handle that seals and opens with an
// authenticated cipher whose key it holds, so the key never enters this
// process, such as a secure element's AES-GCM key. It is this package's own
// rather than cipher.AEAD, whose Seal has no error result and so cannot report
// a destroyed handle or a failed device call.
//
// Seal and Open follow cipher.AEAD's contract on dst, nonce and
// additionalData, except that every failure is an error: [ErrEnclaveDestroyed]
// once the handle is destroyed, [ErrInvalidNonce] for a nonce that is not
// NonceSize bytes, [ErrAEADAuthentication] when Open cannot authenticate, and
// the backend's own typed errors for the device. Neither panics, and a failed
// Open returns no plaintext.
type AEAD interface {
	Handle

	// NonceSize is the nonce length Seal and Open take; 0 for a cipher that
	// draws its own nonce and carries it in the ciphertext. It is a constant
	// of the algorithm, and valid after Destroy.
	NonceSize() int

	// Overhead is the most by which a ciphertext exceeds its plaintext. It is a
	// constant of the algorithm, and valid after Destroy.
	Overhead() int

	// Seal encrypts and authenticates plaintext and additionalData, appends the
	// result to dst and returns it.
	Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error)

	// Open authenticates and decrypts ciphertext and additionalData, appends
	// the plaintext to dst and returns it.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// Attester is the capability of producing evidence of what holds the
// material. A [Backend] that implements it attests the platform (a TDX quote,
// an SEV-SNP report); a [Handle] that implements it attests that one key (a
// TPM certification, a secure element's key attestation).
type Attester interface {
	// Attest returns evidence that binds nonce, which the caller chose and
	// verifies in the evidence. nonce is 1 to 64 bytes; a caller with more
	// hashes it first. A backend that cannot bind every byte it was given
	// refuses rather than truncating. ctx bounds the device work as
	// [RootUnsealer] describes.
	Attest(ctx context.Context, nonce []byte) (Evidence, error)
}

// Evidence is what an [Attester] produced. Verifying it is the caller's,
// against the format's own verifier; this package never parses it.
type Evidence struct {
	// Format names the encoding of Data, as the backend documents it, such as
	// "tdx-quote" or "sev-snp-report".
	Format string

	// Data is the evidence itself. The caller owns it.
	Data []byte
}

// Importer is the capability of a backend that accepts existing material.
// It is how material decrypted by a [Sealer], or generated in locked memory,
// reaches a backend that this process cannot write into directly.
type Importer interface {
	Backend

	// Import moves material into a new handle for the purpose and algorithm
	// opts name, and wipes the caller's slice on every return path, as
	// [NewMemory] does. The backend resolves opts with [NewImportSpec]
	// and returns its error; the handle then follows the contract of the
	// spec's [Purpose]. A backend that cannot hold that purpose and algorithm
	// refuses with a [*CapabilityError] naming [CapabilityImport], and a
	// material length the algorithm does not take is [ErrInvalidImport], both
	// before any device work. ctx bounds the device work as [RootUnsealer]
	// describes.
	Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error)
}

// Purpose says what imported material is for, so a backend can give it the
// object class, algorithm and usage policy its device requires. Each purpose
// fixes the contract of the handle Import returns.
type Purpose string

// The purposes an import may name.
const (
	// PurposeMaterial is arbitrary material the caller reads back, such as
	// what [Sealed] opens into a backend. It takes no algorithm. The
	// handle implements [ByteAccess], its view holds exactly the material,
	// and its Size is the material's length.
	PurposeMaterial Purpose = "material"

	// PurposeWrappingKey is a key that wraps other keys: a [Sealer]'s
	// wrapping key or one of its KEKs. It takes an algorithm. The handle
	// implements [AEAD] for that algorithm, so it wraps in the device, or
	// [ByteAccess], so the caller wraps in this process, or both; its Size is
	// the key's length. A backend that enforces usage limits the key to
	// wrapping.
	PurposeWrappingKey Purpose = "wrapping-key"

	// PurposeDataKey is a key that encrypts data: a data-encryption key
	// (DEK). It takes an algorithm, and its handle has the contract of
	// [PurposeWrappingKey], except that a backend that enforces usage limits
	// the key to encrypting data.
	PurposeDataKey Purpose = "data-key"
)

// Algorithm names the algorithm an imported key is for. It follows the rule
// on [Backend.Name]; a backend documents which it holds.
type Algorithm string

// The algorithms this package's sealing uses. A backend module may name its
// own.
const (
	AlgorithmAES256GCM Algorithm = "aes-256-gcm" // AES-256 in GCM mode
)

// ImportSpec is what an [Importer.Import] call asked for, resolved from its
// [ImportOption] set by [NewImportSpec]. Every import is transient: the
// material lives until its handle is destroyed or swept, and is never
// persisted on the device. Usage and persistence attributes join it as new
// fields and options, each defaulting to what the purpose implies and to
// transient.
type ImportSpec struct {
	// Purpose is what the material is for. Every import names one.
	Purpose Purpose
	// Algorithm is the algorithm a key is for: set for a key purpose, empty
	// for [PurposeMaterial].
	Algorithm Algorithm
}

// ImportOption sets one attribute of an [ImportSpec].
type ImportOption func(*ImportSpec)

// WithPurpose sets the import's [Purpose]. Every import needs one.
func WithPurpose(p Purpose) ImportOption {
	return func(s *ImportSpec) { s.Purpose = p }
}

// WithAlgorithm sets the import's [Algorithm], which a key purpose needs.
func WithAlgorithm(a Algorithm) ImportOption {
	return func(s *ImportSpec) { s.Algorithm = a }
}

// NewImportSpec applies opts in order and validates the result. It returns
// [ErrInvalidImport] for a nil option, a missing or unknown purpose, an
// algorithm on [PurposeMaterial], or a key purpose without a valid algorithm.
// An [Importer] calls it first, so every backend reads opts the same way.
func NewImportSpec(opts ...ImportOption) (ImportSpec, error) {
	var s ImportSpec
	for _, opt := range opts {
		if opt == nil {
			return ImportSpec{}, ErrInvalidImport
		}
		opt(&s)
	}
	switch s.Purpose {
	case PurposeMaterial:
		if s.Algorithm != "" {
			return ImportSpec{}, ErrInvalidImport
		}
	case PurposeWrappingKey, PurposeDataKey:
		if !validName(string(s.Algorithm)) {
			return ImportSpec{}, ErrInvalidImport
		}
	default:
		return ImportSpec{}, ErrInvalidImport
	}
	return s, nil
}

// Sweeper is the capability of a backend that can release every handle it
// holds at once, the backend's share of a shutdown [WipeAll].
type Sweeper interface {
	Backend

	// Sweep releases every live handle the backend made and returns how many
	// it could not release, with nil or a typed error, as [WipeAll] does for
	// locked memory. ctx bounds only waiting, for in-flight operations and
	// contended device sessions: everything not held is released even under
	// a done or nil ctx, a nil ctx never waits and never panics, and a ctx
	// ending during the sweep is not an error. It is safe to call repeatedly
	// and never calls [WipeAll].
	Sweep(ctx context.Context) (held int, err error)
}

// Confiner is the capability of a backend whose trust boundary holds this
// whole process, such as a TEE the process runs inside (TDX, SEV-SNP, a GPU
// confidential VM). Memory the process leaves on its heap, an AES key
// schedule included, is then unreadable from outside the boundary.
type Confiner interface {
	Backend

	// ConfinesProcess reports whether this process runs inside the backend's
	// boundary. It is fixed for the backend's life, and it never blocks.
	ConfinesProcess() bool
}

// Prober is the capability of a backend [Detect] can select: it ranks its own
// security and probes this host for what it needs. Both are the backend's own
// code; this package only compares ranks and records probe results, and
// holds no table of backends or ranks. A registered backend without it is
// never selected.
type Prober interface {
	Backend

	// Rank reports how secure the backend is: [Detect] prefers the usable
	// backend with the highest rank. The locked-memory backend reports 0 and
	// the secretmem backend ([NewSecretMemory]) 1; a backend that holds
	// material beyond the reach of this process's own memory, such as a TEE
	// or a secure element, reports more than 1. It is fixed for
	// the backend's life, and it never blocks.
	Rank() int

	// Probe reports whether the backend is usable on this host: nil, or the
	// backend's own typed error saying what is missing, such as a device that
	// is absent or refuses the process. It is safe to call repeatedly and
	// concurrently, returns the same verdict while the host is unchanged,
	// changes no process state that outlives the call, and never panics. ctx
	// bounds only waiting, for a device or a service; a nil ctx never ends.
	Probe(ctx context.Context) error
}

// Capability names an optional capability in a [CapabilityError].
type Capability string

// The capabilities this package names. A backend module may name its own.
const (
	CapabilityBytes   Capability = "bytes"   // [ByteAccess]
	CapabilityFreeze  Capability = "freeze"  // [Freezer]
	CapabilitySign    Capability = "sign"    // crypto.Signer
	CapabilityDecrypt Capability = "decrypt" // crypto.Decrypter
	CapabilityAEAD    Capability = "aead"    // [AEAD]
	CapabilityDerive  Capability = "derive"  // [Deriver]
	CapabilityAttest  Capability = "attest"  // [Attester]
	CapabilityImport  Capability = "import"  // [Importer]
	CapabilitySweep   Capability = "sweep"   // [Sweeper]
	CapabilityConfine Capability = "confine" // [Confiner]
	CapabilityProbe   Capability = "probe"   // [Prober]
)

// LockedMemoryBackendName is the name of the locked-memory backend, the
// default: what [DefaultBackend] returns and every unbudgeted memory enclave reports. It
// is always registered and cannot be registered again.
const LockedMemoryBackendName = "locked-memory"

// maxBackendName is the longest valid backend name, in bytes.
const maxBackendName = 64

// lockedMemory is the locked-memory backend: this package's own constructors.
type lockedMemory struct{}

// Name returns [LockedMemoryBackendName].
func (lockedMemory) Name() string { return LockedMemoryBackendName }

// lockedMemoryRank is the locked-memory backend's [Prober.Rank]: the floor a
// backend must rank above to be selected in its place.
const lockedMemoryRank = 0

// Rank returns 0: locked memory keeps material out of swap and core dumps,
// but in this process's own address space.
func (lockedMemory) Rank() int { return lockedMemoryRank }

// Probe returns nil: locked memory needs no device, and a refused lock is
// reported by the constructor that asked for it.
func (lockedMemory) Probe(context.Context) error { return nil }

// The backend registry. It holds the default from the start, as a value, so
// no import changes it; only Register adds to it.
var (
	backendsMu sync.RWMutex
	backends   = map[string]Backend{LockedMemoryBackendName: lockedMemory{}}
)

var (
	_ Handle     = (*lockedRegion)(nil)
	_ ByteAccess = (*lockedRegion)(nil)
	_ Freezer    = (*lockedRegion)(nil)
	_ Prober     = lockedMemory{}
	_ Importer   = (*budgetAllocator)(nil)
	_ Prober     = (*budgetAllocator)(nil)
)

// DefaultBackend returns the locked-memory backend, the one every constructor
// in this package uses. It is registered under [LockedMemoryBackendName].
func DefaultBackend() Backend { return lockedMemory{} }

// Register adds b to the process's backend registry under b.Name(), so
// [Lookup] can find it by name. Registering is always the caller's explicit
// act: no backend registers itself at import.
//
// It returns [ErrInvalidBackend] for a nil or typed-nil b, or a name that is
// not valid (see [Backend]), and a [*BackendExistsError] when the name is
// taken, by an earlier Register or by the default ([LockedMemoryBackendName]).
// A name is never rebound and a backend is never unregistered, so a
// configuration that names a backend resolves to the same instance for the
// process's life. Lookup(h.Backend().Name()) returns the backend that made h
// only when the registered instance made it: an injected, unregistered
// backend may share the name (see [Backend]). Register is safe for concurrent
// use.
func Register(b Backend) error {
	if isNilInterface(b) {
		return ErrInvalidBackend
	}
	name := b.Name()
	if !validName(name) {
		return ErrInvalidBackend
	}

	backendsMu.Lock()
	defer backendsMu.Unlock()
	if _, taken := backends[name]; taken {
		return &BackendExistsError{Name: name}
	}
	backends[name] = b
	return nil
}

// Lookup returns the backend registered under name, or a
// [*BackendNotRegisteredError]. [LockedMemoryBackendName] always resolves.
// Lookup is safe for concurrent use.
func Lookup(name string) (Backend, error) {
	backendsMu.RLock()
	b, ok := backends[name]
	backendsMu.RUnlock()
	if !ok {
		return nil, &BackendNotRegisteredError{Name: name}
	}
	return b, nil
}

// BackendNames returns the names of every registered backend, sorted, the
// default included.
func BackendNames() []string {
	backendsMu.RLock()
	names := make([]string, 0, len(backends))
	for name := range backends {
		names = append(names, name)
	}
	backendsMu.RUnlock()
	slices.Sort(names)
	return names
}

// namedSweeper is one entry of a [WipeAll] second-phase snapshot.
type namedSweeper struct {
	name    string
	sweeper Sweeper
}

// registeredSweepers snapshots, sorted by name, every registered backend other
// than the default that implements [Sweeper]. It holds the registry's read lock
// only for the copy, so the caller runs backend code without it.
func registeredSweepers() []namedSweeper {
	backendsMu.RLock()
	var snapshot []namedSweeper
	for name, b := range backends {
		if s, ok := b.(Sweeper); ok && name != LockedMemoryBackendName {
			snapshot = append(snapshot, namedSweeper{name: name, sweeper: s})
		}
	}
	backendsMu.RUnlock()
	slices.SortFunc(snapshot, func(a, b namedSweeper) int { return strings.Compare(a.name, b.name) })
	return snapshot
}

// validName reports whether name follows the rule on [Backend.Name], which
// an [Algorithm] follows too.
func validName(name string) bool {
	if name == "" || len(name) > maxBackendName {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case (c == '-' || c == '.') && i > 0 && i < len(name)-1:
		default:
			return false
		}
	}
	return true
}

// As reports whether v matches target and, if so, sets target to it. It is
// how a caller reaches a backend's, or a handle's, concrete type and so its
// native interface: v matches when its dynamic type is assignable to the type
// target points to, or when v has a method As(any) bool that returns true for
// target, which is how a wrapper exposes what it wraps. The As method sets
// target itself.
//
// It is errors.As without the chain, with one difference: a nil or typed-nil
// v, or a target that is not a non-nil pointer, returns false instead of
// panicking. A typed-nil v is refused before its As method could run on a nil
// receiver. As does not recover a panic raised by v's own As method.
func As(v, target any) bool {
	if isNilInterface(v) || target == nil {
		return false
	}
	ptr := reflect.ValueOf(target)
	if ptr.Kind() != reflect.Pointer || ptr.IsNil() {
		return false
	}
	if reflect.TypeOf(v).AssignableTo(ptr.Type().Elem()) {
		ptr.Elem().Set(reflect.ValueOf(v))
		return true
	}
	if x, ok := v.(interface{ As(any) bool }); ok {
		return x.As(target)
	}
	return false
}
