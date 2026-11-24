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

// The backend seam a hardware enclave module implements; see docs/backends/architecture.md.

// Handle is a reference to material a [Backend] holds; other abilities are capabilities found by type assertion.
type Handle interface {
	// Size reports the length in bytes of the material held, or 0 once it is
	// destroyed. For material that never leaves its device it is the key's
	// length as the backend defines it.
	Size() int

	// IsAlive reports whether the handle still holds its material.
	IsAlive() bool

	// Destroy releases the material; it is idempotent and waits out in-flight borrows.
	Destroy() error

	// Backend returns the backend that made the handle, also once it is
	// destroyed. It never returns nil.
	Backend() Backend
}

// Backend makes and holds the material behind handles; capabilities are found by type assertion.
type Backend interface {
	// Name is the backend's fixed registry label: 1 to 64 bytes of [a-z0-9.-], starting and ending alphanumeric.
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

// Freezer is the capability of a handle that can be made read-only; Freeze is idempotent and irreversible.
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

	// Derive returns a new handle from the same backend holding n bytes derived from this material and bound to info.
	Derive(ctx context.Context, info []byte, n int) (Handle, error)
}

// AEAD is the capability of a handle that seals and opens with a key it holds; every failure is an error.
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

// Attester is the capability of producing evidence of what holds the material.
type Attester interface {
	// Attest returns evidence binding nonce (1 to 64 bytes); longer nonces are refused, never truncated.
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

	// Import moves material into a new handle for the purpose and algorithm in opts, wiping the caller's slice on every path.
	Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error)
}

// Purpose says what imported material is for, so a backend can give it the
// object class, algorithm and usage policy its device requires. Each purpose
// fixes the contract of the handle Import returns.
type Purpose string

// The purposes an import may name.
const (
	// PurposeMaterial is arbitrary material the caller reads back through [ByteAccess].
	PurposeMaterial Purpose = "material"

	// PurposeWrappingKey is a key that wraps other keys, through [AEAD], [ByteAccess] or both.
	PurposeWrappingKey Purpose = "wrapping-key"

	// PurposeDataKey is a data-encryption key with the contract of [PurposeWrappingKey].
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

// ImportSpec is an [Importer.Import] request resolved by [NewImportSpec]; every import is transient.
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

// NewImportSpec applies opts in order and returns [ErrInvalidImport] for an invalid result.
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

	// Sweep releases every live handle the backend made and returns how many it could not release.
	Sweep(ctx context.Context) (held int, err error)
}

// Confiner is the capability of a backend whose trust boundary holds this whole process.
type Confiner interface {
	Backend

	// ConfinesProcess reports whether this process runs inside the backend's
	// boundary. It is fixed for the backend's life, and it never blocks.
	ConfinesProcess() bool
}

// Prober is the capability of a backend [Detect] can select: it ranks itself and probes this host.
type Prober interface {
	Backend

	// Rank is the backend's fixed security rank: locked memory 0, secretmem 1, TEEs and secure elements above 1.
	Rank() int

	// Probe reports whether the backend is usable on this host: nil or a typed error naming what is missing.
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

// Register adds b to the process registry under b.Name(); a name is never rebound and a backend never unregistered.
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

// As reports whether v matches target and sets it, like errors.As without the chain; nil inputs return false.
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
