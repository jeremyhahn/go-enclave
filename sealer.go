// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
)

var (
	// ErrSealerWiped reports that a shutdown sweep ([WipeAll]) destroyed this
	// sealer's keys. Everything sealed through it is permanently unopenable,
	// and the sealer FAILS CLOSED: it will never silently generate fresh keys.
	// Re-initialization is an explicit caller act — construct a new [Sealer] —
	// never an implicit side effect of the next call.
	//
	// The reason this is a DISTINCT error rather than a reuse of a plausible
	// existing one: silent re-keying after a sweep would fail in both
	// directions at once. The next seal would SUCCEED — so nothing is wrong at
	// the point where the mistake is made — and only previously sealed values
	// would fail, reporting [ErrSealedAuthentication], which the docs
	// correctly gloss as "tampered, or sealed under a different key". A
	// lifecycle bug would present to the operator as a security incident and
	// send them hunting an attacker who does not exist. The question to ask of
	// any error is what the operator will DO on reading it; when the honest
	// cause and the likely response diverge, the answer is a distinct error.
	// Never re-mint a key that other data depends on.
	//
	// The two modes differ here, and the asymmetry is deliberate rather than
	// incidental. In [ModeRootKey] the root and KEK hierarchy are registered
	// [MemoryEnclave]s, the sweep destroys them — correctly; leaving the key
	// that opens everything mapped at exit is what the sweep exists to
	// prevent — and this error follows. In [ModePerOperation] there is no
	// in-process root to destroy: the device still holds the key, a sweep
	// does not invalidate sealed values, and sealing continues to work. (The
	// pure-software [SoftwareProvider] is the exception in that mode: its
	// root IS an in-process enclave, so it reports this error after a sweep
	// like the hierarchy does.)
	ErrSealerWiped = errors.New("enclave: this sealer's keys were destroyed by a shutdown sweep; sealed values are unrecoverable and re-initializing requires constructing a new Sealer")

	// ErrProviderMode is returned by [NewSealer] when the injected provider
	// does not implement the interface the selected [Mode] requires —
	// [KeyProtector] for ModePerOperation, [RootUnsealer] for ModeRootKey.
	//
	// The refusal is at CONSTRUCTION on purpose. The capability check could be
	// deferred to the first seal, but a misconfiguration that fails at boot is
	// worth a great deal more than one that fails at the first credential
	// read; this error existing is the reason the seam is two interfaces
	// instead of one.
	ErrProviderMode = errors.New("enclave: provider does not implement the interface the selected sealing mode requires")

	// ErrInvalidMode is returned by [NewSealer] for a [Mode] value that names
	// no mode. It reports a programming mistake, not a runtime condition —
	// the two valid modes are compile-time constants.
	ErrInvalidMode = errors.New("enclave: unknown sealing mode")

	// ErrSealerInstalled is returned by [SetSealer] when the process sealer is
	// already set — by an earlier SetSealer, or by the first seal lazily
	// installing the software default. A sealer that could be replaced under
	// live sealed values would strand every one of them, so installation is
	// one-shot and fails closed. Install before anything can seal.
	ErrSealerInstalled = errors.New("enclave: a process sealer is already installed")

	// ErrNilSealer is returned by [SetSealer] for a nil *Sealer, and by
	// [Sealer.Seal] on a nil receiver. A nil sealer is a lost configuration
	// step, and installing one would turn every subsequent seal into a
	// panic.
	ErrNilSealer = errors.New("enclave: sealer is nil")

	// errHierarchyUninitialized is the internal marker for a ModeRootKey
	// hierarchy that has not been built yet — distinct from wiped, because
	// uninitialized may initialize and wiped must never.
	errHierarchyUninitialized = errors.New("enclave: sealer key hierarchy not yet initialized")

	// errProviderEmptyBlob names the provider-contract violation of a Protect
	// that returned no blob; it surfaces joined under ErrSealFailed.
	errProviderEmptyBlob = errors.New("enclave: provider returned an empty blob from Protect")
)

// Mode selects how often a [Sealer] invokes its provider — not whether one is
// present. Both modes share the same envelope; they differ in what protects
// the per-value DEK, and therefore in what an adversary who can read this
// process's live memory obtains.
//
// # ModePerOperation — the device is called on every seal and open
//
// The provider (a [KeyProtector]) protects each value's DEK individually. The
// long-lived key never enters this process, so a memory-reading adversary is
// bounded to the values actually OPEN during their window — everything else
// stays sealed, because opening it requires the device. The device sees the
// 32-byte DEK only, never the material: sending the value would mean bulk
// throughput across a device boundary, and — the reason that actually decides
// it — the plaintext would come back over the wire into an ordinary heap
// buffer instead of being decrypted directly into locked pages, surrendering
// the one property this type exists for in the mode chosen for being the most
// secure. Suited to an HSM that sustains many concurrent sessions.
//
// # ModeRootKey — the device is called once; an in-memory hierarchy does the rest
//
// The provider (a [RootUnsealer]) yields a root key once. The root protects
// key-encryption keys (KEKs) generated in-process; each value's DEK is
// wrapped under the current KEK. After the single unseal every operation is
// fast in-process crypto — suited to high-load servers, or a TPM that cannot
// sustain many simultaneous sessions.
//
// Stated plainly, because "hardware-rooted" reads as "hardware-safe":
// ModeRootKey is a SCALE ACCOMMODATION, not a security equal of
// ModePerOperation. After the unseal, the root and the current KEK are in
// process memory; against an adversary who can read it, that is a total
// compromise — the root opens every KEK and the KEKs open every DEK. What it
// does buy over the pure-software default is the ORIGIN AND GATING of the
// root: the key cannot be obtained without the device, and it can be bound to
// a TPM PCR policy so it unseals only on an attested boot. That is a real
// property, and it is a different one from "the key never enters the
// process". A deployment that picks this mode for throughput should know
// exactly which guarantee it traded away.
//
// The zero value is ModeRootKey, which is also what the process default uses:
// with the [SoftwareProvider], that is plain software sealing with no
// hardware anywhere — today's behavior, out of the box.
type Mode uint8

const (
	// ModeRootKey unseals a root once and runs an in-memory KEK hierarchy.
	// See [Mode] for what that trades against ModePerOperation.
	ModeRootKey Mode = iota

	// ModePerOperation calls the provider on every seal and open, on the DEK
	// only. See [Mode].
	ModePerOperation
)

// modeNames drives [Mode.String]; a mode missing here is exactly the
// condition [ErrInvalidMode] reports.
var modeNames = map[Mode]string{
	ModeRootKey:      "ModeRootKey",
	ModePerOperation: "ModePerOperation",
}

// String names the mode for diagnostics.
func (m Mode) String() string {
	if name, ok := modeNames[m]; ok {
		return name
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

// kekBytes selects AES-256 for the key-encryption keys of [ModeRootKey].
const kekBytes = 32

// kekMessageLimit is how many DEKs one KEK generation may wrap before it is
// retired.
//
// crypto/cipher is explicit about the bound: "A given key MUST NOT be used to
// encrypt more than 2^32 messages, to limit the risk of a random nonce
// collision to negligible levels." NewGCMWithRandomNonce draws a 96-bit nonce
// per wrap, so the birthday bound is the whole of what stands between this
// and reusing one — and a repeated GCM nonce is not a weakness but a break.
// A KEK wraps exactly one DEK per sealed value, so it is the one key in the
// hierarchy that approaches the bound: the DEK seals a single message, and
// the root wraps a single blob per KEK generation.
//
// Set to half the documented ceiling. The margin costs nothing: a sealer that
// reaches it has wrapped two billion DEKs and simply gets a fresh
// generation. Retiring a generation costs BYTES, not a locked page — the
// retired KEK's enclave is destroyed and its root-wrapped blob (under a
// hundred bytes) is retained so values sealed under it keep opening.
const kekMessageLimit = 1 << 31

// Blob framing. Every wrapped-key blob this package produces itself starts
// with a fixed header that is also the AAD of the wrapping, so a blob cannot
// be re-purposed across kinds or generations even in constructions where the
// keys alone would not catch it. Provider blobs in [ModePerOperation] are
// opaque and carry whatever framing the provider chose.
const (
	// blobVersion versions the internal blob layout. There is no cross-version
	// compatibility promise — sealed values do not outlive the process (see
	// [SealedEnclave] on foreign bytes) — but an explicit version byte makes
	// an accidental format change fail authentication instead of misparse.
	blobVersion = 1

	// blobKindDEK marks a DEK wrapped under a KEK generation.
	blobKindDEK byte = 1
	// blobKindKEK marks a KEK wrapped under the root.
	blobKindKEK byte = 2
	// blobKindProvider marks a key protected by [SoftwareProvider].
	//
	// Kind 4 is RESERVED, not declared: the composed Decrypter+Signer
	// adapter framed its blobs with kind 4 before being split out of the
	// initial seam PR to its own decision (issue #50). A future kind must
	// not take the value, so blobs any historical build produced cannot
	// collide with it.
	blobKindProvider byte = 3

	// blobHeaderLen is version + kind + a 4-byte big-endian generation.
	// Blob kinds without a generation carry zero there rather than a shorter
	// header, so there is exactly one frame to parse.
	blobHeaderLen = 6
)

// blobHeader builds the framing header for kind and gen; it is both prefix
// and AAD of the wrapping it frames.
func blobHeader(kind byte, gen uint32) []byte {
	h := make([]byte, blobHeaderLen)
	h[0] = blobVersion
	h[1] = kind
	binary.BigEndian.PutUint32(h[2:], gen)
	return h
}

// parseBlobHeader splits a blob into its frame and body. Any malformation is
// an authentication failure — a blob this package's own code did not produce.
func parseBlobHeader(blob []byte) (kind byte, gen uint32, body []byte, err error) {
	if len(blob) < blobHeaderLen || blob[0] != blobVersion {
		return 0, 0, nil, ErrSealedAuthentication
	}
	return blob[1], binary.BigEndian.Uint32(blob[2:blobHeaderLen]), blob[blobHeaderLen:], nil
}

// fillRandom fills b from the CSPRNG; it is the WithBytes body every key
// generation in this package uses.
func fillRandom(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// Sealer produces and opens [SealedEnclave] values under an injected crypto
// provider. Construct one with [NewSealer] for explicit configuration, or use
// the package-level [NewSealed]/[SetSealer] for the one-per-process shape
// most consumers want.
//
// A Sealer is safe for concurrent use. It has no Destroy: its keys are
// registered [MemoryEnclave]s reclaimed by the process's shutdown [WipeAll],
// and a sealer is a process-lifetime object — the provider is selected once
// per process, not per value. After a sweep it fails closed; see
// [ErrSealerWiped].
type Sealer struct {
	mode Mode

	// Exactly one of kp / ru is non-nil, established at construction against
	// the mode; protect and unprotect are bound there too, so the mode is
	// decided once instead of branched on per operation.
	kp        KeyProtector
	ru        RootUnsealer
	protect   func(dek *MemoryEnclave) ([]byte, error)
	unprotect func(blob []byte, dek *MemoryEnclave) error

	// ModeRootKey hierarchy state. mu is read-locked for the per-value work —
	// wrapping and unwrapping DEKs — and write-locked only to initialize and
	// to rotate, so seals and opens run concurrently and a rotation waits out
	// in-flight users of the outgoing KEK instead of destroying it under
	// them. root is set once and never cleared: a wiped hierarchy keeps its
	// dead enclaves precisely so the wiped state is DETECTABLE, which is what
	// [ErrSealerWiped]'s fail-closed contract rests on.
	mu       sync.RWMutex
	root     *MemoryEnclave
	kek      *MemoryEnclave
	kekGen   uint32
	kekUsed  atomic.Uint64
	kekBlobs map[uint32][]byte
}

// sealerConfig collects what the options set; see [NewSealer].
type sealerConfig struct {
	provider any
	// providerSet distinguishes "option absent" (default the software
	// provider) from "option passed nil" (refuse) — an untyped nil provider
	// is indistinguishable from absence by value alone.
	providerSet bool
	mode        Mode
}

// SealerOption configures [NewSealer].
type SealerOption func(*sealerConfig)

// WithProvider injects the crypto provider the sealer roots its sealing in.
//
// p is typed any because the seam is TWO capabilities, not one: a provider
// implements [KeyProtector], [RootUnsealer], or both, and which one the
// sealer requires depends on the [Mode] selected alongside it. The static
// typing this gives up is bought back at construction: [NewSealer] refuses,
// with [ErrProviderMode], any provider that does not implement the selected
// mode's interface, so a mismatch cannot survive past boot.
//
// Omitting this option selects the pure-software [SoftwareProvider], which
// serves either mode. PASSING a nil provider — typed or untyped — is refused
// at construction with [ErrProviderMode] instead: a nil here is a lost
// configuration step (a provider variable that was never assigned), and the
// two ways of getting it wrong are both fail-open. Defaulting would silently
// swap the hardware provider a deployment configured for the software one;
// accepting it would pass the interface assertions — a typed nil satisfies
// the TYPE — and panic at the first seal, where a construction-time typed
// error belongs.
func WithProvider(p any) SealerOption {
	return func(c *sealerConfig) { c.provider, c.providerSet = p, true }
}

// WithMode selects the [Mode]. Omitting it selects [ModeRootKey], which with
// the default provider reproduces plain software sealing.
func WithMode(m Mode) SealerOption {
	return func(c *sealerConfig) { c.mode = m }
}

// modeBindings maps each mode to the constructor step that checks the
// provider's capability and binds the mode's protect/unprotect paths. A mode
// absent from this map is invalid by definition, which makes the map the
// validator as well as the dispatcher.
var modeBindings = map[Mode]func(*Sealer, any) error{
	ModeRootKey:      bindRootKey,
	ModePerOperation: bindPerOperation,
}

// NewSealer returns a Sealer for the given provider and mode.
//
// With no options it is the pure-software default — [SoftwareProvider],
// [ModeRootKey] — and cannot fail. With options it returns [ErrInvalidMode]
// for a mode that names nothing and [ErrProviderMode] for a provider that
// does not implement the selected mode's interface; both are construction
// failures on purpose, so a misconfigured deployment dies at boot rather
// than at its first credential.
//
// The returned Sealer performs no crypto and touches no locked memory until
// its first Seal; a hardware provider is therefore not consulted at
// construction, and a device problem surfaces from the first operation that
// needs it.
func NewSealer(opts ...SealerOption) (*Sealer, error) {
	cfg := sealerConfig{mode: ModeRootKey}
	for _, opt := range opts {
		opt(&cfg)
	}

	bind, ok := modeBindings[cfg.mode]
	if !ok {
		return nil, ErrInvalidMode
	}
	if !cfg.providerSet {
		cfg.provider = NewSoftwareProvider()
	} else if isNilInterface(cfg.provider) {
		// Refused HERE, not defaulted and not deferred: see [WithProvider].
		// The typed-nil half is the treacherous one — it satisfies the
		// interface assertions below and detonates at the first seal.
		return nil, ErrProviderMode
	}

	s := &Sealer{mode: cfg.mode}
	if err := bind(s, cfg.provider); err != nil {
		return nil, err
	}
	return s, nil
}

// isNilInterface reports whether v is nil in either of Go's two spellings:
// the untyped nil interface, or a non-nil interface wrapping a nil value of a
// nil-capable kind. The second is the one that `== nil` and interface
// assertions cannot catch — (*SoftwareProvider)(nil) type-asserts
// successfully to both seam interfaces, and a nil *rsa.PrivateKey is a
// perfectly typed crypto.Decrypter — and calling any method on it panics.
//
// It is THE check for every interface-typed input this package will call
// methods on — today that is the injected provider ([NewSealer]). Guarding
// one constructor and not the next is how the class survives its instances:
// the typed-nil defect was found and fixed on WithProvider first, then found
// AGAIN, identical, in the very next interface-taking constructor one review
// round later (the Decrypter/Signer adapter, since split out to issue #50).
// New interface-typed inputs route through here, not through `== nil`. The
// kind switch is scoped to exactly the kinds
// reflect.Value.IsNil accepts, so a legitimate value-typed implementation is
// never probed with a call that would panic on it.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Chan, reflect.Func, reflect.Slice, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// bindRootKey checks and installs a [RootUnsealer]; see [modeBindings].
func bindRootKey(s *Sealer, p any) error {
	ru, ok := p.(RootUnsealer)
	if !ok {
		return ErrProviderMode
	}
	s.ru = ru
	s.protect = s.protectRootKey
	s.unprotect = s.unprotectRootKey
	return nil
}

// bindPerOperation checks and installs a [KeyProtector]; see [modeBindings].
func bindPerOperation(s *Sealer, p any) error {
	kp, ok := p.(KeyProtector)
	if !ok {
		return ErrProviderMode
	}
	s.kp = kp
	s.protect = s.protectPerOperation
	s.unprotect = s.unprotectPerOperation
	return nil
}

// Mode reports the mode this sealer was constructed with.
func (s *Sealer) Mode() Mode {
	return s.mode
}

// Seal encrypts data and returns the sealed enclave holding it. It is
// [NewSealed] for an explicitly constructed Sealer; the ownership contract,
// the envelope and the failure surface are documented there and on
// [SealedEnclave].
func (s *Sealer) Seal(data []byte) (*SealedEnclave, error) {
	if s == nil {
		// The caller's material is not left behind even when the caller lost
		// its sealer: the ownership contract holds on every path.
		Wipe(data)
		return nil, ErrNilSealer
	}
	if len(data) == 0 {
		Wipe(data)
		return nil, ErrEmptyEnclave
	}

	// Wiped on EVERY return path, which is what the ownership contract
	// promises — including the failure paths, where nothing was encrypted and
	// the material would otherwise survive in the caller's memory.
	defer Wipe(data)

	// Before any key is touched, so an oversized input costs nothing — no
	// locked page, no provider call, no KEK message. See [ErrMaterialTooLarge]
	// for why this is an error rather than the panic crypto/cipher would
	// raise.
	if err := sealableLength(uint64(len(data))); err != nil {
		return nil, err
	}

	dek, err := newKeyEnclave(dekBytes)
	if err != nil {
		return nil, err
	}
	defer dek.Destroy()

	blob, err := s.protect(dek)
	if err != nil {
		return nil, err
	}

	// The blob is the AAD: this is the binding [SealedEnclave] documents as
	// load-bearing, and the one a substituted or re-paired envelope fails on.
	sealed, err := sealWithKey(dek, data, blob)
	if err != nil {
		return nil, err
	}

	return &SealedEnclave{sealer: s, sealed: sealed, blob: blob, size: len(data)}, nil
}

// open recovers a sealed envelope produced by this sealer. It is called by
// [SealedEnclave.Open] (a is nil) and [SealedEnclave.OpenWith] (a is the
// caller's Allocator) under that value's read lock.
//
// THE DESTINATION IS ALLOCATED FIRST, and that order is load-bearing rather
// than incidental. It is the one admitted allocation on this path, so taking
// it first makes it the GATE: an open the budget refuses has allocated no
// locked memory at all and has not touched a key, and the transient pages
// below can only exist behind a reservation that was granted. Allocating the
// DEK first — the order this had before budgets existed — would let a flood
// of opens each take an unadmitted locked page BEFORE meeting the budget,
// which is precisely the unbounded consumption an [Allocator] exists to stop.
//
// The cost of the order is that a value whose envelope fails to authenticate
// has had a destination mapped and locked for nothing. That is affordable
// here and would not be everywhere: this package accepts no foreign sealed
// bytes, so an envelope reaching this function was produced by this process.
func (s *Sealer) open(a *Allocator, blob, sealed []byte, size int) (*MemoryEnclave, error) {
	// The gate. allocSized admits it against a, or allocates it unadmitted
	// when a is nil, which is how [SealedEnclave.Open] keeps its contract.
	out, err := allocSized(a, size)
	if err != nil {
		return nil, err
	}

	// The DEK is recovered INTO locked memory: the destination exists before
	// the provider or hierarchy is asked to fill it, which is what lets a
	// capable provider write the key straight into locked pages.
	//
	// It is NOT admitted, and that is a decision with a rejected alternative
	// behind it; see [SealedEnclave.OpenWith] for why a second reservation per
	// open is worse than an unadmitted page that a granted reservation gates.
	dek, err := NewMemoryEnclaveSized(dekBytes)
	if err != nil {
		out.Destroy()
		return nil, err
	}
	defer dek.Destroy()

	if err := s.unprotect(blob, dek); err != nil {
		out.Destroy()
		return nil, err
	}

	if err := out.WithBytes(func(pt []byte) error {
		// The blob is verified as AAD here even though the DEK unwrap already
		// authenticated it: this is what refuses an envelope whose two halves
		// are individually authentic but were never sealed together.
		return openWithKeyInto(dek, sealed, blob, pt)
	}); err != nil {
		out.Destroy()
		return nil, err
	}
	return out, nil
}

// protectPerOperation wraps the DEK by calling the provider, inside the DEK's
// borrow so the provider reads the key straight out of locked pages.
func (s *Sealer) protectPerOperation(dek *MemoryEnclave) ([]byte, error) {
	var blob []byte
	if err := dek.WithBytes(func(k []byte) error {
		b, perr := s.kp.Protect(k)
		if perr != nil {
			return perr
		}
		if len(b) == 0 {
			// A provider that "protected" a key into nothing has violated the
			// contract; sealing under an unrecoverable blob would strand the
			// value at its first Open with a misleading authentication error.
			return errors.Join(ErrSealFailed, errProviderEmptyBlob)
		}
		blob = b
		return nil
	}); err != nil {
		return nil, providerSealFailure(err)
	}
	return blob, nil
}

// unprotectPerOperation recovers the DEK by calling the provider, handing it
// the locked destination. Provider errors surface unchanged, per the
// [KeyProtector] contract: an authentication refusal already matches
// [ErrSealedAuthentication], and an infrastructure failure must not be
// dressed as one.
func (s *Sealer) unprotectPerOperation(blob []byte, dek *MemoryEnclave) error {
	return dek.WithBytes(func(k []byte) error {
		return s.kp.Unprotect(blob, k)
	})
}

// providerSealFailure shapes a seal-path failure: this package's own
// sentinels pass through untouched — [ErrSealerWiped] in particular must stay
// distinct, that being its entire point — and anything else is joined under
// [ErrSealFailed] so a caller matching the documented sentinel catches
// provider-specific failures too, with the cause reachable through errors.As.
func providerSealFailure(err error) error {
	for _, sentinel := range []error{
		ErrSealerWiped, ErrSealFailed, ErrLockedMemoryUnavailable, ErrProviderMessageLimit, ErrEnclaveDestroyed,
	} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	return errors.Join(ErrSealFailed, err)
}

// hierarchyFailure translates a hierarchy-key failure. Root and KEK enclaves
// are used only under s.mu, and nothing holding s.mu destroys them — so an
// [ErrEnclaveDestroyed] from one of them means exactly one thing: a shutdown
// sweep ran, and the honest report is [ErrSealerWiped], not a generic
// destroyed-enclave error pointing at an enclave the caller never knew
// existed.
func hierarchyFailure(err error) error {
	if errors.Is(err, ErrEnclaveDestroyed) {
		return ErrSealerWiped
	}
	return err
}

// protectRootKey wraps the DEK under the current KEK generation, initializing
// or rotating the hierarchy first when needed.
//
// The loop retries after an initialization or rotation rather than composing
// the states inline: each pass re-reads the hierarchy under the read lock, so
// however the race with a concurrent initializer or rotator falls out, the
// wrap below always uses a generation observed consistent under the lock it
// runs under.
func (s *Sealer) protectRootKey(dek *MemoryEnclave) ([]byte, error) {
	for {
		s.mu.RLock()

		if s.root == nil {
			s.mu.RUnlock()
			if err := s.initHierarchy(); err != nil {
				return nil, err
			}
			continue
		}
		if !s.root.IsAlive() || !s.kek.IsAlive() {
			s.mu.RUnlock()
			return nil, ErrSealerWiped
		}

		// Reserve a message from the current generation BEFORE wrapping, so a
		// failed wrap still consumes a count — over-counting rotates slightly
		// early, which is the safe direction to be wrong in. Crossing the
		// limit means this generation is spent: release the read lock, rotate
		// under the write lock, and retry against the fresh generation.
		if s.kekUsed.Add(1) > kekMessageLimit {
			s.mu.RUnlock()
			if err := s.rotateKEK(); err != nil {
				return nil, err
			}
			continue
		}

		header := blobHeader(blobKindDEK, s.kekGen)
		var body []byte
		err := dek.WithBytes(func(k []byte) error {
			b, werr := sealWithKey(s.kek, k, header)
			if werr != nil {
				return werr
			}
			body = b
			return nil
		})
		s.mu.RUnlock()

		if err != nil {
			return nil, hierarchyFailure(err)
		}
		return append(header, body...), nil
	}
}

// unprotectRootKey recovers a DEK wrapped by protectRootKey: current
// generation under the live KEK, retired generations by unwrapping the
// retained KEK blob under the root first.
func (s *Sealer) unprotectRootKey(blob []byte, dek *MemoryEnclave) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.root == nil {
		// This sealer has sealed nothing, so no blob can be its own. Reported
		// as authentication rather than as a state error because that is what
		// it is from the caller's side: a blob this sealer's protect did not
		// produce.
		return ErrSealedAuthentication
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		return ErrSealerWiped
	}

	kind, gen, body, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindDEK {
		return ErrSealedAuthentication
	}
	header := blob[:blobHeaderLen]

	kek := s.kek
	if gen != s.kekGen {
		kekBlob, ok := s.kekBlobs[gen]
		if !ok {
			// A generation this sealer never minted: a foreign or corrupted
			// blob, indistinguishable from any other forgery on purpose.
			return ErrSealedAuthentication
		}
		retired, uerr := s.unwrapRetiredKEKLocked(kekBlob)
		if uerr != nil {
			return uerr
		}
		// A retired generation is materialized for exactly one unwrap: it
		// costs a locked page for the duration of this call instead of for
		// the sealer's lifetime.
		defer retired.Destroy()
		kek = retired
	}

	if uerr := dek.WithBytes(func(k []byte) error {
		return openWithKeyInto(kek, body, header, k)
	}); uerr != nil {
		return hierarchyFailure(uerr)
	}
	return nil
}

// unwrapRetiredKEKLocked recovers a retired KEK generation from its
// root-wrapped blob into a fresh locked enclave the caller must destroy.
// The caller holds s.mu (read is enough: the root is only used, never
// changed) and has verified the hierarchy is alive.
func (s *Sealer) unwrapRetiredKEKLocked(kekBlob []byte) (*MemoryEnclave, error) {
	kek, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		return nil, err
	}
	if uerr := kek.WithBytes(func(k []byte) error {
		return openWithKeyInto(s.root, kekBlob[blobHeaderLen:], kekBlob[:blobHeaderLen], k)
	}); uerr != nil {
		kek.Destroy()
		return nil, hierarchyFailure(uerr)
	}
	return kek, nil
}

// initHierarchy performs the once-per-sealer root unseal and mints the first
// KEK generation. It is retried rather than memoized through sync.Once: the
// first attempt can fail at the RLIMIT_MEMLOCK ceiling or on a transient
// provider condition, and a ceiling is a condition that lifts. A sync.Once
// would make one transient failure permanent for the process lifetime.
func (s *Sealer) initHierarchy() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.root != nil {
		// Lost the initialization race — or found a sealer a sweep already
		// wiped, which must NOT be quietly rebuilt here: that is exactly the
		// silent re-keying [ErrSealerWiped] exists to prevent.
		if !s.root.IsAlive() || !s.kek.IsAlive() {
			return ErrSealerWiped
		}
		return nil
	}

	root, err := NewMemoryEnclaveSized(RootKeyBytes)
	if err != nil {
		return err
	}
	// The provider writes the root DIRECTLY into locked pages; it never
	// exists on the ordinary heap on this path. (What the provider does on
	// its side is its contract; see [RootUnsealer].)
	if err := root.WithBytes(func(b []byte) error {
		return s.ru.UnsealRoot(b)
	}); err != nil {
		root.Destroy()
		return providerSealFailure(err)
	}

	kek, blob, err := newGeneration(root, 1)
	if err != nil {
		root.Destroy()
		return err
	}

	// Published together, once everything has succeeded, so no reader can
	// observe a root without its KEK; the ready checks treat the pair as one
	// state.
	s.root = root
	s.kek, s.kekGen = kek, 1
	s.kekBlobs = map[uint32][]byte{1: blob}
	s.kekUsed.Store(0)
	return nil
}

// rotateKEK retires the current KEK generation and mints the next. The
// outgoing generation's live enclave is destroyed — the write lock guarantees
// no in-flight wrap or unwrap is using it — and its root-wrapped blob stays
// in kekBlobs so values sealed under it keep opening. That retention is the
// point of the hierarchy: rotation must never strand a sealed value, and a
// retired generation costs under a hundred heap bytes rather than a locked
// page.
func (s *Sealer) rotateKEK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.root == nil {
		// Unreachable: rotation is only requested by a seal that found the
		// hierarchy initialized, and nothing un-initializes one. Guarded so a
		// future refactoring mistake fails typed instead of dereferencing nil.
		return errors.Join(ErrSealFailed, errHierarchyUninitialized)
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		return ErrSealerWiped
	}
	if s.kekUsed.Load() <= kekMessageLimit {
		// Another goroutine rotated while this one waited for the lock; its
		// fresh generation has budget.
		return nil
	}

	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if err != nil {
		// The current generation stays in place: it is over its wrap budget
		// for NEW seals, so the next seal will retry this rotation, but every
		// value already sealed under it still opens.
		return err
	}

	s.kek.Destroy()
	s.kek, s.kekGen = kek, s.kekGen+1
	s.kekBlobs[s.kekGen] = blob
	s.kekUsed.Store(0)
	return nil
}

// newGeneration mints KEK generation gen: a fresh key in locked memory, plus
// that key wrapped under the root for retention after retirement.
func newGeneration(root *MemoryEnclave, gen uint32) (*MemoryEnclave, []byte, error) {
	kek, err := newKeyEnclave(kekBytes)
	if err != nil {
		return nil, nil, err
	}

	header := blobHeader(blobKindKEK, gen)
	var body []byte
	if err := kek.WithBytes(func(k []byte) error {
		b, werr := sealWithKey(root, k, header)
		if werr != nil {
			return werr
		}
		body = b
		return nil
	}); err != nil {
		kek.Destroy()
		return nil, nil, hierarchyFailure(err)
	}
	return kek, append(header, body...), nil
}

// The process sealer: the one [NewSealed] uses, so that a consumer with many
// seal sites configures the provider once instead of threading a *Sealer
// through all of them.
var (
	processSealerMu sync.Mutex
	// processSealerInstance is nil until [SetSealer] installs one or the
	// first seal lazily installs the software default. It is never cleared —
	// not even by a shutdown sweep, whose effect is the installed sealer
	// reporting [ErrSealerWiped] rather than a fresh sealer appearing.
	processSealerInstance *Sealer
)

// SetSealer installs s as the process sealer — the one [NewSealed] uses.
//
// It is ONE-SHOT and fails closed with [ErrSealerInstalled] once any process
// sealer exists, including the software default that the first [NewSealed]
// installs lazily. A process sealer that could change under live sealed
// values would strand every one of them, so the order is a startup
// obligation: install before anything can seal. A stray early seal is safe —
// it gets the software default — but it locks the configuration, which is
// stated here because it is surprising to discover.
//
// It returns [ErrNilSealer] for a nil sealer.
func SetSealer(s *Sealer) error {
	if s == nil {
		return ErrNilSealer
	}

	processSealerMu.Lock()
	defer processSealerMu.Unlock()

	if processSealerInstance != nil {
		return ErrSealerInstalled
	}
	processSealerInstance = s
	return nil
}

// processSealer returns the installed process sealer, lazily installing the
// pure-software default the first time nothing else was configured.
func processSealer() (*Sealer, error) {
	processSealerMu.Lock()
	defer processSealerMu.Unlock()

	if processSealerInstance == nil {
		s, err := NewSealer()
		if err != nil {
			// Unreachable — the default construction cannot fail — but
			// plumbed rather than ignored: an error swallowed here would
			// surface as a nil-sealer panic at the seal site.
			return nil, err
		}
		processSealerInstance = s
	}
	return processSealerInstance, nil
}

// resetProcessSealerForTest clears the process sealer so the package's own
// tests can exercise installation, the lazy default and the post-sweep state.
// Production code has no path to it on purpose: un-installing the process
// sealer under live sealed values is exactly what [SetSealer]'s one-shot
// contract exists to prevent.
func resetProcessSealerForTest() {
	processSealerMu.Lock()
	processSealerInstance = nil
	processSealerMu.Unlock()
}
