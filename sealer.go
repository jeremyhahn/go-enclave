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

	// ErrOpenabilityUnknown is returned by [SealedEnclave.Openable] when a
	// shutdown sweep has run since this value was sealed AND the sealer's
	// provider can report nothing about its own sealing state.
	//
	// It says "I cannot determine this", which is different from both of the
	// other answers and must not be collapsed into either. It is NOT
	// [ErrSealerWiped] — nothing is known to have been destroyed, and telling
	// an operator their keys are gone when they may be intact is its own
	// wrong answer — and it is emphatically not nil, which would be the
	// fail-open this sentinel exists to close.
	//
	// # When a caller sees it, and what to do
	//
	// Only in [ModePerOperation], only after a [WipeAll], and only with a
	// provider that supplies no health report. A provider that keeps its
	// sealing key wholly outside this process is unaffected by a sweep and
	// should say so with [WithProviderHealth]; one that does gets a precise
	// answer instead of this one. Until it does, the honest report is that
	// this package cannot see far enough to answer.
	//
	// The action is to OPEN THE VALUE and let the result decide. Open is the
	// operation that knows; this is a diagnostic, and an inconclusive
	// diagnostic is not a failure of the value.
	//
	// IT IS PUBLIC API. Callers will match on it with [errors.Is], so its
	// identity is part of this package's compatibility surface — adding it is
	// not free, and it was weighed as such rather than treated as an
	// implementation detail.
	ErrOpenabilityUnknown = errors.New("enclave: a shutdown sweep has run since this value was sealed and its provider reports no sealing-state health, so openability cannot be determined; open the value to find out")

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
//
// # No mutex of a Sealer's is ever held across its provider
//
// Every call that can reach the provider takes a context, and the provider
// may block for as long as a device does. So the Sealer has TWO locks with
// disjoint jobs, taken in one order — init slot, then mu — and never the
// other way:
//
//   - the INIT SLOT serializes first-time [ModeRootKey] initialization, and is
//     the only lock of the Sealer's held across [RootUnsealer.UnsealRoot]. It
//     is a one-slot channel rather than a mutex so that a caller waiting for
//     it can give up when its context ends; a mutex wait cannot be abandoned.
//   - mu guards the published hierarchy. It is held only to read that state
//     and to publish or rotate it — in-process work with no provider call
//     anywhere beneath it.
//
// The consequence is the guarantee callers can rely on (#87): a provider
// stalled inside UnsealRoot stalls only the callers that need the hierarchy
// it is producing, each for no longer than its own context allows. Seals and
// opens on an initialized Sealer, and every other Sealer, proceed. Beyond the
// init slot, the only lock that spans a provider call is the read borrow of
// the enclave the provider reads from or writes into — a private, per-call
// enclave no other caller can reach.
type Sealer struct {
	mode Mode

	// Exactly one of kp / ru is non-nil, established at construction against
	// the mode; protect and unprotect are bound there too, so the mode is
	// decided once instead of branched on per operation.
	kp KeyProtector
	ru RootUnsealer

	// health is the provider's optional report on its own IN-PROCESS sealing
	// state, supplied with [WithProviderHealth]. nil when the provider
	// offered none, which is the case the sweep-generation fallback covers.
	// Set once at construction and never written again, so it is read without
	// the lock like kp and ru.
	health    func() error
	protect   func(ctx context.Context, dek *MemoryEnclave) ([]byte, error)
	unprotect func(ctx context.Context, blob []byte, dek *MemoryEnclave) error

	// ModeRootKey hierarchy state. mu is read-locked for the per-value work —
	// wrapping and unwrapping DEKs — and write-locked only to PUBLISH the
	// initialized hierarchy and to rotate, so seals and opens run concurrently
	// and a rotation waits out in-flight users of the outgoing KEK instead of
	// destroying it under them. It is never held across a provider call; the
	// root unseal runs under initSlot instead (see [Sealer]). root is set once
	// and never cleared: a wiped hierarchy keeps its dead enclaves precisely so
	// the wiped state is DETECTABLE, which is what [ErrSealerWiped]'s
	// fail-closed contract rests on.
	mu       sync.RWMutex
	root     *MemoryEnclave
	kek      *MemoryEnclave
	kekGen   uint32
	kekUsed  atomic.Uint64
	kekBlobs map[uint32][]byte

	// initSlot is the init lock: a one-slot semaphore, held by sending into
	// it and released by receiving. Holding it is the right to run
	// initHierarchy's unseal-and-mint, and to read or write pendingRoot and
	// pendingGen. A channel rather than a sync.Mutex for exactly one reason:
	// acquiring it is a select against the caller's ctx.Done(), so a caller
	// queued behind a provider that is slow to unseal gives up when its own
	// context ends instead of inheriting the provider's stall. Made by
	// [NewSealer]; a Sealer not built there has no protect path and is not
	// usable anyway.
	initSlot chan struct{}

	// pendingRoot is a root that UnsealRoot DELIVERED but that has not been
	// published as root, because minting the first KEK under it failed —
	// memlock exhausted, the transient condition initHierarchy's retry exists
	// for. It is kept so that retry re-attempts only the mint: the
	// [RootUnsealer] contract is that UnsealRoot is called at most once unless
	// that call failed, and a one-shot root (a consumed unseal handle) cannot
	// be asked again (#83).
	//
	// It is deliberately NOT root. root non-nil means "a hierarchy exists and
	// every dead enclave in it is a sweep", and the wiped checks rely on that;
	// a root with no KEK beside it would read as wiped, since a nil kek is not
	// alive. It is an ordinary registered enclave, so [WipeAll] destroys it
	// like any other; initHierarchy then reports [ErrSealerWiped] rather than
	// unsealing a replacement. A DEAD pendingRoot is therefore the wiped state
	// of a sealer whose hierarchy was never published, and initHierarchy also
	// leaves one deliberately when a sweep overlapped the initialization.
	//
	// Guarded by initSlot, not mu: only the slot holder reads or writes it,
	// and no reader of the published hierarchy ever needs it.
	pendingRoot *MemoryEnclave

	// pendingKEK is the first KEK, minted under pendingRoot, between the mint
	// and publication — and AFTER a discard, any such KEK whose release the
	// kernel refused. It exists for that second case: a KEK minted while a
	// sweep overlapped the initialization is destroyed instead of published,
	// and if its unmap is refused the mapping is still held, so the sealer must
	// keep a reference and retry the release on every later attempt, exactly
	// as it does for the root. Dropping the reference would leave the release
	// to a future sweep alone and let later attempts report a clean
	// ErrSealerWiped over a KEK this sealer still holds. Cleared once the KEK is
	// published or its release succeeds. Guarded by initSlot.
	pendingKEK *MemoryEnclave

	// pendingGen is the sweep sequence read BEFORE the unseal that produced
	// pendingRoot — the same read-first discipline [Sealer.Seal] applies to a
	// value's sealedAtGen, for the same reason. Publication compares it with
	// the current sequence; see initHierarchy. Guarded by initSlot.
	pendingGen uint64
}

// sealerConfig collects what the options set; see [NewSealer].
type sealerConfig struct {
	provider any
	// providerSet distinguishes "option absent" (default the software
	// provider) from "option passed nil" (refuse) — an untyped nil provider
	// is indistinguishable from absence by value alone.
	providerSet bool
	mode        Mode
	health      func() error
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

// WithProviderHealth supplies a callback reporting whether the provider's
// IN-PROCESS sealing state is still intact: nil if this provider can still
// unprotect what it protected, [ErrSealerWiped] if a shutdown [WipeAll]
// destroyed key material it depends on.
//
// # What it is for, and what it is NOT for
//
// It answers ONE question: did a sweep of THIS PROCESS's memory take
// something this provider needs. It is not a device liveness probe. A
// provider whose key lives in a TPM, an HSM or a cloud KMS is unaffected by a
// sweep and should report nil unconditionally — reporting a momentarily
// unreachable device here would make [SealedEnclave.Openable] mean two
// different things depending on which provider is installed, and a caller
// could no longer read its result without knowing the deployment. A liveness
// probe for a device is a different API, and should be designed as one.
//
// That is also why the callback takes no context and MUST NOT block: the
// question is answered from this process's own state, so there is nothing to
// wait for, and [SealedEnclave.Openable] — which calls it — is a diagnostic
// with no context to bound a wait by. It is called with no lock of this
// package's held.
//
// # Why a callback rather than an interface
//
// The health seam inside this package is an unexported interface, which by
// Go's rules NO out-of-package type can satisfy — so before this option, an
// external provider had no way to report a sweep at all and
// [SealedEnclave.Openable] silently assumed it was fine. Exporting that
// interface would have invited the device-liveness confusion above; a
// callback keeps the question narrow and makes opting in explicit.
//
// # It is authoritative
//
// A provider that supplies this is BELIEVED: its answer is terminal, and the
// sweep-generation fallback behind [ErrOpenabilityUnknown] does not
// second-guess it. That is deliberate — a provider volunteering a health
// report is asserting knowledge about its own key storage, and this package
// has no better source. Supplying a callback that lies is therefore worse
// than supplying none.
//
// The trade is deliberate: a provider that opts in and answers wrongly is
// believed. It is still strictly better than the alternative it replaced,
// where EVERY out-of-package provider was silently assumed healthy and had no
// way to say otherwise.
//
// Ignored in [ModeRootKey], where the sealer's own hierarchy is in-process
// and this package can and does inspect it directly.
func WithProviderHealth(fn func() error) SealerOption {
	return func(c *sealerConfig) { c.health = fn }
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

	s := &Sealer{mode: cfg.mode, health: cfg.health, initSlot: make(chan struct{}, 1)}
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
// the envelope, the context contract and the failure surface are documented
// there and on [SealedEnclave].
func (s *Sealer) Seal(ctx context.Context, data []byte) (*SealedEnclave, error) {
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

	// An abandoned call costs nothing either: no locked page, no provider
	// call. After the argument checks, so a malformed call is reported as
	// malformed whatever the caller's deadline.
	if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
		return nil, err
	}

	// Taken BEFORE any key is touched, and deliberately not after. A sweep
	// that runs to completion during this call would leave the after-reading
	// equal to the current sequence, so the value would compare clean against
	// a sweep it actually lived through. Read first, and any sweep that
	// overlaps this seal shows up either as a changed sequence or as an odd
	// one.
	sealedAtGen := sweepGeneration()

	dek, err := newKeyEnclave(dekBytes)
	if err != nil {
		return nil, err
	}
	defer destroyTransient(dek)

	blob, err := s.protect(ctx, dek)
	if err != nil {
		return nil, err
	}

	// The blob is the AAD: this is the binding [SealedEnclave] documents as
	// load-bearing, and the one a substituted or re-paired envelope fails on.
	sealed, err := sealWithKey(dek, data, blob)
	if err != nil {
		return nil, err
	}

	return &SealedEnclave{
		sealer: s, sealed: sealed, blob: blob, size: len(data),
		sealedAtGen: sealedAtGen,
	}, nil
}

// open recovers a sealed envelope produced by this sealer. It is called by
// [SealedEnclave.Open] (a is nil) and [SealedEnclave.OpenWith] (a is the
// caller's Allocator) with NO lock held: the envelope halves are the value's,
// pinned by its in-flight count rather than by its lock, so a Destroy of the
// value never waits behind a provider call here (see [SealedEnclave.Destroy]).
//
// A context that has already ended is refused before the gate below, so an
// abandoned open costs nothing at all.
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
func (s *Sealer) open(ctx context.Context, a *Allocator, blob, sealed []byte, size int) (*MemoryEnclave, error) {
	if err := contextFailure(ctx, ErrOpenFailed, nil); err != nil {
		return nil, err
	}

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
		destroyTransient(out)
		return nil, err
	}
	defer destroyTransient(dek)

	if err := s.unprotect(ctx, blob, dek); err != nil {
		destroyTransient(out)
		return nil, err
	}

	if err := out.WithBytes(func(pt []byte) error {
		// The blob is verified as AAD here even though the DEK unwrap already
		// authenticated it: this is what refuses an envelope whose two halves
		// are individually authentic but were never sealed together.
		return openWithKeyInto(dek, sealed, blob, pt)
	}); err != nil {
		destroyTransient(out)
		return nil, err
	}
	return out, nil
}

// sealHealth is the optional capability a provider implements to report that
// it can no longer unprotect — today only [SoftwareProvider], whose root is an
// in-process enclave a shutdown sweep destroys.
//
// It is UNEXPORTED, and that is a decision rather than an oversight. A
// provider outside this package protects keys in a device, and a device
// survives a sweep of this process's memory: "still openable" is the correct
// answer for every such provider, so there is nothing for one to opt into.
// Exporting it would instead invite a provider to report transient
// infrastructure health (a device momentarily unreachable) through a question
// that is about THIS process's memory, and [SealedEnclave.Openable] would
// start meaning two different things depending on the provider. A liveness
// probe for a device is a different API, designed as one if it is ever wanted.
type sealHealth interface {
	openable() error
}

// openable reports whether this sealer could still open a value it sealed,
// answering only the question [SealedEnclave.Openable] documents: is the
// in-process key material this sealer depends on still there. It performs no
// crypto, generates nothing, and initializes nothing — a wiped sealer must
// never be rebuilt by being asked a question.
//
// It dispatches on STATE rather than on [Mode] deliberately. A switch on the
// mode needs a default arm, and a default arm is where a future mode silently
// acquires "reports openable, checks nothing". Both branches below are
// self-selecting: only a hierarchy mode has a root, and only a
// provider-per-operation mode has a KeyProtector, so a new mode is covered by
// whichever of the two it actually uses.
func (s *Sealer) openable(sealedAtGen uint64) error {
	if err := s.hierarchyOpenable(); err != nil {
		return err
	}

	// AN EXPLICIT ANSWER IS AUTHORITATIVE AND TERMINAL. Both arms below
	// return whatever the provider says, including nil, and the
	// sweep-generation fallback beneath them does not get to second-guess it.
	//
	// That precedence is the whole design, not a convenience, and the argument
	// matters more than the rule: a reader holding only "explicit wins" will
	// eventually decide that applying the fallback as well is the safer,
	// belt-and-braces choice, and will reintroduce the defect.
	//
	// It is not safer. The fallback exists BECAUSE a provider cannot be
	// interrogated; applying it on top of a provider that CAN be would mean a
	// provider supplying a health report could never return nil after a sweep
	// — its considered "the device still holds this key, the value still
	// opens" would be overwritten with "I cannot tell", so the report could
	// not express the one thing it exists to express. That is the same defect
	// as answering "unknown" unconditionally, which was weighed and rejected
	// for exactly this reason: an answer that reads the same whatever the
	// truth is cannot report anything.
	//
	// Both arms below are terminal, and each needs its own check because the
	// two are reached by different providers:
	//
	//	callback arm    TestSealedEnclave_OpenableBelievesAProviderThatReports
	//	                OpenableSplitsByMode/deviceHeldKeySurvivesTheSweep
	//	sealHealth arm  TestSealedEnclave_OpenableBelievesTheInPackageHealthSeam
	//
	// All three go RED if the fallback is allowed to override an explicit
	// answer. Run them before concluding that the extra check is free. The
	// sealHealth one had to be written specially: SoftwareProvider is that
	// seam's only production implementor and always reports wiped after a
	// sweep, so without a provider that reports HEALTHY after one, that arm's
	// precedence is unobservable — measured, by a mutant that survived the
	// entire suite until the test existed.
	if h, ok := s.kp.(sealHealth); ok {
		return h.openable()
	}
	// Gated on kp so the option is IGNORED in ModeRootKey exactly as it is
	// documented to be. Without the gate a caller reusing one health callback
	// across both modes could get ErrSealerWiped from a sealer whose own root
	// and KEK are demonstrably alive and whose Open would succeed — the
	// hierarchy above is authoritative in that mode, and a provider callback
	// must not be able to overrule it.
	if s.kp != nil && s.health != nil {
		return s.health()
	}

	// Nothing can answer. Fall back to whether a sweep has happened at all.
	//
	// Gated on kp because only ModePerOperation reaches here without an
	// answer: in ModeRootKey the hierarchy above IS the authoritative answer —
	// the root and KEK are this package's own enclaves and it inspects them
	// directly — so a nil from it is knowledge, not ignorance, and must not be
	// downgraded to ErrOpenabilityUnknown by a sweep that provably did not
	// take them.
	//
	// Reading one atomic word against a field written once at seal time and
	// never again: there is no pair to tear here and no lock to take that this
	// path does not already hold.
	// Two ways to be suspect, and the second is the one a plain counter
	// misses: a sweep has run since this value was sealed, OR the value was
	// sealed WHILE a sweep was in flight. In the second case the sequence can
	// read equal at both ends while the rest of that same sweep destroyed the
	// provider's key in between; see [sweepGen] on why the parity carries it.
	if s.kp != nil && (sweepInFlight(sealedAtGen) || sweepGeneration() != sealedAtGen) {
		return ErrOpenabilityUnknown
	}
	return nil
}

// hierarchyOpenable applies unprotectRootKey's wiped predicate without
// unwrapping anything. It is nil for a sealer that has no hierarchy at all —
// ModePerOperation, or a ModeRootKey sealer that has never sealed. The second
// case cannot be reached through [SealedEnclave.Openable], since a sealed
// value's existence means protectRootKey ran; if it somehow were, the honest
// answer is still nil, because nothing has been WIPED — an open would fail
// authentication, which is a different question and a different error.
func (s *Sealer) hierarchyOpenable() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// root is set once and never cleared, precisely so that a dead root is a
	// detectable state rather than an absent one; see the field comment.
	if s.root != nil && (!s.root.IsAlive() || !s.kek.IsAlive()) {
		return ErrSealerWiped
	}
	return nil
}

// protectPerOperation wraps the DEK by calling the provider, inside the DEK's
// borrow so the provider reads the key straight out of locked pages. That
// borrow is the only lock held across the call, and it is on an enclave
// private to this seal.
//
// The context is checked again AFTER the provider returns: a caller whose
// context ended while the device worked has abandoned the seal, and a blob it
// will never store is discarded rather than reported as a success the caller
// stopped waiting for.
func (s *Sealer) protectPerOperation(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	var blob []byte
	if err := dek.WithBytes(func(k []byte) error {
		b, perr := s.kp.Protect(ctx, k)
		if cerr := contextFailure(ctx, ErrSealFailed, perr); cerr != nil {
			return cerr
		}
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
// the locked destination. Provider errors are shaped by providerOpenFailure,
// per the [KeyProtector] contract: an authentication refusal already matches
// [ErrSealedAuthentication] and passes through, and an infrastructure failure
// is joined under [ErrOpenFailed] — never dressed as a forgery.
//
// As on the seal side, the context is checked after the provider returns: a
// DEK recovered for a caller that has stopped waiting is not used, and the
// deferred Destroy in open wipes it.
//
// PRECEDENCE when both happen: if the provider returned an error — ANY error,
// including a sentinel providerOpenFailure would otherwise pass through
// untouched — and the context has also ended, the error carries BOTH: it
// matches ErrOpenFailed, the context's error and the provider's error.
// contextFailure keeps the provider's error rather than replacing it. That
// matters most for an authentication failure, a forgery verdict and so a
// security signal that a cancellation landing in the same window must not
// erase; it matters for ErrSealerWiped and ErrLockedMemoryUnavailable too,
// since each still tells the caller something true.
func (s *Sealer) unprotectPerOperation(ctx context.Context, blob []byte, dek *MemoryEnclave) error {
	return providerOpenFailure(dek.WithBytes(func(k []byte) error {
		perr := s.kp.Unprotect(ctx, blob, k)
		if cerr := contextFailure(ctx, ErrOpenFailed, perr); cerr != nil {
			return cerr
		}
		return perr
	}))
}

// contextFailure is how every provider-reaching path in this package reports
// a context that has ended: nil while ctx is live; otherwise op — the
// operation's own sentinel, [ErrSealFailed] or [ErrOpenFailed] — joined with
// the context's error, so a caller matching either the operation's sentinel
// or context.Canceled / context.DeadlineExceeded catches it.
//
// cause is what the provider returned, if a provider call preceded the check,
// and is kept reachable: when it already matches ctx.Err() it REPLACES the bare
// context error, so a provider's wrapping ("tpm: session aborted: context
// canceled") is what the caller reads; otherwise it is joined alongside. A
// distinct [context.Cause] supplied by the canceler is joined too, since it
// is the one piece of this error that says WHY.
func contextFailure(ctx context.Context, op, cause error) error {
	ended := ctx.Err()
	if ended == nil {
		return nil
	}

	errs := []error{op}
	switch {
	case cause == nil:
		errs = append(errs, ended)
	case errors.Is(cause, ended):
		errs = append(errs, cause)
	default:
		errs = append(errs, ended, cause)
	}
	if why := context.Cause(ctx); why != nil && !errors.Is(why, ended) {
		errs = append(errs, why)
	}
	return errors.Join(errs...)
}

// providerSealFailure shapes a seal-path failure: this package's own
// sentinels pass through untouched — [ErrSealerWiped] in particular must stay
// distinct, that being its entire point — and anything else is joined under
// [ErrSealFailed] so a caller matching the documented sentinel catches
// provider-specific failures too, with the cause reachable through errors.As.
//
// "Untouched" holds while the caller's context is live. A provider error
// that arrives as the context ends has already been shaped by contextFailure
// — ErrSealFailed and ctx.Err() joined with it, so it still matches its own
// sentinel too — and passes through here in that joined form.
func providerSealFailure(err error) error {
	return shapeProviderFailure(ErrSealFailed, err,
		ErrSealerWiped, ErrSealFailed, ErrLockedMemoryUnavailable, ErrProviderMessageLimit, ErrEnclaveDestroyed)
}

// providerOpenFailure is providerSealFailure's mirror on the open path. The
// pass-through set differs in the one way that matters: an authentication
// refusal is the provider's verdict on the blob and must reach the caller as
// [ErrSealedAuthentication] alone, while everything that is NOT a verdict —
// a device unreachable, a context that ended — is joined under
// [ErrOpenFailed] and so can never be mistaken for one.
//
// As on the seal side, "untouched" holds while the caller's context is live;
// a provider error that arrives as it ends reaches here already joined with
// the cancellation by contextFailure, and is passed through in that form.
func providerOpenFailure(err error) error {
	return shapeProviderFailure(ErrOpenFailed, err,
		ErrSealedAuthentication, ErrSealerWiped, ErrOpenFailed, ErrLockedMemoryUnavailable, ErrEnclaveDestroyed)
}

// shapeProviderFailure returns err untouched if it is nil or matches one of
// passThrough, and joins it under op otherwise.
func shapeProviderFailure(op, err error, passThrough ...error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range passThrough {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	return errors.Join(op, err)
}

// hierarchyFailure translates a hierarchy-key failure. Root and KEK enclaves
// are used only under s.mu once published, and before publication only by
// the holder of initSlot; nothing in either position destroys one it is
// using — so an [ErrEnclaveDestroyed] from one of them means exactly one
// thing: a shutdown sweep ran, and the honest report is [ErrSealerWiped], not
// a generic destroyed-enclave error pointing at an enclave the caller never
// knew existed.
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
//
// Each pass checks the context first. That is the "after" half of honoring
// it around the one provider call this mode makes: an initialization that
// returned after this caller's context ended has still published its root —
// the unseal succeeded and must not be repeated — but the caller that asked
// for it is told it was abandoned rather than handed a seal it stopped
// waiting for.
func (s *Sealer) protectRootKeyInner(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	for {
		if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
			return nil, err
		}

		s.mu.RLock()

		if s.root == nil {
			s.mu.RUnlock()
			if err := s.initHierarchy(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if !s.root.IsAlive() || !s.kek.IsAlive() {
			s.mu.RUnlock()
			return nil, ErrSealerWiped // cleanup is retried at the boundary
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
//
// It takes the context only to fit the mode-independent unprotect seam: this
// path makes no provider call — the root was unsealed once, at the first seal
// — and is in-process crypto under the read lock, so there is nothing for a
// context to bound that open's entry check has not already covered.
// protectRootKey and unprotectRootKey are the single boundary every root-mode
// seal and open passes through, and the one place a dead hierarchy's cleanup
// is retried (#102): whatever path inside reported ErrSealerWiped — the
// liveness check, a wait for initialization that found the hierarchy already
// swept, a retired-generation unwrap whose root a sweep destroyed mid-call —
// the error is checked against the published hierarchy here, with no lock
// held, and if it is really dead the release of its keys is retried and any
// refusal joined in. Doing it at the boundary rather than at each exit is what
// keeps a new exit from silently skipping it.
func (s *Sealer) protectRootKey(ctx context.Context, dek *MemoryEnclave) ([]byte, error) {
	blob, err := s.protectRootKeyInner(ctx, dek)
	return blob, s.withDeadHierarchyCleanup(err)
}

func (s *Sealer) unprotectRootKey(ctx context.Context, blob []byte, dek *MemoryEnclave) error {
	return s.withDeadHierarchyCleanup(s.unprotectRootKeyRLocked(ctx, blob, dek))
}

// withDeadHierarchyCleanup returns err unchanged unless it reports
// ErrSealerWiped AND the published hierarchy is dead; then it retries the
// release of the hierarchy's keys and joins any refusal. The caller must not
// hold s.mu.
func (s *Sealer) withDeadHierarchyCleanup(err error) error {
	if err == nil || !errors.Is(err, ErrSealerWiped) {
		return err
	}
	s.mu.RLock()
	dead := s.root != nil && (!s.root.IsAlive() || !s.kek.IsAlive())
	s.mu.RUnlock()
	if !dead {
		return err
	}
	s.mu.Lock()
	cerr := s.wipeHierarchyLocked(nil)
	s.mu.Unlock()
	if cerr != nil {
		return errors.Join(err, cerr)
	}
	return err
}

func (s *Sealer) unprotectRootKeyRLocked(_ context.Context, blob []byte, dek *MemoryEnclave) error {
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
		return ErrSealerWiped // cleanup is retried at the boundary
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
		defer destroyTransient(retired)
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
		destroyTransient(kek)
		return nil, hierarchyFailure(uerr)
	}
	return kek, nil
}

// initHierarchy performs the once-per-sealer root unseal and mints the first
// KEK generation. It is retried rather than memoized through sync.Once: the
// first attempt can fail at the RLIMIT_MEMLOCK ceiling or on a transient
// provider condition, and a ceiling is a condition that lifts. A sync.Once
// would make one transient failure permanent for the process lifetime.
//
// The retry re-attempts only the step that FAILED. A failed unseal is retried
// with a fresh UnsealRoot call, as the [RootUnsealer] contract permits; a
// successful unseal followed by a failed KEK mint retains the root in
// pendingRoot and retries only the mint. Destroying that root and unsealing
// again — what this did until #83 — called UnsealRoot a second time after it
// had succeeded, which the contract forbids and a one-shot root provider
// cannot survive.
//
// # Locking: the slot spans the provider, mu spans only the publication
//
// Until #87 this whole function ran under mu held exclusively, so a provider
// stalled in UnsealRoot stalled every caller that touched the sealer's state
// — every Seal, every Open, every Openable — and none of them could give up,
// because a mutex wait has no context. Now:
//
//   - initSlot is acquired in a select against ctx.Done(), so only callers
//     that actually need the first initialization queue for it, and each
//     queues for no longer than its own context allows;
//   - the unseal and the mint run holding the slot and NOTHING ELSE, so mu is
//     free for every reader throughout;
//   - mu is write-locked only to publish root, KEK and generation map as one
//     state, exactly as before.
//
// At-most-once survives the split because every write to pendingRoot, and
// every decision to call UnsealRoot, is made by the one slot holder after it
// has re-read the published state; a caller that queued behind a successful
// initializer finds root published and returns without calling the provider.
//
// # A sweep that overlaps the initialization leaves the sealer wiped
//
// The root is unsealed into a registered enclave, so [WipeAll] can reach it —
// but not while UnsealRoot is writing into it: the borrow holds the enclave's
// lock, and a sweep never unmaps memory a reader is using. It waits for the
// borrow for as long as ITS context allows. If that ends first — a shutdown
// deadline passing while a provider is stalled — the sweep returns without
// the root, and a provider returning afterwards hands back a root the sweep
// failed to take; publishing it would leave the key that opens everything
// mapped and in use after the sweep that exists to remove it. If the sweep
// instead waits the borrow out, it destroys the root the moment UnsealRoot
// lets go, and publishing would install a dead root. So the sweep sequence is read BEFORE the unseal and checked
// again on every exit once a root exists — before the mint, after a failed
// mint, and at publication under mu; a sequence that moved, or was odd to
// begin with, means a sweep overlapped this initialization, and the root (and
// KEK, if minted) are destroyed rather than published or retained. The dead root stays in pendingRoot,
// which every later attempt reads as wiped: this sealer then reports
// [ErrSealerWiped] exactly as one whose published hierarchy was swept does,
// and never asks the provider again.
func (s *Sealer) initHierarchy(ctx context.Context) error {
	select {
	case s.initSlot <- struct{}{}:
	case <-ctx.Done():
		return contextFailure(ctx, ErrSealFailed, nil)
	}
	defer func() { <-s.initSlot }()

	// select chooses at random among ready cases, so a context that had
	// already ended can still win the slot; it is refused here, before the
	// provider, rather than spending an unseal on a caller that has gone.
	if err := contextFailure(ctx, ErrSealFailed, nil); err != nil {
		return err
	}

	return initFailure(ctx, s.initHierarchyHeld(ctx))
}

// initFailure shapes every error initHierarchy returns once it holds the
// slot. If the caller's context has ended by then, the failure is reported as
// that cancellation — ErrSealFailed and ctx.Err(), with the cause — AND as
// itself, joined, so neither the abandonment nor what actually went wrong
// (a refused mint, a sweep) is lost. An error that already carries both, as
// the unseal's own refusal does, is returned as it is.
func initFailure(ctx context.Context, err error) error {
	ended := ctx.Err()
	if err == nil || ended == nil || (errors.Is(err, ErrSealFailed) && errors.Is(err, ended)) {
		return err
	}
	return contextFailure(ctx, ErrSealFailed, err)
}

// initHierarchyHeld is initHierarchy's body; the caller holds initSlot.
//
// The sweep-overlap check runs on EVERY exit after a root exists — before the
// mint, after a failed mint, and at publication — not only at publication.
// A failed mint never reaches publication, and checking only there would let
// a root that survived a sweep (borrowed by UnsealRoot when the sweep ran)
// stay resident in pendingRoot for as long as allocation kept failing, with
// each attempt reporting the allocation error instead of the sweep.
func (s *Sealer) initHierarchyHeld(ctx context.Context) error {
	if done, err := s.publishedHierarchy(); done {
		return err
	}

	root := s.pendingRoot
	if root == nil {
		// Read BEFORE the root exists, for the same reason Seal reads a
		// value's sequence before touching a key: a sweep that runs to
		// completion in between must show up as a changed sequence, and one
		// already running as an odd one.
		gen := sweepGeneration()

		var err error
		root, err = NewMemoryEnclaveSized(RootKeyBytes)
		if err != nil {
			return err
		}
		// The provider writes the root DIRECTLY into locked pages; it never
		// exists on the ordinary heap on this path. (What the provider does on
		// its side is its contract; see [RootUnsealer].)
		if err := root.WithBytes(func(b []byte) error {
			uerr := s.ru.UnsealRoot(ctx, b)
			if uerr == nil {
				return nil
			}
			if cerr := contextFailure(ctx, ErrSealFailed, uerr); cerr != nil {
				return cerr
			}
			return uerr
		}); err != nil {
			// The unseal itself failed — a context that ended included — so
			// the contract permits asking again and nothing is retained.
			destroyTransient(root)
			return providerSealFailure(err)
		}
		// From here the unseal has SUCCEEDED and must not be repeated; the
		// root is retained across a failed mint below. A context that ended
		// during a SUCCESSFUL unseal does not undo that: the root is kept and
		// published like any other, and the abandoned caller is told of its
		// context — by initFailure if the mint fails, by protectRootKey's next
		// pass if it succeeds.
		s.pendingRoot, s.pendingGen = root, gen
	}

	// A retained root a sweep destroyed between attempts, or one a sweep
	// overlapped — this attempt's unseal or an earlier one. UnsealRoot already
	// succeeded and may not be called again, so this sealer is wiped exactly
	// as one whose published root was swept is; rebuilding it would be the
	// silent re-keying [ErrSealerWiped] exists to prevent. The overlap check
	// runs FIRST so that a root whose release was refused on an earlier
	// attempt is retried here rather than only reported dead.
	if err := s.discardIfSwept(); err != nil {
		return err
	}
	if !root.IsAlive() {
		return ErrSealerWiped
	}

	kek, blob, err := newGeneration(root, 1)
	if err != nil {
		if derr := s.discardIfSwept(); derr != nil {
			// Both halves are reported: the sweep's verdict, and whatever the
			// failed mint said — including a release the kernel refused, which
			// the ledger now owns (#102).
			return errors.Join(derr, err)
		}
		// root stays in pendingRoot: the next attempt mints again under it.
		// A sweep that destroyed it during the mint surfaces here as
		// ErrSealerWiped through hierarchyFailure, and on the next attempt
		// through the checks above.
		return err
	}

	// Held as pendingKEK from here until it is published, so that a discard
	// below whose release is refused leaves a reference to retry.
	s.pendingKEK = kek

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.discardIfSwept(); err != nil {
		return err
	}

	// Published together, once everything has succeeded, so no reader can
	// observe a root without its KEK; the ready checks treat the pair as one
	// state.
	s.root = root
	s.pendingRoot, s.pendingKEK = nil, nil
	s.kek, s.kekGen = kek, 1
	s.kekBlobs = map[uint32][]byte{1: blob}
	s.kekUsed.Store(0)
	return nil
}

// discardIfSwept returns nil unless a sweep has overlapped the
// initialization that produced pendingRoot — the sequence moved since
// pendingGen was read, or was odd then. If one has, it destroys pendingKEK
// (when non-nil) and pendingRoot here, by the slot holder, so no sweep's luck
// with a borrowed enclave decides whether they survive, and returns
// [ErrSealerWiped]. pendingRoot keeps the root, which every later attempt
// reads as the wiped state. The caller holds initSlot.
//
// A REFUSED release is reported, not swallowed, and RETRIED: Destroy keeps a
// mapping the kernel would not take back — and keeps it on the [WipeAll]
// ledger, so a shutdown sweep still retries and counts it — its error is
// joined with ErrSealerWiped here so the caller learns the key is still
// resident, and the reference stays where the next attempt will find it:
// pendingRoot always, pendingKEK until its release succeeds. The state stays
// wiped all the same, and because the sweep sequence never returns to
// pendingGen, every later attempt reaches this function again and retries
// BOTH releases.
func (s *Sealer) discardIfSwept() error {
	if !sweepInFlight(s.pendingGen) && sweepGeneration() == s.pendingGen {
		return nil
	}
	errs := []error{ErrSealerWiped}
	if s.pendingKEK != nil {
		if err := s.pendingKEK.Destroy(); err != nil {
			errs = append(errs, err)
		} else {
			s.pendingKEK = nil
		}
	}
	if err := s.pendingRoot.Destroy(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) == 1 {
		return ErrSealerWiped
	}
	return errors.Join(errs...)
}

// publishedHierarchy reads the published hierarchy under the read lock and
// reports whether initialization is already decided: done with a nil error
// when another caller published a live hierarchy first, done with
// [ErrSealerWiped] when a sweep destroyed the published one — which must NOT
// be quietly rebuilt, that being exactly the silent re-keying ErrSealerWiped
// exists to prevent — and not done when nothing has been published yet.
func (s *Sealer) publishedHierarchy() (done bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.root == nil {
		return false, nil
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		return true, ErrSealerWiped
	}
	return true, nil
}

// rotateKEK retires the current KEK generation and mints the next. The
// outgoing generation's live enclave is destroyed — the write lock guarantees
// no in-flight wrap or unwrap is using it — and its root-wrapped blob stays
// in kekBlobs so values sealed under it keep opening. That retention is the
// point of the hierarchy: rotation must never strand a sealed value, and a
// retired generation costs under a hundred heap bytes rather than a locked
// page.
//
// It holds mu exclusively across the mint, which is in-process work — a
// locked allocation and one AES-GCM wrap under the root — and never a
// provider call: the root was unsealed once, at initialization, and rotation
// does not consult the provider. That is what makes holding the write lock
// here compatible with the rule initHierarchy was restructured to keep.
func (s *Sealer) rotateKEK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The sweep sequence is read FIRST, before anything is looked at (#102):
	// any sweep that runs at any point from here on — including one that
	// slips in while the liveness checks below hold a key's read lock, which
	// a sweep skips — shows up as an odd value now or a different one at the
	// end. Reading it after those checks left a window: with releases
	// refused, a sweep could wipe the old KEK after its check and finish
	// before a later read, and rotation would publish a fresh generation
	// under the surviving root.
	gen := sweepGeneration()

	if s.root == nil {
		// Unreachable: rotation is only requested by a seal that found the
		// hierarchy initialized, and nothing un-initializes one. Guarded so a
		// future refactoring mistake fails typed instead of dereferencing nil.
		return errors.Join(ErrSealFailed, errHierarchyUninitialized)
	}
	if !s.root.IsAlive() || !s.kek.IsAlive() {
		if err := s.wipeHierarchyLocked(nil); err != nil {
			return errors.Join(ErrSealerWiped, err)
		}
		return ErrSealerWiped
	}
	if s.kekUsed.Load() <= kekMessageLimit {
		// Another goroutine rotated while this one waited for the lock; its
		// fresh generation has budget.
		return nil
	}

	// A sweep that overlaps the rotation must leave the sealer wiped, exactly
	// as one overlapping initialization does (#102). newGeneration borrows the
	// root and the new KEK while it wraps, and WipeAll skips a borrowed
	// enclave — so a sweep landing here can destroy the OLD current KEK and
	// leave the root standing, and publishing the new generation afterwards
	// would hand the caller a working sealer after a WipeAll: the silent
	// re-keying ErrSealerWiped exists to prevent. gen was read before any of
	// this; an odd value (a sweep already in flight) or any change by the
	// time the mint returns is an overlap.
	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if sweepInFlight(gen) || sweepGeneration() != gen {
		// Finish what the sweep set out to do: no key of this hierarchy may
		// outlive it. A refused release is reported, never suppressed.
		if werr := s.wipeHierarchyLocked(kek); werr != nil {
			err = errors.Join(err, werr)
		}
		if err != nil {
			return errors.Join(ErrSealerWiped, err)
		}
		return ErrSealerWiped
	}
	if err != nil {
		// The current generation stays in place: it is over its wrap budget
		// for NEW seals, so the next seal will retry this rotation, but every
		// value already sealed under it still opens.
		return err
	}

	destroyTransient(s.kek)
	s.kek, s.kekGen = kek, s.kekGen+1
	s.kekBlobs[s.kekGen] = blob
	s.kekUsed.Store(0)
	return nil
}

// wipeHierarchyLocked destroys every key of a hierarchy a sweep has
// overlapped or already killed: a just-minted generation that will not be
// published (newKEK, may be nil), the current KEK and the root. Each Destroy is
// idempotent on what the sweep already reclaimed, and detected canary
// corruption panics, as Destroy does.
//
// WHO OWNS A REFUSED RELEASE (#102). The package has one owner for every
// release the kernel refuses: the WipeAll ledger. A refused Destroy keeps the
// mapping registered — wiped first, so it holds no key material, only locked
// pages — and the next sweep retries it; every transient enclave a seal or
// open creates already relies on that. On top of it, the sealer REPORTS every
// refusal here, joined into the error the caller gets, and RETRIES the keys it
// still references — the published root and KEK — every time a seal or open
// finds the hierarchy dead (see withDeadHierarchyCleanup). A generation that was never
// published is not referenced after this call: its refusal is reported once
// and the ledger owns it from then on. Requires s.mu held exclusively.
func (s *Sealer) wipeHierarchyLocked(newKEK *MemoryEnclave) error {
	var errs []error
	for _, k := range []*MemoryEnclave{newKEK, s.kek, s.root} {
		if k == nil {
			continue
		}
		if err := k.Destroy(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
		// A refused release is REPORTED, joined into the error, and owned by
		// the WipeAll ledger from here (see wipeHierarchyLocked) — never
		// silently dropped as destroyTransient would (#102).
		if derr := kek.Destroy(); derr != nil {
			return nil, nil, errors.Join(hierarchyFailure(err), derr)
		}
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
