package backendtest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// faults are the defects a broken fake carries; the zero value is a fake that
// passes every check.
type faults struct {
	badName, noSweep, panicConfine, unstableConfine, sweepLeavesLive, sweepTwiceHeld bool
	// unstableRank and unstableProbe make Rank and Probe alternate between
	// two answers; panicProbe makes Probe panic.
	unstableRank, unstableProbe, panicProbe bool
	// sweepKeepsMaterial makes Sweep report every handle dead but keep its
	// material, so Size and every capability still work.
	sweepKeepsMaterial bool
	// importRefusalLive makes an Import refused with ErrInvalidImport also
	// return a live handle holding the material.
	importRefusalLive bool

	noWipe, importIgnoresCanceled, acceptBadAESSize, importAltersMaterial bool

	destroyLeavesLive, foreignBackend, byteAccessLies, withBytesDropsErr, sizeLies, residueLeak, materialOpaque, panicConcurrent bool

	// racingDestroyLeavesLive makes Destroy return nil and leave the handle
	// alive while a WithBytes call is under way; at rest it destroys.
	racingDestroyLeavesLive bool
	// racingDestroyReturnsEarly makes Destroy, while a WithBytes call is
	// under way, report the handle destroyed and return nil at once; the
	// material is wiped only as a borrow exits. At rest it destroys.
	racingDestroyReturnsEarly bool
	// racingDestroyKeepsWorking makes Destroy, while a WithBytes call is
	// under way, wait the borrows out and return nil with IsAlive false, but
	// leave Size and every capability working on the material. At rest it
	// destroys.
	racingDestroyKeepsWorking bool
	// sizeRacesDestroy and freezeRacesDestroy make Size return -1, or Freeze
	// errFake, once a Destroy has been called while a WithBytes call was
	// under way; at rest Destroy leaves both alone.
	sizeRacesDestroy, freezeRacesDestroy bool
	// destroyRefusedOnce makes each handle's first Destroy return
	// ErrLockedMemoryUnavailable with the material held, as a refused munlock
	// does; the next Destroy releases it. Not a fault: the Destroy contract
	// documents the refusal as resumed by a retry.
	destroyRefusedOnce bool

	freezeNoop, freezeRefuses, freezeDestroys, freezeAfterDestroy bool
	// freezeHeadOnly makes Freeze protect only the first page of the view
	// WithBytes lends from then on.
	freezeHeadOnly bool

	deriveIgnoresInfo, deriveRandom, deriveIgnoresCanceled, deriveWrongSize, deriveFails, deriveAfterDestroy, deriveOpaque bool

	// deriveOpaqueOtherInfo derives the material of "backendtest derive A"
	// for any other info too, into an opaque handle.
	deriveOpaqueOtherInfo bool

	aeadAcceptsTamper, aeadIgnoresDst, aeadIgnoresNonceSize, aeadWrongKey, aeadBadOverhead, aeadAfterDestroy bool

	signWrongKey, signAfterDestroy, signUnknownKey, publicChanges bool

	decryptAcceptsTamper, decryptWrong, decryptAfterDestroy, decryptNotRSA bool

	// attestRandom ignores the nonce and returns random evidence, which
	// differs between calls but binds nothing.
	attestRandom bool

	attestIgnoresNonce, attestTruncates, attestAcceptsEmpty, attestRefusesShort, attestIgnoresCanceled, attestEmptyEvidence, attestAfterDestroy bool

	// signerKey is the signer's key type, "ecdsa" when empty, "rsa" or
	// "ed25519"; not a fault.
	signerKey string
	// rejectsNonceReuse makes Seal refuse a nonce the handle has sealed
	// under before, with errNonceReused, as a careful backend may; not a
	// fault.
	rejectsNonceReuse bool
	// cancel, if set, is called inside every call cancelOn names ("import",
	// "derive" or "attest"), which then honors the ended context as a
	// compliant backend does; not a fault.
	cancelOn string
	cancel   context.CancelFunc
}

// cancelIn ends the run context inside call, if the fake is set to.
func (f *faults) cancelIn(call string) {
	if f.cancelOn == call && f.cancel != nil {
		f.cancel()
	}
}

// fakeConfig is a Config for a fake with flt: an imported material case and an
// imported AES-256-GCM key, and a generated signer and decrypter.
func fakeConfig(flt faults) Config {
	cfg := Config{
		New: func() (enclave.Backend, error) { return newFake(flt), nil },
		BackendCapabilities: []enclave.Capability{
			enclave.CapabilityImport, enclave.CapabilitySweep, enclave.CapabilityConfine, enclave.CapabilityAttest,
			enclave.CapabilityProbe,
		},
		Handles: []HandleCase{
			{
				Name:         "material",
				Import:       []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
				ImportSize:   materialBytes,
				Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze, enclave.CapabilityDerive},
			},
			{
				Name: "key",
				Import: []enclave.ImportOption{
					enclave.WithPurpose(enclave.PurposeWrappingKey),
					enclave.WithAlgorithm(enclave.AlgorithmAES256GCM),
				},
				ImportSize:   materialBytes,
				Capabilities: []enclave.Capability{enclave.CapabilityAEAD, enclave.CapabilityDerive},
			},
			{
				Name: "signer",
				New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
					return fakeOf(b).newSigner(ctx)
				},
				Capabilities: []enclave.Capability{enclave.CapabilitySign, enclave.CapabilityAttest},
			},
			{
				Name: "decrypter",
				New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
					return fakeOf(b).newDecrypter(ctx)
				},
				Capabilities: []enclave.Capability{enclave.CapabilityDecrypt},
			},
		},
	}
	cfg.SkipResidueSweep = "the residue sweep is run by swept configs only, it dominates the race-enabled run"
	cfg.VerifyEvidence = verifyFakeEvidence
	return cfg
}

// errEvidenceUnbound is verifyFakeEvidence's refusal.
var errEvidenceUnbound = errors.New("fake: evidence does not bind the nonce")

// verifyFakeEvidence is the fake's relying party: evidence binds nonce when it
// is the digest the backend or the signer attests over nonce.
func verifyFakeEvidence(nonce []byte, e enclave.Evidence) error {
	if e.Format != "fake-evidence" {
		return errEvidenceUnbound
	}
	for _, subject := range []string{"backend", "signer"} {
		if sum := sha256.Sum256(append([]byte(subject), nonce...)); bytes.Equal(e.Data, sum[:]) {
			return nil
		}
	}
	return errEvidenceUnbound
}

// swept returns cfg with the residue sweep on wherever memscan can run it.
func swept(cfg Config) Config {
	cfg.SkipResidueSweep = ""
	if !memscan.Supported {
		cfg.SkipResidueSweep = memscan.UnsupportedReason
	}
	return cfg
}

// edit returns cfg changed by fn.
func edit(cfg Config, fn func(*Config)) Config {
	fn(&cfg)
	return cfg
}

type fakeBackend struct {
	faults
	// self is the backend handles report: the fake, or the wrapper hiding Sweep.
	self enclave.Backend

	mu       sync.Mutex
	handles  []enclave.Handle
	sweeps   int
	confines int
	ranks    int
	probes   int
	// inFlight counts WithBytes calls under way: one is held across Destroy
	// only in the suite's concurrency check.
	inFlight atomic.Int32
	// destroying is set by a Destroy called with a borrow open, for
	// sizeRacesDestroy and freezeRacesDestroy.
	destroying atomic.Bool
	// refused holds the memory of each handle whose Destroy was refused,
	// for destroyRefusedOnce.
	refused sync.Map
	// retired holds the memory of each handle a fault reports dead while it
	// keeps the material.
	retired sync.Map
}

func newFake(flt faults) enclave.Backend {
	f := &fakeBackend{faults: flt}
	f.self = f
	if flt.noSweep {
		f.self = &noSweepBackend{f: f}
	}
	return f.self
}

// fakeOf returns the fake behind b.
func fakeOf(b enclave.Backend) *fakeBackend {
	return b.(interface{ fake() *fakeBackend }).fake()
}

func (f *fakeBackend) fake() *fakeBackend { return f }

func (f *fakeBackend) Name() string {
	if f.badName {
		return "Bad_Name"
	}
	return "fake-backend"
}

func (f *fakeBackend) track(h enclave.Handle) enclave.Handle {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handles = append(f.handles, h)
	return h
}

// fakeMemory is every locked region a fake allocated, so a run's leaks, the
// faults' among them, go back before the next run.
var fakeMemory struct {
	mu   sync.Mutex
	mems []enclave.ByteAccess
	// unmaps release the freezeHeadOnly views.
	unmaps []func() error
}

// releaseFakes destroys every region a fake allocated.
func releaseFakes() {
	fakeMemory.mu.Lock()
	defer fakeMemory.mu.Unlock()
	for _, m := range fakeMemory.mems {
		_ = m.Destroy()
	}
	for _, unmap := range fakeMemory.unmaps {
		_ = unmap()
	}
	fakeMemory.mems, fakeMemory.unmaps = nil, nil
}

// runFake runs TestBackend and then releases what the fake left.
func runFake(ctx context.Context, cfg Config) error {
	defer releaseFakes()
	return TestBackend(ctx, cfg)
}

func (f *fakeBackend) core(material []byte) (handleCore, error) {
	mem, err := enclave.NewMemorySized(len(material))
	if err != nil {
		return handleCore{}, err
	}
	fakeMemory.mu.Lock()
	fakeMemory.mems = append(fakeMemory.mems, mem)
	fakeMemory.mu.Unlock()
	if err := mem.WithBytes(func(b []byte) error {
		copy(b, material)
		if f.importAltersMaterial {
			b[0] ^= 1
		}
		return nil
	}); err != nil {
		return handleCore{}, err
	}
	return handleCore{backend: f, mem: mem}, nil
}

func (f *fakeBackend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	defer func() {
		if !f.noWipe {
			enclave.Wipe(material)
		}
	}()
	f.cancelIn("import")
	if err := ended(ctx, f.importIgnoresCanceled); err != nil {
		return nil, err
	}
	spec, err := enclave.NewImportSpec(opts...)
	if err != nil {
		return f.refuse(material, err)
	}
	if spec.Algorithm == enclave.AlgorithmAES256GCM && len(material) != materialBytes && !f.acceptBadAESSize {
		return f.refuse(material, enclave.ErrInvalidImport)
	}
	c, err := f.core(material)
	if err != nil {
		return nil, err
	}
	switch {
	case spec.Purpose != enclave.PurposeMaterial:
		return f.track(&keyHandle{handleCore: c}), nil
	case f.materialOpaque:
		return f.track(&opaqueHandle{handleCore: c}), nil
	}
	h := &memHandle{handleCore: c}
	if f.residueLeak {
		h.shadow = append([]byte(nil), material...)
	}
	return f.track(h), nil
}

// refuse returns Import's refusal err, with no handle unless
// importRefusalLive makes it hand back a live one over material too.
func (f *fakeBackend) refuse(material []byte, err error) (enclave.Handle, error) {
	if !f.importRefusalLive {
		return nil, err
	}
	c, cerr := f.core(material)
	if cerr != nil {
		return nil, cerr
	}
	return f.track(&memHandle{handleCore: c}), err
}

func (f *fakeBackend) Sweep(context.Context) (int, error) {
	f.mu.Lock()
	handles := f.handles
	f.handles = nil
	f.sweeps++
	again := f.sweeps > 1
	f.mu.Unlock()
	if f.sweepTwiceHeld && again {
		return 1, nil
	}
	if f.sweepLeavesLive {
		return len(handles), nil
	}
	if f.sweepKeepsMaterial {
		for _, h := range handles {
			h.(interface{ retire() }).retire()
		}
		return 0, nil
	}
	for _, h := range handles {
		// A refused release is resumed by the next Destroy.
		err := h.Destroy()
		for errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			err = h.Destroy()
		}
	}
	return 0, nil
}

func (f *fakeBackend) ConfinesProcess() bool {
	if f.panicConfine {
		panic("fake: ConfinesProcess")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confines++
	return !f.unstableConfine || f.confines%2 == 0
}

func (f *fakeBackend) Rank() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ranks++
	if f.unstableRank && f.ranks%2 == 0 {
		return 1
	}
	return 100
}

func (f *fakeBackend) Probe(context.Context) error {
	if f.panicProbe {
		panic("fake: Probe")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	if f.unstableProbe && f.probes%2 == 0 {
		return errFake
	}
	return nil
}

func (f *fakeBackend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	return f.attest(ctx, nonce, "backend")
}

// attest binds nonce and subject into fake evidence, honoring the nonce and
// context contract unless a fault says otherwise.
func (f *faults) attest(ctx context.Context, nonce []byte, subject string) (enclave.Evidence, error) {
	f.cancelIn("attest")
	if err := ended(ctx, f.attestIgnoresCanceled); err != nil {
		return enclave.Evidence{}, err
	}
	if len(nonce) == 0 && !f.attestAcceptsEmpty || len(nonce) > maxNonce && !f.attestTruncates ||
		len(nonce) == 1 && f.attestRefusesShort {
		return enclave.Evidence{}, enclave.ErrInvalidNonce
	}
	if f.attestEmptyEvidence {
		return enclave.Evidence{}, nil
	}
	if f.attestRandom {
		return enclave.Evidence{Format: "fake-evidence", Data: randomBytes(sha256.Size)}, nil
	}
	if f.attestIgnoresNonce {
		nonce = nil
	}
	sum := sha256.Sum256(append([]byte(subject), nonce...))
	return enclave.Evidence{Format: "fake-evidence", Data: sum[:]}, nil
}

func (f *fakeBackend) newSigner(ctx context.Context) (enclave.Handle, error) {
	var key crypto.Signer
	var err error
	switch f.signerKey {
	case "rsa":
		key = rsaKey()
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, err
	}
	c, err := f.core(randomBytes(materialBytes))
	if err != nil {
		return nil, err
	}
	return f.track(&signerHandle{handleCore: c, key: key}), ended(ctx, false)
}

func (f *fakeBackend) newDecrypter(context.Context) (enclave.Handle, error) {
	c, err := f.core(randomBytes(materialBytes))
	if err != nil {
		return nil, err
	}
	return f.track(&decrypterHandle{handleCore: c}), nil
}

// noSweepBackend is a fake that does not implement Sweeper.
type noSweepBackend struct{ f *fakeBackend }

func (n *noSweepBackend) fake() *fakeBackend { return n.f }
func (n *noSweepBackend) Name() string       { return n.f.Name() }
func (n *noSweepBackend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	return n.f.Import(ctx, material, opts...)
}
func (n *noSweepBackend) ConfinesProcess() bool { return n.f.ConfinesProcess() }
func (n *noSweepBackend) Rank() int             { return n.f.Rank() }
func (n *noSweepBackend) Probe(ctx context.Context) error {
	return n.f.Probe(ctx)
}
func (n *noSweepBackend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	return n.f.Attest(ctx, nonce)
}

// ended returns ctx's error unless ignore is set.
func ended(ctx context.Context, ignore bool) error {
	if ignore || ctx == nil {
		return nil
	}
	return ctx.Err()
}

// handleCore is a handle's lifecycle over locked memory, with no capability.
type handleCore struct {
	backend *fakeBackend
	mem     enclave.ByteAccess
}

// strayBackend is a backend no handle under test belongs to.
var strayBackend = &fakeBackend{}

func (h *handleCore) IsAlive() bool { return !h.retired() && h.mem.IsAlive() }

// retire reports the handle dead while it keeps the material, for the faults
// that do.
func (h *handleCore) retire() { h.backend.retired.Store(h.mem, true) }

func (h *handleCore) retired() bool {
	_, ok := h.backend.retired.Load(h.mem)
	return ok
}

// gone reports a handle racingDestroyReturnsEarly reported destroyed: it
// answers as one while its material waits for the borrow to exit.
func (h *handleCore) gone() bool { return h.backend.racingDestroyReturnsEarly && h.retired() }

func (h *handleCore) Size() int {
	if h.backend.sizeRacesDestroy && h.backend.destroying.Load() {
		return -1
	}
	if h.gone() {
		return 0
	}
	n := h.mem.Size()
	if h.backend.sizeLies && n > 0 {
		n++
	}
	return n
}

func (h *handleCore) Backend() enclave.Backend {
	if h.backend.foreignBackend {
		return strayBackend
	}
	return h.backend.self
}

func (h *handleCore) Destroy() error {
	f := h.backend
	if f.destroyLeavesLive {
		return nil
	}
	// Only the suite's concurrency check calls Destroy with a borrow open.
	racing := f.inFlight.Load() > 0
	if f.racingDestroyLeavesLive && racing {
		return nil
	}
	if racing {
		f.destroying.Store(true)
	}
	switch {
	case f.racingDestroyReturnsEarly && racing:
		h.retire()
		return nil
	case f.racingDestroyKeepsWorking && racing:
		// Freeze waits out the borrows, as Destroy must.
		if err := h.mem.(enclave.Freezer).Freeze(); err != nil {
			return err
		}
		h.retire()
		return nil
	}
	if f.destroyRefusedOnce {
		if _, again := f.refused.LoadOrStore(h.mem, true); !again {
			return enclave.ErrLockedMemoryUnavailable
		}
	}
	return h.mem.Destroy()
}

// derive returns n bytes of HKDF-SHA-256 over the material and info, in a new
// handle that wrap makes.
func (h *handleCore) derive(ctx context.Context, info []byte, n int, wrap func(handleCore) enclave.Handle) (enclave.Handle, error) {
	f := h.backend
	if h.gone() {
		return nil, enclave.ErrEnclaveDestroyed
	}
	f.cancelIn("derive")
	if err := ended(ctx, f.deriveIgnoresCanceled); err != nil {
		return nil, err
	}
	if f.deriveFails {
		return nil, enclave.ErrLockedMemoryUnavailable
	}
	if f.deriveWrongSize {
		n++
	}
	if f.deriveIgnoresInfo {
		info = nil
	}
	if f.deriveRandom {
		info = randomBytes(materialBytes)
	}
	opaque := f.deriveOpaque
	if f.deriveOpaqueOtherInfo && string(info) != "backendtest derive A" {
		info, opaque = []byte("backendtest derive A"), true
	}
	var out []byte
	if err := h.mem.WithBytes(func(key []byte) error {
		var herr error
		out, herr = hkdf.Key(sha256.New, key, nil, string(info), n)
		return herr
	}); err != nil {
		if !f.deriveAfterDestroy {
			return nil, err
		}
		out = randomBytes(n)
	}
	defer enclave.Wipe(out)
	c, err := f.core(out)
	if err != nil {
		return nil, err
	}
	if opaque {
		return f.track(&opaqueHandle{handleCore: c}), nil
	}
	return f.track(wrap(c)), nil
}

// opaqueHandle has no capability at all.
type opaqueHandle struct{ handleCore }

// memHandle is ByteAccess, Freezer and Deriver.
type memHandle struct {
	handleCore
	// shadow is the residueLeak fault: a heap copy Destroy never wipes.
	shadow []byte
	// view, for freezeHeadOnly, is the copy of the material WithBytes lends
	// once Freeze has protected its first page.
	view   atomic.Pointer[[]byte]
	frozen sync.Once
}

func (h *memHandle) WithBytes(fn func([]byte) error) error {
	if h.gone() {
		return enclave.ErrEnclaveDestroyed
	}
	// The count is what tells the fake's Destroy that a borrow is under way;
	// the suite holds one open while it calls Destroy, so no sleep is needed.
	n := h.backend.inFlight.Add(1)
	defer h.backend.inFlight.Add(-1)
	if h.backend.panicConcurrent && n > 1 {
		panic("fake: WithBytes under concurrent use")
	}
	if v := h.view.Load(); v != nil {
		return h.mem.WithBytes(func([]byte) error { return fn(*v) })
	}
	if h.backend.byteAccessLies {
		return h.mem.WithBytes(func(b []byte) error { return fn(make([]byte, len(b))) })
	}
	err := h.mem.WithBytes(fn)
	if h.gone() {
		// The racingDestroyReturnsEarly wipe, once a borrow exits.
		_ = h.mem.Destroy()
	}
	if h.backend.withBytesDropsErr && !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return nil
	}
	return err
}

func (h *memHandle) EqualTo(other []byte) (bool, error) {
	if h.gone() {
		return false, enclave.ErrEnclaveDestroyed
	}
	if h.backend.byteAccessLies {
		return true, h.mem.WithBytes(func([]byte) error { return nil })
	}
	return h.mem.EqualTo(other)
}

func (h *memHandle) Freeze() error {
	switch {
	case h.gone():
		return enclave.ErrEnclaveDestroyed
	case h.backend.freezeRacesDestroy && h.backend.destroying.Load():
		return errFake
	case h.backend.freezeHeadOnly:
		var err error
		if h.frozen.Do(func() { err = h.freezeHead() }); err != nil {
			return err
		}
		return h.mem.(enclave.Freezer).Freeze()
	case h.backend.freezeAfterDestroy && !h.IsAlive():
		return nil
	case h.backend.freezeRefuses:
		return enclave.ErrLockedMemoryUnavailable
	case h.backend.freezeNoop:
		return h.mem.WithBytes(func([]byte) error { return nil })
	case h.backend.freezeDestroys:
		return h.mem.Destroy()
	}
	return h.mem.(enclave.Freezer).Freeze()
}

// freezeHead is the freezeHeadOnly fault: it copies the material into a
// mapping whose first page alone is read-only, and WithBytes lends that copy
// from then on.
func (h *memHandle) freezeHead() error {
	return h.mem.WithBytes(func(b []byte) error {
		view, unmap, err := mapFrozenHead(b)
		if err != nil {
			return err
		}
		fakeMemory.mu.Lock()
		fakeMemory.unmaps = append(fakeMemory.unmaps, unmap)
		fakeMemory.mu.Unlock()
		h.view.Store(&view)
		return nil
	})
}

func (h *memHandle) Derive(ctx context.Context, info []byte, n int) (enclave.Handle, error) {
	return h.derive(ctx, info, n, func(c handleCore) enclave.Handle { return &memHandle{handleCore: c} })
}

// keyHandle is an AES-256-GCM AEAD and Deriver, with no ByteAccess.
type keyHandle struct {
	handleCore
	// nonces holds every nonce Seal used, for rejectsNonceReuse.
	nonces sync.Map
}

// errNonceReused is the rejectsNonceReuse backend's refusal of a nonce it
// sealed under before.
var errNonceReused = errors.New("fake: AEAD nonce reused under this key")

func (h *keyHandle) NonceSize() int { return 12 }
func (h *keyHandle) Overhead() int {
	if h.backend.aeadBadOverhead {
		return 15
	}
	return 16
}

func (h *keyHandle) Seal(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	var out []byte
	err := h.withGCM(nonce, func(g cipher.AEAD, nonce []byte) error {
		if h.backend.rejectsNonceReuse {
			if _, reused := h.nonces.LoadOrStore(string(nonce), true); reused {
				return errNonceReused
			}
		}
		if h.backend.aeadIgnoresDst {
			dst = nil
		}
		out = g.Seal(dst, nonce, plaintext, aad)
		return nil
	})
	return out, err
}

func (h *keyHandle) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	var out []byte
	err := h.withGCM(nonce, func(g cipher.AEAD, nonce []byte) error {
		if h.backend.aeadAcceptsTamper {
			out = append(dst, "not authenticated"...)
			return nil
		}
		var oerr error
		if out, oerr = g.Open(dst, nonce, ciphertext, aad); oerr != nil {
			return enclave.ErrAEADAuthentication
		}
		return nil
	})
	return out, err
}

func (h *keyHandle) withGCM(nonce []byte, fn func(g cipher.AEAD, nonce []byte) error) error {
	use := func(key []byte) error {
		if len(nonce) != h.NonceSize() {
			if !h.backend.aeadIgnoresNonceSize {
				return enclave.ErrInvalidNonce
			}
			nonce = append(append([]byte(nil), nonce...), make([]byte, h.NonceSize())...)[:h.NonceSize()]
		}
		if h.backend.aeadWrongKey {
			sum := sha256.Sum256(key)
			key = sum[:]
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		g, err := newFakeGCM(block)
		if err != nil {
			return err
		}
		return fn(g, nonce)
	}
	err := h.mem.WithBytes(use)
	if errors.Is(err, enclave.ErrEnclaveDestroyed) && h.backend.aeadAfterDestroy {
		return use(make([]byte, materialBytes))
	}
	return err
}

// newFakeGCM is the keyHandle's AES-256-GCM. FIPS 140-only mode refuses GCM
// under a caller-chosen nonce, which the fake takes so the suite can catch
// nonce reuse; there it is fipsGCM instead.
func newFakeGCM(block cipher.Block) (cipher.AEAD, error) {
	if !fips140.Enforced() {
		return cipher.NewGCM(block)
	}
	mac := make([]byte, 2*aes.BlockSize)
	block.Encrypt(mac[:aes.BlockSize], []byte("fake fipsGCM mac"))
	block.Encrypt(mac[aes.BlockSize:], []byte("fake fipsGCM key"))
	return &fipsGCM{block: block, mac: mac}, nil
}

// fipsGCM stands in for AES-GCM under FIPS 140-only mode from approved
// primitives: AES-CTR from GCM's second counter block, so its ciphertext body
// is GCM's, then a 16-byte HMAC-SHA256 tag over the nonce, additional data and
// ciphertext. It is a test double, not GCM.
type fipsGCM struct {
	block cipher.Block
	mac   []byte
}

func (g *fipsGCM) NonceSize() int { return 12 }
func (g *fipsGCM) Overhead() int  { return 16 }

func (g *fipsGCM) Seal(dst, nonce, plaintext, aad []byte) []byte {
	n := len(dst)
	dst = append(dst, plaintext...)
	g.stream(nonce).XORKeyStream(dst[n:], dst[n:])
	return append(dst, g.tag(nonce, aad, dst[n:])...)
}

func (g *fipsGCM) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < g.Overhead() {
		return nil, enclave.ErrAEADAuthentication
	}
	body, tag := ciphertext[:len(ciphertext)-g.Overhead()], ciphertext[len(ciphertext)-g.Overhead():]
	if !hmac.Equal(tag, g.tag(nonce, aad, body)) {
		return nil, enclave.ErrAEADAuthentication
	}
	n := len(dst)
	dst = append(dst, body...)
	g.stream(nonce).XORKeyStream(dst[n:], dst[n:])
	return dst, nil
}

func (g *fipsGCM) stream(nonce []byte) cipher.Stream {
	return cipher.NewCTR(g.block, binary.BigEndian.AppendUint32(bytes.Clone(nonce), 2))
}

func (g *fipsGCM) tag(nonce, aad, body []byte) []byte {
	m := hmac.New(sha256.New, g.mac)
	m.Write(nonce)
	m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(aad))))
	m.Write(aad)
	m.Write(body)
	return m.Sum(nil)[:g.Overhead()]
}

func (h *keyHandle) Derive(ctx context.Context, info []byte, n int) (enclave.Handle, error) {
	return h.derive(ctx, info, n, func(c handleCore) enclave.Handle { return &keyHandle{handleCore: c} })
}

// otherKey is a key no handle holds.
var otherKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
})

// rsaKey is every decrypter's key, generated once for the run: 2048 bits,
// the least FIPS 140-only mode accepts.
var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

// unknownKey is a public key type the suite cannot verify signatures under.
type unknownKey struct{}

// signerHandle is a crypto.Signer, ECDSA P-256 unless faults.signerKey says
// otherwise, and an Attester.
type signerHandle struct {
	handleCore
	key crypto.Signer
}

func (h *signerHandle) Public() crypto.PublicKey {
	switch {
	case h.backend.signUnknownKey:
		return unknownKey{}
	case h.backend.publicChanges && !h.IsAlive():
		return &otherKey().PublicKey
	}
	return h.key.Public()
}

func (h *signerHandle) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	key := h.key
	if h.backend.signWrongKey {
		key = otherKey()
	}
	var sig []byte
	err := h.mem.WithBytes(func([]byte) error {
		var serr error
		sig, serr = key.Sign(rand, digest, opts)
		return serr
	})
	if errors.Is(err, enclave.ErrEnclaveDestroyed) && h.backend.signAfterDestroy {
		return key.Sign(rand, digest, opts)
	}
	return sig, err
}

func (h *signerHandle) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if !h.IsAlive() && !h.backend.attestAfterDestroy {
		return enclave.Evidence{}, enclave.ErrEnclaveDestroyed
	}
	return h.backend.attest(ctx, nonce, "signer")
}

// decrypterHandle is an RSA crypto.Decrypter.
type decrypterHandle struct{ handleCore }

func (h *decrypterHandle) Public() crypto.PublicKey {
	if h.backend.decryptNotRSA {
		return &otherKey().PublicKey
	}
	return &rsaKey().PublicKey
}

func (h *decrypterHandle) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var out []byte
	err := h.mem.WithBytes(func([]byte) error {
		var derr error
		out, derr = rsaKey().Decrypt(rand, ciphertext, opts)
		return derr
	})
	switch {
	case errors.Is(err, enclave.ErrEnclaveDestroyed) && h.backend.decryptAfterDestroy:
		return rsaKey().Decrypt(rand, ciphertext, opts)
	case err != nil && !errors.Is(err, enclave.ErrEnclaveDestroyed) && h.backend.decryptAcceptsTamper:
		return []byte("forged"), nil
	case err == nil && h.backend.decryptWrong && len(out) > 0:
		out[0] ^= 1
	}
	return out, err
}

// simpleBackend has no capability and makes valueHandles.
type simpleBackend struct{}

func (simpleBackend) Name() string { return "simple-backend" }

// valueHandle is a handle that is not a pointer.
type valueHandle struct{ backend enclave.Backend }

func (valueHandle) Size() int                  { return 1 }
func (valueHandle) IsAlive() bool              { return true }
func (valueHandle) Destroy() error             { return nil }
func (h valueHandle) Backend() enclave.Backend { return h.backend }

func nonPointerConfig() Config {
	return Config{
		New: func() (enclave.Backend, error) { return simpleBackend{}, nil },
		Handles: []HandleCase{{
			Name: "value",
			New: func(_ context.Context, b enclave.Backend) (enclave.Handle, error) {
				return valueHandle{backend: b}, nil
			},
		}},
	}
}
