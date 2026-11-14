package backendtest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

const (
	materialBytes   = 32
	deriveBytes     = 32
	concurrencyRuns = 32
	// maxNonce is the longest nonce Attest takes.
	maxNonce = 64
	// destroyAttempts bounds the Destroy calls the suite makes while a backend
	// reports the release refused for a retry to resume.
	destroyAttempts = 4
	// holdBound is how long the concurrency check's first borrow stays open
	// once Destroy is called. A backend that waits out the borrow, as the
	// Destroy contract requires, gets it back after the bound; one that does
	// not returns from Destroy while the borrow is still open, a finding.
	holdBound = 20 * time.Millisecond
)

// Config describes the backend under test.
type Config struct {
	// New returns a fresh backend ready for use. It is called at most once per
	// check, so a check that leaves a backend in a terminal state does not
	// affect the next.
	New func() (enclave.Backend, error)
	// BackendCapabilities is exactly what the backend itself claims:
	// CapabilityImport, CapabilitySweep, CapabilityConfine, CapabilityAttest
	// and CapabilityProbe.
	BackendCapabilities []enclave.Capability
	// Handles are the kinds of handle the backend makes; at least one.
	Handles []HandleCase
	// SkipResidueSweep, if set, is the reason the residue sweep may not run.
	// Without it, a sweep that cannot run is reported as ErrNotMeasured.
	SkipResidueSweep string
	// VerifyEvidence, if set, returns nil when evidence binds nonce and an
	// error when it does not, as the attestation's relying party would judge
	// it. With it the suite checks that Attest binds its nonce: evidence for
	// one nonce verifies against that nonce and not against another. Without
	// it the suite cannot tell bound evidence from evidence that merely
	// differs between calls, and reports CapabilityAttest as an
	// [*UncheckedCapabilityError] for every Attester it meets.
	VerifyEvidence func(nonce []byte, evidence enclave.Evidence) error
	// Logf receives notes about skipped optional measurements.
	Logf func(format string, args ...any)
}

// HandleCase is one kind of handle. Exactly one of New and Import is set.
type HandleCase struct {
	// Name is unique among the cases and names the case in every failure.
	Name string
	// New returns a live handle of b, such as a key the device generates. A
	// ByteAccess handle's material should be random: the residue sweep cannot
	// tell one repeated byte from the rest of the process and leaves it
	// unmeasured.
	New func(ctx context.Context, b enclave.Backend) (enclave.Handle, error)
	// Import, for an Importer, is the option set the suite imports ImportSize
	// random bytes with; the case then also checks the purpose's handle contract.
	Import     []enclave.ImportOption
	ImportSize int
	// Capabilities is exactly what this case's handles claim: CapabilityBytes,
	// CapabilityFreeze, CapabilitySign, CapabilityDecrypt, CapabilityAEAD,
	// CapabilityDerive, CapabilityAttest.
	Capabilities []enclave.Capability
}

// TestBackend runs every check against cfg's backend and returns nil, a
// [*ConfigError], an [*UncheckedCapabilityError] for a capability the suite
// refuses from the configuration alone, or a [*FindingsError] holding every
// finding of the run.
func TestBackend(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	r := &report{ctx: ctx, logf: cfg.Logf}
	checks := []func(*report, Config){
		checkBackendIdentity,
		checkBackendCapabilities,
		checkHandleCapabilities,
		checkHandleCore,
		checkByteAccess,
		checkFreezer,
		checkDeriver,
		checkSigner,
		checkDecrypter,
		checkAEAD,
		checkAttester,
		checkImporter,
		checkSweeper,
		checkConfiner,
		checkProber,
		checkConcurrentUse,
		checkResidue,
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			break
		}
		r.run(check, cfg)
	}
	if err := ctx.Err(); err != nil {
		r.add(&AbortedError{Cause: err})
	}
	return findingsOf(r.findings)
}

type report struct {
	ctx  context.Context
	logf func(format string, args ...any)

	mu       sync.Mutex
	findings []error
}

func (r *report) run(check func(*report, Config), cfg Config) {
	defer func() {
		if p := recover(); p != nil {
			r.panicked(p)
		}
	}()
	check(r, cfg)
}

func (r *report) add(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, err)
}

// record adds a finding observed while the run context was live. Once it has
// ended, a backend that honors it fails its calls with the context's error, so
// what the suite observes then is the abort, not the backend: the run reports
// ErrAborted instead.
func (r *report) record(err error) {
	if r.ctx.Err() != nil {
		return
	}
	r.add(err)
}

// panicked reports a panic, which no context explains.
func (r *report) panicked(p any) {
	r.add(&PropertyError{Property: "panic safety", Detail: fmt.Sprintf("suite observed a panic instead of a typed error: %v", p)})
}

func (r *report) fail(property, detail string, args ...any) {
	r.record(&PropertyError{Property: property, Detail: fmt.Sprintf(detail, args...)})
}

func (r *report) unmeasured(property, reason string, args ...any) {
	r.record(&NotMeasuredError{Property: property, Reason: fmt.Sprintf(reason, args...)})
}

func (r *report) unchecked(caseName string, c enclave.Capability, reason string, args ...any) {
	r.record(&UncheckedCapabilityError{Case: caseName, Capability: c, Reason: fmt.Sprintf(reason, args...)})
}

func (r *report) note(format string, args ...any) {
	if r.logf != nil {
		r.logf(format, args...)
	}
}

func validateConfig(cfg Config) error {
	if cfg.New == nil {
		return &ConfigError{Field: "New", Reason: "is nil; the suite has no backend to test"}
	}
	if len(cfg.Handles) == 0 {
		return &ConfigError{Field: "Handles", Reason: "is empty; the suite needs at least one handle case"}
	}
	names := make(map[string]bool, len(cfg.Handles))
	for i, hc := range cfg.Handles {
		field := fmt.Sprintf("Handles[%d]", i)
		if hc.Name == "" {
			return &ConfigError{Field: field + ".Name", Reason: "is empty"}
		}
		if names[hc.Name] {
			return &ConfigError{Field: field + ".Name", Reason: "duplicates another handle case"}
		}
		names[hc.Name] = true
		hasNew := hc.New != nil
		hasImport := hc.Import != nil
		if hasNew == hasImport {
			return &ConfigError{Field: field, Reason: "must set exactly one of New and Import"}
		}
		if hasImport && hc.ImportSize <= 0 {
			return &ConfigError{Field: field + ".ImportSize", Reason: "must be positive for an imported case"}
		}
		if err := validateCapabilities(hc.Name, field+".Capabilities", hc.Capabilities, handleCapabilitySet, backendCapabilitySet); err != nil {
			return err
		}
		if hasCap(hc.Capabilities, enclave.CapabilityFreeze) && !hasCap(hc.Capabilities, enclave.CapabilityBytes) {
			return &UncheckedCapabilityError{Case: hc.Name, Capability: enclave.CapabilityFreeze,
				Reason: "read-only material is observable only through ByteAccess, which the case does not claim; " +
					"the seam has opaque handles read-only by nature and without Freezer"}
		}
	}
	if err := validateCapabilities("", "BackendCapabilities", cfg.BackendCapabilities, backendCapabilitySet, handleCapabilitySet); err != nil {
		return err
	}
	if hasCap(cfg.BackendCapabilities, enclave.CapabilityImport) && !hasImportedCase(cfg.Handles) {
		return &UncheckedCapabilityError{Capability: enclave.CapabilityImport,
			Reason: "no handle case sets Import, so the suite never sees a valid import succeed and an Importer " +
				"that refuses every one would pass; add an imported case"}
	}
	return nil
}

func hasImportedCase(cases []HandleCase) bool {
	for _, hc := range cases {
		if hc.Import != nil {
			return true
		}
	}
	return false
}

// validateCapabilities refuses a capability listed on the wrong side of the
// seam as a configuration error, and one the enclave package does not name as
// unchecked: the suite has no contract to hold it to.
func validateCapabilities(caseName, field string, caps []enclave.Capability, allowed, other map[enclave.Capability]bool) error {
	seen := make(map[enclave.Capability]bool, len(caps))
	for _, c := range caps {
		if !allowed[c] {
			if other[c] {
				return &ConfigError{Field: field, Reason: fmt.Sprintf("contains %q, which belongs to the other side of the seam", c)}
			}
			return &UncheckedCapabilityError{Case: caseName, Capability: c,
				Reason: "the enclave package does not name it, so the suite has no contract to check it against"}
		}
		if seen[c] {
			return &ConfigError{Field: field, Reason: fmt.Sprintf("contains duplicate %q", c)}
		}
		seen[c] = true
	}
	return nil
}

var backendCapabilitySet = map[enclave.Capability]bool{
	enclave.CapabilityImport:  true,
	enclave.CapabilitySweep:   true,
	enclave.CapabilityConfine: true,
	enclave.CapabilityAttest:  true,
	enclave.CapabilityProbe:   true,
}

var handleCapabilitySet = map[enclave.Capability]bool{
	enclave.CapabilityBytes:   true,
	enclave.CapabilityFreeze:  true,
	enclave.CapabilitySign:    true,
	enclave.CapabilityDecrypt: true,
	enclave.CapabilityAEAD:    true,
	enclave.CapabilityDerive:  true,
	enclave.CapabilityAttest:  true,
}

func checkBackendIdentity(r *report, cfg Config) {
	const property = "backend identity"
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	name := b.Name()
	if !validBackendName(name) {
		r.fail(property, "Name returned %q; backend names are 1 to 64 bytes of lowercase ASCII letters, digits, '-' and '.', starting and ending with a letter or digit", name)
	}
	if again := b.Name(); again != name {
		r.fail(property, "Name changed from %q to %q", name, again)
	}
}

func checkBackendCapabilities(r *report, cfg Config) {
	const property = "backend capabilities are exact"
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}
	claimed := capSet(cfg.BackendCapabilities)
	checkBackendCapability[enclave.Importer](r, property, b, claimed, enclave.CapabilityImport)
	checkBackendCapability[enclave.Sweeper](r, property, b, claimed, enclave.CapabilitySweep)
	checkBackendCapability[enclave.Confiner](r, property, b, claimed, enclave.CapabilityConfine)
	checkBackendCapability[enclave.Attester](r, property, b, claimed, enclave.CapabilityAttest)
	checkBackendCapability[enclave.Prober](r, property, b, claimed, enclave.CapabilityProbe)
}

func checkBackendCapability[T any](r *report, property string, b enclave.Backend, claimed map[enclave.Capability]bool, c enclave.Capability) {
	_, ok := b.(T)
	if claimed[c] && !ok {
		r.fail(property, "Config claims backend capability %q, but %T does not implement it", c, b)
	}
	if !claimed[c] && ok {
		r.fail(property, "Config does not claim backend capability %q, but %T implements it", c, b)
	}
}

func checkHandleCapabilities(r *report, cfg Config) {
	const property = "handle capabilities are exact"
	eachCase(r, cfg, property, "", func(hc HandleCase, _ enclave.Backend, h enclave.Handle, _ []byte) {
		claimed := capSet(hc.Capabilities)
		checkHandleCapability[enclave.ByteAccess](r, property, hc.Name, h, claimed, enclave.CapabilityBytes)
		checkHandleCapability[enclave.Freezer](r, property, hc.Name, h, claimed, enclave.CapabilityFreeze)
		checkHandleCapability[crypto.Signer](r, property, hc.Name, h, claimed, enclave.CapabilitySign)
		checkHandleCapability[crypto.Decrypter](r, property, hc.Name, h, claimed, enclave.CapabilityDecrypt)
		checkHandleCapability[enclave.AEAD](r, property, hc.Name, h, claimed, enclave.CapabilityAEAD)
		checkHandleCapability[enclave.Deriver](r, property, hc.Name, h, claimed, enclave.CapabilityDerive)
		checkHandleCapability[enclave.Attester](r, property, hc.Name, h, claimed, enclave.CapabilityAttest)
	})
}

func checkHandleCapability[T any](r *report, property, name string, h enclave.Handle, claimed map[enclave.Capability]bool, c enclave.Capability) {
	_, ok := h.(T)
	if claimed[c] && !ok {
		r.fail(property, "%s: Config claims handle capability %q, but %T does not implement it", name, c, h)
	}
	if !claimed[c] && ok {
		r.fail(property, "%s: Config does not claim handle capability %q, but %T implements it", name, c, h)
	}
}

func checkHandleCore(r *report, cfg Config) {
	const property = "handle lifecycle"
	for _, hc := range cfg.Handles {
		b, h, material, err := newHandle(r.ctx, cfg, hc)
		if err != nil {
			r.fail(property, "%s: %v", hc.Name, err)
			continue
		}
		if reflect.TypeOf(h).Kind() != reflect.Pointer {
			r.fail(property, "%s: handle dynamic type is %T, not a pointer to shared state", hc.Name, h)
		}
		owner := h.Backend()
		if isNilInterface(owner) {
			r.fail(property, "%s: Backend returned nil", hc.Name)
		} else if !sameBackend(owner, b) {
			r.fail(property, "%s: Backend returned %T %q, not the backend under test", hc.Name, owner, owner.Name())
		}
		if !h.IsAlive() {
			r.fail(property, "%s: new handle is not alive", hc.Name)
		}
		if h.Size() <= 0 {
			r.fail(property, "%s: new handle size is %d", hc.Name, h.Size())
		}
		if material != nil && h.Size() != len(material) {
			r.fail(property, "%s: Size is %d, want imported material size %d", hc.Name, h.Size(), len(material))
		}
		consts := constantsOf(h)
		checkDestroy(r, property, hc.Name+": Destroy", h)
		checkDestroy(r, property, hc.Name+": a second Destroy", h)
		checkDestroyed(r, property, hc.Name+": after Destroy", h, owner, consts)
	}
}

// destroy calls h.Destroy, and again while it returns
// ErrLockedMemoryUnavailable, the refusal the Destroy contract documents as
// keeping the material for a retried Destroy to release, at most
// destroyAttempts times. It returns the last call's error.
func destroy(h enclave.Handle) error {
	var err error
	for range destroyAttempts {
		if err = h.Destroy(); !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			return err
		}
	}
	return err
}

// checkDestroy destroys h through destroy, which who names, and judges the
// outcome with judgeDestroy.
func checkDestroy(r *report, property, who string, h enclave.Handle) {
	judgeDestroy(r, property, who, h, destroy(h))
}

// judgeDestroy fails property unless err, what destroy returned for h, is an
// outcome the Destroy contract allows: a nil error leaves the handle dead, a
// refusal to release is resumed by a retry, and any other error leaves the
// handle dead too.
func judgeDestroy(r *report, property, who string, h enclave.Handle, err error) {
	switch {
	case err == nil && h.IsAlive():
		r.fail(property, "%s returned nil and left the handle alive", who)
	case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
		r.fail(property, "%s returned %v on each of %d attempts; a retried Destroy resumes the release", who, err, destroyAttempts)
	case err != nil && h.IsAlive():
		r.fail(property, "%s returned %v and left the handle alive", who, err)
	}
}

// constants are what a handle keeps reporting after Destroy: AEAD's NonceSize
// and Overhead, and the public key of a signing or decryption key.
type constants struct {
	nonceSize, overhead int
	public              crypto.PublicKey
}

func constantsOf(h enclave.Handle) constants {
	var c constants
	if a, ok := h.(enclave.AEAD); ok {
		c.nonceSize, c.overhead = a.NonceSize(), a.Overhead()
	}
	c.public = publicOf(h)
	return c
}

func publicOf(h enclave.Handle) crypto.PublicKey {
	if s, ok := h.(crypto.Signer); ok {
		return s.Public()
	}
	if d, ok := h.(crypto.Decrypter); ok {
		return d.Public()
	}
	return nil
}

// checkDestroyed fails property for every way h, which owner made, departs
// from the destroyed state, its core methods and its capabilities checked
// apart. who names the handle and what destroyed it.
func checkDestroyed(r *report, property, who string, h enclave.Handle, owner enclave.Backend, c constants) {
	for _, wrong := range destroyedCore(h, owner) {
		r.fail(property, "%s, %s", who, wrong)
	}
	for _, wrong := range destroyedCapabilities(r.ctx, h, c) {
		r.fail(property, "%s, %s", who, wrong)
	}
}

// destroyedCore returns how the core methods of h, which owner made, depart
// from the destroyed state: IsAlive false, Size 0 and Backend still owner.
func destroyedCore(h enclave.Handle, owner enclave.Backend) []string {
	var wrong []string
	if h.IsAlive() {
		wrong = append(wrong, "IsAlive is true")
	}
	if n := h.Size(); n != 0 {
		wrong = append(wrong, fmt.Sprintf("Size is %d, want the destroyed size 0", n))
	}
	if after := h.Backend(); isNilInterface(after) || (!isNilInterface(owner) && !sameBackend(after, owner)) {
		wrong = append(wrong, "Backend changed")
	}
	return wrong
}

// destroyedCapabilities calls every capability method of h and returns how
// each departs from the destroyed state: each that returns an error must
// return ErrEnclaveDestroyed, and each that cannot must keep its non-secret
// constant.
func destroyedCapabilities(ctx context.Context, h enclave.Handle, c constants) []string {
	var wrong []string
	want := func(method string, err error) {
		if !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			wrong = append(wrong, fmt.Sprintf("%s returned %v, want ErrEnclaveDestroyed", method, err))
		}
	}
	if ba, ok := h.(enclave.ByteAccess); ok {
		called := false
		want("WithBytes", ba.WithBytes(func([]byte) error { called = true; return nil }))
		if called {
			wrong = append(wrong, "WithBytes called fn")
		}
		_, err := ba.EqualTo(nil)
		want("EqualTo", err)
	}
	if f, ok := h.(enclave.Freezer); ok {
		want("Freeze", f.Freeze())
	}
	if d, ok := h.(enclave.Deriver); ok {
		child, err := d.Derive(ctx, []byte("backendtest derive"), deriveBytes)
		want("Derive", err)
		if !isNilInterface(child) {
			wrong = append(wrong, "Derive returned a handle")
			_ = destroy(child)
		}
	}
	if s, ok := h.(crypto.Signer); ok {
		digest, opts := signArgs(c.public, []byte("backendtest destroyed"))
		_, err := s.Sign(rand.Reader, digest, opts)
		want("Sign", err)
	}
	if d, ok := h.(crypto.Decrypter); ok {
		ciphertext, opts := decryptArgs(c.public)
		_, err := d.Decrypt(rand.Reader, ciphertext, opts)
		want("Decrypt", err)
	}
	if a, ok := h.(enclave.AEAD); ok {
		nonce := make([]byte, c.nonceSize)
		_, err := a.Seal(nil, nonce, []byte("x"), nil)
		want("Seal", err)
		_, err = a.Open(nil, nonce, make([]byte, c.overhead+1), nil)
		want("Open", err)
		if a.NonceSize() != c.nonceSize || a.Overhead() != c.overhead {
			wrong = append(wrong, "AEAD constants changed")
		}
	}
	if at, ok := h.(enclave.Attester); ok {
		_, err := at.Attest(ctx, randomBytes(materialBytes))
		want("Attest", err)
	}
	if c.public != nil && !samePublic(publicOf(h), c.public) {
		wrong = append(wrong, "Public changed; a public key is not secret and keeps being reported")
	}
	return wrong
}

func checkConcurrentUse(r *report, cfg Config) {
	const property = "concurrent use"
	for _, hc := range cfg.Handles {
		b, h, material, err := newHandle(r.ctx, cfg, hc)
		if err != nil {
			r.fail(property, "%s: %v", hc.Name, err)
			continue
		}
		var stale atomic.Bool
		dr := &destroyRace{started: make(chan struct{}), called: make(chan struct{}), destroyed: make(chan struct{})}
		ops := operations(r.ctx, b, h, material, &stale, dr)
		consts := constantsOf(h)
		dead := func() ([]string, []string) {
			return destroyedCore(h, b), destroyedCapabilities(r.ctx, h, consts)
		}
		// Every worker reaches the start line before any runs, so they all
		// race the one Destroy.
		var ready, wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, concurrencyRuns)
		for i := 0; i < concurrencyRuns; i++ {
			ready.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				ready.Done()
				<-start
				errs <- exercise(ops, dr, dead)
			}()
		}
		ready.Wait()
		close(start)
		finished := make(chan struct{})
		go func() {
			wg.Wait()
			close(finished)
		}()
		// Destroy once an operation is in flight, or once every worker has
		// stopped short of one.
		select {
		case <-dr.started:
		case <-finished:
		}
		close(dr.called)
		dr.err = destroy(h)
		early := dr.open.Load()
		close(dr.destroyed)
		<-finished
		close(errs)
		judgeDestroy(r, property, hc.Name+": Destroy during concurrent operations", h, dr.err)
		if early {
			r.fail(property, "%s: Destroy returned while a WithBytes borrow was still open; Destroy waits out in-flight borrows", hc.Name)
		}
		for _, wrong := range dr.core {
			r.fail(property, "%s: after a Destroy racing concurrent operations returned nil, %s", hc.Name, wrong)
		}
		for _, wrong := range dr.capabilities {
			r.fail(property, "%s: after a Destroy racing concurrent operations returned nil, %s", hc.Name, wrong)
		}
		for err := range errs {
			var pe *panicError
			if errors.As(err, &pe) {
				r.panicked(pe.value)
				continue
			}
			if err != nil && !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				r.fail(property, "%s: concurrent operation returned %v", hc.Name, err)
			}
		}
		if stale.Load() {
			r.fail(property, "%s: a borrow racing Destroy saw bytes other than the handle's material, such as wiped or freed memory", hc.Name)
		}
	}
}

// operation is one call of a handle's method, prepared before the race so the
// racing goroutines share no setup.
type operation func() error

// destroyRace is one concurrency run's rendezvous with its Destroy.
type destroyRace struct {
	once sync.Once
	// started is closed once an operation is under way: the first borrow,
	// which holds the view, for a handle with ByteAccess, else any operation.
	started chan struct{}
	// called is closed as Destroy is called.
	called chan struct{}
	// destroyed is closed once Destroy has returned err.
	destroyed chan struct{}
	err       error
	// open is true while the held borrow's fn runs.
	open atomic.Bool

	mu sync.Mutex
	// core and capabilities are how the handle departed from the destroyed
	// state in a pass begun after Destroy returned nil, each recorded once.
	core, capabilities []string
}

// begin reports an operation under way.
func (dr *destroyRace) begin() { dr.once.Do(func() { close(dr.started) }) }

// hold, inside a borrow, makes the run's first borrow the one Destroy is
// called against: it reports it under way and open, and keeps the view from
// then until Destroy has returned or, for a Destroy that waits the borrow
// out, holdBound has passed since Destroy was called. It reports whether this
// borrow was held; the held borrow calls release as its fn returns.
func (dr *destroyRace) hold() bool {
	first := false
	dr.once.Do(func() {
		first = true
		dr.open.Store(true)
		close(dr.started)
	})
	if !first {
		return false
	}
	<-dr.called
	t := time.NewTimer(holdBound)
	defer t.Stop()
	select {
	case <-dr.destroyed:
	case <-t.C:
	}
	return true
}

// release reports the held borrow's fn returning.
func (dr *destroyRace) release() { dr.open.Store(false) }

// over reports whether Destroy has returned.
func (dr *destroyRace) over() bool {
	select {
	case <-dr.destroyed:
		return true
	default:
		return false
	}
}

// observe records what a pass begun after Destroy returned nil found, each
// finding once however many workers made it.
func (dr *destroyRace) observe(core, capabilities []string) {
	dr.mu.Lock()
	defer dr.mu.Unlock()
	for _, wrong := range core {
		if !slices.Contains(dr.core, wrong) {
			dr.core = append(dr.core, wrong)
		}
	}
	for _, wrong := range capabilities {
		if !slices.Contains(dr.capabilities, wrong) {
			dr.capabilities = append(dr.capabilities, wrong)
		}
	}
}

// operations returns what the concurrency check races against Destroy: Size,
// IsAlive and Backend always, Freeze for a Freezer, and one operation per
// optional capability h has. A borrow that sees anything but material, on
// entry or after it was held across Destroy, sets stale. Every operation
// reports itself to dr, the borrow by holding and releasing.
func operations(ctx context.Context, b enclave.Backend, h enclave.Handle, material []byte, stale *atomic.Bool, dr *destroyRace) []operation {
	// The borrows come first and Freeze, which waits them out, last, so a
	// pending Freeze does not keep the other workers from the held borrow.
	var ops []operation
	ba, borrows := h.(enclave.ByteAccess)
	if borrows {
		if material == nil {
			material = snapshot(ba)
		}
		ops = append(ops,
			func() error {
				called := false
				err := ba.WithBytes(func(v []byte) error {
					called = true
					if !bytes.Equal(v, material) {
						stale.Store(true)
					}
					if dr.hold() {
						if !bytes.Equal(v, material) {
							stale.Store(true)
						}
						dr.release()
					}
					return nil
				})
				if err == nil && !called {
					return &raceError{detail: "WithBytes returned nil without calling fn"}
				}
				return err
			},
			func() error { _, err := ba.EqualTo(material); return err })
	}
	size := h.Size()
	ops = append(ops,
		func() error {
			if n := h.Size(); n != size && n != 0 {
				return &raceError{detail: fmt.Sprintf("Size returned %d, neither the live size %d nor the destroyed size 0", n, size)}
			}
			return nil
		},
		func() error { _ = h.IsAlive(); return nil },
		func() error {
			if owner := h.Backend(); isNilInterface(owner) || !sameBackend(owner, b) {
				return &raceError{detail: fmt.Sprintf("Backend returned %T, not the backend that made the handle", owner)}
			}
			return nil
		},
	)
	if a, ok := h.(enclave.AEAD); ok {
		ops = append(ops, func() error {
			nonce := nonceFor(a)
			sealed, err := a.Seal(nil, nonce, []byte("x"), nil)
			if err != nil {
				return err
			}
			_, err = a.Open(nil, nonce, sealed, nil)
			return err
		})
	}
	if s, ok := h.(crypto.Signer); ok {
		digest, opts := signArgs(s.Public(), []byte("backendtest concurrent"))
		ops = append(ops, func() error { _, err := s.Sign(rand.Reader, digest, opts); return err })
	}
	if d, ok := h.(crypto.Decrypter); ok {
		ciphertext, opts := decryptArgs(d.Public())
		ops = append(ops, func() error { _, err := d.Decrypt(rand.Reader, ciphertext, opts); return err })
	}
	if d, ok := h.(enclave.Deriver); ok {
		ops = append(ops, func() error {
			child, err := d.Derive(ctx, []byte("backendtest concurrent"), deriveBytes)
			if !isNilInterface(child) {
				_ = destroy(child)
			}
			return err
		})
	}
	if at, ok := h.(enclave.Attester); ok {
		nonce := randomBytes(materialBytes)
		ops = append(ops, func() error { _, err := at.Attest(ctx, nonce); return err })
	}
	if f, ok := h.(enclave.Freezer); ok {
		ops = append(ops, f.Freeze)
	}
	if !borrows {
		// With no borrow to hold, any operation under way will do.
		for i, op := range ops {
			ops[i] = func() error {
				dr.begin()
				return op()
			}
		}
	}
	return ops
}

// exercise runs ops in a worker goroutine, where report.run's recover cannot
// reach: a panic is recovered here and returned as a *panicError. It runs them
// in turn until one fails with an error other than ErrEnclaveDestroyed, or
// until a pass begun after Destroy returned has run. After a nil Destroy that
// last pass is dead's, which finds how the handle departs from the destroyed
// state, its core methods and its capabilities apart; after an error, which
// may leave the material held, it is one more pass of ops.
func exercise(ops []operation, dr *destroyRace, dead func() (core, capabilities []string)) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &panicError{value: p}
		}
	}()
	for {
		last := dr.over()
		if last && dr.err == nil {
			dr.observe(dead())
			return nil
		}
		for _, op := range ops {
			if err := op(); err != nil && !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				return err
			}
		}
		if last {
			return nil
		}
	}
}

// eachCase runs fn on a fresh handle of every case that claims c, or of every
// case for an empty c, and destroys the handle afterwards.
func eachCase(r *report, cfg Config, property string, c enclave.Capability, fn func(hc HandleCase, b enclave.Backend, h enclave.Handle, material []byte)) {
	for _, hc := range cfg.Handles {
		if c != "" && !hasCap(hc.Capabilities, c) {
			continue
		}
		b, h, material, err := newHandle(r.ctx, cfg, hc)
		if err != nil {
			r.fail(property, "%s: %v", hc.Name, err)
			continue
		}
		func() {
			defer func() {
				checkDestroy(r, property, hc.Name+": Destroy after the check", h)
			}()
			fn(hc, b, h, material)
		}()
	}
}

func newBackend(cfg Config) (enclave.Backend, error) {
	b, err := cfg.New()
	if err != nil {
		return nil, &stepError{step: "Config.New", err: err}
	}
	if isNilInterface(b) {
		return nil, &nilBackendError{backend: b}
	}
	return b, nil
}

func newHandle(ctx context.Context, cfg Config, hc HandleCase) (enclave.Backend, enclave.Handle, []byte, error) {
	b, err := newBackend(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	h, material, err := newHandleFromBackend(ctx, b, hc)
	return b, h, material, err
}

func newHandleFromBackend(ctx context.Context, b enclave.Backend, hc HandleCase) (enclave.Handle, []byte, error) {
	if hc.New != nil {
		h, err := hc.New(ctx, b)
		if err != nil {
			return nil, nil, &stepError{step: hc.Name + ".New", err: err}
		}
		if isNilInterface(h) {
			return nil, nil, &nilHandleError{step: hc.Name + ".New", handle: h}
		}
		return h, nil, nil
	}
	imp, ok := b.(enclave.Importer)
	if !ok {
		return nil, nil, &enclave.CapabilityError{Backend: b.Name(), Capability: enclave.CapabilityImport}
	}
	material := randomBytes(hc.ImportSize)
	src := append([]byte(nil), material...)
	h, err := imp.Import(ctx, src, hc.Import...)
	if err != nil {
		return nil, nil, &stepError{step: hc.Name + ".Import", err: err}
	}
	if isNilInterface(h) {
		return nil, nil, &nilHandleError{step: hc.Name + ".Import", handle: h}
	}
	return h, material, nil
}

// sameBackend reports whether got is want: the same value where the type is
// comparable, or reached from got through enclave.As; for an uncomparable
// type, whose identity cannot be told, the same name.
func sameBackend(got, want enclave.Backend) bool {
	if isNilInterface(got) || isNilInterface(want) {
		return false
	}
	tw := reflect.TypeOf(want)
	found := any(got)
	if reflect.TypeOf(got) != tw {
		target := reflect.New(tw)
		if !enclave.As(got, target.Interface()) {
			return false
		}
		found = target.Elem().Interface()
	}
	if !tw.Comparable() {
		return got.Name() == want.Name()
	}
	return found == any(want)
}

// samePublic reports whether two public keys are equal, by their Equal method
// where they have one, as every standard library public key does.
func samePublic(a, b crypto.PublicKey) bool {
	if eq, ok := a.(interface{ Equal(crypto.PublicKey) bool }); ok {
		return eq.Equal(b)
	}
	return reflect.DeepEqual(a, b)
}

// signArgs returns what Sign takes to sign msg under pub: msg itself for
// Ed25519, else its SHA-256 digest.
func signArgs(pub crypto.PublicKey, msg []byte) ([]byte, crypto.SignerOpts) {
	if _, ok := pub.(ed25519.PublicKey); ok {
		return msg, crypto.Hash(0)
	}
	sum := sha256.Sum256(msg)
	return sum[:], crypto.SHA256
}

// decryptArgs returns a well-formed ciphertext for pub where the suite knows
// how to make one (RSA-OAEP with SHA-256), else filler bytes.
func decryptArgs(pub crypto.PublicKey) ([]byte, crypto.DecrypterOpts) {
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
	if rp, ok := pub.(*rsa.PublicKey); ok {
		if ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rp, []byte("backendtest"), nil); err == nil {
			return ciphertext, opts
		}
	}
	return randomBytes(materialBytes), opts
}

// snapshot returns a copy of a handle's material, or nil when it cannot be
// read.
func snapshot(ba enclave.ByteAccess) []byte {
	var out []byte
	_ = ba.WithBytes(func(b []byte) error {
		out = append([]byte{}, b...)
		return nil
	})
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func capSet(caps []enclave.Capability) map[enclave.Capability]bool {
	out := make(map[enclave.Capability]bool, len(caps))
	for _, c := range caps {
		out[c] = true
	}
	return out
}

func hasCap(caps []enclave.Capability, want enclave.Capability) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// nonceFor returns a fresh random nonce for aead, nil when it takes none. Every
// Seal draws its own, so no key/nonce pair is used twice, as cipher.AEAD
// requires, and a backend that refuses a reused nonce is not penalized.
func nonceFor(aead enclave.AEAD) []byte {
	if aead.NonceSize() == 0 {
		return nil
	}
	return randomBytes(aead.NonceSize())
}

func wrongNonceFor(aead enclave.AEAD) []byte {
	if aead.NonceSize() == 0 {
		return []byte{1}
	}
	return make([]byte, aead.NonceSize()-1)
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func canceledContext(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	cancel()
	return ctx
}

func contextName(ctx context.Context) string {
	if ctx == nil {
		return "nil"
	}
	return "done"
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func validBackendName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
		if !ok {
			return false
		}
	}
	first, last := s[0], s[len(s)-1]
	return isLowerDigit(first) && isLowerDigit(last)
}

func isLowerDigit(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
