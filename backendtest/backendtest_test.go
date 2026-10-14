package backendtest

import (
	"context"
	"errors"
	"os"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// errFake is the error the fakes' factories fail with.
var errFake = errors.New("fake: factory failure")

func TestBackendConformance_Allocator(t *testing.T) {
	cfg := Config{
		New: func() (enclave.Backend, error) {
			return enclave.NewAllocator(1 << 20)
		},
		BackendCapabilities: []enclave.Capability{enclave.CapabilityImport, enclave.CapabilityProbe},
		Handles: []HandleCase{
			{
				Name:       "material",
				Import:     []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
				ImportSize: materialBytes,
				Capabilities: []enclave.Capability{
					enclave.CapabilityBytes,
					enclave.CapabilityFreeze,
				},
			},
			{
				Name: "wrapping-key",
				Import: []enclave.ImportOption{
					enclave.WithPurpose(enclave.PurposeWrappingKey),
					enclave.WithAlgorithm(enclave.AlgorithmAES256GCM),
				},
				ImportSize: materialBytes,
				Capabilities: []enclave.Capability{
					enclave.CapabilityBytes,
					enclave.CapabilityFreeze,
				},
			},
		},
		Logf: t.Logf,
	}
	if !memscan.Supported {
		cfg.SkipResidueSweep = memscan.UnsupportedReason
	}
	if err := TestBackend(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

// TestBackendConformance_Fake pins that the fake every broken fake is built
// from passes, so each finding below is its fault's alone.
func TestBackendConformance_Fake(t *testing.T) {
	cfg := swept(fakeConfig(faults{}))
	cfg.Logf = t.Logf
	if err := runFake(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// One imported case is enough for a claimed Importer.
	oneImport := edit(fakeConfig(faults{}), func(c *Config) { c.Handles = c.Handles[1:] })
	if err := runFake(context.Background(), oneImport); err != nil {
		t.Fatalf("TestBackend with one imported case = %v", err)
	}
}

// TestBackendConformance_SignerKeys pins that a signer passes under every key
// type the suite verifies.
func TestBackendConformance_SignerKeys(t *testing.T) {
	for _, key := range []string{"rsa", "ed25519"} {
		t.Run(key, func(t *testing.T) {
			cfg := edit(fakeConfig(faults{signerKey: key}), func(c *Config) { c.Handles = c.Handles[1:3] })
			if err := runFake(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestBackendConformance_NonceReuseRejected pins that a backend refusing a
// reused nonce, as cipher.AEAD lets it, passes: the suite seals every time
// under a fresh nonce, concurrent calls included.
func TestBackendConformance_NonceReuseRejected(t *testing.T) {
	cfg := fakeConfig(faults{rejectsNonceReuse: true})
	if err := runFake(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// The fake does refuse a reused nonce, so the pass above means something.
	defer releaseFakes()
	imp := newFake(faults{rejectsNonceReuse: true}).(enclave.Importer)
	h, err := imp.Import(context.Background(), randomBytes(materialBytes),
		enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM))
	if err != nil {
		t.Fatal(err)
	}
	a := h.(enclave.AEAD)
	nonce := make([]byte, a.NonceSize())
	if _, err := a.Seal(nil, nonce, []byte("x"), nil); err != nil {
		t.Fatalf("first Seal = %v", err)
	}
	if _, err := a.Seal(nil, nonce, []byte("x"), nil); !errors.Is(err, errNonceReused) {
		t.Fatalf("Seal with a reused nonce = %v, want errNonceReused", err)
	}
}

// TestBackendConformance_RetryableDestroy pins that a Destroy refused once
// with the documented retryable error, then completed, passes: only a nil
// return obliges the handle to be dead.
func TestBackendConformance_RetryableDestroy(t *testing.T) {
	if err := runFake(context.Background(), fakeConfig(faults{destroyRefusedOnce: true})); err != nil {
		t.Fatal(err)
	}
}

// TestBackendConformance_BrokenFakesFail proves each check fails: every fake
// carries one defect, and the run must report the property that names it.
func TestBackendConformance_BrokenFakesFail(t *testing.T) {
	tests := []struct {
		name     string
		property string
		cfg      Config
	}{
		{name: "bad name", property: "backend identity", cfg: fakeConfig(faults{badName: true})},
		{name: "backend capability overclaim", property: "backend capabilities are exact", cfg: fakeConfig(faults{noSweep: true})},
		{name: "backend capability underclaim", property: "backend capabilities are exact", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.BackendCapabilities = c.BackendCapabilities[:3]
		})},
		{name: "handle capability underclaim", property: "handle capabilities are exact", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[0].Capabilities = []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze}
		})},
		{name: "handle capability overclaim", property: "handle capabilities are exact", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[3].Capabilities = []enclave.Capability{enclave.CapabilityDecrypt, enclave.CapabilitySign}
		})},
		{name: "non pointer handle", property: "handle lifecycle", cfg: nonPointerConfig()},
		{name: "destroy leaves live", property: "handle lifecycle", cfg: fakeConfig(faults{destroyLeavesLive: true})},
		{name: "racing Destroy returns nil and leaves live", property: "concurrent use", cfg: fakeConfig(faults{racingDestroyLeavesLive: true})},
		{name: "racing Destroy returns before the held borrow exits", property: "concurrent use", cfg: fakeConfig(faults{racingDestroyReturnsEarly: true})},
		{name: "capabilities work after a racing Destroy", property: "concurrent use", cfg: fakeConfig(faults{racingDestroyKeepsWorking: true})},
		{name: "Size racing Destroy is neither live nor destroyed", property: "concurrent use", cfg: fakeConfig(faults{sizeRacesDestroy: true})},
		{name: "Freeze racing Destroy fails", property: "concurrent use", cfg: fakeConfig(faults{freezeRacesDestroy: true})},
		{name: "handle of another backend", property: "handle lifecycle", cfg: fakeConfig(faults{foreignBackend: true})},
		{name: "byte access lies", property: "ByteAccess", cfg: fakeConfig(faults{byteAccessLies: true})},
		{name: "view length is not Size", property: "ByteAccess", cfg: fakeConfig(faults{sizeLies: true})},
		{name: "WithBytes drops fn's error", property: "ByteAccess", cfg: fakeConfig(faults{withBytesDropsErr: true})},
		{name: "Freeze is a no-op", property: "Freezer", cfg: fakeConfig(faults{freezeNoop: true})},
		{name: "Freeze refuses", property: "Freezer", cfg: fakeConfig(faults{freezeRefuses: true})},
		{name: "Freeze protects only the first page", property: "Freezer", cfg: edit(fakeConfig(faults{freezeHeadOnly: true}), func(c *Config) {
			c.Handles[0].ImportSize = 2 * os.Getpagesize()
		})},
		{name: "Freeze destroys", property: "Freezer", cfg: fakeConfig(faults{freezeDestroys: true})},
		{name: "Freeze after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{freezeAfterDestroy: true})},
		{name: "Derive ignores info", property: "Deriver", cfg: fakeConfig(faults{deriveIgnoresInfo: true})},
		{name: "Derive is not deterministic", property: "Deriver", cfg: fakeConfig(faults{deriveRandom: true})},
		{name: "Derive ignores canceled context", property: "Deriver", cfg: fakeConfig(faults{deriveIgnoresCanceled: true})},
		{name: "Derive returns the wrong size", property: "Deriver", cfg: fakeConfig(faults{deriveWrongSize: true})},
		{name: "Derive fails", property: "Deriver", cfg: fakeConfig(faults{deriveFails: true})},
		{name: "Derive after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{deriveAfterDestroy: true})},
		{name: "Sign with the wrong key", property: "crypto.Signer", cfg: fakeConfig(faults{signWrongKey: true})},
		{name: "RSA Sign with the wrong key", property: "crypto.Signer", cfg: fakeConfig(faults{signerKey: "rsa", signWrongKey: true})},
		{name: "Ed25519 Sign with the wrong key", property: "crypto.Signer", cfg: fakeConfig(faults{signerKey: "ed25519", signWrongKey: true})},
		{name: "Sign after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{signAfterDestroy: true})},
		{name: "Public changes after Destroy", property: "handle lifecycle", cfg: fakeConfig(faults{publicChanges: true})},
		{name: "Decrypt accepts tamper", property: "crypto.Decrypter", cfg: fakeConfig(faults{decryptAcceptsTamper: true})},
		{name: "Decrypt returns the wrong plaintext", property: "crypto.Decrypter", cfg: fakeConfig(faults{decryptWrong: true})},
		{name: "Decrypt after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{decryptAfterDestroy: true})},
		{name: "aead accepts tamper", property: "AEAD", cfg: fakeConfig(faults{aeadAcceptsTamper: true})},
		{name: "Seal ignores dst", property: "AEAD", cfg: fakeConfig(faults{aeadIgnoresDst: true})},
		{name: "AEAD accepts any nonce length", property: "AEAD", cfg: fakeConfig(faults{aeadIgnoresNonceSize: true})},
		{name: "AEAD understates Overhead", property: "AEAD", cfg: fakeConfig(faults{aeadBadOverhead: true})},
		{name: "AEAD after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{aeadAfterDestroy: true})},
		{name: "Attest ignores the nonce", property: "Attester", cfg: fakeConfig(faults{attestIgnoresNonce: true})},
		{name: "Attest ignores the nonce with fresh random evidence", property: "Attester", cfg: fakeConfig(faults{attestRandom: true})},
		{name: "Attest truncates a long nonce", property: "Attester", cfg: fakeConfig(faults{attestTruncates: true})},
		{name: "Attest accepts an empty nonce", property: "Attester", cfg: fakeConfig(faults{attestAcceptsEmpty: true})},
		{name: "Attest refuses a 1-byte nonce", property: "Attester", cfg: fakeConfig(faults{attestRefusesShort: true})},
		{name: "Attest ignores canceled context", property: "Attester", cfg: fakeConfig(faults{attestIgnoresCanceled: true})},
		{name: "Attest returns empty evidence", property: "Attester", cfg: fakeConfig(faults{attestEmptyEvidence: true})},
		{name: "Attest after Destroy succeeds", property: "handle lifecycle", cfg: fakeConfig(faults{attestAfterDestroy: true})},
		{name: "import does not wipe", property: "Importer", cfg: fakeConfig(faults{noWipe: true})},
		{name: "import ignores canceled context", property: "Importer", cfg: fakeConfig(faults{importIgnoresCanceled: true})},
		{name: "import accepts bad AES size", property: "Importer", cfg: fakeConfig(faults{acceptBadAESSize: true})},
		{name: "import alters the material", property: "Importer", cfg: fakeConfig(faults{importAltersMaterial: true})},
		{name: "imported AEAD holds another key", property: "Importer", cfg: fakeConfig(faults{aeadWrongKey: true})},
		{name: "imported AES key reports the wrong Overhead", property: "Importer", cfg: fakeConfig(faults{aeadBadOverhead: true})},
		{name: "imported material is opaque", property: "Importer", cfg: fakeConfig(faults{materialOpaque: true})},
		{name: "refused import returns a live handle", property: "Importer", cfg: fakeConfig(faults{importRefusalLive: true})},
		{name: "sweeper leaves live", property: "Sweeper", cfg: fakeConfig(faults{sweepLeavesLive: true})},
		{name: "Sweep keeps the material of handles it reports dead", property: "Sweeper", cfg: fakeConfig(faults{sweepKeepsMaterial: true})},
		{name: "repeated sweep reports held", property: "Sweeper", cfg: fakeConfig(faults{sweepTwiceHeld: true})},
		{name: "confiner unstable", property: "Confiner", cfg: fakeConfig(faults{unstableConfine: true})},
		{name: "Rank unstable", property: "Prober", cfg: fakeConfig(faults{unstableRank: true})},
		{name: "Probe unstable", property: "Prober", cfg: fakeConfig(faults{unstableProbe: true})},
		{name: "panic", property: "panic safety", cfg: fakeConfig(faults{panicConfine: true})},
		{name: "Probe panics", property: "panic safety", cfg: fakeConfig(faults{panicProbe: true})},
		{name: "panic under concurrent use only", property: "panic safety", cfg: fakeConfig(faults{panicConcurrent: true})},
		{name: "Config.New fails", property: "backend identity", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.New = func() (enclave.Backend, error) { return nil, errFake }
		})},
		{name: "Config.New returns a typed nil", property: "backend identity", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.New = func() (enclave.Backend, error) { return (*fakeBackend)(nil), nil }
		})},
		{name: "case New fails", property: "handle lifecycle", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[2].New = func(context.Context, enclave.Backend) (enclave.Handle, error) { return nil, errFake }
		})},
		{name: "case New returns a typed nil", property: "handle lifecycle", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[2].New = func(context.Context, enclave.Backend) (enclave.Handle, error) { return (*signerHandle)(nil), nil }
		})},
		{name: "imported case without an Importer", property: "handle lifecycle", cfg: edit(nonPointerConfig(), func(c *Config) {
			c.Handles = []HandleCase{{Name: "material", Import: []enclave.ImportOption{}, ImportSize: materialBytes}}
		})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runFake(context.Background(), tc.cfg)
			if !hasProperty(err, tc.property) {
				t.Fatalf("TestBackend did not report property %q: %v", tc.property, err)
			}
		})
	}
}

// TestBackendConformance_UncheckedCapabilities proves a declared capability
// the suite cannot exercise is refused, naming it, rather than passed.
func TestBackendConformance_UncheckedCapabilities(t *testing.T) {
	tests := []struct {
		name string
		cap  enclave.Capability
		cfg  Config
	}{
		{name: "unknown handle capability", cap: "teleport", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[0].Capabilities = append(c.Handles[0].Capabilities, "teleport")
		})},
		{name: "unknown backend capability", cap: "teleport", cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.BackendCapabilities = append(c.BackendCapabilities, "teleport")
		})},
		{name: "Attester without an evidence verifier", cap: enclave.CapabilityAttest, cfg: edit(fakeConfig(faults{attestRandom: true}), func(c *Config) {
			c.VerifyEvidence = nil
		})},
		{name: "Freezer without ByteAccess", cap: enclave.CapabilityFreeze, cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[1].Capabilities = append(c.Handles[1].Capabilities, enclave.CapabilityFreeze)
		})},
		{name: "Signer with an unknown key type", cap: enclave.CapabilitySign, cfg: fakeConfig(faults{signUnknownKey: true})},
		{name: "Decrypter with a key that is not RSA", cap: enclave.CapabilityDecrypt, cfg: fakeConfig(faults{decryptNotRSA: true})},
		{name: "Deriver with opaque derived handles", cap: enclave.CapabilityDerive, cfg: fakeConfig(faults{deriveOpaque: true})},
		{name: "Deriver with an opaque handle for different info", cap: enclave.CapabilityDerive, cfg: fakeConfig(faults{deriveOpaqueOtherInfo: true})},
		{name: "Importer without an imported case", cap: enclave.CapabilityImport, cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles = c.Handles[2:]
		})},
		{name: "imported AEAD of an algorithm the suite cannot verify", cap: enclave.CapabilityImport, cfg: edit(fakeConfig(faults{}), func(c *Config) {
			c.Handles[1].Import = []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeWrappingKey), enclave.WithAlgorithm("fake-cipher")}
		})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runFake(context.Background(), tc.cfg)
			if !errors.Is(err, ErrUncheckedCapability) {
				t.Fatalf("TestBackend = %v, want ErrUncheckedCapability", err)
			}
			if !hasUnchecked(err, tc.cap) {
				t.Fatalf("TestBackend did not name capability %q: %v", tc.cap, err)
			}
		})
	}
}

func TestBackendConformance_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*Config)
	}{
		{name: "nil New", fn: func(c *Config) { c.New = nil }},
		{name: "no handles", fn: func(c *Config) { c.Handles = nil }},
		{name: "empty case name", fn: func(c *Config) { c.Handles[0].Name = "" }},
		{name: "duplicate case name", fn: func(c *Config) { c.Handles[1].Name = c.Handles[0].Name }},
		{name: "both New and Import", fn: func(c *Config) { c.Handles[2].Import = c.Handles[0].Import }},
		{name: "neither New nor Import", fn: func(c *Config) { c.Handles[2].New = nil }},
		{name: "zero ImportSize", fn: func(c *Config) { c.Handles[0].ImportSize = 0 }},
		{name: "backend capability on a handle", fn: func(c *Config) {
			c.Handles[0].Capabilities = append(c.Handles[0].Capabilities, enclave.CapabilitySweep)
		}},
		{name: "handle capability on the backend", fn: func(c *Config) {
			c.BackendCapabilities = append(c.BackendCapabilities, enclave.CapabilityBytes)
		}},
		{name: "duplicate capability", fn: func(c *Config) {
			c.Handles[0].Capabilities = append(c.Handles[0].Capabilities, enclave.CapabilityBytes)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runFake(context.Background(), edit(fakeConfig(faults{}), tc.fn))
			var ce *ConfigError
			if !errors.Is(err, ErrInvalidConfig) || !errors.As(err, &ce) {
				t.Fatalf("TestBackend = %v, want a *ConfigError", err)
			}
		})
	}
}

func TestBackendConformance_Aborted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runFake(ctx, fakeConfig(faults{}))
	var ae *AbortedError
	if !errors.As(err, &ae) || !errors.Is(err, ErrAborted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("TestBackend with an ended context = %v, want an *AbortedError caused by context.Canceled", err)
	}
	// A nil context is part of TestBackend's contract.
	if err := runFake(nil, fakeConfig(faults{})); err != nil {
		t.Fatalf("TestBackend with a nil context = %v", err)
	}
}

// A context that ends inside a call the compliant fake then refuses with the
// context's error is an abort, not a finding against the backend.
func TestBackendConformance_AbortedMidCall(t *testing.T) {
	for _, call := range []string{"import", "derive", "attest"} {
		t.Run(call, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := runFake(ctx, fakeConfig(faults{cancelOn: call, cancel: cancel}))
			var fe *FindingsError
			if !errors.As(err, &fe) || len(fe.Findings) != 1 || !errors.Is(fe.Findings[0], ErrAborted) {
				t.Fatalf("TestBackend canceled inside %s = %v, want ErrAborted alone", call, err)
			}
		})
	}
}

// TestBackendConformance_Residue proves the residue check fails a backend that
// keeps a copy, reports a blind or failing sweep as unmeasured rather than
// passed, and notes a skipped one.
func TestBackendConformance_Residue(t *testing.T) {
	if !memscan.Supported {
		t.Skip(memscan.UnsupportedReason)
	}
	t.Run("leak", func(t *testing.T) {
		if err := runFake(context.Background(), residueConfig(faults{residueLeak: true})); !hasProperty(err, "residue") {
			t.Fatalf("TestBackend did not report the residue: %v", err)
		}
	})
	t.Run("Sweep keeps the material", func(t *testing.T) {
		if err := runFake(context.Background(), residueConfig(faults{sweepKeepsMaterial: true})); !hasProperty(err, "residue") {
			t.Fatalf("TestBackend did not report the residue a Sweep left: %v", err)
		}
	})
	sweeps := []struct {
		name  string
		sweep func([]byte, uintptr) ([]string, error)
	}{
		{name: "blind", sweep: func([]byte, uintptr) ([]string, error) { return nil, nil }},
		{name: "failing", sweep: func([]byte, uintptr) ([]string, error) { return nil, errFake }},
	}
	for _, tc := range sweeps {
		t.Run(tc.name, func(t *testing.T) {
			defer func(orig func([]byte, uintptr) ([]string, error)) { sweepProcess = orig }(sweepProcess)
			sweepProcess = tc.sweep
			if err := runFake(context.Background(), residueConfig(faults{})); !errors.Is(err, ErrNotMeasured) || hasProperty(err, "residue") {
				t.Fatalf("TestBackend with a %s sweep = %v, want ErrNotMeasured and no residue finding", tc.name, err)
			}
		})
	}
	t.Run("sweep fails after its control", func(t *testing.T) {
		defer func(orig func([]byte, uintptr) ([]string, error)) { sweepProcess = orig }(sweepProcess)
		calls := 0
		sweepProcess = func(needle []byte, home uintptr) ([]string, error) {
			if calls++; calls == 1 {
				return memscan.Find(needle, home)
			}
			return nil, errFake
		}
		cfg := residueConfig(faults{})
		if err := runFake(context.Background(), cfg); !errors.Is(err, ErrNotMeasured) {
			t.Fatalf("TestBackend = %v, want ErrNotMeasured", err)
		}
	})
	t.Run("short material", func(t *testing.T) {
		cfg := edit(residueConfig(faults{}), func(c *Config) { c.Handles[0].ImportSize = residueNeedleMin - 1 })
		if err := runFake(context.Background(), cfg); !errors.Is(err, ErrNotMeasured) {
			t.Fatalf("TestBackend = %v, want ErrNotMeasured", err)
		}
	})
	t.Run("skipped", func(t *testing.T) {
		notes := 0
		cfg := residueConfig(faults{residueLeak: true})
		cfg.SkipResidueSweep = "accepted for the test"
		cfg.Logf = func(string, ...any) { notes++ }
		if err := runFake(context.Background(), cfg); err != nil || notes == 0 {
			t.Fatalf("TestBackend with the sweep skipped = %v after %d notes, want nil and a note", err, notes)
		}
	})
}

// residueConfig is a swept fake with flt and only its material case, the one
// the sweep measures.
func residueConfig(flt faults) Config {
	cfg := swept(fakeConfig(flt))
	cfg.Handles = cfg.Handles[:1]
	return cfg
}

// hasProperty reports whether err holds a PropertyError for property.
func hasProperty(err error, property string) bool {
	var fe *FindingsError
	if !errors.As(err, &fe) {
		return false
	}
	for _, f := range fe.Findings {
		var pe *PropertyError
		if errors.As(f, &pe) && pe.Property == property {
			return true
		}
	}
	return false
}

// hasUnchecked reports whether err is or holds an UncheckedCapabilityError
// for c.
func hasUnchecked(err error, c enclave.Capability) bool {
	findings := []error{err}
	var fe *FindingsError
	if errors.As(err, &fe) {
		findings = fe.Findings
	}
	for _, f := range findings {
		var ue *UncheckedCapabilityError
		if errors.As(f, &ue) && ue.Capability == c {
			return true
		}
	}
	return false
}
