//go:build swtpm

package tpm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// swtpmVar names the TPM the conformance test runs against: a device path,
// or a swtpm command socket as "unix:<path>" or "tcp:<host:port>". swtpm
// must be started with --flags startup-clear, since the provider sends no
// TPM2_Startup.
const swtpmVar = "GO_ENCLAVE_SWTPM"

// sealedBlobBytes is the exact blob length for a 32-byte key: the version
// byte, the 46-byte public area and the 158-byte private area, each behind
// its 2-byte size field: 209 bytes.
const sealedBlobBytes = 1 + 2 + sealedPublicBytes + 2 + sealedPrivateBytes

func openSWTPM(t *testing.T) *KeyProtector {
	t.Helper()
	path := os.Getenv(swtpmVar)
	if path == "" {
		t.Skipf("%s is not set; set it to a TPM device or a swtpm socket to run the TPM conformance test", swtpmVar)
	}
	p, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestProviderConformance_OnSWTPM runs providertest against the TPM. Forge
// seals the key under the standard storage template (no label) on the same
// TPM, so the suite measures the label binding.
func TestProviderConformance_OnSWTPM(t *testing.T) {
	p := openSWTPM(t)
	cfg := providertest.Config{
		New:   func() (any, error) { return p, nil },
		Modes: []enclave.Mode{enclave.ModePerOperation},
		Forge: func(kp enclave.KeyProtector, key []byte) ([]byte, error) {
			return kp.(*KeyProtector).protect(context.Background(), key, storageTemplate(make([]byte, 32)))
		},
		Logf: t.Logf,
	}
	if err := providertest.TestProvider(context.Background(), cfg); err != nil {
		t.Fatalf("the TPM provider fails conformance: %v", err)
	}
}

func TestBlobLength_OnSWTPM(t *testing.T) {
	p := openSWTPM(t)
	blob, err := p.Protect(context.Background(), make([]byte, 32))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	if len(blob) != sealedBlobBytes {
		t.Fatalf("a 32-byte key sealed into %d bytes, want %d", len(blob), sealedBlobBytes)
	}
}

// trip cancels a context the moment a chosen command has been written to the
// TPM, so that the interrupt lands while the TPM runs the command and its
// response is lost.
type trip struct {
	mu     sync.Mutex
	cc     tpm2.TPMCC
	cancel context.CancelFunc
	fired  bool
}

func (tr *trip) arm(cc tpm2.TPMCC, cancel context.CancelFunc) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.cc, tr.cancel, tr.fired = cc, cancel, false
}

func (tr *trip) check(cmd []byte) {
	if len(cmd) < 10 {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.cancel != nil && tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == tr.cc {
		tr.cancel()
		tr.cancel, tr.fired = nil, true
	}
}

func (tr *trip) hasFired() bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.fired
}

// tripStream is the provider's TPM stream with a trip on its writes. It keeps
// the stream's deadlines, which the provider's interrupt sets.
type tripStream struct {
	io.ReadWriteCloser
	trip *trip
}

func (s tripStream) Write(cmd []byte) (int, error) {
	n, err := s.ReadWriteCloser.Write(cmd)
	s.trip.check(cmd)
	return n, err
}

func (s tripStream) SetDeadline(t time.Time) error {
	if d, ok := s.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}

// openTripSWTPM is openSWTPM with a trip on the stream and on every stream
// the provider reopens.
func openTripSWTPM(t *testing.T) (*KeyProtector, *trip) {
	t.Helper()
	p := openSWTPM(t)
	tr := &trip{}
	st := p.dev.(*tpmDevice).t
	st.rw = tripStream{st.rw, tr}
	dial := st.dial
	st.dial = func(ctx context.Context) (io.ReadWriteCloser, error) {
		rw, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return tripStream{rw, tr}, nil
	}
	return p, tr
}

// liveHandles counts the transient objects and loaded sessions the TPM
// holds, with TPM2_GetCapability on the provider's stream, between calls.
func liveHandles(t *testing.T, p *KeyProtector) (objects, sessions int) {
	t.Helper()
	p.sem <- struct{}{}
	defer p.release()
	st := p.dev.(*tpmDevice).t
	ctx := context.Background()
	if err := st.reopen(ctx); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	count := func(ht tpm2.TPMHT) int {
		defer st.wipe()
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      uint32(ht) << 24,
			PropertyCount: 254,
		}.Execute(st.bind(ctx))
		if err != nil {
			t.Fatalf("TPM2_GetCapability(%#x): %v", uint32(ht)<<24, err)
		}
		hs, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			t.Fatalf("TPM2_GetCapability(%#x): %v", uint32(ht)<<24, err)
		}
		return len(hs.Handle)
	}
	return count(tpm2.TPMHTTransient), count(tpm2.TPMHTLoadedSession)
}

// TestReclaimAfterInterrupt_OnSWTPM interrupts each handle-bearing command
// of Protect and Unprotect, right after it reaches the TPM, more times than
// the TPM has transient-object and session slots (swtpm has 3 of each). A
// simulator socket has no resource manager, so every handle the calls made
// must be flushed by the provider: the counts end where they began, and the
// next Protect and Unprotect succeed.
func TestReclaimAfterInterrupt_OnSWTPM(t *testing.T) {
	p, tr := openTripSWTPM(t)
	key := bytes.Repeat([]byte{0x5a}, 32)
	blob, err := p.Protect(context.Background(), key)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	objects, sessions := liveHandles(t, p)
	const rounds = 8
	for _, c := range []struct {
		op string
		cc tpm2.TPMCC
	}{
		{"Protect", tpm2.TPMCCCreatePrimary},
		{"Protect", tpm2.TPMCCStartAuthSession},
		{"Protect", tpm2.TPMCCCreate},
		{"Unprotect", tpm2.TPMCCLoad},
		{"Unprotect", tpm2.TPMCCUnseal},
	} {
		for i := range rounds {
			ctx, cancel := context.WithCancel(context.Background())
			tr.arm(c.cc, cancel)
			if c.op == "Protect" {
				_, err = p.Protect(ctx, key)
			} else {
				err = p.Unprotect(ctx, blob, make([]byte, len(key)))
			}
			cancel()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s interrupted in %v, round %d: %v, want context.Canceled", c.op, c.cc, i, err)
			}
			if !tr.hasFired() {
				t.Fatalf("%s, round %d: %v never reached the TPM", c.op, i, c.cc)
			}
		}
	}
	if o, s := liveHandles(t, p); o != objects || s != sessions {
		t.Fatalf("after %d interrupts the TPM holds %d transient objects and %d sessions, %d and %d before", 5*rounds, o, s, objects, sessions)
	}
	got := make([]byte, len(key))
	if blob, err = p.Protect(context.Background(), key); err != nil {
		t.Fatalf("Protect after the interrupts: %v", err)
	}
	if err := p.Unprotect(context.Background(), blob, got); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("Unprotect after the interrupts: %v", err)
	}
}
