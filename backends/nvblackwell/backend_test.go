package nvblackwell

import (
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

func TestName(t *testing.T) {
	if Name != "nvidia-blackwell" {
		t.Errorf("Name = %q, want %q, the design's backend name", Name, "nvidia-blackwell")
	}
}

func TestNewRefusesNoInner(t *testing.T) {
	b, err := New(nil)
	if b != nil || !errors.Is(err, ErrNoInner) {
		t.Fatalf("New(nil) = %v, %v; want nil, ErrNoInner", b, err)
	}
}

// The locked-memory backend is a real backend that is no CPU TEE: it does not
// import, attest or confine, so New refuses it with a *CapabilityError naming
// it and the first missing capability, import, before any probe.
func TestNewRefusesABackendThatIsNoCPUTEE(t *testing.T) {
	inner := enclave.DefaultBackend()
	b, err := New(inner)
	if b != nil {
		t.Fatalf("New(locked memory) = %v, want nil", b)
	}
	var ce *enclave.CapabilityError
	if !errors.As(err, &ce) || !errors.Is(err, enclave.ErrCapabilityUnsupported) {
		t.Fatalf("New(locked memory) error = %v, want a *enclave.CapabilityError", err)
	}
	if ce.Backend != inner.Name() || ce.Capability != enclave.CapabilityImport {
		t.Errorf("CapabilityError = %+v, want backend %q lacking %q", ce, inner.Name(), enclave.CapabilityImport)
	}
}
