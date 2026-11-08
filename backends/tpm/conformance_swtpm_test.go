//go:build swtpm

package tpm

import (
	"context"
	"os"
	"testing"

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
