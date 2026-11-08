//go:build optee

package armtrustzone

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// opteeEndpointVar names the TEE device, as the arm-trustzone harness sets
// it in the guest: /dev/tee0.
const opteeEndpointVar = "GO_ENCLAVE_OPTEE_ENDPOINT"

// opteeSealVar makes SEAL a requirement: "required" fails the KeyProtector
// test, rather than skipping it, when the trusted application has no SEAL.
const opteeSealVar = "GO_ENCLAVE_OPTEE_SEAL"

// TestBackendConformance_OnOPTEE registers the backend in-process and runs
// backendtest against the trusted application on OP-TEE, with the TA's
// capabilities: the GET_INFO probe and random-filled handles. It is the
// optee-tagged binary the harness drops into the guest.
func TestBackendConformance_OnOPTEE(t *testing.T) {
	endpoint := os.Getenv(opteeEndpointVar)
	if endpoint == "" {
		t.Fatalf("the arm-trustzone conformance test cannot run: %v", &backendtest.EndpointError{Variable: opteeEndpointVar})
	}
	if err := enclave.Register(Connector{}); err != nil {
		t.Fatalf("enclave.Register: %v", err)
	}
	registered, err := enclave.Lookup(Name)
	if err != nil {
		t.Fatalf("enclave.Lookup(%q): %v", Name, err)
	}
	var connector interface {
		Connect(endpoint string) (enclave.Backend, error)
	}
	if !enclave.As(registered, &connector) {
		t.Fatalf("the registered %q backend has no Connect", Name)
	}
	cfg := backendtest.Config{
		New: func() (enclave.Backend, error) {
			b, err := connector.Connect(endpoint)
			if err == nil {
				t.Cleanup(func() { _ = b.(*Backend).Close() })
			}
			return b, err
		},
		BackendCapabilities: []enclave.Capability{enclave.CapabilityProbe},
		Handles: []backendtest.HandleCase{{
			Name: "rng",
			New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
				return b.(*Backend).Random(ctx, 32)
			},
			Capabilities: []enclave.Capability{enclave.CapabilityBytes},
		}},
		Logf: t.Logf,
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatalf("the arm-trustzone backend fails conformance: %v", err)
	}
}

// TestKeyProtectorConformance_OnOPTEE runs the provider suite against the
// backend's KeyProtector, on the same fixture. A trusted application that
// has no SEAL (see sealAbsent) predates trusted-firmware's SEAL, and the
// test is skipped, or fails when GO_ENCLAVE_OPTEE_SEAL is "required"; any
// other failure fails it.
func TestKeyProtectorConformance_OnOPTEE(t *testing.T) {
	endpoint := os.Getenv(opteeEndpointVar)
	if endpoint == "" {
		t.Fatalf("the arm-trustzone KeyProtector conformance test cannot run: %v", &backendtest.EndpointError{Variable: opteeEndpointVar})
	}
	var required bool
	switch v := os.Getenv(opteeSealVar); v {
	case "":
	case "required":
		required = true
	default:
		t.Fatalf("%s=%q: want empty or \"required\"", opteeSealVar, v)
	}
	newProtector := func() (*KeyProtector, error) {
		b, err := Connect(endpoint)
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = b.Close() })
		return b.KeyProtector(), nil
	}

	ctx := context.Background()
	p, err := newProtector()
	if err != nil {
		t.Fatalf("Connect(%q): %v", endpoint, err)
	}
	// GET_INFO cannot decide: trusted-firmware's TA reports interface
	// version 1 and flags 0 with SEAL and without it, and Connect refuses any
	// other pair. The TA's answer to SEAL decides.
	version, flags, err := p.b.c.getInfo(ctx)
	if err != nil {
		t.Fatalf("GET_INFO: %v", err)
	}
	t.Logf("GET_INFO: interface version %d, flags %#x; neither says whether SEAL is present", version, flags)
	if _, err := p.Protect(ctx, make([]byte, 32)); err != nil {
		absent, why := sealAbsent(ctx, p.b.c, err)
		switch {
		case absent && required:
			t.Fatalf("%s=required, but the trusted application has no SEAL: %s", opteeSealVar, why)
		case absent:
			t.Skipf("trusted-firmware's SEAL is not yet in the pinned trusted application: %s", why)
		}
		t.Fatalf("Protect: %v", err)
	}

	cfg := providertest.Config{
		New: func() (any, error) {
			p, err := newProtector()
			if err != nil {
				return nil, err
			}
			return p, nil
		},
		Modes: []enclave.Mode{enclave.ModePerOperation},
		Logf:  t.Logf,
	}
	if err := providertest.TestProvider(ctx, cfg); err != nil {
		t.Fatalf("the arm-trustzone KeyProtector fails conformance: %v", err)
	}
}

// sealAbsent reports whether err, from a first Protect, shows that the
// trusted application has no SEAL, and why. TEE_ERROR_NOT_SUPPORTED says so.
// TEE_ERROR_BAD_PARAMETERS alone does not, since a TA with SEAL answers it
// to malformed parameters: it counts only when the TA answers a command no
// TA defines with the same code, so that SEAL is just another unknown
// command to it. Anything else is a failure of SEAL.
func sealAbsent(ctx context.Context, c *client, err error) (bool, string) {
	const (
		teecErrorBadParameters = 0xffff0006 // TEE_ERROR_BAD_PARAMETERS
		teecErrorNotSupported  = 0xffff000a // TEE_ERROR_NOT_SUPPORTED
		taCmdUndefined         = 0x7fffffff // no TFW_TA_CMD_*
	)
	var ce *CommandError
	if !errors.As(err, &ce) || ce.Command != taCmdSeal {
		return false, ""
	}
	switch ce.Code {
	case teecErrorNotSupported:
		return true, fmt.Sprintf("SEAL answers TEE_ERROR_NOT_SUPPORTED (%v)", err)
	case teecErrorBadParameters:
	default:
		return false, ""
	}
	if err := c.lock(ctx); err != nil {
		return false, ""
	}
	defer c.unlock()
	var params [teeNumParams]teeParam
	uerr := c.invoke(ctx, taCmdUndefined, &params)
	var ue *CommandError
	if errors.As(uerr, &ue) && ue.Code == ce.Code {
		return true, fmt.Sprintf("SEAL answers %#x, as the undefined command %#x does (%v)", ce.Code, uint32(taCmdUndefined), err)
	}
	return false, ""
}
