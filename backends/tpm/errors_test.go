package tpm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Format-one response code fields, TPM 2.0 Part 2 section 6.6.3.
const (
	rcParameterBit = 0x040
	rcNumberShift  = 8
	rcSessionBit   = 0x800
)

func onParameter(rc tpm2.TPMRC, n uint32) tpm2.TPMRC {
	return rc | rcParameterBit | tpm2.TPMRC(n<<rcNumberShift)
}

func onHandle(rc tpm2.TPMRC, n uint32) tpm2.TPMRC { return rc | tpm2.TPMRC(n<<rcNumberShift) }

func onSession(rc tpm2.TPMRC, n uint32) tpm2.TPMRC {
	return rc | rcSessionBit | tpm2.TPMRC(n<<rcNumberShift)
}

func TestMapResult(t *testing.T) {
	allCommands := []command{cmdCreatePrimary, cmdStartAuthSession, cmdCreate, cmdLoad, cmdUnseal, cmdFlushContext}
	type row struct {
		name string
		cmd  command
		err  error
		want outcome
	}
	rows := []row{
		{"load_integrity", cmdLoad, tpm2.TPMRCIntegrity, outcomeAuth},
		{"load_integrity_on_parameter_1", cmdLoad, onParameter(tpm2.TPMRCIntegrity, 1), outcomeAuth},
		{"load_integrity_on_handle_1", cmdLoad, onHandle(tpm2.TPMRCIntegrity, 1), outcomeAuth},
		{"load_size_on_parameter_1_inPrivate", cmdLoad, onParameter(tpm2.TPMRCSize, 1), outcomeAuth},
		{"load_size_on_parameter_2_inPublic", cmdLoad, onParameter(tpm2.TPMRCSize, 2), outcomeAuth},
		{"load_value_on_parameter_2_inPublic", cmdLoad, onParameter(tpm2.TPMRCValue, 2), outcomeAuth},
		{"load_size_on_parameter_3", cmdLoad, onParameter(tpm2.TPMRCSize, 3), outcomeFail},
		{"load_size_on_handle_1_not_a_parameter", cmdLoad, onHandle(tpm2.TPMRCSize, 1), outcomeFail},
		{"load_size_on_handle_2_not_a_parameter", cmdLoad, onHandle(tpm2.TPMRCSize, 2), outcomeFail},
		{"load_size_on_session_1_not_a_parameter", cmdLoad, onSession(tpm2.TPMRCSize, 1), outcomeFail},
		{"load_bad_auth_on_session_1", cmdLoad, onSession(tpm2.TPMRCBadAuth, 1), outcomeFail},
		{"unseal_bad_auth", cmdUnseal, onSession(tpm2.TPMRCBadAuth, 1), outcomeAuth},
		{"unseal_auth_fail", cmdUnseal, onSession(tpm2.TPMRCAuthFail, 1), outcomeAuth},
		{"unseal_policy_fail", cmdUnseal, onSession(tpm2.TPMRCPolicyFail, 1), outcomeAuth},
		{"unseal_integrity", cmdUnseal, tpm2.TPMRCIntegrity, outcomeFail},
		{"lockout_on_unseal", cmdUnseal, tpm2.TPMRCLockout, outcomeFail},
		{"lockout_on_load", cmdLoad, tpm2.TPMRCLockout, outcomeFail},
		{"transport_failure", cmdLoad, &DeviceError{Path: "/dev/tpmrm0", Op: "read", Err: io.ErrUnexpectedEOF}, outcomeFail},
		{"go_tpm_local_error", cmdUnseal, errors.New("response HMAC mismatch"), outcomeFail},
		{"load_other_code", cmdLoad, tpm2.TPMRCFailure, outcomeFail},
		{"unseal_other_code", cmdUnseal, onHandle(tpm2.TPMRCHandle, 1), outcomeFail},
		{"wrapped_load_integrity", cmdLoad, fmt.Errorf("%w - cleanup", tpm2.TPMRCIntegrity), outcomeAuth},
		{"success", cmdLoad, nil, outcomeSuccess},
	}
	for _, c := range allCommands {
		for _, rc := range []tpm2.TPMRC{tpm2.TPMRCRetry, tpm2.TPMRCYielded, tpm2.TPMRCTesting} {
			rows = append(rows, row{fmt.Sprintf("%v_retry_%#x", c, uint32(rc)), c, rc, outcomeRetry})
		}
		rows = append(rows, row{fmt.Sprintf("%v_lockout", c), c, tpm2.TPMRCLockout, outcomeFail})
	}
	for _, c := range []command{cmdCreatePrimary, cmdStartAuthSession, cmdCreate, cmdFlushContext} {
		for _, rc := range []tpm2.TPMRC{
			tpm2.TPMRCIntegrity, onParameter(tpm2.TPMRCSize, 1), onParameter(tpm2.TPMRCSize, 2),
			onSession(tpm2.TPMRCBadAuth, 1), tpm2.TPMRCAuthFail, tpm2.TPMRCPolicyFail, tpm2.TPMRCHandle,
		} {
			rows = append(rows, row{fmt.Sprintf("%v_any_code_%#x", c, uint32(rc)), c, rc, outcomeFail})
		}
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := classify(r.cmd, r.err); got != r.want {
				t.Fatalf("classify(%v, %v) = %d, want %d", r.cmd, r.err, got, r.want)
			}
			err := mapResult(r.cmd, r.err)
			switch r.want {
			case outcomeSuccess:
				if err != nil {
					t.Fatalf("mapResult = %v, want nil", err)
				}
			case outcomeAuth:
				if !errors.Is(err, enclave.ErrSealedAuthentication) || errors.Is(err, ErrCommandFailed) {
					t.Fatalf("mapResult = %v, want only ErrSealedAuthentication", err)
				}
			default:
				if !errors.Is(err, ErrCommandFailed) || errors.Is(err, enclave.ErrSealedAuthentication) {
					t.Fatalf("mapResult = %v, want only the provider's ErrCommandFailed", err)
				}
				if !errors.Is(err, r.err) {
					t.Fatalf("mapResult = %v does not wrap %v", err, r.err)
				}
			}
		})
	}
}

func TestMapResult_KeepsTheResponseCode(t *testing.T) {
	err := mapResult(cmdCreatePrimary, onHandle(tpm2.TPMRCHierarchy, 1))
	var fmt1 tpm2.TPMFmt1Error
	if !errors.As(err, &fmt1) {
		t.Fatalf("%v: the go-tpm format-one error is not reachable", err)
	}
	if isHandle, n := fmt1.Handle(); !isHandle || n != 1 {
		t.Fatalf("handle = %v, %d; want true, 1", isHandle, n)
	}
}

func TestErrors_Match(t *testing.T) {
	cases := []struct {
		err    error
		target error
	}{
		{&PlatformError{GOOS: "plan9"}, ErrUnsupportedPlatform},
		{&DeviceError{Path: "/dev/tpmrm0", Op: "open", Err: io.EOF}, ErrDeviceUnavailable},
		{&CommandError{Command: "TPM2_Create", Err: io.EOF}, ErrCommandFailed},
		{&KeySizeError{Len: 129}, ErrKeySize},
		{&authError{reason: "x"}, enclave.ErrSealedAuthentication},
	}
	for _, c := range cases {
		if !errors.Is(c.err, c.target) || c.err.Error() == "" {
			t.Errorf("%T does not match %v", c.err, c.target)
		}
	}
}

// TestErrors_Contract pins each error type's exact text, the one sentinel
// it matches, and that errors.As finds it through a %w wrap.
func TestErrors_Contract(t *testing.T) {
	cases := []struct {
		name string
		err  error
		text string
		is   error
		as   func(error) bool
	}{
		{
			name: "PlatformError",
			err:  &PlatformError{GOOS: "plan9"},
			text: `tpm: the TPM provider is not available on this platform: "plan9"`,
			is:   ErrUnsupportedPlatform,
			as:   func(err error) bool { var e *PlatformError; return errors.As(err, &e) && e.GOOS == "plan9" },
		},
		{
			name: "DeviceError",
			err:  &DeviceError{Path: "/dev/tpmrm0", Op: "open", Err: os.ErrNotExist},
			text: `tpm: the TPM device is unavailable: open "/dev/tpmrm0": file does not exist`,
			is:   ErrDeviceUnavailable,
			as:   func(err error) bool { var e *DeviceError; return errors.As(err, &e) && e.Op == "open" },
		},
		{
			name: "CommandError",
			err:  &CommandError{Command: "TPM2_Create", Err: os.ErrNotExist},
			text: "tpm: a TPM command failed: TPM2_Create: file does not exist",
			is:   ErrCommandFailed,
			as:   func(err error) bool { var e *CommandError; return errors.As(err, &e) && e.Command == "TPM2_Create" },
		},
		{
			name: "KeySizeError",
			err:  &KeySizeError{Len: 129},
			text: "tpm: a sealed key must be 1 to 128 bytes: got 129",
			is:   ErrKeySize,
			as:   func(err error) bool { var e *KeySizeError; return errors.As(err, &e) && e.Len == 129 },
		},
		{
			name: "authError",
			err:  &authError{reason: "TPM2_Unseal refused the blob", err: os.ErrNotExist},
			text: enclave.ErrSealedAuthentication.Error() + ": tpm: TPM2_Unseal refused the blob: file does not exist",
			is:   enclave.ErrSealedAuthentication,
			as:   func(err error) bool { var e *authError; return errors.As(err, &e) && e.reason != "" },
		},
		{
			name: "authError without cause",
			err:  &authError{reason: "x"},
			text: enclave.ErrSealedAuthentication.Error() + ": tpm: x",
			is:   enclave.ErrSealedAuthentication,
			as:   func(err error) bool { var e *authError; return errors.As(err, &e) && e.err == nil },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Error(); got != c.text {
				t.Errorf("Error() = %q, want %q", got, c.text)
			}
			wrapped := fmt.Errorf("outer: %w", c.err)
			for _, s := range allSentinels() {
				want := s == c.is
				if got := errors.Is(c.err, s); got != want {
					t.Errorf("errors.Is(err, %q) = %v, want %v", s, got, want)
				}
				if got := errors.Is(wrapped, s); got != want {
					t.Errorf("errors.Is(wrapped, %q) = %v, want %v", s, got, want)
				}
			}
			if !c.as(wrapped) {
				t.Errorf("errors.As through %%w does not find %T", c.err)
			}
		})
	}
}

// TestErrors_Unwrap checks that each wrapping type returns its cause and
// that errors.Is reaches the cause through it.
func TestErrors_Unwrap(t *testing.T) {
	cases := []struct {
		name  string
		err   interface{ Unwrap() error }
		cause error
	}{
		{"DeviceError", &DeviceError{Path: "/dev/tpmrm0", Op: "read", Err: os.ErrNotExist}, os.ErrNotExist},
		{"CommandError", &CommandError{Command: "TPM2_Load", Err: os.ErrNotExist}, os.ErrNotExist},
		{"authError", &authError{reason: "x", err: os.ErrNotExist}, os.ErrNotExist},
		{"authError without cause", &authError{reason: "x"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Unwrap(); got != c.cause { //nolint:errorlint // identity is the contract
				t.Errorf("Unwrap() = %v, want %v", got, c.cause)
			}
			err, ok := c.err.(error)
			if !ok {
				t.Fatalf("%T is not an error", c.err)
			}
			wantIs := c.cause != nil
			if got := errors.Is(fmt.Errorf("outer: %w", err), os.ErrNotExist); got != wantIs {
				t.Errorf("errors.Is(wrapped, os.ErrNotExist) = %v, want %v", got, wantIs)
			}
		})
	}
}

// TestCommand_String names every command constant and an out-of-range value.
func TestCommand_String(t *testing.T) {
	cases := []struct {
		cmd  command
		want string
	}{
		{cmdCreatePrimary, "TPM2_CreatePrimary"},
		{cmdStartAuthSession, "TPM2_StartAuthSession"},
		{cmdCreate, "TPM2_Create"},
		{cmdLoad, "TPM2_Load"},
		{cmdUnseal, "TPM2_Unseal"},
		{cmdFlushContext, "TPM2_FlushContext"},
		{0, "command(0)"},
		{cmdFlushContext + 1, "command(7)"},
		{255, "command(255)"},
	}
	for _, c := range cases {
		if got := c.cmd.String(); got != c.want {
			t.Errorf("command(%d).String() = %q, want %q", uint8(c.cmd), got, c.want)
		}
	}
}
