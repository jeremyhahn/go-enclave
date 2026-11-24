package armtrustzone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// opteeSealVar says whether the fixture's trusted application has SEAL:
// empty or "required" expects it, and any SEAL error fails the KeyProtector
// test; "absent:<release>", which scripts/optee-fixture.sh sets for its
// pinned trusted-firmware release, lets the test skip a TA without SEAL.
const opteeSealVar = "GO_ENCLAVE_OPTEE_SEAL"

// opteeSealAbsentRelease is the trusted-firmware release, pinned as
// TRUSTED_FIRMWARE_TAG in scripts/tool-pins.sh, whose trusted application is
// known to have no SEAL. scripts/optee-fixture.sh declares it as
// GO_ENCLAVE_OPTEE_SEAL=absent:<release>; a new pin without SEAL must raise
// both.
const opteeSealAbsentRelease = "v0.4.2-alpha"

// sealVerdict is what the OP-TEE KeyProtector test does after a first
// Protect: run the provider suite, skip, or fail.
type sealVerdict int

const (
	sealRun sealVerdict = iota
	sealSkip
	sealFail
)

func (v sealVerdict) String() string {
	switch v {
	case sealRun:
		return "run"
	case sealSkip:
		return "skip"
	case sealFail:
		return "fail"
	}
	return fmt.Sprintf("sealVerdict(%d)", int(v))
}

// sealDecision decides, from GO_ENCLAVE_OPTEE_SEAL's value knob and err, the
// error of a first Protect, what TestKeyProtectorConformance_OnOPTEE does,
// and why. A SEAL that works runs the suite under every value. Otherwise,
// with knob empty SEAL is expected and any error fails, as it does under
// "required"; under "absent:<release>", the fixture's declaration that its
// pinned trusted-firmware release lacks SEAL, TEE_ERROR_BAD_PARAMETERS or
// TEE_ERROR_NOT_SUPPORTED from SEAL skips, if <release> is
// opteeSealAbsentRelease. No error code alone shows that SEAL is absent: a
// TA with SEAL can answer TEE_ERROR_BAD_PARAMETERS to a broken SEAL call and
// to an unknown command alike.
func sealDecision(knob string, err error) (sealVerdict, string) {
	const (
		teecErrorBadParameters = 0xffff0006 // TEE_ERROR_BAD_PARAMETERS
		teecErrorNotSupported  = 0xffff000a // TEE_ERROR_NOT_SUPPORTED
	)
	release, legacy := strings.CutPrefix(knob, "absent:")
	switch {
	case knob == "", knob == "required":
	case legacy && release != "":
	default:
		return sealFail, fmt.Sprintf("%s=%q: want empty, \"required\" or \"absent:<trusted-firmware release>\"", opteeSealVar, knob)
	}
	if err == nil {
		return sealRun, ""
	}
	if !legacy {
		return sealFail, fmt.Sprintf("Protect: %v (%s=%q expects SEAL)", err, opteeSealVar, knob)
	}
	var ce *CommandError
	if !errors.As(err, &ce) || ce.Command != taCmdSeal || (ce.Code != teecErrorBadParameters && ce.Code != teecErrorNotSupported) {
		return sealFail, fmt.Sprintf("Protect: %v", err)
	}
	if release != opteeSealAbsentRelease {
		return sealFail, fmt.Sprintf("%s=%q, but the release known to lack SEAL is %s (opteeSealAbsentRelease); a pin without SEAL raises both: Protect: %v", opteeSealVar, knob, opteeSealAbsentRelease, err)
	}
	return sealSkip, fmt.Sprintf("the fixture's trusted-firmware %s has no SEAL, as declared: Protect: %v", release, err)
}

// fakeCmdUndefined is a command no TFW_TA_CMD_* names.
const fakeCmdUndefined uint32 = 0x7fffffff

// TestSealDecision runs a first Protect against the fake TEE, its SEAL
// answering as each case says, and checks what the OP-TEE KeyProtector test
// would do under each GO_ENCLAVE_OPTEE_SEAL value. The fake's TA has SEAL, so
// only the fixture's declaration that its pinned release lacks SEAL may turn
// a SEAL error into a skip.
func TestSealDecision(t *testing.T) {
	const legacy = "absent:" + opteeSealAbsentRelease
	for _, tc := range []struct {
		name      string
		seal      uint32 // SEAL's answer; 0 seals
		undefined uint32 // the undefined command's answer; 0 is the fake's NOT_SUPPORTED
		knob      string
		want      sealVerdict
	}{
		// A SEAL-capable TA that answers BAD_PARAMETERS to a broken SEAL
		// call and to unknown commands alike is not a TA without SEAL.
		{"bad parameters like an unknown command, knob unset", fakeErrBadParameters, fakeErrBadParameters, "", sealFail},
		{"bad parameters, knob unset", fakeErrBadParameters, 0, "", sealFail},
		{"not supported, knob unset", fakeErrNotSupported, 0, "", sealFail},
		{"generic, knob unset", fakeErrGeneric, 0, "", sealFail},
		{"bad parameters, legacy", fakeErrBadParameters, fakeErrBadParameters, legacy, sealSkip},
		{"not supported, legacy", fakeErrNotSupported, 0, legacy, sealSkip},
		{"generic, legacy", fakeErrGeneric, 0, legacy, sealFail},
		{"bad parameters, another release declared", fakeErrBadParameters, 0, "absent:v0.0.0-unknown", sealFail},
		{"not supported, no release declared", fakeErrNotSupported, 0, "absent:", sealFail},
		{"bad parameters, required", fakeErrBadParameters, fakeErrBadParameters, "required", sealFail},
		{"not supported, required", fakeErrNotSupported, 0, "required", sealFail},
		{"seals, knob unset", 0, 0, "", sealRun},
		{"seals, required", 0, 0, "required", sealRun},
		{"seals, legacy", 0, 0, legacy, sealRun},
		{"seals, another release declared", 0, 0, "absent:v0.0.0-unknown", sealRun},
		{"seals, unknown knob", 0, 0, "yes", sealFail},
		{"not supported, unknown knob", fakeErrNotSupported, 0, "yes", sealFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTEE(t, true)
			f.fail(taCmdSeal, tc.seal)
			f.fail(fakeCmdUndefined, tc.undefined)
			p := connectFake(t, f)
			ctx := context.Background()
			_, err := p.Protect(ctx, make([]byte, 32))
			got, why := sealDecision(tc.knob, err)
			if got != tc.want {
				t.Fatalf("%s=%q, Protect error %v: decision %v (%s), want %v", opteeSealVar, tc.knob, err, got, why, tc.want)
			}
			if got != sealRun && why == "" {
				t.Fatalf("%s=%q: decision %v gives no reason", opteeSealVar, tc.knob, got)
			}
		})
	}
}
