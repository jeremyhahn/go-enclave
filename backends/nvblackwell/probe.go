package nvblackwell

import (
	"bytes"
	"context"
	"errors"
)

// driverVersionPath is the NVIDIA kernel driver's procfs entry, which the
// driver creates when it loads (nv-procfs.c in NVIDIA's open-gpu-kernel-modules).
const driverVersionPath = "/proc/driver/nvidia/version"

// driverVersionMax bounds the read of [driverVersionPath]: the entry is two
// short lines, and anything longer is malformed.
const driverVersionMax = 4096

// Probe reports whether the host can serve the backend's GPU side: nil, or a
// typed error naming the failing step. It checks ctx, then, on linux, that
// the NVIDIA open kernel module is loaded: its procfs entry exists, reads,
// parses and names the open module, which the design requires of the guest.
// Off linux it is a [*PlatformError].
//
// The NVML checks the design lists (at least one GPU, every GPU Blackwell, CC
// on, DevTools off, a proven multi-GPU mode, the ready state set) are the next
// slice's; until then Probe accepts no host the backend could not serve but
// does not yet prove one it could. It does not run the CPU TEE backend's
// probe: [Backend.Probe] does that first. A nil ctx never ends. Probe is safe
// to call concurrently and keeps no state.
func Probe(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return probeHost()
}

// driverVersion is what [parseDriverVersion] reads from the procfs entry.
type driverVersion struct {
	// open reports the open kernel module rather than the proprietary one.
	open bool
	// version is the driver's version, such as "570.86.15".
	version string
}

var errMalformedDriverVersion = errors.New("no NVRM version line with a driver version")

// The NVRM line's prefixes, as nv-procfs.c writes them: the open module's
// line reads "NVRM version: NVIDIA UNIX Open Kernel Module for <arch>  <version>  ...",
// the proprietary module's "NVRM version: NVIDIA UNIX <arch> Kernel Module  <version>  ...".
var (
	nvrmPrefix       = []byte("NVRM version: ")
	openModulePrefix = []byte("NVIDIA UNIX Open Kernel Module for ")
)

// parseDriverVersion reads the procfs entry's "NVRM version:" line: whether it
// names the open kernel module, and the first field shaped as a version
// (digits separated by dots, at least one dot).
func parseDriverVersion(buf []byte) (driverVersion, error) {
	for line := range bytes.Lines(buf) {
		rest, ok := bytes.CutPrefix(line, nvrmPrefix)
		if !ok {
			continue
		}
		for _, f := range bytes.Fields(rest) {
			if isVersion(f) {
				return driverVersion{open: bytes.HasPrefix(rest, openModulePrefix), version: string(f)}, nil
			}
		}
		break
	}
	return driverVersion{}, errMalformedDriverVersion
}

// isVersion reports digits separated by single dots, with at least one dot.
func isVersion(f []byte) bool {
	dots, digits := 0, 0
	for _, c := range f {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' && digits > 0:
			dots++
			digits = 0
		default:
			return false
		}
	}
	return dots > 0 && digits > 0
}

// checkDriverVersion is the probe's verdict on the procfs entry's content.
func checkDriverVersion(buf []byte) error {
	v, err := parseDriverVersion(buf)
	if err != nil {
		return &DriverError{Path: driverVersionPath, Op: "parse", Cause: err}
	}
	if !v.open {
		return &DriverError{Path: driverVersionPath, Op: "open-kernel-module"}
	}
	return nil
}
