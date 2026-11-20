// Package guestcfg is the contract between the SEV-SNP kit's host side and
// its guest: the kernel command line parameters the host sets, and the console
// lines the guest prints.
package guestcfg

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The console lines.
const (
	// ExitMarker precedes the in-guest tests' exit status, the init's last
	// line before it powers the guest off.
	ExitMarker = "amdsev-guest: exit "
	// NeedleMarker precedes the hex needle a guest holds in an enclave.
	NeedleMarker = "amdsev-needle: "
	// ReleasedLine follows the hold, once the needle's enclave is destroyed.
	ReleasedLine = "amdsev-needle: released"
)

// The guest modes, the kernel command line's amdsev.mode.
const (
	ModeSEV   = "sev"
	ModeSEVES = "sev-es"
	ModeSNP   = "snp"
	ModePlain = "plain"
)

// DefaultHold is how long a guest holds its needle when amdsev.hold is unset.
const DefaultHold = 120 * time.Second

// ErrNotKitGuest is returned for a command line without amdsev.mode: the
// process does not run in a guest the kit booted.
var ErrNotKitGuest = errors.New("guestcfg: no amdsev.mode on the kernel command line; not a guest booted by scripts/amd-sev-snp/guest.sh")

// Config is what the host told the guest.
type Config struct {
	// Mode is one of SEVModes or ModePlain.
	Mode string
	// Run is the -test.run pattern for the in-guest tests.
	Run string
	// Hold is how long the needle is held.
	Hold time.Duration
}

// DefaultRun is the in-guest test selection for a mode.
func DefaultRun(mode string) string {
	if mode == ModeSNP {
		return "^TestAmdSev_Guest(Conformance|HoldNeedle)$"
	}
	return "^TestAmdSev_Guest(Refusal|HoldNeedle)$"
}

// SEVModes lists the encrypted guests the kit boots: SEV, SEV-ES and SEV-SNP.
// Only an SEV-SNP guest gives the backend what it needs; in the others it
// refuses, as it does in the plain control.
func SEVModes() []string {
	return []string{ModeSEV, ModeSEVES, ModeSNP}
}

// ValidMode reports whether m is a mode the kit boots: one of SEVModes or
// ModePlain.
func ValidMode(m string) bool {
	return m == ModePlain || slices.Contains(SEVModes(), m)
}

// Parse reads a kernel command line (the contents of /proc/cmdline).
func Parse(cmdline string) (Config, error) {
	var c Config
	for _, f := range strings.Fields(cmdline) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "amdsev.mode":
			c.Mode = v
		case "amdsev.run":
			c.Run = v
		case "amdsev.hold":
			secs, err := strconv.Atoi(v)
			if err != nil || secs <= 0 {
				return Config{}, fmt.Errorf("guestcfg: amdsev.hold=%q is not a positive number of seconds", v)
			}
			c.Hold = time.Duration(secs) * time.Second
		}
	}
	switch {
	case c.Mode == "":
		return Config{}, ErrNotKitGuest
	case !ValidMode(c.Mode):
		return Config{}, fmt.Errorf("guestcfg: amdsev.mode=%q, want one of %s or %s", c.Mode, strings.Join(SEVModes(), ", "), ModePlain)
	}
	if c.Run == "" {
		c.Run = DefaultRun(c.Mode)
	}
	if c.Hold == 0 {
		c.Hold = DefaultHold
	}
	return c, nil
}
