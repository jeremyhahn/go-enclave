package guestcfg

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestAmdSev_Parse(t *testing.T) {
	for _, tc := range []struct {
		name, cmdline string
		want          Config
	}{
		{"snp defaults", "console=ttyS0 panic=-1 amdsev.mode=snp", Config{ModeSNP, DefaultRun(ModeSNP), DefaultHold}},
		{"plain defaults", "amdsev.mode=plain", Config{ModePlain, DefaultRun(ModePlain), DefaultHold}},
		{"sev defaults", "amdsev.mode=sev", Config{ModeSEV, DefaultRun(ModeSEV), DefaultHold}},
		{"sev-es defaults", "amdsev.mode=sev-es", Config{ModeSEVES, DefaultRun(ModeSEVES), DefaultHold}},
		{"run and hold", "amdsev.mode=snp amdsev.run=^TestAmdSev_GuestHoldNeedle$ amdsev.hold=30", Config{ModeSNP, "^TestAmdSev_GuestHoldNeedle$", 30 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.cmdline)
			if err != nil || got != tc.want {
				t.Fatalf("Parse(%q) = %+v, %v; want %+v", tc.cmdline, got, err, tc.want)
			}
		})
	}
}

func TestAmdSev_ParseRefuses(t *testing.T) {
	if _, err := Parse("console=ttyS0 root=/dev/sda1"); !errors.Is(err, ErrNotKitGuest) {
		t.Fatalf("no mode: %v, want ErrNotKitGuest", err)
	}
	for _, c := range []string{"amdsev.mode=tdx", "amdsev.mode=SEV", "amdsev.mode=snp amdsev.hold=0", "amdsev.mode=snp amdsev.hold=x"} {
		if _, err := Parse(c); err == nil || errors.Is(err, ErrNotKitGuest) {
			t.Errorf("Parse(%q) = %v, want a refusal naming the parameter", c, err)
		}
	}
}

func TestAmdSev_DefaultRunSelectsByMode(t *testing.T) {
	if DefaultRun(ModeSNP) == DefaultRun(ModePlain) {
		t.Fatal("snp and plain select the same in-guest tests")
	}
	// SEV and SEV-ES guests are not SEV-SNP guests: the backend refuses in
	// them as in a plain guest, so they run the refusal, not conformance.
	for _, m := range []string{ModeSEV, ModeSEVES} {
		if got := DefaultRun(m); got != DefaultRun(ModePlain) {
			t.Errorf("DefaultRun(%s) = %q; want the refusal run %q", m, got, DefaultRun(ModePlain))
		}
	}
}

func TestAmdSev_Modes(t *testing.T) {
	want := []string{ModeSEV, ModeSEVES, ModeSNP}
	if got := SEVModes(); !slices.Equal(got, want) {
		t.Fatalf("SEVModes() = %v; want %v", got, want)
	}
	for _, m := range append(want, ModePlain) {
		if !ValidMode(m) {
			t.Errorf("ValidMode(%q) = false", m)
		}
	}
	for _, m := range []string{"", "tdx", "SEV", "sev_es"} {
		if ValidMode(m) {
			t.Errorf("ValidMode(%q) = true", m)
		}
	}
}
