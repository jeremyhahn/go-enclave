package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dirWith(t *testing.T, names ...string) string {
	t.Helper()
	d := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(d, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestAmdSev_ModulesInOrder(t *testing.T) {
	d := dirWith(t, "2-sev-guest.ko.zst", "10-z.ko.zst", "1-tsm_report.ko.zst", "3-a.ko.zst", "4-b.ko.zst", "5-c.ko.zst", "6-d.ko.zst", "7-e.ko.zst", "8-f.ko.zst", "9-g.ko.zst")
	got, err := modulesInOrder(d)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got[0]) != "1-tsm_report.ko.zst" || filepath.Base(got[1]) != "2-sev-guest.ko.zst" || filepath.Base(got[9]) != "10-z.ko.zst" {
		t.Fatalf("order %v", got)
	}
}

func TestAmdSev_ModulesInOrderRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dir   string
		wants string
	}{
		{"missing dir", filepath.Join(t.TempDir(), "none"), "modules:"},
		{"empty", dirWith(t), "sev-guest"},
		{"unnumbered", dirWith(t, "sev-guest.ko.zst"), "<n>-<module>"},
		{"a gap", dirWith(t, "1-a.ko.zst", "3-c.ko.zst"), "no module 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := modulesInOrder(tc.dir); err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("err %v, want one naming %q", err, tc.wants)
			}
		})
	}
}
