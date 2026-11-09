package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// opteeImagePin is the form of the OP-TEE fixture image pin: an image in
// ghcr.io, which a GitHub-hosted runner pulls without a private network,
// pinned by its manifest digest.
var opteeImagePin = regexp.MustCompile(`^ghcr\.io/[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9._-]*@sha256:[0-9a-f]{64}$`)

// TestOpteeFixtureImagePin checks OPTEE_FIXTURE_IMAGE in scripts/tool-pins.sh:
// the hosted optee job pulls it, so it names a public ghcr image by digest,
// and needs no lab-string waiver on its line or the line before it.
func TestOpteeFixtureImagePin(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "tool-pins.sh"))
	if err != nil {
		t.Fatalf("read tool-pins.sh: %v", err)
	}
	lines := strings.Split(string(src), "\n")
	found := false
	for i, line := range lines {
		value, ok := strings.CutPrefix(line, "OPTEE_FIXTURE_IMAGE=")
		if !ok {
			continue
		}
		found = true
		if !opteeImagePin.MatchString(value) {
			t.Errorf("tool-pins.sh:%d: OPTEE_FIXTURE_IMAGE=%q is not ghcr.io/<owner>/<name>@sha256:<64 hex>", i+1, value)
		}
		if strings.Contains(line, waiverPrefix) || (i > 0 && strings.Contains(lines[i-1], waiverPrefix)) {
			t.Errorf("tool-pins.sh:%d: OPTEE_FIXTURE_IMAGE carries a %s waiver; the public pin needs none", i+1, waiverPrefix)
		}
	}
	if !found {
		t.Fatal("tool-pins.sh has no OPTEE_FIXTURE_IMAGE= line")
	}
}
