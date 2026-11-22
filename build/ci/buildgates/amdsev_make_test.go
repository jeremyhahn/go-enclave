package buildgates

import (
	"fmt"
	"testing"
)

// TestAMDSEVMake_HostileGuestsAreData drives make integration-test-amd-sev
// with each hostile AMDSEV_GUESTS value, as a command-line assignment and
// through the environment. Neither make nor the recipe's shell may run the
// payload, and host-record.sh refuses every value, so the run fails at its
// first step without hardware.
func TestAMDSEVMake_HostileGuestsAreData(t *testing.T) {
	marker := t.TempDir()
	env := map[string]string{"AMDSEV_CACHE": t.TempDir(), "AMDSEV_RESULTS": ""}
	for i, value := range hostileValues(marker) {
		out, ok := runMake(t, env, "integration-test-amd-sev", "AMDSEV_GUESTS="+value)
		requireNoMarkers(t, marker, fmt.Sprintf("make integration-test-amd-sev AMDSEV_GUESTS=<payload %d>", i), out)
		if ok {
			t.Fatalf("make integration-test-amd-sev accepted AMDSEV_GUESTS=%q:\n%s", value, out)
		}

		out, ok = runMake(t, mergeEnv(env, map[string]string{"AMDSEV_GUESTS": value}), "integration-test-amd-sev")
		requireNoMarkers(t, marker, fmt.Sprintf("AMDSEV_GUESTS=<payload %d> make integration-test-amd-sev", i), out)
		if ok {
			t.Fatalf("make integration-test-amd-sev accepted AMDSEV_GUESTS=%q from the environment:\n%s", value, out)
		}
	}
}
