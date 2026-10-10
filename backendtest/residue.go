package backendtest

import (
	"crypto/rand"
	"io"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// residueNeedleMin is the shortest material the sweep looks for: a shorter
// needle could match by chance, and a hit would prove nothing.
const residueNeedleMin = 16

// checkResidue requires that no copy of a handle's material is findable in the
// process once Destroy returns, or, for a Sweeper, once Sweep does. For every
// case with ByteAccess it copies the material into a locked needle, sweeps the
// process with the handle alive as the control, ends the handle and sweeps
// again: any hit outside the needle's own mapping is a copy the backend kept
// or did not wipe.
func checkResidue(r *report, cfg Config) {
	const property = "residue"
	if cfg.SkipResidueSweep != "" {
		r.note("backendtest: residue sweep SKIPPED by Config.SkipResidueSweep: %q. Retention of material after "+
			"Destroy is unmeasured for this backend", cfg.SkipResidueSweep)
		return
	}
	if !memscan.Supported {
		r.unmeasured(property, "residue sweep not run: %s. Retention after Destroy is unmeasured on this platform; "+
			"run the suite on Linux to measure it, or accept that with Config.SkipResidueSweep", memscan.UnsupportedReason)
		return
	}
	for _, hc := range cfg.Handles {
		if !hasCap(hc.Capabilities, enclave.CapabilityBytes) {
			continue
		}
		checkCaseResidue(r, property, cfg, hc, hc.Name, "Destroy", destroyEnds)
		if hasCap(cfg.BackendCapabilities, enclave.CapabilitySweep) {
			checkCaseResidue(r, property, cfg, hc, hc.Name+" under Sweep", "Sweep", sweepEnds)
		}
	}
}

// An ender ends h, a handle of b, as its residue check measures, and reports
// whether it did; who names the case in a failure.
type ender func(r *report, property, who string, b enclave.Backend, h enclave.Handle) bool

// destroyEnds ends h with Destroy.
func destroyEnds(r *report, property, who string, _ enclave.Backend, h enclave.Handle) bool {
	if err := destroy(h); err != nil {
		r.fail(property, "%s: Destroy returned %v", who, err)
		return false
	}
	return true
}

// sweepEnds ends h with its backend's Sweep, which must release it.
func sweepEnds(r *report, property, who string, b enclave.Backend, _ enclave.Handle) bool {
	sw, ok := b.(enclave.Sweeper)
	if !ok {
		// checkBackendCapabilities reports the claim.
		return false
	}
	if held, err := sw.Sweep(r.ctx); held != 0 || err != nil {
		r.fail(property, "%s: Sweep = %d, %v; want 0, nil", who, held, err)
		return false
	}
	return true
}

// checkCaseResidue measures hc's material after end, which how names; who
// names the case in every finding.
func checkCaseResidue(r *report, property string, cfg Config, hc HandleCase, who, how string, end ender) {
	b, err := newBackend(cfg)
	if err != nil {
		r.fail(property, "%s: %v", who, err)
		return
	}
	h, err := residueHandle(r, b, hc)
	if err != nil {
		r.fail(property, "%s: %v", who, err)
		return
	}
	// Destroy is idempotent, and releases what an end that failed, or a Sweep
	// that kept the material, left.
	defer func() { _ = destroy(h) }()
	ba, ok := h.(enclave.ByteAccess)
	if !ok {
		return
	}
	if h.Size() < residueNeedleMin {
		r.unmeasured(property, "%s: residue sweep not run: the material is %d bytes, under the %d a sweep can tell from chance",
			who, h.Size(), residueNeedleMin)
		return
	}

	// The needle is a locked copy: a heap copy would be found by the sweep.
	needle, err := enclave.NewMemorySized(h.Size())
	if err != nil {
		r.unmeasured(property, "%s: residue sweep not run: locked memory is unavailable (%v)", who, err)
		return
	}
	defer release(r, "needle", needle)
	var home uintptr
	if err := needle.WithBytes(func(n []byte) error {
		var aerr error
		if home, aerr = memscan.Addr(n); aerr != nil {
			return aerr
		}
		return ba.WithBytes(func(m []byte) error {
			copy(n, m)
			return nil
		})
	}); err != nil {
		r.fail(property, "%s: copying the material into the needle: %v", who, err)
		return
	}

	// Control: with the handle alive its own mapping holds the material, so the
	// sweep must find it, or a negative result below would be vacuous.
	control, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.unmeasured(property, "%s: residue sweep not run: %v", who, err)
		return
	}
	if len(control) == 0 {
		r.unmeasured(property, "%s: residue sweep not run: with the handle alive the sweep found its material in no "+
			"mapping outside the needle's own, so it cannot see where the backend keeps it and a negative result "+
			"would be vacuous", who)
		return
	}

	if !end(r, property, who, b, h) {
		return
	}
	after, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.unmeasured(property, "%s: residue sweep failed after its control succeeded: %v", who, err)
		return
	}
	if len(after) > 0 {
		r.fail(property, "%s: the material is byte-exact resident in %d mapping(s) after %s returned: %q. "+
			"%s wipes every copy; this same sweep found the material while the handle was alive, so it is not blind",
			who, len(after), how, after[0], how)
	}
}

// residueHandle makes hc's handle without leaving a copy of its material
// outside locked memory: imported material is generated in a locked source,
// which Import wipes and which is released before the sweep.
func residueHandle(r *report, b enclave.Backend, hc HandleCase) (enclave.Handle, error) {
	if hc.New != nil {
		h, _, err := newHandleFromBackend(r.ctx, b, hc)
		return h, err
	}
	imp, ok := b.(enclave.Importer)
	if !ok {
		return nil, &enclave.CapabilityError{Backend: b.Name(), Capability: enclave.CapabilityImport}
	}
	src, err := enclave.NewMemorySized(hc.ImportSize)
	if err != nil {
		return nil, &stepError{step: "allocating a locked import source", err: err}
	}
	defer release(r, "import source", src)
	var h enclave.Handle
	if err := src.WithBytes(func(s []byte) error {
		if _, err := io.ReadFull(rand.Reader, s); err != nil {
			return err
		}
		var ierr error
		h, ierr = imp.Import(r.ctx, s, hc.Import...)
		return ierr
	}); err != nil {
		return nil, &stepError{step: hc.Name + ".Import", err: err}
	}
	if isNilInterface(h) {
		return nil, &nilHandleError{step: hc.Name + ".Import", handle: h}
	}
	return h, nil
}

// sweepProcess is memscan.Find; a test blinds it to prove the control
// reports the sweep unmeasured.
var sweepProcess = memscan.Find

// sweepOutsideHome reports every mapping outside home that holds the needle.
func sweepOutsideHome(probe *enclave.Memory, home uintptr) ([]string, error) {
	var hits []string
	var scanErr error
	if err := probe.WithBytes(func(needle []byte) error {
		hits, scanErr = sweepProcess(needle, home)
		return nil
	}); err != nil {
		return nil, &stepError{step: "borrowing the needle", err: err}
	}
	return hits, scanErr
}

func release(r *report, what string, m *enclave.Memory) {
	if err := m.Destroy(); err != nil {
		r.note("backendtest: releasing the residue check's %s was refused: %v", what, err)
	}
}
