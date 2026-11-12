package backendtest

import (
	"context"
	"fmt"
	"slices"

	enclave "github.com/jeremyhahn/go-enclave"
)

// RefusalConfig describes a hardware backend module to [CheckRefusal], run
// on a host without the module's hardware.
type RefusalConfig struct {
	// New is the module's constructor, such as a Connect over the default
	// endpoint. On a host without the hardware it must return a nil
	// interface and the module's typed unavailable error.
	New func() (enclave.Backend, error)
	// Probe, if set, is the module's probe for its hardware that needs no
	// backend from New. It must refuse as New does. A module whose only
	// probe is the backend's own [enclave.Prober.Probe], run inside New,
	// leaves it nil.
	Probe func(ctx context.Context) error
	// Step reports whether err is the module's typed unavailable error and,
	// if so, the step it names as failing, such as "open". It is the
	// module's own errors.As over its error types.
	Step func(err error) (step string, ok bool)
}

// The properties [CheckRefusal] reports, each as a [*PropertyError].
const (
	// PropertyRefusalNew: New refused, with a nil backend, without panicking.
	PropertyRefusalNew = "refusal-new"
	// PropertyRefusalProbe: Probe refused without panicking.
	PropertyRefusalProbe = "refusal-probe"
	// PropertyRefusalTyped: each refusal is the module's typed unavailable
	// error, as Step judges it.
	PropertyRefusalTyped = "refusal-typed"
	// PropertyRefusalStep: each typed refusal names the step that failed.
	PropertyRefusalStep = "refusal-step"
	// PropertyRefusalRegistration: refusing registered no backend.
	PropertyRefusalRegistration = "refusal-registration"
	// PropertyRefusalBudget: refusing left the process's locked-memory
	// budget, its allocator, limit and reservations, unchanged.
	PropertyRefusalBudget = "refusal-budget"
)

// CheckRefusal checks that a hardware backend module, on a host without its
// hardware, refuses in New and in Probe with its typed unavailable error
// naming the failing step, registers no backend, and leaves the process's
// locked-memory budget unchanged.
//
// It returns a [*ConfigError] ([ErrInvalidConfig]) when New or Step is nil,
// nil when the module refuses cleanly, and otherwise a [*FindingsError]
// holding a [*PropertyError] for each property broken. It reads the
// process-wide registry and budget, so it must not run in parallel with a
// test that registers a backend or changes the budget. A nil ctx never ends.
func CheckRefusal(ctx context.Context, cfg RefusalConfig) error {
	if cfg.New == nil {
		return &ConfigError{Field: "New", Reason: "is nil; CheckRefusal needs the module's constructor"}
	}
	if cfg.Step == nil {
		return &ConfigError{Field: "Step", Reason: "is nil; CheckRefusal needs the module's judge of its typed errors"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []error
	fail := func(property, format string, args ...any) {
		findings = append(findings, &PropertyError{Property: property, Detail: fmt.Sprintf(format, args...)})
	}
	judge := func(call string, err error) {
		step, ok := cfg.Step(err)
		switch {
		case !ok:
			fail(PropertyRefusalTyped, "%s refused with %T %q, not the module's typed unavailable error", call, err, err)
		case step == "":
			fail(PropertyRefusalStep, "%s refused with %q, which names no failing step", call, err)
		}
	}

	// The baseline starts the process allocator before New runs (see budgetOf).
	budget := budgetOf()
	names := enclave.BackendNames()

	b, panicked, err := refusalNew(cfg.New)
	switch {
	case panicked != nil:
		fail(PropertyRefusalNew, "New panicked: %v", panicked)
	case err == nil:
		fail(PropertyRefusalNew, "New returned %T and no error on a host without the hardware", b)
	case b != nil && isNilInterface(b):
		fail(PropertyRefusalNew, "New returned a nil %T inside the interface with its error %q; a refusal returns a nil interface", b, err)
		judge("New", err)
	case b != nil:
		fail(PropertyRefusalNew, "New returned %T with its error %q; a refusal returns a nil interface", b, err)
		judge("New", err)
	default:
		judge("New", err)
	}
	if cfg.Probe != nil {
		panicked, err := refusalProbe(ctx, cfg.Probe)
		switch {
		case panicked != nil:
			fail(PropertyRefusalProbe, "Probe panicked: %v", panicked)
		case err == nil:
			fail(PropertyRefusalProbe, "Probe returned nil on a host without the hardware")
		default:
			judge("Probe", err)
		}
	}

	if after := enclave.BackendNames(); !slices.Equal(names, after) {
		fail(PropertyRefusalRegistration, "registered backends went from %q to %q", names, after)
	}
	// With no baseline allocator there is nothing to compare, and a second
	// budgetOf would start one itself.
	if !budget.unset {
		if after := budgetOf(); after != budget {
			fail(PropertyRefusalBudget, "locked-memory budget went from %s to %s", budget, after)
		}
	}
	return findingsOf(findings)
}

// refusalNew calls newFn, turning a panic into its value.
func refusalNew(newFn func() (enclave.Backend, error)) (b enclave.Backend, panicked any, err error) {
	defer func() {
		if v := recover(); v != nil {
			b, panicked, err = nil, v, nil
		}
	}()
	b, err = newFn()
	return b, nil, err
}

// refusalProbe calls probe, turning a panic into its value.
func refusalProbe(ctx context.Context, probe func(context.Context) error) (panicked any, err error) {
	defer func() {
		if v := recover(); v != nil {
			panicked, err = v, nil
		}
	}()
	return nil, probe(ctx)
}

// budgetSnapshot is the process's locked-memory budget at one moment.
type budgetSnapshot struct {
	alloc        enclave.Allocator
	inUse, limit int64
	unset        bool
}

func (s budgetSnapshot) String() string {
	if s.unset {
		return "no process allocator"
	}
	return fmt.Sprintf("%p limit %d in use %d", s.alloc, s.limit, s.inUse)
}

// budgetOf snapshots the process allocator's identity, limit and reservations.
// The enclave package has no read-only view of the process allocator, so the
// first call starts it. CheckRefusal makes that first call before the
// constructor runs, so New and Probe see the same started allocator the
// comparison reads, and it takes the second snapshot only when the first one
// found an allocator: when the first could not start one, a second call would
// start it itself and report the check's own side effect as the module's.
func budgetOf() budgetSnapshot {
	a, err := enclave.ProcessAllocator()
	if err != nil || isNilInterface(a) {
		return budgetSnapshot{unset: true}
	}
	return budgetSnapshot{alloc: a, inUse: a.InUse(), limit: a.Limit()}
}
