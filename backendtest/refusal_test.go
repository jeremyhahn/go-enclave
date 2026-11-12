package backendtest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// errNoHardware is the typed unavailable error of the refusal fakes.
var errNoHardware = errors.New("fake: the hardware is absent")

// hardwareError is a fake module's typed refusal: it names the failing step.
type hardwareError struct{ step string }

func (e *hardwareError) Error() string        { return "fake: " + e.step + ": no hardware" }
func (e *hardwareError) Is(target error) bool { return target == errNoHardware }

// stepOf is the fakes' RefusalConfig.Step.
func stepOf(err error) (string, bool) {
	var he *hardwareError
	if !errors.As(err, &he) {
		return "", false
	}
	return he.step, true
}

// refusalBackend is the backend a faulty fake registers or returns.
type refusalBackend struct{}

// namedRefusalBackend is a refusalBackend under a caller-chosen name, so a
// test can register a fresh name on every run of the test binary.
type namedRefusalBackend struct {
	refusalBackend
	name string
}

func (b namedRefusalBackend) Name() string { return b.name }

// registerRuns numbers the registers case's registrations across runs.
var registerRuns atomic.Int64

func (refusalBackend) Name() string                    { return "refusal-fake" }
func (refusalBackend) Rank() int                       { return 2 }
func (refusalBackend) Probe(ctx context.Context) error { return &hardwareError{step: "probe"} }
func (refusalBackend) String() string                  { return "refusal-fake" }
func (refusalBackend) GoString() string                { return "refusalBackend{}" }
func refuseNew() (enclave.Backend, error)              { return nil, &hardwareError{step: "open"} }
func refuseProbe(ctx context.Context) error            { return &hardwareError{step: "open"} }
func passingRefusal() RefusalConfig {
	return RefusalConfig{New: refuseNew, Probe: refuseProbe, Step: stepOf}
}
func withNew(f func() (enclave.Backend, error)) RefusalConfig {
	cfg := passingRefusal()
	cfg.New = f
	return cfg
}

// refusalProperty reports whether err is a FindingsError holding a
// PropertyError for property.
func refusalProperty(err error, property string) bool {
	var fe *FindingsError
	if !errors.As(err, &fe) {
		return false
	}
	for _, f := range fe.Findings {
		var pe *PropertyError
		if errors.As(f, &pe) && pe.Property == property {
			return true
		}
	}
	return false
}

// TestCheckRefusalPasses pins that a module that refuses cleanly, in New and
// in Probe, has no findings.
func TestCheckRefusalPasses(t *testing.T) {
	if err := CheckRefusal(context.Background(), passingRefusal()); err != nil {
		t.Fatalf("CheckRefusal(clean refusal) = %v, want nil", err)
	}
	cfg := passingRefusal()
	cfg.Probe = nil
	if err := CheckRefusal(nil, cfg); err != nil {
		t.Fatalf("CheckRefusal(clean refusal, no Probe) = %v, want nil", err)
	}
}

// TestCheckRefusalConfig pins that a configuration without New or Step is
// refused before anything runs.
func TestCheckRefusalConfig(t *testing.T) {
	for name, cfg := range map[string]RefusalConfig{
		"no New":  {Step: stepOf},
		"no Step": {New: refuseNew},
	} {
		if err := CheckRefusal(context.Background(), cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: CheckRefusal = %v, want ErrInvalidConfig", name, err)
		}
	}
}

// TestCheckRefusalCatches pins that each faulty module is caught under the
// property it breaks.
func TestCheckRefusalCatches(t *testing.T) {
	registered := false
	alloc, err := enclave.ProcessAllocator()
	if err != nil || alloc == nil {
		t.Fatalf("ProcessAllocator = %v, %v", alloc, err)
	}
	limit := alloc.Limit()
	t.Cleanup(func() { _, _ = alloc.ForceLimit(limit) })
	cases := []struct {
		name     string
		cfg      RefusalConfig
		property string
	}{
		{"constructs", withNew(func() (enclave.Backend, error) { return refusalBackend{}, nil }), PropertyRefusalNew},
		{"backend with error", withNew(func() (enclave.Backend, error) {
			return refusalBackend{}, &hardwareError{step: "open"}
		}), PropertyRefusalNew},
		{"untyped", withNew(func() (enclave.Backend, error) { return nil, errors.New("no device") }), PropertyRefusalTyped},
		{"no step", withNew(func() (enclave.Backend, error) { return nil, &hardwareError{} }), PropertyRefusalStep},
		{"panics", withNew(func() (enclave.Backend, error) { panic("boom") }), PropertyRefusalNew},
		{"probe accepts", func() RefusalConfig {
			cfg := passingRefusal()
			cfg.Probe = func(context.Context) error { return nil }
			return cfg
		}(), PropertyRefusalProbe},
		{"probe untyped", func() RefusalConfig {
			cfg := passingRefusal()
			cfg.Probe = func(context.Context) error { return errors.New("no device") }
			return cfg
		}(), PropertyRefusalTyped},
		{"registers", withNew(func() (enclave.Backend, error) {
			if !registered {
				registered = true
				// The registry is process-wide and has no unregister, so each
				// run (-count, -cpu) registers a name no earlier run took.
				name := fmt.Sprintf("refusal-fake-%d", registerRuns.Add(1))
				if err := enclave.Register(namedRefusalBackend{name: name}); err != nil {
					t.Errorf("Register(%q) = %v", name, err)
				}
			}
			return nil, &hardwareError{step: "open"}
		}), PropertyRefusalRegistration},
		{"typed nil", withNew(func() (enclave.Backend, error) {
			return (*refusalBackend)(nil), &hardwareError{step: "open"}
		}), PropertyRefusalNew},
		{"budget", budgetFault(alloc), PropertyRefusalBudget},
		{"budget leak", withNew(func() (enclave.Backend, error) {
			// A constructor that takes locked memory through the process
			// allocator and keeps it when it refuses.
			a, err := enclave.ProcessAllocator()
			if err != nil {
				return nil, &hardwareError{step: "open"}
			}
			leaked, err := a.NewSized(1)
			if err == nil {
				t.Cleanup(func() { _ = leaked.Destroy() })
			}
			return nil, &hardwareError{step: "open"}
		}), PropertyRefusalBudget},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckRefusal(context.Background(), c.cfg)
			if !refusalProperty(err, c.property) {
				t.Fatalf("CheckRefusal = %v, want a %s finding", err, c.property)
			}
		})
	}
}

// budgetFault is a refusing constructor that moves alloc's limit, which
// CheckRefusal must report as a budget change.
func budgetFault(alloc enclave.Allocator) RefusalConfig {
	return withNew(func() (enclave.Backend, error) {
		// Lower an unbounded limit instead: MaxInt64+1 would wrap negative
		// and ForceLimit would refuse it, moving nothing.
		limit := alloc.Limit()
		if limit < math.MaxInt64 {
			limit++
		} else {
			limit--
		}
		_, _ = alloc.ForceLimit(limit)
		return nil, &hardwareError{step: "open"}
	})
}

// TestCheckRefusalBudgetUnbounded runs the budget fault against an unbounded
// budget, the default on a host whose locked-memory ceiling does not bind.
func TestCheckRefusalBudgetUnbounded(t *testing.T) {
	alloc, err := enclave.ProcessAllocator()
	if err != nil || alloc == nil {
		t.Fatalf("ProcessAllocator = %v, %v", alloc, err)
	}
	limit := alloc.Limit()
	t.Cleanup(func() { _, _ = alloc.ForceLimit(limit) })
	if _, err := alloc.ForceLimit(math.MaxInt64); err != nil {
		t.Fatalf("ForceLimit(MaxInt64) = %v", err)
	}
	err = CheckRefusal(context.Background(), budgetFault(alloc))
	if !refusalProperty(err, PropertyRefusalBudget) {
		t.Fatalf("CheckRefusal = %v, want a %s finding", err, PropertyRefusalBudget)
	}
}
