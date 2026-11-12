package backendtest

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// RefusalConfig describes a hardware backend module to [CheckRefusal].
type RefusalConfig struct {
	// New is the module's constructor.
	New func() (enclave.Backend, error)
	// Probe, if set, is the module's probe without a backend from New.
	Probe func(ctx context.Context) error
	// Step reports the step a refusal names.
	Step func(err error) (step string, ok bool)
}

// The properties [CheckRefusal] reports.
const (
	PropertyRefusalNew          = "refusal-new"
	PropertyRefusalProbe        = "refusal-probe"
	PropertyRefusalTyped        = "refusal-typed"
	PropertyRefusalStep         = "refusal-step"
	PropertyRefusalRegistration = "refusal-registration"
	PropertyRefusalBudget       = "refusal-budget"
)

// CheckRefusal is a stub.
func CheckRefusal(ctx context.Context, cfg RefusalConfig) error { return nil }
