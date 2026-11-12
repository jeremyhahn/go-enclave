package macse

import (
	"context"
	"runtime"
)

// createKey has no Security framework to call in this build, so it refuses
// with the typed unavailable error naming the create step. This slice ships
// no binding, so the file builds everywhere; the next slice adds the cgo
// binding in a darwin-and-cgo file (the proposal's Q2, the recommended
// option), and this file then takes the constraint !darwin || !cgo.
//
//nolint:unparam // the darwin binding's createKey returns the key
func createKey(context.Context) (seKey, error) {
	return nil, &PlatformError{Op: OpCreate, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}
