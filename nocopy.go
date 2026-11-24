package enclave

import "sync"

// noCopy marks a struct that must not be copied after first use, for go vet's copylocks check.
type noCopy struct{}

var _ sync.Locker = (*noCopy)(nil)

// Lock is a no-op; it exists for copylocks.
func (*noCopy) Lock() {}

// Unlock is a no-op; it exists for copylocks.
func (*noCopy) Unlock() {}
