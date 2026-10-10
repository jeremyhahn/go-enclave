package enclave

import "sync"

// noCopy marks a struct that must not be copied after first use. A struct that
// embeds it as a field gets pointer-receiver Lock and Unlock methods, which is
// what go vet's copylocks analyser looks for: it then reports any copy of the
// struct by value, in this module and in modules that embed their own handle
// types. It costs no memory and does nothing at run time.
type noCopy struct{}

var _ sync.Locker = (*noCopy)(nil)

// Lock is a no-op; it exists for copylocks.
func (*noCopy) Lock() {}

// Unlock is a no-op; it exists for copylocks.
func (*noCopy) Unlock() {}
