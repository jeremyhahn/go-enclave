// Command consumer is the program scripts/consumer-check.sh builds against a
// published go-enclave version, in a scratch module outside this repository
// with GOWORK=off, so it exercises what `go get` hands a consumer rather than
// the working tree.
//
// It lives under testdata/ so the root module's `./...` (build, vet, lint,
// coverage) never sees it. build/ci/buildgates builds and runs it against the
// working tree on every change, so an API change that breaks it fails in that
// change's PR rather than at the next tag.
//
// It checks the lifecycle every consumer depends on: construction wipes the
// caller's buffer, the material is readable in the borrow window and comparable
// with EqualTo, Destroy releases it, and a destroyed enclave returns
// ErrEnclaveDestroyed. It then seals the marker through a typed provider option
// and opens it again. The value is a fixed, non-secret marker. Last, it runs
// the provider-author suite, providertest.TestProvider, against the software
// provider, so the SDK a provider author imports works from outside too.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "consumer-check: FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("consumer-check: ok")
}

func run() error {
	if err := lifecycle(); err != nil {
		return err
	}
	if err := sealing(); err != nil {
		return err
	}
	return conformance()
}

func lifecycle() error {
	marker := []byte("go-enclave consumer check")
	material := bytes.Clone(marker)

	e, err := enclave.NewMemory(material)
	if err != nil {
		return fmt.Errorf("NewMemory: %w", err)
	}
	defer func() { _ = e.Destroy() }() // second call after the explicit one: idempotent

	if !bytes.Equal(material, make([]byte, len(marker))) {
		return errors.New("NewMemory left the caller's buffer unwiped")
	}
	if !e.IsAlive() {
		return errors.New("a new enclave reports itself not alive")
	}
	if got := e.Size(); got != len(marker) {
		return fmt.Errorf("Size() = %d, want %d", got, len(marker))
	}
	if err := e.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, marker) {
			return errors.New("the borrowed view does not hold the material")
		}
		return nil
	}); err != nil {
		return fmt.Errorf("WithBytes: %w", err)
	}
	if ok, err := e.EqualTo(marker); !ok || err != nil {
		return fmt.Errorf("EqualTo(marker) = (%t, %v), want (true, nil)", ok, err)
	}

	if err := e.Destroy(); err != nil {
		return fmt.Errorf("Destroy: %w", err)
	}
	if e.IsAlive() {
		return errors.New("a destroyed enclave reports itself alive")
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return fmt.Errorf("WithBytes after Destroy returned %v, want ErrEnclaveDestroyed", err)
	}
	if ok, err := e.EqualTo(marker); ok || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		return fmt.Errorf("EqualTo after Destroy = (%t, %v), want (false, ErrEnclaveDestroyed)", ok, err)
	}
	return nil
}

// sealing round-trips the marker through a per-operation sealer over the
// software provider.
func sealing() error {
	ctx := context.Background()
	marker := []byte("go-enclave consumer check")
	p := enclave.NewSoftwareProvider()
	defer func() { _ = p.Destroy() }()

	s, err := enclave.NewSealer(enclave.WithKeyProtector(p))
	if err != nil {
		return fmt.Errorf("NewSealer: %w", err)
	}
	defer func() { _ = s.Destroy() }()
	if s.Mode() != enclave.ModePerOperation {
		return fmt.Errorf("Mode() = %v, want ModePerOperation", s.Mode())
	}

	v, err := s.Seal(ctx, bytes.Clone(marker))
	if err != nil {
		return fmt.Errorf("Seal: %w", err)
	}
	o, err := v.Open(ctx)
	if err != nil {
		return fmt.Errorf("Open: %w", err)
	}
	defer func() { _ = o.Destroy() }()
	if ok, err := o.EqualTo(marker); !ok || err != nil {
		return fmt.Errorf("opened EqualTo(marker) = (%t, %v), want (true, nil)", ok, err)
	}
	if err := v.Destroy(); err != nil {
		return fmt.Errorf("Sealed.Destroy: %w", err)
	}
	return nil
}

// conformance runs the provider-author suite, providertest.TestProvider,
// against the software provider in both sealing modes, so the SDK a provider
// author imports is built and run from outside the repository too.
func conformance() error {
	err := providertest.TestProvider(context.Background(), providertest.Config{
		New:   func() (any, error) { return enclave.NewSoftwareProvider(), nil },
		Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
		// The residue sweep needs Linux and locked memory, which the host
		// running this check may not grant, and it is the slow part of the
		// suite. providertest's own tests measure it against this provider;
		// this check proves the provider-author surface builds and runs from
		// a published module.
		SkipResidueSweep: "measured by providertest's own tests; this check covers the published SDK surface",
	})
	if err != nil {
		return fmt.Errorf("providertest.TestProvider(software provider): %w", err)
	}
	return nil
}
