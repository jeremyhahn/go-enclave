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
// and opens it again. The value is a fixed, non-secret marker.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	enclave "github.com/jeremyhahn/go-enclave"
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
	return sealing()
}

func lifecycle() error {
	marker := []byte("go-enclave consumer check")
	material := bytes.Clone(marker)

	e, err := enclave.NewMemoryEnclave(material)
	if err != nil {
		return fmt.Errorf("NewMemoryEnclave: %w", err)
	}
	defer func() { _ = e.Destroy() }() // second call after the explicit one: idempotent

	if !bytes.Equal(material, make([]byte, len(marker))) {
		return errors.New("NewMemoryEnclave left the caller's buffer unwiped")
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
		return fmt.Errorf("SealedEnclave.Destroy: %w", err)
	}
	return nil
}
