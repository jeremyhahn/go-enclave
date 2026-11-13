# go-enclave

[![Go Reference](https://pkg.go.dev/badge/github.com/jeremyhahn/go-enclave.svg)](https://pkg.go.dev/github.com/jeremyhahn/go-enclave)
[![CI](https://github.com/jeremyhahn/go-enclave/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jeremyhahn/go-enclave/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/jeremyhahn/go-enclave)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Locked, guarded memory for key material in Go, with sealing at rest.

A memory enclave, held as a `ByteAccess`, is a region of locked memory that
holds sensitive material such as private keys, credentials, passphrases and
tokens for its whole lifetime in the process. `Sealed` holds the same kind of
material encrypted at rest, and decrypts it into a fresh memory enclave only
while a caller has it open.

The package is meant to sit at the bottom of a dependency graph, so that every
library that handles key material can share one implementation.

## Features

- **Memory enclaves.** Each enclave is `mlock`ed, fenced by inaccessible guard
  pages, checked by a random canary, kept out of core dumps where the kernel
  allows it, and wiped on `Destroy`. `Freeze` makes an enclave read-only.
  Every mapping failure is a typed error that touches no other enclave.
- **Admission control.** An `Allocator` admits each enclave against a budget
  of page-rounded locked bytes before it allocates, so one caller cannot
  exhaust the process's `RLIMIT_MEMLOCK`. The binary installs one process
  allocator and libraries draw on it.
- **Sealing.** `Sealed` holds an AES-256-GCM envelope and opens it only into a
  fresh, frozen memory enclave. A `Sealer` seals under a key provider, in
  `ModeRootKey` or `ModePerOperation`. Providers ship for software
  (`NewSoftwareProvider`), TPM 2.0 ([`backends/tpm`](backends/tpm)) and
  OP-TEE on Arm TrustZone ([`backends/armtrustzone`](backends/armtrustzone)).
- **Backends.** A small `Backend` and `Handle` core with optional
  capabilities, found with `As`. Backends are registered by name with
  `Register`; importing the package registers nothing. `Detect` probes the
  registered backends and returns the most secure one the host can run, or
  the locked-memory backend when none ranks higher.
- **linux-secretmem.** `NewSecretMemory` returns a backend whose pages are
  `memfd_secret(2)` memory: locked, out of core dumps, removed from the
  kernel's direct map, and refused to `ptrace` and `/proc/<pid>/mem`.
- **arm-trustzone.** The `backends/armtrustzone` backend fills enclave handles
  with random bytes from an OP-TEE trusted application.
- **Shutdown sweep.** `WipeAll(ctx)` wipes every live enclave at exit, within
  the caller's deadline.
- **Conformance suites.** `providertest.TestProvider` checks a key provider
  and `backendtest.TestBackend` checks a backend, each against the contract
  the package relies on.
- **FIPS 140-3 mode.** Sealing uses only approved algorithms (AES-256-GCM and
  HKDF-SHA256) and runs under Go's native FIPS 140-3 module in strict mode
  (`GOFIPS140=latest GODEBUG=fips140=only`). This is tested compatibility, not
  a validation ([details](docs/sealing/engineering.md#fips-140-3)).

## Install

```sh
go get github.com/jeremyhahn/go-enclave
```

Requires Go 1.27.4 or later. The root module depends only on
`golang.org/x/sys`. The hardware providers are separate modules with their own
dependencies, so the root module never pulls them in:

```sh
go get github.com/jeremyhahn/go-enclave/backends/tpm           # adds github.com/google/go-tpm
go get github.com/jeremyhahn/go-enclave/backends/armtrustzone  # pure Go, no cgo
```

## Quick start

```go
import "github.com/jeremyhahn/go-enclave"

// Bring existing material in. keyPEM is wiped on every path.
e, err := enclave.NewMemory(keyPEM)
if err != nil {
	return err
}
defer e.Destroy()

err = e.WithBytes(func(key []byte) error {
	cert, err := tls.X509KeyPair(certPEM, key)
	_ = cert // use it here; the borrow ends with the callback
	return err
})
```

Generate new material straight into locked memory, then make it read-only:

```go
k, err := enclave.NewMemorySized(32)
if err != nil {
	return err
}
defer k.Destroy()

if err := k.WithBytes(func(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)
	return err
}); err != nil {
	return err
}
var f enclave.Freezer // NewMemorySized returns a ByteAccess; Freeze is a capability
if !enclave.As(k, &f) {
	return errors.New("not freezable")
}
if err := f.Freeze(); err != nil { // a refused Freeze leaves it writable
	return err
}
```

Seal material that is used only now and then:

```go
s, err := enclave.NewSealed(ctx, credential) // credential is wiped
if err != nil {
	return err
}
p, err := s.Open(ctx) // plaintext decrypted into locked pages
if err != nil {
	return err
}
defer p.Destroy() // open late, destroy early
```

Seal under a TPM instead of a software key:

```go
tp, err := tpm.Open("") // /dev/tpmrm0
if err != nil {
	return err
}
defer tp.Close()

sealer, err := enclave.NewSealer(enclave.WithKeyProtector(tp))
if err != nil {
	return err
}
defer sealer.Destroy()

s, err := sealer.Seal(ctx, credential)
```

Sweep at shutdown, in `main` and never in a library, with a deadline taken
then:

```go
defer func() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
		log.Printf("enclave: %d still held at exit: %v", n, err)
	}
}()
```

## Platforms

Linux (including Android), the BSDs, darwin, iOS, illumos, Solaris, AIX and
Windows compile. Any other GOOS (js, wasip1, plan9) fails to compile. Only
Linux runs the tests; the BSDs and Windows are build-only
([test status](docs/memory-enclave/engineering.md#test-status)). The per-OS
lock primitive, core-dump exclusion and `CoreDumpsDisabled()` result are in the
[platform contract](docs/memory-enclave/engineering.md#platform-contract).

The linux-secretmem backend needs Linux on 386, amd64, arm64, loong64, riscv64
or s390x, and a kernel that allows `memfd_secret`. The arm-trustzone backend
needs Linux with the TEE subsystem (`/dev/tee0`).

## Documentation

The [documentation index](docs/README.md) lists every feature, each with
`user.md`, `architecture.md`, `engineering.md` and `api.md`. Breaking changes
between releases are in [Upgrading](docs/README.md#upgrading). The API
reference is on [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave).

## Development

Build targets, test prerequisites, changelog fragments and naming rules are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

The threat model, meaning what each type protects against and what it does
not, is in
[docs/memory-enclave/architecture.md](docs/memory-enclave/architecture.md#trust-boundaries)
and
[docs/sealing/architecture.md](docs/sealing/architecture.md#what-each-mode-buys-against-a-live-memory-reader).
Report a vulnerability privately, never in a public issue, as
[SECURITY.md](SECURITY.md) describes. It also lists supported versions, scope
and the disclosure policy.

## License

MIT. See [LICENSE](LICENSE).
