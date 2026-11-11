# go-enclave

A locked-memory primitive for Go. A memory enclave, held as a `ByteAccess`,
is a region of locked, zeroized memory for holding sensitive material — private keys, credentials,
passphrases, tokens — for its whole lifetime in the process. `Sealed`
holds the same kind of material encrypted at rest and decrypts it into a fresh
memory enclave only while a caller has it open.

It is built to sit at the bottom of a dependency graph so libraries that handle
key material can share one implementation. Each enclave is `mlock`'d, fenced by
inaccessible guard pages, guarded by a random canary, kept out of core dumps
where the kernel allows, and wiped on release (if a sandbox denies the
`mprotect` a frozen enclave needs for that wipe, the pages are unmapped unwiped
and `Destroy` reports `ErrReleasedWithoutWipe`). Every mapping failure is a typed
error that touches no other enclave, and admission control stops one caller from
exhausting the process's locked-memory ceiling.

## Install

```sh
go get github.com/jeremyhahn/go-enclave
```

Requires Go 1.27.4 or later. The only dependency is `golang.org/x/sys`.

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

In `main` — never in a library — sweep at shutdown with a deadline taken then:

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
Windows compile; any other GOOS (js, wasip1, plan9) fails to compile. Only Linux
runs the tests; the BSDs and Windows are build-only
([test status](docs/memory-enclave/engineering.md#test-status)). The per-OS lock
primitive, core-dump exclusion and `CoreDumpsDisabled()` result are in the
[platform contract](docs/memory-enclave/engineering.md#platform-contract).

## Documentation

The [documentation index](docs/README.md) lists every feature, each with
`user.md`, `architecture.md`, `engineering.md` and `api.md`. Breaking changes
between releases are in [Upgrading](docs/README.md#upgrading). The API
reference is on [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave).

## Development

| Target | What it does |
|---|---|
| `make test` | Unit tests with `-race` across `-cpu=1,2,8` |
| `make coverage` | The same run with coverage; fails below 90% (`make coverage-report` for HTML) |
| `make test-fips` | Build and test under `GOFIPS140=latest GODEBUG=fips140=only`: strict-mode compatibility, not validation ([details](docs/sealing/engineering.md#fips-140-3)) |
| `make lint` / `make staticcheck` / `make security` | gofmt, vet, golangci-lint, actionlint, shellcheck / staticcheck / gosec, govulncheck, module verification, trivy. golangci-lint, staticcheck and govulncheck also analyze the `build/ci/buildgates` module |
| `make vuln` | Alias for `make govulncheck` |
| `make cross-build` | Build and vet the configured `CROSS_TARGETS` matrix (`make help` lists the targets; the matrix includes `android/arm64`) |
| `make bench` | Benchmarks with allocation counts |
| `make check-releasability` | Fails if a tracked file names private hosts, addresses or workstation paths |
| `make ci-fast` | The full gate except anything that needs Docker |
| `make ci` | The full local gate a change must pass |
| `make integration-test` | The integration suite, `test/integration/enclave/`, run in the project devcontainer (needs Docker); fails rather than passes when there is nothing to run. Which test covers which feature: `test/integration/COVERAGE.md` |
| `make docker-build` / `make docker-run CMD='make lint'` / `make toolchain-image` | Build the devcontainer (`build/docker/devcontainer/`) / run a command in its `toolchain` image with the checkout mounted, offline, as you / print that image's content-addressed tag |
| `make help` | Every target |

Analysis tools are pinned and checksum-verified in `scripts/tool-pins.sh`; `make`
uses a verified copy on `PATH`, or installs them into `bin/tools/`. The
devcontainer's `toolchain` image carries Go and every pinned tool, and every
gate passes in it offline. Per-package variants exist (`test-providertest`,
`coverage-enclave`, ...). The unit suite has no skip guards: it needs a soft
`RLIMIT_MEMLOCK` of at least 2 MiB (or unlimited; with `CAP_IPC_LOCK`, a hard
limit of at least 2 MiB), a readable `/proc`, and permission to lower its own
limits — and it FAILS, with one message at startup, where that is missing.

**Changelog and releases.** A change adds a fragment,
`changelog.d/<issue>-<slug>.md`, instead of editing `CHANGELOG.md`.
Three targets cut a release from `main`, each of exactly one kind:
`make release VERSION=vX.Y.Z` (production), `make release-candidate
VERSION=vX.Y.Z-rc.N` and `make release-alpha VERSION=vX.Y.Z-alpha`; each
refuses the other two kinds. All three run `scripts/release.sh`, which refuses a
missing or malformed version, any other branch, a tag that exists locally or on
the remote (or a remote it cannot reach), a dirty tree and a version that does
not move forward; then it folds the fragments into `CHANGELOG.md`, checks the
result, and commits, tags and pushes. An `-alpha` or `-rc.N` release is
published as a pre-release. The tag triggers the release workflow, which runs
`make release-verify`, the full gate (FIPS and trivy included),
`make consumer-check` (a throwaway module that `go get`s the tag) and, on the
project's Gitea forge only, `make release-publish`. The publish job is skipped
when the workflow runs on github.com, and the script refuses GitHub hosts; a
GitHub release is published manually.

**Naming.** The types describe their mechanism — locked memory — not their
contents. Do not introduce `Secret`, `SecureString`, `SecureBytes` or
`ProtectedBuffer` synonyms.

## Security

The threat model — what each type protects against and what it does not — is in
[docs/memory-enclave/architecture.md](docs/memory-enclave/architecture.md#trust-boundaries)
and [docs/sealing/architecture.md](docs/sealing/architecture.md#what-each-mode-buys-against-a-live-memory-reader).
To report a vulnerability, follow [SECURITY.md](SECURITY.md) — privately, never
in a public issue. It also lists supported versions, scope and the disclosure
policy.

## License

MIT. See [LICENSE](LICENSE).
