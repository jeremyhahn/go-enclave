### Changed

- **`make cross-build` links every package's test binaries for each target** (#188). After `go build` and `go vet`, it runs `go test -c` for every `CROSS_TARGETS` entry, so a test that compiles but does not link off Linux fails the gate; nothing runs. The BSDs and Windows are build-only and tests run on Linux only ([runtime testing](docs/memory-enclave/runtime-testing.md)). Nothing changes for Go callers.
