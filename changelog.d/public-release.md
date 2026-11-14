### Added

- **public-release**: `make release-tree-check TAG=vX.Y.Z REF=<published ref>` checks, offline in the local clone, that the published commit's tree is byte-identical to the release tag's tree, and refuses naming both trees when they differ, when either does not resolve, or when the tag is not a release version (#332), and writes nothing.
- **public-release**: runnable examples on pkg.go.dev for the memory enclave, the locked-memory budget, backend detection and the shutdown sweep, linked from their user guides; `go test` runs them (#333). Documentation only; nothing changes for Go callers.

### Changed

- **public-release**: [Upgrading](docs/README.md#upgrading) covers v0.10.0-alpha, v0.11.0-alpha, v0.11.1-alpha and the next release, with the next release's Go 1.27.4 minimum and how to require the nested `backends/armtrustzone` and `backends/tpm` modules. Documentation only; nothing changes for Go callers.
