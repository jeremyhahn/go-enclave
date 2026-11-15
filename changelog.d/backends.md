### Added

- **backends**: A race test drives the named backend registry from many goroutines, so concurrent `Register`, `Lookup` and `BackendNames` calls each register a name once, refuse duplicates with `*BackendExistsError` and return sorted, complete snapshots (#369).
- **backends**: The nested module `github.com/jeremyhahn/go-enclave/backends/imxele` ships the i.MX EdgeLock backend's typed errors and a probe and constructor that check `/dev/tee0` for a GlobalPlatform TEE client. Its feature is withdrawn from the [specification](docs/SPEC.md#scope), and a later release removes the module. ([#195](https://github.com/jeremyhahn/go-enclave/issues/195))
