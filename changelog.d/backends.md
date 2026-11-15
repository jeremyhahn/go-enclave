### Added

- **backends**: A race test drives the named backend registry from many goroutines, so concurrent `Register`, `Lookup` and `BackendNames` calls each register a name once, refuse duplicates with `*BackendExistsError` and return sorted, complete snapshots (#369).

### Removed

- **backends**: The nested module `github.com/jeremyhahn/go-enclave/backends/imxele` and the i.MX EdgeLock backend's proposal are removed: the i.MX 95 EdgeLock Enclave holds keys only, so it moved to [go-xkms](https://github.com/jeremyhahn/go-xkms). On the i.MX 95, `backends/armtrustzone` stays the protected-memory backend. See [Upgrading](docs/README.md#imx-edgelock-backend-module-moved-to-go-xkms).
