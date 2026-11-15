### Added

- **backends**: A race test drives the named backend registry from many goroutines, so concurrent `Register`, `Lookup` and `BackendNames` calls each register a name once, refuse duplicates with `*BackendExistsError` and return sorted, complete snapshots (#369).

### Removed

- **backends**: The nested module `github.com/jeremyhahn/go-enclave/backends/imxele` is removed; the i.MX EdgeLock Enclave holds keys only and moved to [go-xkms](https://github.com/jeremyhahn/go-xkms). See [Upgrading](docs/README.md#imx-edgelock-backend-module-moved-to-go-xkms).
