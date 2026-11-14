### Added

- **backends**: A race test drives the named backend registry from many goroutines, so concurrent `Register`, `Lookup` and `BackendNames` calls each register a name once, refuse duplicates with `*BackendExistsError` and return sorted, complete snapshots (#369).
