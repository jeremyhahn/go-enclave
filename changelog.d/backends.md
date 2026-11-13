### Added

- **backends**: `TestRegistryConcurrent` drives the named backend registry from many goroutines at once: concurrent `Register` of distinct and duplicate names registers each name exactly once and refuses every duplicate with `*BackendExistsError`, every `BackendNames` snapshot is sorted, duplicate-free, holds the locked-memory name and never drops a name, and `Lookup` never fails once `Register` returned nil (#369).
