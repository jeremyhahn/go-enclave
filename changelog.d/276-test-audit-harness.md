### Changed

- The backendtest and providertest unit suites drop their allocator and software-provider positive controls, which the integration harness already runs (#276). Nothing changes for Go callers.
