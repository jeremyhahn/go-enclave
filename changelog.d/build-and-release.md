### Added

- Unit tests for the integration suites' devcontainer guard: `Problems` now delegates to a pure function of its inputs (environment, `/proc/self/status`, euid, RLIMIT_MEMLOCK, FIPS state), and every refusal and the clean case are table-tested with their messages; `make lint-integration` runs them (#344).
