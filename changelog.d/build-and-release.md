### Added

- **build-and-release**: Unit tests for the integration suites' devcontainer guard: `Problems` now delegates to a pure function of its inputs (environment, `/proc/self/status`, euid, RLIMIT_MEMLOCK, FIPS state), and every refusal and the clean case are table-tested with their messages; `make lint-integration` runs them (#344).
- **build-and-release**: a build gate for `build/ci/release-tag.sh`: plain version tags such as `v1.2.3` and `v1.2.3-alpha.1` become exactly the `tag=` and `sha=` release outputs, and a branch ref, an empty or unset ref, or a tag holding shell metacharacters, spaces, slashes, quotes, backticks, `$(...)`, newlines or a leading dash is refused with nothing written and the name not echoed (#370).
