### Removed

- **`make check-action-pins`**, the deprecated alias for `make check-buildgates` (#136).
- **`make bench-providertest` and `make bench-memscan`**, which ran zero benchmarks; `make bench` runs the root package's (#136).

### Fixed

- **`GOEXPERIMENT=runtimesecret` is linted and scanned** (`lint-runtimesecret`, `gosec-runtimesecret`, `govulncheck-runtimesecret`, gated in `ci-lint` and `ci-security`), so the key-erasure code is no longer skipped (#136).
- **`TESTFLAGS` on the command line no longer drops `-race`**, which is now `TEST_RACE` (#136).
- **`go vet` of the build gates runs once per `ci-lint`**, not four times (#136).
- **`scripts/tool.sh` with `TOOL_INSTALL=0` compares the Go that built a Go tool with the module's toolchain** and fails on a mismatch (#136).
- **`scripts/deps-latest.sh` fails when `go list` fails** instead of hiding it (#136).
- **Changelog fragments fold in numeric issue order** (`9x` before `10x`) (#136).
- **`scripts/consumer-check.sh` clears the runner's `GOFLAGS`** (#136).
- **The integration run removes its merged-profile temporary file** on exit (#136).
