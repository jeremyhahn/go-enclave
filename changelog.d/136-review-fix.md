### Changed

- **The integration image is built once, scanned by ID, and shared** (#136). `scripts/integration-image.sh` builds it under a unique tag, runs trivy on that image, and runs the userns, default and FIPS suites on it with no rebuild; it removes the image last. `INTEGRATION_SCAN` is gone.
- **The trivy copied out of the toolchain image is hash-checked** (#136). `build/ci/toolchain-trivy.sh` verifies it against `TRIVY_BIN_SHA256_LINUX_*`, and `scripts/tool.sh` with `TOOL_INSTALL=0` does the same for archive tools before running them.
- **`scripts/features.sh` strips only GOOS/GOARCH suffixes** when it maps a test file to its source file (#136).
- **The workflow permissions gate fails closed** (#136). Only `read-all`, `{}` and known scopes at `read` or `none` pass.
- **The release publish job checks every stage before it checks out code** (#136). An inline step requires every `needs` result, `verify` included, to be `success` first; checkouts in write-capable jobs set `persist-credentials: false`, and a build gate pins both.
