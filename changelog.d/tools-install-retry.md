### Fixed

- **The toolchain image's tool builds retry a failed module fetch** (m850). Both `go install` steps in `scripts/tool.sh` (the gosec build and every other Go tool) make up to 3 attempts, 10 s then 20 s apart, each from an empty install directory, before failing as before, so one transient module-proxy error no longer fails `make docker-build`. Pins and checksum verification are unchanged. Nothing changes for Go callers.
