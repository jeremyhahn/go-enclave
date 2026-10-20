### Fixed

- **The toolchain image build retries a failed module download** (m850). Both `go mod download` steps in `build/docker/devcontainer/Dockerfile` make up to 3 attempts, 10 s then 20 s apart, before failing, so one transient module-proxy error no longer fails `make docker-build`. `go mod verify` and checksum verification are unchanged. Nothing changes for Go callers.
