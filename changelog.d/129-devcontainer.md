### Changed

- **The devcontainer is the one toolchain for every build and test** (#129). `build/docker/devcontainer/Dockerfile` ships two stages from a shared `base` (Go, gcc/musl-dev, the `dev` user, the module and build caches at `/gomodcache` and `/gocache`): `toolchain`, which adds every pinned tool, bash, make, git, jq and the GNU userland and is usable as any non-root uid with `HOME=/tmp` and `GOPROXY=off`; and `integration`, which adds the source with today's hardening unchanged and ships none of the tools. Modules are fetched only at build time, through the `GO_BUILD_PROXY` build argument. The compose service that runs the integration suite is now `integration`, beside a new `toolchain` service.
- **Tool pins live only in `scripts/tool-pins.sh`** (#129). The Makefile includes it and the image's tools stage installs from it through `scripts/tool.sh`, which now uses a verified copy already on `PATH` (pinned version and build toolchain, or pinned SHA-256) instead of building or downloading one.
- **Every pin tracks upstream latest** (#129): golangci-lint v2.14.0, govulncheck v1.8.0, actionlint v1.7.12, trivy v0.75.0 and shellcheck v0.11.0, Go 1.27.1 on `golang:1.27.1-alpine3.24` (by digest), and checkout v7, setup-go v7 and codeql-action v4 (by commit SHA). A pin exists only so a build is reproducible, a version plus a SHA-256 or digest, and is never below the latest release.
- **`docker-build` and `docker-run` target the toolchain** (#129). `make docker-build` builds both stages and tags `go-enclave-toolchain:<content tag>` and `:latest`; `make docker-run CMD='make lint'` runs a command in the toolchain image with the checkout mounted, offline, as the invoking user.

### Added

- **`make toolchain-image`** (#129) prints the toolchain image's content-addressed tag, a hash of the files that build it, for running gates in it (`VERIFY_IMAGE`).
