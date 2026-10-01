### Fixed

- **`make ci` builds its lint tools with this module's toolchain** (#83).
  `go install tool@version` runs outside the module, so under
  `GOTOOLCHAIN=auto` it built golangci-lint and staticcheck with the tools'
  own go1.26 floor, and both then refused this go 1.27.0 module: `make ci`
  failed at lint on a tree CI passes. Every tool install now runs under
  `GOTOOLCHAIN=$(go env GOVERSION)` resolved inside the module.
- **`make coverage` enforces the 90% floor** that previously existed only in
  `ci.yml`, so the gate reproduces locally (project-scaffold §6).
- **`make release-alpha`'s remote-tag guard fails closed.** `! git ls-remote`
  passed on every failure, including a clone with no `dev` remote; only
  exit 2 (no such ref) now counts as free, and a missing `dev` remote is named.
- **nightly.yml runs Go 1.27.0**, matching `ci.yml` and `go.mod` (it was
  1.26.7).

### Added

- **`make cross-build`**, in `make ci` and the CI Build job: builds and vets
  every package for linux amd64/arm64/386/arm, darwin, freebsd, openbsd,
  netbsd and windows. DragonFly is unsupported: the pinned memcall v0.5.0 does
  not compile there.
