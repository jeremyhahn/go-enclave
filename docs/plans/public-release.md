# Plan: SPEC row public-release

Status: REFERENCE. Last verified: 2026-11-24.

## Objective

Meet the release criteria in [docs/SPEC.md](../SPEC.md#release-criteria) for
the first public release. This branch makes every criterion that can hold
before a release candidate hold on a branch from `main`, and leaves the
candidate itself to the owner. It cuts no tag and runs no `make release*`
target.

## Slices, in order

Each slice ends with `make lint-gates` and the unit tests of every module it
touches (`make test-enclave`, `make test-backends`).

1. Criteria 4 and 5. `make deps-check` passes: every module it checks (the
   root, `backends/*`, `build/ci/buildgates`) requires the latest release of
   each dependency, raised with `go get <mod>@latest && go mod tidy`, one
   commit per module. The root keeps `golang.org/x/sys` as its only
   dependency; the backend modules require a released root and use no
   `replace`. `make check-releasability` passes: every tracked file that
   names a private host, address or workstation path is fixed in that file,
   and no gate changes.
2. Upgrading notes. The Upgrading section of [docs/README.md](../README.md)
   covers every breaking change since the last alpha tag
   (`git log --oneline $(git describe --tags --abbrev=0 --match 'v*')..HEAD`),
   each with its migration, in the section's existing format.
3. The release candidate: `make release-candidate VERSION=vX.Y.Z-rc.N` from
   `main`, its release workflow, and a week in staging (criterion 6), then
   the release (criteria 7 and 8). This slice waits on the owner and does
   not start before the owner says so.

## Out of scope

- New features or SPEC rows; the future confiner row and the arm-trustzone
  vault storage.
- Changes to any gate to make it pass.
- Release tags: slices 1 and 2 cut none.
