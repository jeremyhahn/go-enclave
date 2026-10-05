### Security

- **Auto-merge decides only from the base branch's workflow definition**
  (#106). `automerge.yml` now triggers on `pull_request_target`,
  `workflow_run` and a schedule, so a PR can no longer rewrite the workflow
  that holds the merge token. A `code-review` PR's approval must come from
  someone other than its author, and the label and reviews are read after CI
  is green, immediately before the merge call (owner ruling 2026-10-04).
- **`.gitea/CODEOWNERS`** names the owner for `.github/`, the Makefile and
  `scripts/` (#106).

### Fixed

- **`scripts/release-version-check.sh` orders pre-release identifiers as
  strings** (#106). AWK coerced identifiers such as `1e10` and numerics past
  2^53 to floating point, which could accept a lower version or refuse a
  higher one.
- **`release.yml` runs `make test-runtimesecret` before publishing** (#106), so
  a regression confined to the erasing build cannot ship.

### Added

- **`make vuln`** runs govulncheck (#106). `lint-go`, `staticcheck` and
  `govulncheck` now also analyze the `test/buildgates` module.
