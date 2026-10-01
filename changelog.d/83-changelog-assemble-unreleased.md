### Fixed

- **`scripts/changelog-assemble.sh` refuses to release over entries still in
  `[Unreleased]`** (#83). When `CHANGELOG.md` already had a hand-written
  section for the version and no fragment was waiting, the script took its
  no-op exit without looking at `[Unreleased]`, so `make release-alpha`
  could tag a CHANGELOG whose release section left out every entry still
  sitting there. It now fails, changing nothing, and quotes the first such
  entry. A bare `### ` heading with nothing under it is not an entry and
  does not block, matching how the fold already drops empty subsections.
