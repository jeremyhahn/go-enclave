### Added

- **Public-releasability gate: `make check-releasability`** (#80). Every
  tracked file is published — the public tree is byte-identical to the release
  tag — so the scrub has to hold in the source. The gate reads the git index
  and fails on any address in the 192.168/16 private block, a fleet hostname or private DNS
  zone, a path under the owner's home directory or the lab's NFS mount, and
  any tracked agent-only file (`CLAUDE.md`, `AGENTS.md`, `.claude/`,
  `.serena/`, `local.mk`, `task-worker.yml`). A line whose value is the point
  is waived in place with `lab-string-ok: <reason>`, the same spelling
  go-quicbaas uses. It lives in `test/buildgates` beside the action-pin gate,
  runs in `make ci` and in the Lint job, and is proven by planted values: an
  address in a tracked file fails it, the same address in an untracked file
  does not. Run against the previous `main` it reports exactly the seven
  findings removed below.
- `changelog.d/`: changes now land as fragments rather than edits to
  `CHANGELOG.md` (handbook release-versioning §5). The existing
  `[Unreleased]` section stays and releases normally.
- **`make release-alpha` assembles the fragments before tagging** (#80).
  `scripts/changelog-assemble.sh` merges `[Unreleased]` and every fragment,
  subsection by subsection, into the new version's section, deletes the
  fragments it folded in, and the release commit carries both with `VERSION`.
  It refuses, changing nothing, when a fragment is waiting behind a section
  already written by hand, when text sits outside a `###` subsection, or when
  there is nothing to release. `make check-changelog-assembly` (in `make ci`
  and the Lint job) proves every entry lands exactly once, on scratch trees
  and on a copy of this repository's own CHANGELOG.

### Changed

- **`CLAUDE.md` is no longer tracked** (#80). Agent working notes stay out of
  the published tree; the file is in `.gitignore` and the gate refuses it.
  Build, test and contribution notes for humans remain in the README.

### Fixed

- **`VERSION` reads `0.6.0-alpha`, unprefixed** (#80), as release-versioning
  §2 requires; the tag stays `v0.6.0-alpha`. `make release-alpha` wrote the
  tag string verbatim, so it now writes `$(VERSION:v%=%)`, the fix the shared
  `release-alpha.mk` template made in v2.3.
- **No lab address or fleet hostname in tracked files** (#80). The CHANGELOG's
  link references for v0.1.0-alpha through v0.3.0-alpha pointed at the retired
  internal forge by address and are removed, the #73 entry no longer quotes
  that address, and a test comment names "a factory runner" instead of the
  host a timing was measured on.
