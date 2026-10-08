### Changed

- **Migration guidance lives once, in `docs/README.md` "Upgrading"** (#129), now
  with a v0.8.0-alpha section covering the breaking changes since v0.7. The
  "Migrating from" sections of each `user.md` and the version history of each
  `api.md` link to it instead of repeating it.
- **The README links to the platform contract and the documentation index**
  (#129) instead of copying their tables, and no longer says Android is missing
  from `cross-build`. `docs/locked-memory/engineering.md` says Linux is the only
  OS the tests run on, not the only OS in CI (CI cross-builds every target).

### Added

- **Root `CLAUDE.md` and `AGENTS.md`** (#129): the layout, the Make contract, the
  devcontainer, Serena and typed-error rules, and where the feature docs live.
