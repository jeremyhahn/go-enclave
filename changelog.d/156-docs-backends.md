### Changed

- **The backends docs match the code, and `backendtest` has its own feature folder** (#156). `docs/backend-conformance/` holds the suite's five files and the conformance material that was in `docs/backends/architecture.md`. `docs/backends/api.md` lists every exported symbol of the seam, errors included; `architecture.md` drops the review records, decisions and migration text (renames are in Upgrading), gains a data-flow section and cites the ownership rules; the status banner is `NORMATIVE`.
