### Changed

- **The locked-memory docs cover process hardening, the error vocabulary and the data flow** (#157). `api.md` lists `ProcessHardening.NotDumpable` and `.CoreDumpsDisabled`, `(*Memory).GoString`, and every locked-memory and hardening sentinel with its error type. `architecture.md` gains the process-hardening shape and its rejected alternatives (including why `RLIMIT_CORE` is not lowered at import), a data-flow section, and the handbook ownership citation in the component boundaries.
