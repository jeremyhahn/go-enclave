### Fixed

- The memscan signal-frame test is bounded: it skips under the race detector (#331 tracks a race variant), reads 4 MiB of first-byte memory instead of 64 MiB, and signals each sweep for at most 2 s, so the coverage step on main finishes instead of timing out (#328). Nothing changes for Go callers.
