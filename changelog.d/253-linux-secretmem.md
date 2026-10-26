### Changed

- **docs: the linux-secretmem backend is a planned row.** `docs/SPEC.md` and `ROADMAP.md` gain `linux-secretmem`, a Linux-only software backend on `memfd_secret(2)` ranked above the memory enclave and below every hardware backend, and `docs/backends/linux-secretmem.md` states what it adds, its kernel requirements, its failure modes and the questions open before any code. Nothing changes for Go callers.
