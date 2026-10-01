### Changed

- **go-enclave owns its OS memory layer; `github.com/awnumar/memcall` is
  gone** (#86). Allocation, locking, protection, unmapping and core-dump
  hardening now go directly through `golang.org/x/sys/unix` (`mmap`, `mlock`,
  `munlock`, `mprotect`, `munmap`, `setrlimit`) and `golang.org/x/sys/windows`
  (`VirtualAlloc`, `VirtualLock`, `VirtualUnlock`, `VirtualProtect`,
  `VirtualFree`), one system call per primitive. The module's only dependency
  is now `golang.org/x/sys`. Release is the explicit sequence make writable →
  wipe → verify canary → munlock → munmap, with nothing hidden inside a
  primitive: memcall's `Free` re-protected and re-wiped the region itself,
  which forced a second "direct" unmap and fallback logic choosing between the
  two. There is now one unmap, so a successful release makes one `mprotect`
  instead of two, and an orphaned failed construction's retry no longer
  depends on which of two unmaps happens to be allowed. Every #83 guarantee —
  no unwiped unmap outside the denied-`mprotect` path (`ErrReleasedWithoutWipe`),
  sticky corruption across retries, at most one successful unlock, the
  locked/mapped refund classification and the orphan ledger — is unchanged.
### Changed — BREAKING: Windows `CoreDumpsDisabled()` reports the truth

- **`CoreDumpsDisabled()` on Windows returns `ErrCoreDumpLimitUnsupported`
  instead of `nil`** (#86). Windows has no process-wide core-dump limit:
  dumps are written under machine policy (WER `LocalDumps`) or by any process
  with access calling `MiniDumpWriteDump`, and neither honours `VirtualLock`.
  memcall reported that no-op as success, telling a caller who checked that a
  hardening step had taken when none exists. Code that treats a non-nil
  result as fatal will now see the truth on Windows; match the new sentinel to
  accept it deliberately. Unix semantics are unchanged: `RLIMIT_CORE` soft and
  hard are both lowered to zero, exactly as memcall did. That stops core
  *files*; a Linux `core_pattern` piping to a collector (systemd-coredump,
  apport) ignores `RLIMIT_CORE` (core(5)), and there the per-mapping
  `MADV_DONTDUMP` is what keeps enclave pages out — the docs now say so.
- **The per-mapping core-dump exclusion now covers DragonFly** (#86):
  `MAP_NOCORE` plus a verified `MADV_NOCORE` on FreeBSD and DragonFly. OpenBSD's
  `MAP_CONCEAL` (a property of the `mmap` itself, so a mapping that exists is
  concealed), which memcall already applied, is preserved and now lives in this
  package; `MADV_DONTDUMP` on Linux as before. Windows'
  `WerRegisterExcludedMemoryBlock` is deliberately not used: it covers WER
  reports only, and its process-wide pool of 512 registered entries is shared
  with every other WER user, so failing closed would cap live enclaves and
  starve other libraries while best effort would be silently partial
  (rationale in `dontdump_windows.go`).
- **An unsupported GOOS fails to compile with one deliberate error**,
  `undefined: go_enclave_does_not_support_this_GOOS`, from this package
  (js, wasip1, plan9, and any future GOOS until it is checked), instead of a
  failure inside a dependency.

### Added

- **`ErrCoreDumpLimitUnsupported`** (#86), the sentinel `CoreDumpsDisabled`
  returns on a platform with no process-wide core-dump limit to lower
  (Windows).
- **illumos, Solaris and AIX are supported** (#86), and are in
  `make cross-build` along with DragonFly and windows/386. On those three,
  `mlock` requires a privilege an ordinary process lacks, so an unprivileged
  process gets `ErrLockedMemoryUnavailable` from every allocation.

### Fixed

- **go-enclave builds on DragonFly** (#86). memcall v0.5.0 referenced
  `unix.MADV_DONTDUMP`, which x/sys does not define for DragonFly, so the
  package did not compile there; it is now built and vetted by
  `make cross-build`.

### Removed

- **The `github.com/awnumar/memcall` dependency** (#86).
