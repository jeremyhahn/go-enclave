### Changed

- **One naming scheme for the OS-specific files** (#129). Each concern has one
  implementation per GOOS, named `<concern>_linux.go`, `_bsd.go`, `_windows.go`
  or `_unix.go` (code the platforms share), with `_unsupported.go` as the only
  catch-all; `_other` and `_nocore` are retired. `dontdump` and `dontfork` are
  one `madvise` concern around a single helper, Linux and the BSDs share one
  `getrlimit` path, and one table translates page protections. No exported API
  changes. `TestPlatformLayer_EveryGOOSHasExactlyOneImplementation` now covers
  every concern, not only the memory primitives.
