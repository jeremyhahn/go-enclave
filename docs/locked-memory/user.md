# Locked-memory enclaves — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Prerequisites

- Go 1.27.0 or later; `go get github.com/jeremyhahn/go-enclave`.
- A locked-memory allowance. Every enclave locks at least one page (4 KiB on
  most hosts). Check it with `ulimit -l`; raise it with `LimitMEMLOCK=` in a
  systemd unit, `--ulimit memlock=<soft>:<hard>` for a container, or
  `CAP_IPC_LOCK` on Linux.
- On AIX, Solaris and illumos `mlock` needs privilege; an unprivileged process
  cannot create enclaves there.

## Bring existing material in

```go
e, err := enclave.NewMemoryEnclave(keyPEM) // keyPEM is wiped, on every path
if err != nil {
	return err
}
defer e.Destroy()

err = e.WithBytes(func(key []byte) error {
	cert, err := tls.X509KeyPair(certPEM, key)
	_ = cert // use cert here; never keep `key` past this callback
	return err
})
```

If you must keep your buffer (you do not own it), use
`NewMemoryEnclaveCopy(src)` and wipe `src` yourself as soon as you can — the
heap copy is outside every protection this package gives.

## Generate material in place

Material that is about to be created should never touch the heap:

```go
e, err := enclave.NewMemoryEnclaveSized(32)
if err != nil {
	return err
}
defer e.Destroy()

if err := e.WithBytes(func(key []byte) error {
	_, err := io.ReadFull(rand.Reader, key) // straight into locked pages
	return err
}); err != nil {
	return err
}

// Make the pages read-only. A refused Freeze leaves the enclave WRITABLE,
// so check the error.
if err := e.Freeze(); err != nil {
	return err
}
```

Finish the fill before sharing the enclave with other goroutines; two borrows
writing at once is a data race.

## Read, compare, hand to a string API

- `WithBytes(fn)` — the default. Do not retain the slice and do not call back
  into the same enclave from `fn`.
- `EqualToErr(b)` — constant-time compare that tells "did not match" apart from
  "enclave already destroyed". `EqualTo(b)` returns `false` for both, which is
  fail-closed for `if e.EqualTo(x) { grant() }` but wrong if you invert it.
- `OpenString()` — only for APIs that insist on a `string`; the copy cannot be
  wiped.
- `Open()` — returns a slice that is **not** protected by any lock. A concurrent
  `Destroy` or `WipeAll` unmaps it and a later read crashes the process. Avoid.

## Release

`defer e.Destroy()` is the right default. When you want to know what happened:

```go
if err := e.Destroy(); err != nil {
	switch { // order matters: an unwiped release matches both sentinels
	case errors.Is(err, enclave.ErrReleasedWithoutWipe):
		// Pages are gone; the environment denies mprotect (seccomp/sandbox).
	case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
		// Kernel refused the release; pages are still held.
		// Call Destroy again later; a shutdown WipeAll also retries it.
	}
}
```

`Destroy` **panics** with a value matching `ErrEnclaveCorrupted` if the guard
canary was overwritten. Do not recover from it to keep running: something wrote
into memory it did not own, and every other key in the process is in its reach.

## Check core-dump hardening

```go
if err := enclave.CoreDumpsDisabled(); err != nil {
	log.Printf("core dumps not disabled process-wide: %v", err)
}
```

On Windows this always returns `ErrCoreDumpLimitUnsupported`; govern crash
dumps with host policy. On Linux hosts whose `core_pattern` pipes to a
collector, `RLIMIT_CORE` is ignored; enclave pages are still excluded per
mapping.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ErrLockedMemoryUnavailable` from a constructor | `RLIMIT_MEMLOCK` reached (or no privilege on AIX/Solaris/illumos), or a sandbox denies `mlock`/`madvise` | Raise the limit; destroy enclaves you no longer need; budget them ([locked-memory-budget](../locked-memory-budget/user.md)). |
| `ErrInvalidSize` | `NewMemoryEnclaveSized(n)` with `n <= 0` or absurdly large | Fix the size computation. |
| `ErrEnclaveDestroyed` on an enclave you did not destroy | A shutdown `WipeAll` ran, or the constructor raced one | Stop workers before the shutdown sweep. |
| `ErrReleasedWithoutWipe` from `Destroy` | `mprotect` denied by seccomp or a sandbox | Allow `mprotect` on the process's own memory. The pages were released (never swapped; zeroed by the kernel before reuse), but the in-process wipe was skipped. The error also matches `ErrLockedMemoryUnavailable`. |
| Process crashes (SIGSEGV) reading a slice | A slice from `Open` (or one kept past `WithBytes`) outlived the enclave | Use `WithBytes`; never retain borrowed slices. |
| Process crashes writing through a slice | Writing to a frozen enclave — including one `SealedEnclave.Open` returned, which is always frozen | Writes are only for sized enclaves, inside `WithBytes`, before `Freeze`; to edit opened plaintext, copy it into your own sized enclave inside the borrow. |
| Panic matching `ErrEnclaveCorrupted` | Buffer underflow or memory corruption elsewhere | Treat as a security incident; find the writer. |
| Build error `undefined: go_enclave_does_not_support_this_GOOS` | Unsupported GOOS (js, wasip1, plan9) | Not supported by design. |

## Migrating from v0.6

**`Destroy` returns the release report; `DestroyErr` is gone.**

```go
// v0.6
if err := e.DestroyErr(); err != nil { /* ... */ }
defer e.Destroy()

// v0.7
if err := e.Destroy(); err != nil { /* ... */ }
defer e.Destroy() // still compiles; still discards the report
```

Semantics are `DestroyErr`'s: `nil`, `ErrReleasedWithoutWipe` (released
without the wipe; this error also matches `ErrLockedMemoryUnavailable`, so test
it first), or `ErrLockedMemoryUnavailable` alone (refused; retry by calling
`Destroy` again). Corruption still panics.

**`CoreDumpsDisabled()` on Windows returns `ErrCoreDumpLimitUnsupported`**
instead of `nil`. Code that treats any non-nil result as fatal now fails on
Windows; accept the sentinel deliberately if host policy covers dumps:

```go
// v0.7
if err := enclave.CoreDumpsDisabled(); err != nil &&
	!errors.Is(err, enclave.ErrCoreDumpLimitUnsupported) {
	return err
}
```

**Dependency change:** `github.com/awnumar/memcall` is no longer required; the
module depends only on `golang.org/x/sys`. Run `go mod tidy`. DragonFly now
compiles, and illumos, Solaris and AIX are supported.
