# Locked-memory enclaves — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Prerequisites

- Go 1.27.1 or later; `go get github.com/jeremyhahn/go-enclave`.
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

## Read and compare

- `WithBytes(fn)` — the only way to read. Do not retain the slice and do not
  call back into the same enclave from `fn`. A string-only API gets the borrowed
  bytes converted inside `fn`, knowing that string cannot be wiped.
- `EqualTo(b)` — returns `(bool, error)`: `(false, nil)` means "did not
  match", and a destroyed or nil enclave returns `ErrEnclaveDestroyed`. The time
  taken does not depend on the contents, but it does reveal whether the lengths
  differ; compare fixed-length values (digests) if the length is secret.

There is no accessor that hands out a slice beyond a borrow: a slice that
outlives the lock is unmapped under its reader by `Destroy` or `WipeAll`.
String material comes in as `NewMemoryEnclave([]byte(s))`.

## Release

`defer e.Destroy()` is the right default. When you want to know what happened:

```go
if err := e.Destroy(); err != nil {
	switch {
	case errors.Is(err, enclave.ErrReleasedWithoutWipe):
		// Pages are gone; the environment denies mprotect (seccomp/sandbox).
	case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
		// Kernel refused the release; pages are still held.
		// Call Destroy again later; a shutdown WipeAll also retries it.
	}
}
```

`Destroy` returns an error matching `ErrEnclaveCorrupted` if the guard canary
was overwritten, after wiping the material and releasing the pages. Treat it as
a security incident: something wrote into memory it did not own, and every
other key in the process is in its reach. A `defer e.Destroy()` that discards
the error does not lose it: the next `WipeAll` reports it in its `SweepError`.

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

Importing the package lowers `RLIMIT_CORE` to 0, soft and hard, at init. Child
processes inherit that limit, so a tool your binary runs will not write core
files either, and cannot raise the limit back without privilege.

On Linux, enclave pages are also excluded from `fork(2)` children
(`MADV_DONTFORK`): a forked child has no mapping there, so touching an enclave
in the child faults rather than reading the material.

## Harden the process (opt-in)

`HardenProcess` marks the process non-dumpable on Linux. It is never called by
the package; call it from `main` if your deployment accepts the trade-offs.

```go
func main() {
	if report, err := enclave.HardenProcess(); err != nil {
		log.Printf("process hardening: %v (applied: %+v)", err, report)
	}
	// ...
}
```

What it buys: no core dump of any kind (piped collectors included), and no
`ptrace` attach or `/proc/<pid>/mem` read by other processes of the same uid.

What it costs: same-uid debuggers (`dlv attach`, `gdb -p`), profilers and crash
collectors stop working, and `/proc/<pid>` entries become owned by root, so
same-uid monitoring that reads `maps`, `fd` or `environ` loses access. The flag
carries into `fork` children and is reset by `execve`.

On other platforms it returns `ErrProcessHardeningUnsupported`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ErrLockedMemoryUnavailable` from a constructor | `RLIMIT_MEMLOCK` reached (or no privilege on AIX/Solaris/illumos), or a sandbox denies `mlock`/`madvise` | Raise the limit; destroy enclaves you no longer need; budget them ([locked-memory-budget](../locked-memory-budget/user.md)). |
| `ErrInvalidSize` | `NewMemoryEnclaveSized(n)` with `n <= 0` or absurdly large | Fix the size computation. |
| `ErrEnclaveDestroyed` on an enclave you did not destroy | A shutdown `WipeAll` ran, or the constructor raced one | Stop workers before the shutdown sweep. |
| `ErrReleasedWithoutWipe` from `Destroy` | `mprotect` denied by seccomp or a sandbox | Allow `mprotect` on the process's own memory. The pages were released (never swapped; zeroed by the kernel before reuse), but the in-process wipe was skipped. It does not match `ErrLockedMemoryUnavailable`, which means the pages are still held. |
| Process crashes (SIGSEGV) reading a slice | A slice kept past `WithBytes` outlived the enclave | Use `WithBytes`; never retain borrowed slices. |
| Process crashes writing through a slice | Writing to a frozen enclave — including one `SealedEnclave.Open` returned, which is always frozen | Writes are only for sized enclaves, inside `WithBytes`, before `Freeze`; to edit opened plaintext, copy it into your own sized enclave inside the borrow. |
| `ErrEnclaveCorrupted` from `Destroy` or `WipeAll` | Buffer underflow or memory corruption elsewhere | Treat as a security incident; find the writer. |
| Build error `undefined: go_enclave_does_not_support_this_GOOS` | Unsupported GOOS (js, wasip1, plan9) | Not supported by design. |

## Upgrading

Migration guidance lives in one place: [Upgrading](../README.md#upgrading).
