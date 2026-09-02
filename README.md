# go-enclave

A locked-memory primitive for Go. `MemoryEnclave` is a region of locked,
zeroized memory for holding sensitive material — private keys, credentials,
passphrases and tokens — for the whole of its lifetime in the process.

It is built to sit at the bottom of a dependency graph, so that libraries which
handle key material can share one implementation rather than each rolling their
own. It maps its own memory — mlock'd pages, inaccessible guard pages either
side, a random canary, wiped on release, and kept out of core dumps — reports
every mapping failure as a typed error rather than aborting, and adds admission
control so an untrusted caller cannot exhaust the process's locked-memory
ceiling and starve everything else.

```go
import "github.com/jeremyhahn/go-enclave"

e, err := enclave.NewMemoryEnclave(keyPEM) // keyPEM is wiped
if err != nil {
    return err
}
defer e.Destroy()

err = e.WithBytes(func(key []byte) error {
    cert, err := tls.X509KeyPair(certPEM, key)
    // ... use cert; the borrow is valid only inside this callback
    return err
})
```

Material that is about to be **generated** never needs to reach the heap at all.
`NewMemoryEnclaveSized` hands back locked, zeroed pages, and the same borrow
window is where they are filled:

```go
e, err := enclave.NewMemoryEnclaveSized(32)
if err != nil {
    return err
}
defer e.Destroy()

err = e.WithBytes(func(key []byte) error {
    _, err := io.ReadFull(rand.Reader, key) // straight into locked memory
    return err
})
if err != nil {
    return err
}

// The fill is done. Freeze can be refused — a sandbox denying mprotect leaves
// the enclave alive and WRITABLE — so the property only holds if this is checked.
if err := e.Freeze(); err != nil {
    return err
}
```

Use it wherever the alternative would be `make` + generate + `NewMemoryEnclave`:
that shape puts the key on swappable, core-dumpable memory first, and the wipe
that follows cannot reach copies the compiler or the collector already made.

Pages that have to be filled cannot arrive read-only, so a sized enclave is
writable while it is being filled. `Freeze` `mprotect`s it read-only once the
material is final, which is what leaves it with the same protection an enclave
built from existing material has: a write through a retained slice **faults**
rather than silently corrupting a key. Without it that window is the enclave's
whole lifetime.

## Why this exists

Locked memory is a process-wide resource with a hard ceiling, and the obvious
library for it — [memguard](https://github.com/awnumar/memguard) — answers a
failed `mlock` by calling `Purge()`, which destroys **every** live protected
buffer in the process, and then panicking. A foundational library must not abort
its host over a resource limit it does not control, and it must not let one
path's exhaustion unmap another path's live key material.

go-enclave used memguard through v0.2.0-alpha and wrapped both problems: the
panic became a typed error, and a process-wide lock held borrows safe across a
purge. That lock was itself the problem — allocating inside a live borrow
deadlocked against it, which blocked real consumers outright — and a `recover`
cannot undo a purge that already ran.

Since v0.3.0-alpha go-enclave maps its own memory through `memcall`, the layer
memguard itself uses. There is no global registry, so nothing can purge these
pages:

1. **Error, not abort.** Every mapping, lock and protect failure returns a typed
   `LockedMemoryError` (matched via `ErrLockedMemoryUnavailable`) having released
   whatever it already took. The caller's source slice is wiped on every return
   path, including the failure paths.
2. **No collateral damage, and no lock.** An allocation failure anywhere in the
   process fails exactly that allocation. Enclaves are destroyed when their owner
   destroys them and at no other time — so there is nothing to serialize borrows
   against, and allocating inside a live borrow just works.
3. **Admission control.** `Allocator` is a lock-free bounded allocator with a
   typed `ErrBudgetExhausted`, accounted in **locked bytes** — the unit
   `RLIMIT_MEMLOCK` uses, so the budget and the ceiling are directly comparable.
   Every enclave costs at least one page (`LockedSize` computes it), which is
   what a budget must be sized in. Sizing its budget below `RLIMIT_MEMLOCK` and
   admitting untrusted allocations through it turns a remote memlock-drain
   (measured: a Noise responder allocating key buffers before authentication)
   into a local, typed refusal, leaving headroom for the sessions that did
   authenticate.

## API surface

| Symbol | Purpose |
|---|---|
| `NewMemoryEnclave(data []byte)` | Move `data` into a locked enclave; wipes `data`. |
| `NewMemoryEnclaveCopy(src []byte)` | Copy `src` into a locked enclave and leave `src` **intact**, for callers that do not own their buffer. The result is frozen read-only like `NewMemoryEnclave`'s. The cost is explicit: an unprotected copy stays on the heap for as long as the caller keeps `src`. |
| `NewMemoryEnclaveSized(n int)` | `n` bytes of locked, **zeroed** memory the caller fills in place through the borrow — generate-in-place, so the material never touches the heap. |
| `NewMemoryEnclaveFromString(s)` | Boundary helper for string-only APIs (the string cannot be wiped). |
| `(*MemoryEnclave) WithBytes(fn)` | **Preferred access.** Borrow the bytes for the duration of `fn` under the read lock. |
| `(*MemoryEnclave) OpenString / EqualTo / Size / IsAlive / String` | Locked, concurrency-safe accessors. |
| `(*MemoryEnclave) Freeze()` | Make the pages read-only once a sized enclave's fill is done, so a stray write **faults** instead of silently corrupting the material. Idempotent, not reversible, waits out in-flight borrows. A no-op on an enclave that is already frozen. |
| `(*MemoryEnclave) Open()` | **Unsafe.** Returns a slice not covered by the lock; see its doc. |
| `(*MemoryEnclave) Destroy()` | Zeroize and release; idempotent, nil-safe, deferrable. |
| `WipeAll() (int, error)` | **Orderly shutdown only, and only from the program that owns the process** — never from a library, since it destroys enclaves belonging to subsystems it knows nothing about. The **count** is how many are still held; read it as "these were still in use" rather than as a diagnosis, since a read outlasting the bounded bounded retry budget counts the same as a shutdown-ordering mistake. The **error** reports detected canary corruption (matching `ErrEnclaveCorrupted`) and nothing else; a corrupt enclave's pages *are* reclaimed, so it never appears in the count, which is why it needs its own return value. Never panics, and never waits indefinitely on a reader — an enclave being read is retried on later passes with a short backoff between them. Nothing calls it for you. |
| `NewAllocator(maxBytes)` / `(*Allocator) New(data)` / `(*Allocator) NewSized(n)` | Bounded allocation with `ErrBudgetExhausted`; admission is decided before anything is mapped, and reservations are released on `Destroy`. The budget is in **locked bytes**, the unit `RLIMIT_MEMLOCK` uses. |
| `LockedSize(n int) int64` | What an enclave of `n` bytes actually costs — `n` rounded up to a whole page. Size budgets with this: every enclave occupies at least one page, so a budget for a hundred small credentials is a hundred **pages**. Returns `int64` to match the budget, so `NewAllocator(100 * LockedSize(32))` needs no conversion. |
| `NewAllocatorWithinRLimit(maxBytes)` | `NewAllocator` plus a **startup check**: discovers `RLIMIT_MEMLOCK` and refuses a budget above it with `ErrBudgetExceedsRLimit`, naming both figures — a budget that was never satisfiable fails at construction rather than at the first allocation under load. It refuses nothing when the ceiling is unlimited, unenforceable (`CAP_IPC_LOCK`), or absent because the platform exposes none: there is no ceiling to be above. A ceiling that could not be **read** is a different case and is not silent — a failing `getrlimit` returns `ErrLimitDiscoveryFailed`, since nothing was compared. Never exits, logs or panics; every one of those is a return value and the decision is the application's. |
| `DiscoverLockedMemoryLimit()` | Read the ceiling yourself, to **derive** a budget from the host instead of guessing one. Reports the figure, whether it is a ceiling to rely on, and where it came from (`LimitSource`), so the derivation can be logged next to the number. An unbounded or absent ceiling is not an error — it comes back with `Bounded` false and a source saying which; only a failed read is an error, and it is `ErrLimitDiscoveryFailed`. |
| `Wipe(b []byte)` | Zero a transient plain slice. |
| `CoreDumpsDisabled()` | Whether lowering `RLIMIT_CORE` at import succeeded. Best effort by nature — a sandbox can deny it and anything in the process can raise it again — so it is reported rather than promised. Each enclave's pages are separately marked `MADV_DONTDUMP`, which **is** verified and fails the allocation if refused. |

Errors: `ErrEmptyEnclave`, `ErrInvalidSize`, `ErrEnclaveDestroyed`, `ErrLockedMemoryUnavailable`
(+ `LockedMemoryError`), `ErrBudgetExhausted` (+ `BudgetError`), `ErrInvalidBudget`,
`ErrBudgetExceedsRLimit` (+ `RLimitError`), `ErrLimitDiscoveryFailed` (+ `LimitDiscoveryError`).

### The obligation admission control does not remove

An `Allocator` bounds the enclaves **it** creates. It cannot bound locked memory
allocated elsewhere in the process. If any other allocator or a direct
`NewMemoryEnclave` exhausts `RLIMIT_MEMLOCK`, allocations through this allocator
start failing with `ErrLockedMemoryUnavailable` even though its own budget has
room: **admitted is not the same as allocated**, and callers must handle both
errors.

What you no longer have to tolerate, since v0.3.0-alpha, is an enclave you hold
reporting `ErrEnclaveDestroyed` because something *failed* elsewhere. Nothing in
this package destroys an enclave as a reaction to a fault.

Enclaves are destroyed by their owner's `Destroy` — or by an explicit `WipeAll`,
which is a deliberate call and never a fault handler. If your process calls
`WipeAll` at shutdown, every enclave in it is destroyed, including ones other
components still hold. That is the point of a shutdown sweep, and it is the one
way an enclave you hold can be destroyed by something other than you.

### What the startup check does not promise

`NewAllocatorWithinRLimit` is one-sided. A refusal is conclusive — that budget
could not have been satisfied. Acceptance is not a promise that any particular
allocation will succeed: `RLIMIT_MEMLOCK` is process-wide and shared with every
other user of locked memory, a cgroup v2 `memory.max` frequently binds well
below it in a container, and the limit can be changed afterwards. The ceiling is
read once, at construction, and never on the allocation path — a syscall there
would buy nothing, since the kernel's refusal already arrives as
`ErrLockedMemoryUnavailable` on the allocation that hit it.

The ceiling is read on Linux and on the BSDs. On a platform that exposes none —
Windows bounds a working-set size rather than a locked-memory rlimit — the
constructor accepts every positive budget and reports `LimitUnsupported`, which
says *this was not checked* rather than *this host has no limit*. Reporting that
where a ceiling **was** readable would be a fail-open guard, so it is reported
only where there is genuinely nothing to read.

The BSD path is not exercised by CI, which is Linux-only. What is exercised
everywhere is its classification: `classifyRlimit` is shared, and its tests run
both platforms' `RLIM_INFINITY` sentinels — the BSDs use the largest positive
`int64`, Linux all-bits-set, and reading one with the other's value silently
produces a ceiling of nine exabytes or of -1.

## Vocabulary

The type describes its mechanism — a region of locked memory — rather than what
a caller keeps in it. "Secret" is deliberately avoided: in most systems that
word is already taken by a config value, a secret reference, an account secret
or a key share, and a name that collides with three existing meanings makes
every call site ambiguous. Avoid introducing `Secret`, `SecureString`,
`SecureBytes` or `ProtectedBuffer` synonyms alongside it.

## FIPS

A `MemoryEnclave` performs no cryptography. It maps, locks and wipes memory; the
only cryptographic primitive anywhere near it is `crypto/rand` filling the
canary, a FIPS-approved DRBG. The package builds and its tests pass under
`GOFIPS140=latest GODEBUG=fips140=only` (`make test-fips`).

Dropping memguard removed a non-approved algorithm from the build graph of
everything that imports this package: go-enclave never called its
`Enclave`/`Seal` paths, but NaCl secretbox was in the dependency regardless.
That matters to anyone who has to certify what their binary contains.

## Development

```
make test        # race suite
make test-fips   # build + tests under FIPS 140-3 strict mode
make security    # gosec, govulncheck, modverify, trivy
make ci          # the full local gate
```

Requires Go 1.26.7. Some tests (`_linux` fault-injection) lower
`RLIMIT_MEMLOCK` in a subprocess and skip where they cannot.

## License

MIT. See [LICENSE](LICENSE).
