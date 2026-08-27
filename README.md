# go-enclave

Foundational locked-memory primitive for the Automate The Things trusted-computing
stack. `MemoryEnclave` is a region of locked, zeroized memory for holding
sensitive material — private keys, credentials, passphrases and tokens — for the
whole of its lifetime in the process.

It is the portfolio's single locked-memory primitive: **Layer 0**, importable by
every Layer 0–3 library. It maps its own memory — mlock'd pages, inaccessible
guard pages either side, a random canary, wiped on release, and kept out of core
dumps — reports every mapping failure as a typed error rather than aborting, and
adds admission control so an untrusted caller cannot exhaust the process's
locked-memory ceiling and starve everything else.

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
```

Use it wherever the alternative would be `make` + generate + `NewMemoryEnclave`:
that shape puts the key on swappable, core-dumpable memory first, and the wipe
that follows cannot reach copies the compiler or the collector already made.

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
| `NewMemoryEnclaveSized(n int)` | `n` bytes of locked, **zeroed** memory the caller fills in place through the borrow — generate-in-place, so the material never touches the heap. |
| `NewMemoryEnclaveFromString(s)` | Boundary helper for string-only APIs (the string cannot be wiped). |
| `(*MemoryEnclave) WithBytes(fn)` | **Preferred access.** Borrow the bytes for the duration of `fn` under the read lock. |
| `(*MemoryEnclave) OpenString / EqualTo / Size / IsAlive / String` | Locked, concurrency-safe accessors. |
| `(*MemoryEnclave) Open()` | **Unsafe.** Returns a slice not covered by the lock; see its doc. |
| `(*MemoryEnclave) Destroy()` | Zeroize and release; idempotent, nil-safe, deferrable. |
| `WipeAll() (int, error)` | **Orderly shutdown only, and only from the program that owns the process** — never from a library, since it destroys enclaves belonging to subsystems it knows nothing about. The **count** is how many are still held; read it as "these were still in use" rather than as a diagnosis, since a read outlasting the bounded bounded retry budget counts the same as a shutdown-ordering mistake. The **error** reports detected canary corruption (matching `ErrEnclaveCorrupted`) and nothing else; a corrupt enclave's pages *are* reclaimed, so it never appears in the count, which is why it needs its own return value. Never panics, and never waits indefinitely on a reader — an enclave being read is retried on later passes with a short backoff between them. Nothing calls it for you. |
| `NewAllocator(maxBytes)` / `(*Allocator) New(data)` / `(*Allocator) NewSized(n)` | Bounded allocation with `ErrBudgetExhausted`; admission is decided before anything is mapped, and reservations are released on `Destroy`. The budget is in **locked bytes**, the unit `RLIMIT_MEMLOCK` uses. |
| `LockedSize(n int) int64` | What an enclave of `n` bytes actually costs — `n` rounded up to a whole page. Size budgets with this: every enclave occupies at least one page, so a budget for a hundred small credentials is a hundred **pages**. Returns `int64` to match the budget, so `NewAllocator(100 * LockedSize(32))` needs no conversion. |
| `Wipe(b []byte)` | Zero a transient plain slice. |
| `CoreDumpsDisabled()` | Whether lowering `RLIMIT_CORE` at import succeeded. Best effort by nature — a sandbox can deny it and anything in the process can raise it again — so it is reported rather than promised. Each enclave's pages are separately marked `MADV_DONTDUMP`, which **is** verified and fails the allocation if refused. |

Errors: `ErrEmptyEnclave`, `ErrInvalidSize`, `ErrEnclaveDestroyed`, `ErrLockedMemoryUnavailable`
(+ `LockedMemoryError`), `ErrBudgetExhausted` (+ `BudgetError`), `ErrInvalidBudget`.

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

## Vocabulary

The type describes its mechanism — a region of locked memory. It is **never**
called a "secret" (already a config value / secret reference / ACME account
secret / Shamir share in this codebase). Do not introduce `Secret`,
`SecureString`, `SecureBytes` or `ProtectedBuffer` synonyms.

## FIPS

A `MemoryEnclave` performs no cryptography. It maps, locks and wipes memory; the
only cryptographic primitive anywhere near it is `crypto/rand` filling the
canary, a FIPS-approved DRBG. The package builds and its tests pass under
`GOFIPS140=latest GODEBUG=fips140=only` (`make test-fips`).

Dropping memguard removed a non-approved algorithm from every consumer's build
graph: go-enclave never called its `Enclave`/`Seal` paths, but NaCl secretbox
was in the dependency regardless.

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
