# go-enclave

Foundational locked-memory primitive for the Automate The Things trusted-computing
stack. `MemoryEnclave` is a region of locked, zeroized memory for holding
sensitive material — private keys, credentials, passphrases and tokens — for the
whole of its lifetime in the process.

It is the portfolio's single locked-memory primitive: **Layer 0**, importable by
every Layer 0–3 library. It wraps a [memguard](https://github.com/awnumar/memguard)
`LockedBuffer` (mlock'd pages, guard pages, canary, wipe on release, core dumps
disabled process-wide), but converts memguard's process-abort failure mode into
a typed error, and adds admission control so an untrusted caller cannot drive the
process to the ceiling that triggers that failure.

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

memguard's `NewBuffer` calls `Purge()` — which destroys **every** live protected
buffer in the process — and then panics when it cannot mlock pages (typically an
`RLIMIT_MEMLOCK` ceiling). A foundational library must not abort its host over a
resource limit it does not control, and it must not let one path's exhaustion
silently unmap another path's live key material.

go-enclave addresses both halves:

1. **Error, not abort.** `NewMemoryEnclave` recovers memguard's panic and returns
   a typed `LockedMemoryError` (matched via `ErrLockedMemoryUnavailable`). The
   caller's source slice is wiped on every return path, including the failure
   path memguard never reaches.
2. **Borrows survive foreign purges.** A process-wide `purgeMu` serializes
   allocation against every borrow, so a goroutine inside `WithBytes` keeps a
   valid view even if an unrelated allocation elsewhere exhausts locked memory
   and purges the process.
3. **Admission control.** `Allocator` is a lock-free bounded allocator with a
   typed `ErrBudgetExhausted`. Sizing its budget below `RLIMIT_MEMLOCK` and
   admitting untrusted allocations through it turns a remote memlock-drain
   (measured: a Noise responder allocating key buffers before authentication)
   into a local, typed refusal — the ceiling, and therefore the purge, is never
   reached.

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
| `NewAllocator(maxBytes)` / `(*Allocator) New(data)` / `(*Allocator) NewSized(n)` | Bounded allocation with `ErrBudgetExhausted`; admission is decided before memguard is entered, and reservations are released on `Destroy`. |
| `Wipe(b []byte)` | Zero a transient plain slice. |

Errors: `ErrEmptyEnclave`, `ErrInvalidSize`, `ErrEnclaveDestroyed`, `ErrLockedMemoryUnavailable`
(+ `LockedMemoryError`), `ErrBudgetExhausted` (+ `BudgetError`), `ErrInvalidBudget`.

### The obligation admission control does not remove

An `Allocator` bounds the enclaves **it** creates. It cannot bound locked memory
allocated elsewhere in the process. If any other allocator or a direct
`NewMemoryEnclave` exhausts locked memory, memguard's purge still unmaps every
live buffer, including this allocator's. An in-flight `WithBytes` borrow is held
safe across such a purge, but an enclave you hold **can start returning
`ErrEnclaveDestroyed` even though you never called `Destroy`**. Code that keeps
enclaves across untrusted allocation activity must treat that as a survivable
runtime condition — re-establish the material or fail the one operation — never
as an invariant it can assume away.

## Vocabulary

The type describes its mechanism — a region of locked memory. It is **never**
called a "secret" (already a config value / secret reference / ACME account
secret / Shamir share in this codebase). Do not introduce `Secret`,
`SecureString`, `SecureBytes` or `ProtectedBuffer` synonyms.

## FIPS

A `MemoryEnclave` performs no cryptography. It uses only the memguard
`LockedBuffer` path — never `Enclave`/`Seal`, whose NaCl secretbox sealing is not
FIPS 140-approved. The package builds and its tests pass under
`GOFIPS140=latest GODEBUG=fips140=only` (`make test-fips`).

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

Dual-licensed under AGPL-3.0 or a commercial license. See [LICENSE](LICENSE);
contact licensing@automatethethings.com for commercial terms.
