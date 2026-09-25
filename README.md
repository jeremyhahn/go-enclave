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

## Two enclave types — which one?

`SealedEnclave` (the sealing surface) holds material **encrypted at rest**
inside the process: plaintext exists only for the duration of an `Open`,
inside the `MemoryEnclave` that `Open` returns.

```go
s, err := enclave.NewSealed(credential) // credential is wiped
if err != nil {
    return err
}
// ... later, per use:
e, err := s.Open() // plaintext decrypted straight into locked pages
if err != nil {
    return err
}
defer e.Destroy() // open late, destroy early; s keeps only ciphertext
```

The two types make **different promises**, and the difference is the
plaintext's residency window. A `MemoryEnclave`'s protections (mlock, guard
pages, canary, core-dump exclusion, wipe on destroy) keep the material off
*disk*; the plaintext is resident, and readable by anything that can read this
process's live memory, for the object's **whole life**. A `SealedEnclave` is
unreadable to a memory reader **between opens** — the window narrows from the
process lifetime to the operations.

Choose by **access pattern**:

- **`MemoryEnclave`** for material in hot or continuous use, or that must be
  handed to an API needing a stable buffer for its lifetime. Sealing it would
  buy nothing — it would always be open. Cost: at least one locked page,
  charged against `RLIMIT_MEMLOCK` (and any `Allocator` budget) continuously.
- **`SealedEnclave`** for material used intermittently — a credential opened
  per request, a key touched a few times an hour. The classic secure-buffer
  versus secret split: buffer-shaped usage converts to `MemoryEnclave`,
  secret-shaped usage to `SealedEnclave`. Cost: the envelope is near-free
  heap ciphertext, but **every `Open` allocates a fresh locked page**, and
  `Open` charges it to no `Allocator` budget — it takes no `Allocator`.
  `OpenWith` is the admitted variant (#17): it takes the destination
  `Allocator` and charges the page against that budget, refusing a nil one
  rather than falling back. Either way a service opening per connection
  should size `RLIMIT_MEMLOCK` for it.

Honestly stated, because it decides whether sealing is worth it to you: the
sealed **material** never reaches the heap (its plaintext is decrypted only
into locked pages — verified by sweeping the process's anonymous mappings),
but the per-value **key** transits the Go heap on every seal and open, because
building the AEAD expands it into `aes.NewCipher`'s key schedule; that copy
persists until its heap span is reused. Sealing **narrows a window; it does
not close one**: it is no protection against an attacker reading memory while
an `Open` is in flight, or one who can drive `Open`s through your own surface
— and with the pure-software default the sealing keys themselves live in this
process, so a live-memory adversary gets everything anyway. Rooting the seal
in hardware is what the provider seam is for: go-enclave defines
`KeyProtector`/`RootUnsealer` and ships only the software default; TPM, HSM
or KMS providers are injected from above (`NewSealer`, `SetSealer`), with two
modes trading device traffic against what a memory reader obtains — see
`Mode` for the honest comparison.

One trap: `IsAlive` is a **different predicate** on the two types.
`MemoryEnclave.IsAlive` means "usable" — false once the material is gone,
however it went. `SealedEnclave.IsAlive` reports that the *ciphertext* is
held, and can be true for a value that can no longer be opened (after a
shutdown `WipeAll` destroyed the sealing keys, `Open` says so with
`ErrSealerWiped`). `Openable` is the explicit probe (#33): `nil` when nothing
this package can see prevents an open, `ErrSealerWiped` after a sweep,
`ErrEnclaveDestroyed` when the value is gone, and `ErrOpenabilityUnknown` when
a sweep has run and the provider reports no health, so the answer is not
knowable without opening.

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
   authenticate. The budget is not fixed at construction: it can be raised,
   lowered or moved between allocators while allocation is in flight, because a
   budget change and an admission are the same compare-and-swap on the same
   counter and cannot both take the last page.

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
| `(*Allocator) SetLimit(n)` / `ForceLimit(n)` / `TransferTo(dst, n)` | **Runtime retune.** `SetLimit` raises or lowers the budget and REFUSES (`ErrBudgetInUse`) rather than shrink below the memory already reserved, changing nothing on refusal. `ForceLimit` records a ceiling that moved anyway — a resized container, a lowered `RLIMIT_MEMLOCK` — keeping live enclaves alive, returning the over-subscription in bytes and admitting nothing until it drains. `TransferTo` moves headroom between two allocators in one operation, so a slack one can fund a pressured one; it takes the two locks in a fixed order and passes through "in neither", never "in both". All three are safe against concurrent allocation: a retune and an in-flight admission are decided by the same compare-and-swap on the same word, so they cannot both take the last page. |
| `LockedSize(n int) int64` | What an enclave of `n` bytes actually costs — `n` rounded up to a whole page. Size budgets with this: every enclave occupies at least one page, so a budget for a hundred small credentials is a hundred **pages**. Returns `int64` to match the budget, so `NewAllocator(100 * LockedSize(32))` needs no conversion. |
| `NewAllocatorWithinRLimit(maxBytes)` | `NewAllocator` plus a **sticky ceiling check**: discovers `RLIMIT_MEMLOCK` and refuses a budget above it with `ErrBudgetExceedsRLimit`, naming both figures — a budget that was never satisfiable fails at construction rather than at the first allocation under load. It refuses nothing when the ceiling is unlimited, unenforceable (`CAP_IPC_LOCK`), or absent because the platform exposes none: there is no ceiling to be above. A ceiling that could not be **read** is a different case and is not silent — a failing `getrlimit` returns `ErrLimitDiscoveryFailed`, since nothing was compared. Never exits, logs or panics; every one of those is a return value and the decision is the application's. The check **outlives construction**: `SetLimit` re-reads the ceiling (fresh — it moves) and refuses to raise this allocator's budget above it, and `TransferTo` applies the same to the allocator it credits, since a transfer is a raise on the receiving side. Raises only, so an over-ceiling allocator can always move back towards compliance; `ForceLimit` overrides it, as it overrides every other refusal here. A plain `NewAllocator` allocator is never checked, on any path. Nothing was added to the admission path. |
| `SetAllocator(a)` / `ProcessAllocator()` | **One budget per process.** `RLIMIT_MEMLOCK` is process-wide, so admission bounds anything only when every library admits against the same allocator. The **binary** sizes it once at startup and installs it with `SetAllocator`; that is one-shot and fails closed with `ErrAllocatorInstalled`, the same contract as `SetSealer`. A **library** never builds or installs one. It calls `ProcessAllocator()` and allocates through the result. With nothing installed, the first call installs a default whose budget is the discovered ceiling (sticky, like `NewAllocatorWithinRLimit`), a zero budget for a zero ceiling, or unbounded where no ceiling binds. It leaves no headroom, because sizing is the binary's call. A ceiling that could not be read returns `ErrLimitDiscoveryFailed` and installs nothing. |
| `DiscoverLockedMemoryLimit()` | Read the ceiling yourself, to **derive** a budget from the host instead of guessing one. Reports the figure, whether it is a ceiling to rely on, and where it came from (`LimitSource`), so the derivation can be logged next to the number. An unbounded or absent ceiling is not an error — it comes back with `Bounded` false and a source saying which; only a failed read is an error, and it is `ErrLimitDiscoveryFailed`. |
| `NewSealed(data []byte)` | Seal `data` under the process sealer (software default installed lazily); wipes `data`. Returns a `*SealedEnclave` — heap ciphertext, no locked pages held at rest. |
| `(*SealedEnclave) Open()` | Decrypt into a **new** locked `MemoryEnclave` the caller owns and must `Destroy`. Fails with `ErrSealedAuthentication` for anything tampered, truncated, re-paired or foreign, and `ErrSealerWiped` after a shutdown sweep. |
| `(*SealedEnclave) IsAlive / Destroy / String` | Ciphertext-presence probe (see the trap above), idempotent destroy that wipes both envelope halves, masked printing. |
| `NewSealer(WithProvider(p), WithMode(m))` | An explicitly configured sealer. Refuses a provider that does not implement the selected mode's interface (`ErrProviderMode`, including nil and typed-nil providers) and unknown modes (`ErrInvalidMode`) **at construction**. |
| `SetSealer(s)` | Install the process sealer `NewSealed` uses — **one-shot**, before anything seals; fails closed with `ErrSealerInstalled` afterwards. |
| `KeyProtector` / `RootUnsealer` | The provider seam: per-operation key protection and one-shot root unseal. Implementations must supply confidentiality **and** authenticity; both recover into caller-supplied (locked) memory. |
| `providertest.TestProvider(cfg)` | **Conformance suite for the provider seam** — `providertest` is a subpackage go-enclave ships and any implementer runs against its own provider, in the shape of `fstest.TestFS`. It enforces the half the signatures cannot: that a provider RETAINS nothing. See [Implementing a provider](#implementing-a-provider). |
| `NewSoftwareProvider()` | The pure-software provider (both interfaces); the process default. Its root lives in this process — read its docs for what that trades away. |
| `Wipe(b []byte)` | Zero a transient plain slice. |
| `CoreDumpsDisabled()` | Whether lowering `RLIMIT_CORE` at import succeeded. Best effort by nature — a sandbox can deny it and anything in the process can raise it again — so it is reported rather than promised. Each enclave's pages are separately marked `MADV_DONTDUMP`, which **is** verified and fails the allocation if refused. |

Errors: `ErrEmptyEnclave`, `ErrInvalidSize`, `ErrEnclaveDestroyed`, `ErrLockedMemoryUnavailable`
(+ `LockedMemoryError`), `ErrBudgetExhausted` (+ `BudgetError`), `ErrInvalidBudget`, `ErrNilAllocator`, `ErrAllocatorInstalled`,
`ErrBudgetExceedsRLimit` (+ `RLimitError`), `ErrLimitDiscoveryFailed` (+ `LimitDiscoveryError`);
sealing: `ErrSealFailed`, `ErrSealedAuthentication`, `ErrSealerWiped`, `ErrProviderMode`,
`ErrInvalidMode`, `ErrSealerInstalled`, `ErrNilSealer`, `ErrProviderMessageLimit`,
`ErrMaterialTooLarge`, `ErrPlaintextEscaped`.

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

### One budget per process: the binary sizes it, libraries draw from it

A library that builds its own `Allocator` has bounded only itself. Two libraries
doing that in one binary can each stay inside budget while together locking past
the single `RLIMIT_MEMLOCK` ceiling. The split is the same as for `WipeAll`:

```go
// main — the only code that owns the process
budget, err := enclave.NewAllocatorWithinRLimit(64 << 20)
if err != nil {
	log.Fatal(err)
}
if err := enclave.SetAllocator(budget); err != nil { // before anything allocates
	log.Fatal(err)
}
defer enclave.WipeAll()

// any library
a, err := enclave.ProcessAllocator()
if err != nil {
	return err
}
key, err := a.NewSized(32) // ErrBudgetExhausted: refuse this request, not the process
```

A library must not call `SetAllocator` or `WipeAll`: each one makes a
process-wide decision on behalf of components the library knows nothing about.

### What the ceiling check does not promise

`NewAllocatorWithinRLimit` is one-sided. A refusal is conclusive — that budget
could not have been satisfied. Acceptance is not a promise that any particular
allocation will succeed: `RLIMIT_MEMLOCK` is process-wide and shared with every
other user of locked memory, a cgroup v2 `memory.max` frequently binds well
below it in a container, and the limit can be changed afterwards. The ceiling is
re-read on every budget RAISE — freshly, because it moves — and never on the
allocation path; a syscall there would buy nothing, since the kernel's refusal
already arrives as `ErrLockedMemoryUnavailable` on the allocation that hit it.
Between one raise and the next, nothing is watching the ceiling: this is a check
on the settings a process chooses, not a monitor of the host.

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

## Implementing a provider

A `KeyProtector` or `RootUnsealer` lives above this package — a TPM, an HSM, a
cloud KMS — and is injected through `NewSealer(WithProvider(p), WithMode(m))`.
Nothing hardware-specific ever lands here.

**Run the conformance suite.** `providertest` is shipped for exactly this and
takes no dependency in either direction:

```go
func TestConformance(t *testing.T) {
    err := providertest.TestProvider(providertest.Config{
        New:   func() (any, error) { return NewTPMProvider(dev) },
        Modes: []enclave.Mode{enclave.ModePerOperation},
        Logf:  t.Logf,
    })
    if err != nil {
        t.Fatal(err)
    }
}
```

### The property it enforces is retention, not destination

`Unprotect(blob, key []byte)` and `UnsealRoot(dst []byte)` constrain where the
plaintext is **written**. They constrain nothing about what a provider **keeps**.
A provider may write into the caller's locked slice and hold its own copy
indefinitely, and from this package's side a conforming signature and a
retaining implementation are indistinguishable. That is the unenforced half of
`KeyProtector`'s "protects short key material outside this process".

The suite does **not** demand that a provider never materializes plaintext.
Every real backend returns a fresh `[]byte` from its decrypt — the native TPM2
path is `RSADecrypt(...) ([]byte, error)`, PKCS#11 wrappers return a slice, and
the cloud KMS backends return HTTP response bodies. No hardware decrypts
directly into an arbitrary caller page, so a conforming provider materializes the
plaintext in its own memory and copies into the destination. What it must then
do is **wipe that transient**, which is what the interface requires in words and
what the suite measures.

### Name only the modes you serve

`Config.Modes` is a claim the suite checks in both directions: each named mode
must be accepted by `NewSealer`, and each **unnamed** one must be refused with
`ErrProviderMode`. The second direction is what finds a stub. A provider built
for `ModePerOperation` that also carries an `UnsealRoot` — added by someone who
thought the seam required both halves, returning a constant — is accepted in
`ModeRootKey` by a `Sealer` with no way to tell a placeholder from an unseal,
and every value in the process is then sealed under a root the provider never
produced.

### What it can and cannot see

The **spy** is the primary instrument and is deterministic: the suite is the
caller, so it owns every slice the provider is handed, and it watches each one
afterwards. It catches retention **by reference** — a `Protect` that filed the
caller's slice instead of copying out of it, an `Unprotect` that writes into a
destination the caller has already wiped and released. Every assertion carries a
control that fails first if the setup did not hold, so a destination that was
never populated cannot read as one that was respected.

The **residue sweep** is corroboration and Linux-only. It is the only instrument
that can see a retained **copy**, so it is not optional, but it has two measured
limits: a sweep that does not wipe its scan buffer replants its own needle, and
a sweep-based residue claim is unfalsifiable for anything transiting a stack
local, because a stack growth strands the pre-wipe bytes on the freed old stack.
It refuses to report a negative it has not first proven it could turn positive.

`Config.SkipResidueSweep` takes a **reason**, not a boolean, and the reason is
echoed into the log. The legitimate one is a transit the provider cannot reach:
a cloud KMS receives its plaintext in an HTTP response body owned by
`net/http`, and no wipe reclaims the `bufio` buffer behind it. Skipping is then
honest; claiming the property is not.

`Config.SingleUseRoot` is the same shape for the other direction. The seam
guarantees only that a `Sealer` calls `UnsealRoot` **at most once**, so a
provider that consumes a session, an authorization or a one-shot handle on a
successful unseal honors the contract while failing a suite that calls it
twice. The default stays the strong one — the full-width-write proof and the
destination spy both need a second call — and a genuinely one-shot provider
names its reason, which is logged along with exactly which proofs were not
taken.

There is no residue sweep for `RootUnsealer`, and the asymmetry is deliberate: a
root unsealer legitimately **retains** the root — that is the whole of what it
does, and `SoftwareProvider` holds it in a locked enclave in this process.

## Vocabulary

The type describes its mechanism — a region of locked memory — rather than what
a caller keeps in it. "Secret" is deliberately avoided: in most systems that
word is already taken by a config value, a secret reference, an account secret
or a key share, and a name that collides with three existing meanings makes
every call site ambiguous. Avoid introducing `Secret`, `SecureString`,
`SecureBytes` or `ProtectedBuffer` synonyms alongside it.

## FIPS

The locked-memory core performs no cryptography — `MemoryEnclave`, `Allocator`
and `WipeAll` touch nothing beyond `crypto/rand` filling the canary. The
sealing surface performs only FIPS-approved cryptography through the standard
library — AES-256-GCM via `cipher.NewGCMWithRandomNonce`, and nothing else.
The whole package builds and its tests pass under `GOFIPS140=latest
GODEBUG=fips140=only` (`make test-fips`).

`GOEXPERIMENT=boringcrypto` builds cannot seal, deliberately: the only route
would be `cipher.NewGCM` with caller-supplied nonces, abandoning the
construction that makes nonce misuse structurally impossible, to serve a
mechanism superseded by Go's native FIPS 140-3 module. The refusal and its
reasoning are in the package docs.

Dropping memguard removed a non-approved algorithm from the build graph of
everything that imports this package: go-enclave never called its
`Enclave`/`Seal` paths, but NaCl secretbox was in the dependency regardless.
That matters to anyone who has to certify what their binary contains.

## Development

```
make test        # race suite, across -cpu=1,2,8
make test-fips   # build + tests under FIPS 140-3 strict mode
make security    # gosec, govulncheck, modverify, trivy
make check-releasability  # no tracked file names the lab fleet
make ci          # the full local gate
```

Every tracked file is published, so the tree must not name private hosts,
addresses or paths. `make check-releasability` enforces it; the rules and the
waiver syntax are in `test/buildgates/releasability_test.go`.

Changes are recorded as fragments in `changelog.d/<issue>-<slug>.md`, not as
edits to `CHANGELOG.md`; `make release-alpha` folds them into the version's
section before tagging (`scripts/changelog-assemble.sh`).

Requires Go 1.27.0. Some tests (`_linux` fault-injection) lower
`RLIMIT_MEMLOCK` in a subprocess and skip where they cannot.

## License

MIT. See [LICENSE](LICENSE).
