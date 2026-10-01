# Sealing and the provider seam — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `NewSealed(ctx context.Context, data []byte) (*SealedEnclave, error)` | Seals under the process sealer (lazily the software default). Wipes `data` on every path. |
| `NewSealer(opts ...SealerOption) (*Sealer, error)` | No options: `SoftwareProvider`, `ModeRootKey`, cannot fail. Touches no provider and no locked memory until the first seal. |
| `WithProvider(p any) SealerOption` | `p` must implement the mode's interface; nil or typed-nil is refused. |
| `WithMode(m Mode) SealerOption` | `ModeRootKey` (zero value) or `ModePerOperation`. |
| `WithProviderHealth(fn func() error) SealerOption` | Non-blocking report of the provider's **in-process** sealing state: `nil` or `ErrSealerWiped`. Believed and terminal. Ignored in `ModeRootKey`. |
| `SetSealer(s *Sealer) error` | Installs the process sealer. One-shot. |
| `(*Sealer).Seal(ctx, data) (*SealedEnclave, error)` / `Mode() Mode` | `NewSealed` for an explicit sealer. |
| `(*SealedEnclave).Open(ctx) (*MemoryEnclave, error)` | Decrypts into a **new** enclave the caller owns and must `Destroy`. Unbudgeted. |
| `(*SealedEnclave).OpenWith(ctx, a *Allocator) (*MemoryEnclave, error)` | As `Open`, destination admitted against `a`. |
| `(*SealedEnclave).Openable() error` | Diagnostic snapshot; takes no context and calls no provider. |
| `(*SealedEnclave).IsAlive() bool` | Ciphertext still held — **not** "can be opened". |
| `(*SealedEnclave).Destroy()` / `String()` | Idempotent, nil-safe; does not wait for in-flight opens. |
| `KeyProtector` | `Protect(ctx, key []byte) (blob []byte, err error)`; `Unprotect(ctx, blob, key []byte) error` |
| `RootUnsealer` | `UnsealRoot(ctx, dst []byte) error` |
| `RootKeyBytes = 32` | Length of every root and of every key handed to a provider. |
| `SoftwareProvider`, `NewSoftwareProvider()` | Implements both interfaces; root generated into a locked enclave at first use. |

## Provider contract

1. **Authenticated.** `Unprotect` refuses any blob its own `Protect` did not
   produce (tampered, truncated, forged, other provider) with an error matching
   `ErrSealedAuthentication`. A length mismatch is an authentication failure.
   Confidentiality alone (bare RSA-OAEP) does not qualify.
2. **Recover into the caller's buffer.** `Unprotect` writes into `key` (exactly
   the length `Protect` received); `UnsealRoot` writes into `dst` (exactly
   `RootKeyBytes`). Both alias locked pages.
3. **Retain nothing.** `Protect` must not keep `key`; a provider whose API
   returns a fresh slice must copy into the destination and wipe the transient.
   (`RootUnsealer` legitimately retains the root.)
4. **Blob is opaque** to go-enclave and non-empty; key IDs and versions live
   inside it.
5. **Honor the context.** An already-ended context is refused before device work
   with an error matching `ctx.Err()`; a context ending mid-call returns
   promptly; a refused call writes no key material and, for `UnsealRoot`,
   consumes nothing a later call needs.
6. **Infrastructure failures are the provider's own errors**, not
   `ErrSealedAuthentication`.

## Invariants

1. **Recovered plaintext only in locked pages.** `Seal` reads the caller's
   slice and wipes it on every return path; this package makes no other copy of
   the plaintext. `Open` allocates the destination first,
   with capacity exactly the plaintext length, and decrypts in place; a length
   mismatch is refused **before** decrypting. `ErrPlaintextEscaped` guards the
   (unreachable) case of the AEAD reallocating.
2. **No `Sealer` or `SealedEnclave` mutex across a provider call.** Two
   things do span one, by design: the init slot (a one-slot semaphore acquired
   in a `select` against `ctx.Done()`) spans `UnsealRoot`, and the read lock of
   the private, per-call enclave the provider reads from or writes into (the
   DEK, or the root destination) spans every provider call.
3. **At most one successful `UnsealRoot` per `Sealer`.** Success is the
   provider's result, not the caller's context: a call that returns an error
   (including one reporting the ended context) retains nothing, and a later
   seal calls `UnsealRoot` again; a call that returns `nil` succeeded even if the
   caller's context ended meanwhile — its root is retained and published, and
   only the abandoned caller is told of its context. A successful unseal
   followed by a failed KEK mint keeps the root and retries only the mint.
4. **A sweep overlapping a successful unseal leaves the sealer wiped.** The
   sweep generation is read before the unseal and, once a root has been
   obtained and retained, compared before the mint, after a failed mint, and at
   publication; on overlap the root (and KEK) are destroyed, the sealer reports
   `ErrSealerWiped`, and the provider is never asked again. An unseal that
   *fails* returns before that check and retains nothing, so a later seal may
   call `UnsealRoot` again even if a sweep overlapped the failed attempt.
5. **Fail closed after a sweep.** Once `WipeAll` destroys the root or current
   KEK (`ModeRootKey`), every seal and open that reaches the hierarchy reports
   `ErrSealerWiped` (an open can still fail earlier, for example on its budget
   or a refused locked page); the sealer never mints a replacement. That holds
   for a sweep that overlaps KEK **rotation** too: rotation reads the sweep
   sequence before it inspects anything, and if a sweep ran at any point
   during it — including one that skipped the root because the rotation was
   borrowing it — the new generation is discarded, the old KEK and the root
   are destroyed, and the call reports `ErrSealerWiped`. A release the kernel
   refuses in that cleanup — or while discarding a KEK whose mint failed — is
   reported with the error, never suppressed. Key bytes are wiped before any
   unmap is attempted, so a refusal leaves locked pages, not key material: the
   sealer retries its published root and KEK on every seal or open that finds
   the hierarchy dead, and an unpublished generation is owned by the `WipeAll`
   ledger, which retries every refused release. Recovery
   is constructing a new `Sealer` (and re-sealing from source).
6. **KEK rotation.** A KEK generation wraps at most 2^31 DEKs, then a new
   generation is minted under the root (no provider call). The retired KEK's
   enclave is destroyed; its root-wrapped blob is kept so older values still
   open (one transient locked page per retired-generation open).
7. **`SoftwareProvider` message bound.** In `ModePerOperation` its single root
   protects at most 2^31 keys, then `Protect` returns `ErrProviderMessageLimit`.
8. **Context checks.** Every provider-reaching call checks `ctx` on entry,
   again after winning the init slot (before `UnsealRoot`), and after each
   provider call returns. An already-ended context on `NewSealed` is refused
   before the process sealer is looked up, so it never installs the default.
   In `ModeRootKey`, `Open` makes no provider call and checks `ctx` on entry only.
9. **Process sealer is one-shot.** `SetSealer` fails with `ErrSealerInstalled`
   after any install, including the lazy default from the first `NewSealed`.
10. **`SealedEnclave.Destroy` does not wait for opens in flight.** They complete
    against the envelope they pinned; the last one out wipes the ciphertext;
    opens starting afterwards return `ErrEnclaveDestroyed`.
11. **`OpenWith` admits one reservation, first.** An open refused **before** the
    destination is allocated — destroyed value, nil allocator, context already
    ended, budget refused — allocates nothing. Once the destination is
    allocated, the DEK page (and, for a retired generation, a KEK page) follow
    unadmitted, and a later failure (provider, authentication, context) has
    already allocated them; they are destroyed before `Open` returns. Peak use
    can therefore exceed the budget by one page (two across a retired-generation
    unwrap) per open **in flight**. That bound assumes those destroys succeed: a
    transient whose release the kernel refuses stays mapped, on the `WipeAll`
    ledger, until a later retry reclaims it.

## Error semantics

| Error | From | Meaning |
|---|---|---|
| `ErrSealFailed` | seal paths | AEAD, CSPRNG or provider failure (cause joined), or the context ended (joined with `ctx.Err()`). |
| `ErrOpenFailed` | `Open`, `OpenWith` | The context ended, or a `ModePerOperation` provider failed with its own error (joined, reachable). It says nothing about the value, which is intact, and nothing about whether the provider's failure is transient. It can be **joined** with a verdict the provider returned as the context ended — `ErrSealedAuthentication`, `ErrSealerWiped`, `ErrEnclaveDestroyed` — so test those first, then inspect the provider's cause before retrying (see [Classifying an open failure](#classifying-an-open-failure)). |
| `ErrSealedAuthentication` | open paths, providers | Tampered, truncated, forged, re-paired or foreign. Deliberately indistinguishable between causes. |
| `ErrSealerWiped` | all sealing paths, `Openable` | **This sealer could not serve this operation because an enclave it was using is gone** — not, on its own, proof that the sealer is dead. See [Where `ErrSealerWiped` comes from](#where-errsealerwiped-comes-from). |
| `ErrOpenabilityUnknown` | `Openable` | A sweep ran since sealing (or during it), `ModePerOperation`, and the provider reports no health. Open the value to find out. |
| `ErrEnclaveDestroyed` | `Open`, `OpenWith`, `Openable`; seal paths | From `Openable`, and from `Open`/`OpenWith` before any work: the `SealedEnclave` was destroyed (or is nil). From later in a seal or open: an enclave **this call** allocated was destroyed by a concurrent `WipeAll`, and the sealed value may be intact — the DEK while sealing the material under it (either mode), the open's destination or DEK while decrypting into it (either mode), or the DEK while a `ModePerOperation` provider uses it. A provider returning it is passed through too. In `ModeRootKey`, a destroyed DEK *during the wrap or unwrap under the KEK* is reported as `ErrSealerWiped` instead (see below). |
| `ErrLockedMemoryUnavailable` | seal, open | Kernel refused a locked page; the sealed value survives an open failure. |
| `ErrNilAllocator` / `ErrBudgetExhausted` | `OpenWith` | Nil allocator (never falls back) / over budget. Decided before any provider call. |
| `ErrEmptyEnclave`, `ErrMaterialTooLarge` | seal | Empty input; input above AES-GCM's single-message limit, (2^32−2)·16 bytes. |
| `ErrProviderMode`, `ErrInvalidMode` | `NewSealer` | Provider lacks the mode's interface (incl. nil/typed nil); unknown mode. |
| `ErrSealerInstalled`, `ErrNilSealer` | `SetSealer`, nil `(*Sealer).Seal` | One-shot install; nil sealer. |
| `ErrProviderMessageLimit` | `SoftwareProvider.Protect` | Per-key message bound reached. |
| `ErrPlaintextEscaped` | open | Defensive; unreachable while destination capacity is exact. |

### Context error shapes

Built by `contextFailure` in [sealer.go](../../sealer.go): `errors.Join(op,
…)`, where `op` is `ErrSealFailed` or `ErrOpenFailed`.

| Situation | Matches (`errors.Is`) |
|---|---|
| Context ended before or between provider calls | `op`, `ctx.Err()` |
| Provider returned an error wrapping `ctx.Err()` | `op`, the provider's error (and so `ctx.Err()`) |
| Provider returned some other error as the context ended | `op`, `ctx.Err()`, the provider's error — so a forgery verdict stays visible alongside the cancellation |
| `context.Cause` distinct from `ctx.Err()` | additionally the cause |
| Queued for the init slot when the context ended | `ErrSealFailed`, `ctx.Err()` |
| Successful unseal, then failed mint, context ended | `ErrSealFailed`, `ctx.Err()`, the mint failure; the root is kept |

While the context is live, a provider error passes through unjoined when it
matches one of these sentinels, and is joined under `op` otherwise
(`providerSealFailure` / `providerOpenFailure` in [sealer.go](../../sealer.go)):

- open: `ErrSealedAuthentication`, `ErrSealerWiped`, `ErrOpenFailed`,
  `ErrLockedMemoryUnavailable`, `ErrEnclaveDestroyed`;
- seal: `ErrSealerWiped`, `ErrSealFailed`, `ErrLockedMemoryUnavailable`,
  `ErrProviderMessageLimit`, `ErrEnclaveDestroyed`.

### Where `ErrSealerWiped` comes from

Four paths produce it. Paths 1 and 3 are permanent for that sealer; path 2 is
not; path 4 is whatever the provider means by it:

1. **The hierarchy is dead** (`ModeRootKey`): the root or the current KEK was
   destroyed by a sweep, or a sweep overlapped initialization and the retained
   root was discarded. Every later seal and open that reaches the hierarchy
   fails the same way.
2. **A per-call key was destroyed mid-operation** (`ModeRootKey`).
   `hierarchyFailure` ([sealer.go](../../sealer.go)) converts *any*
   `ErrEnclaveDestroyed` from a key operation into `ErrSealerWiped`, including
   the call's own DEK (wrap on seal, unwrap on open), a transient retired-KEK
   enclave, or a KEK being minted. That happens only when a concurrent `WipeAll`
   destroyed that per-call enclave; the hierarchy may still be alive.
3. **`SoftwareProvider`'s root is dead** (a sweep destroyed it). Permanent for
   the PROVIDER: it refuses every later `Protect`, `Unprotect` and
   `UnsealRoot` rather than minting a new root. That makes it permanent for a
   `ModePerOperation` sealer using the provider, and for a `ModeRootKey`
   sealer that still needs a successful unseal. It does NOT reach a
   `ModeRootKey` sealer that is already initialized: `UnsealRoot` copied the
   root into the sealer's OWN locked root, and that sealer consults only its
   own root and KEK — if the sweep skipped those (they were borrowed) and no
   initialization or rotation overlap invalidated them, it keeps working.
4. **A provider or a `WithProviderHealth` callback returned it.** Its
   permanence is the provider's own statement; a hardware provider may use it
   for a key that is gone for good, or for a device that is merely unreachable.
   Inspect the provider's cause before acting on it.

So never infer permanence from `ErrSealerWiped` alone. Read it as "this sealer
could not serve this operation", and check the sealer's health — `Openable()` on
a value it sealed reports `ErrSealerWiped` only for path 1 or 3 (or a health
callback's report). Separating case 2 from hierarchy loss in the code is
tracked as a planned change; until then the conflation stands as described.

### Classifying an open failure

Several sentinels can match one error, so test in this order and act on the
first match:

1. `ErrSealedAuthentication` — a forgery verdict; never retry, investigate.
2. `ErrSealerWiped` — this sealer could not serve the operation. Check
   `Openable()` before concluding anything: `ErrSealerWiped` there means the
   sealer's own keys are gone (or its health callback says so); `nil` or
   `ErrOpenabilityUnknown` means they are not known to be gone — a sweep in
   progress destroyed a per-call enclave, or the provider itself returned
   `ErrSealerWiped` (inspect the provider's error). Do not retry during a
   shutdown sweep.
3. `ErrEnclaveDestroyed` — the value was destroyed, or a sweep destroyed this
   call's working enclaves during shutdown; do not retry.
4. `ErrNilAllocator`, `ErrBudgetExhausted`, `ErrLockedMemoryUnavailable` —
   resource refusals; the value is intact and a later retry can succeed.
5. `ErrOpenFailed` — the context ended, or a provider failed with its own
   error. The value is intact, but `ErrOpenFailed` alone does not say the
   failure is transient: a provider's permanent errors (a deleted or disabled
   key, a revoked authorization) are joined under it exactly like transient
   ones, and the same error can carry a cancellation AND a provider failure
   that arrived as the context ended. Classify the provider's cause FIRST with
   `errors.Is`/`errors.As`: a permanent cause means do not retry, whatever
   else is joined; a transient one means retry. Only when no provider cause
   rules it out is a cancellation worth retrying with a live context.

### Openable

| Sealer | After no sweep | After a sweep |
|---|---|---|
| `ModeRootKey` (any provider) | `nil` | `ErrSealerWiped` if the root or current KEK was destroyed, else `nil` |
| `ModePerOperation` + `SoftwareProvider` | `nil` | `ErrSealerWiped` if the sweep destroyed the provider's root; `nil` if the root survived (it was borrowed when the sweep's context ended) or was never created |
| `ModePerOperation` + `WithProviderHealth(fn)` | `fn()` | `fn()` |
| `ModePerOperation`, no health report | `nil` | `ErrOpenabilityUnknown` |

`nil` is narrower than "will succeed": it does not predict authentication
failures, a refused locked page, or device availability.

## Key-schedule heap exposure

This package never writes recovered plaintext to the heap. The **keys** do
reach it, on every seal and open, and those copies outlive the call: `aes.NewCipher` returns a heap-allocated
block whose first round key is the AES-256 key itself (byte-exact on the
hardware-AES path, which is also the path taken under `GODEBUG=fips140=only`; as big-endian words on the
generic path). Go neither zeroes nor finalizes it, so the copy persists until
the allocator reuses the span — in a quiet process, effectively until exit. A
reader needs access to this process's anonymous memory (`ptrace` or
`/proc/<pid>/mem` at the same uid, a swap device, a cold-boot image, or a core
dump the hardening did not stop); `mlock` and `MADV_DONTDUMP` do not cover the
heap. Per key class, and when its schedule reaches the heap:

| Key | Schedule on the heap | A recovered copy opens |
|---|---|---|
| DEK | Every seal and every open of that value, in every mode | That value (its ciphertext is on the heap too) |
| KEK (`ModeRootKey`) | Every DEK wrap (seal) and unwrap (open) under it | Every value of its generation |
| Root (`ModeRootKey`) | Every KEK mint — the first seal and each rotation (`newGeneration`) — and every open of a value under a retired generation | Everything |
| `SoftwareProvider` root (`ModePerOperation`) | Every `Protect` and `Unprotect` | Everything |

In `ModePerOperation` with a hardware provider, the long-lived key never enters
the process, but DEK schedules still do: values sealed or opened recently remain
recoverable until their schedules' memory is reused. This is accepted rather than replacing the standard library's AES (see [architecture.md](architecture.md#rejected-alternatives)); the full audit is
on `withAEAD` in [sealed.go](../../sealed.go), and a test fails if the exposure
stops appearing (so the audit is re-measured when it changes).

## FIPS 140-3

Three different claims, and this package makes only the first two:

1. **Approved algorithms.** All cryptography is AES-256-GCM through
   `cipher.NewGCMWithRandomNonce`, an approved algorithm in Go's FIPS 140-3
   module; there is no `NewGCM` fallback.
2. **Strict-mode compatibility, tested.** `make test-fips` (run nightly and on
   release) builds and runs the tests under
   `GOFIPS140=latest GODEBUG=fips140=only`. That is compatibility EVIDENCE,
   not proof: Go documents `fips140=only` as a best-effort check that can miss
   a non-approved use (false negatives) and as unsuitable for production, and
   it only sees the paths the tests execute. `latest` also builds the module
   from the toolchain's current source rather than a certified snapshot. A
   green run says the tested paths raised no strict-mode error; it does not
   prove that no path uses a non-approved algorithm, and it is not
   validation.
3. **A validated deployment** is the consumer's configuration: build with
   `GOFIPS140` set to a specific module snapshot version whose CMVP certificate
   status you have checked, and operate it as that module's security policy
   requires — normally `GODEBUG=fips140=on`. `fips140=only` is a testing aid,
   not a production setting. No gate in this repository builds against a
   pinned snapshot.

`GOEXPERIMENT=boringcrypto` builds fail every seal with `ErrSealFailed`
wrapping `cipher: NewGCMWithRandomNonce requires aes.Block` — deliberately;
use Go's native FIPS 140-3 module.

## Configuration and persistence

Configuration is code: `NewSealer` options or `SetSealer`. No environment
variables. **No persistence**: there is no constructor for sealed bytes, and the
envelope format is internal, unversioned across releases and keyed to a
process-lifetime `Sealer` (an AST guard test keeps it that way).

## Test strategy

- Unit and race tests for seal/open, rotation, context shapes, `Openable`,
  installation and the init slot (`make test`, `make coverage`).
- Linux tests sweep the process's readable anonymous mappings for complete
  copies of known plaintext at chosen moments, as evidence that the tested
  executions left plaintext only in locked pages. It is evidence, not proof:
  the sweep skips mappings it cannot read, stops scanning a mapping at a read
  error, looks only for whole needles, and sees only the paths and moments the
  tests exercise. A test pins the documented key-schedule heap exposure.
- Package-private `resetProcessSealerForTest` exercises the one-shot install.
- Provider behavior is checked by [provider-conformance](../provider-conformance/engineering.md),
  which `SoftwareProvider` passes in this repository's own tests.
- `make test-fips` runs the suite in FIPS strict mode (`GOFIPS140=latest`; see [FIPS 140-3](#fips-140-3)).

## Observability

No logs or metrics. `Openable`, `Sealer.Mode`, and the error shapes above are
the diagnostic surface.
