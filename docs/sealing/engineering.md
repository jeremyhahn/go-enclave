# Sealing and the provider seam — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-10
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `NewSealed(ctx context.Context, data []byte) (*Sealed, error)` | Seals under the process sealer (lazily the software default). Wipes `data` on every path. |
| `NewSealer(opts ...SealerOption) (*Sealer, error)` | No options: `SoftwareProvider`, `ModeRootKey`, cannot fail. Touches no provider and no locked memory until the first seal. |
| `WithKeyProtector(kp KeyProtector) SealerOption` | Selects `ModePerOperation` over `kp`. Nil or typed-nil: `ErrInvalidProvider`. |
| `WithRootUnsealer(ru RootUnsealer) SealerOption` | Selects `ModeRootKey` over `ru`. Nil or typed-nil: `ErrInvalidProvider`. Giving both provider options is `ErrInvalidProvider` too. |
| `WithKEKRotationLimit(n uint64) SealerOption` | `ModeRootKey` only: DEK wraps per KEK generation before rotation, 1 to 2^31 (the default, half of crypto/cipher's 2^32 random-nonce bound). Out of range, or with `ModePerOperation`: `ErrInvalidRotationLimit`. |
| `SetSealer(s *Sealer) error` | Installs the process sealer. One-shot. |
| `(*Sealer).Seal(ctx, data) (*Sealed, error)` / `Mode() Mode` | `NewSealed` for an explicit sealer. |
| `(*Sealer).Destroy() error` | Ends the sealer: later seals, opens and `Openable` report `ErrSealerDestroyed`, and a `Sealed` opens only through the sealer that sealed it, so this package cannot open its values again. `ModeRootKey` releases the root, wrapping key, current KEK, retained KEK blobs and any pending root or KEK, plus the default `SoftwareProvider` it created. `ModePerOperation` holds no key of its own and releases none. It never destroys an injected provider, so that provider's key outlives the sealer. Retries every handle a `CleanupError` reported. Idempotent, nil-safe. |
| `(*Sealer).SealFrom(ctx, src Handle) (*Sealed, error)` / `NewSealedFrom(ctx, src Handle)` | `Seal` for material already in an enclave, such as a frozen `Memory` that `Seal` refuses with `ErrSealSourceReadOnly`. Reads `src` under its own borrow and leaves it unwiped and undestroyed; the caller keeps it. `src` needs `ByteAccess` (`*CapabilityError`, `CapabilityBytes`). Nil or destroyed: `ErrEnclaveDestroyed`. |
| `(*Sealed).Open(ctx) (*Memory, error)` | Decrypts into a **new** enclave the caller owns and must `Destroy`. Unbudgeted. |
| `(*Sealed).OpenIn(ctx, b Backend) (Handle, error)` | `Open` into any backend that can hold the material; the caller owns the handle. `DefaultBackend` is `Open`; an `*Allocator` admits the destination against its budget (typed-nil: `ErrNilAllocator`); another `Importer` receives the plaintext from a locked scratch enclave. Nil or typed-nil `b`: `ErrInvalidBackend`; not an `Importer`: `*CapabilityError` (`CapabilityImport`). Backend contract: [backends](../backends/engineering.md). |
| `(*Sealed).Openable() error` | Diagnostic snapshot; takes no context and calls no provider. |
| `(*Sealed).IsAlive() bool` | Ciphertext still held — **not** "can be opened". |
| `(*Sealed).Destroy() error` / `String()` / `GoString()` | Idempotent, nil-safe; does not wait for in-flight opens; the error is always `nil` today. `%v` and `%#v` print a redacted form. |
| `KeyProtector` | `Protect(ctx, key []byte) (blob []byte, err error)`; `Unprotect(ctx, blob, key []byte) error` |
| `RootUnsealer` | `UnsealRoot(ctx, dst []byte) error` |
| `HealthReporter` | `Health() error`: optional on a `KeyProtector`, found by type assertion. Non-blocking report of the provider's **in-process** sealing state: `nil` or `ErrSealerWiped`. Believed and terminal. Not consulted in `ModeRootKey`. |
| `RootKeyBytes = 32` | Length of every root and of every key handed to a provider. |
| `SoftwareProvider`, `NewSoftwareProvider()` | Implements `KeyProtector`, `RootUnsealer` and `HealthReporter`; root generated into a locked enclave at first use. `Protect` wraps under HKDF-SHA256 of the root (info `go-enclave v1 SoftwareProvider Protect key`), never the root `UnsealRoot` exports. State is behind a pointer: a copy shares the original's root and lock. |
| `(*SoftwareProvider).Destroy() error` | Releases the root and Protect key; later calls, on it or a copy, report `ErrSealerDestroyed`. Idempotent, nil-safe. |
| `WithBackend(b Backend) SealerOption` | `ModeRootKey`: the wrapping key and every KEK are imported into `b` (`PurposeWrappingKey`, `AlgorithmAES256GCM`); a handle with `AEAD` wraps inside the device, one with only `ByteAccess` wraps here. Data keys stay in this process. In `ModePerOperation` it only answers `WithRequireKeyScheduleErasure`. Nil or typed-nil: `ErrInvalidBackend`; not an `Importer`: `*CapabilityError` (`CapabilityImport`). |
| `WithRequireKeyScheduleErasure() SealerOption` | `NewSealer` refuses, with `*KeyScheduleExposedError` matching `ErrKeyScheduleExposed`, a configuration where an AES key schedule would stay on the heap: each key class must be covered by `KeyScheduleErasure()` or by a backend that is a `Confiner` confining this process. Checked once, in `NewSealer`. |
| `KeyScheduleErasure() bool` | Whether this build erases AES key schedules (`GOEXPERIMENT=runtimesecret`, linux/amd64 or linux/arm64 (not Android)). See [Erasure under `runtime/secret`](#erasure-under-runtimesecret). |

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
   inside it. The `Sealer` copies it, so the provider keeps the slice it
   returned and may reuse it; `Unprotect` must not retain or modify the blob
   it is handed.
5. **Honor the context.** An already-ended context is refused before device work
   with an error matching `ctx.Err()`; a context ending mid-call returns
   promptly; a refused call writes no key material and, for `UnsealRoot`,
   consumes nothing a later call needs.
6. **Infrastructure failures are the provider's own errors**, not
   `ErrSealedAuthentication`.
7. **Concurrent calls.** The `Sealer` holds no lock of its own across a
   provider call, so concurrent seals and opens call the provider
   concurrently. A provider that ignores its context stalls only its own
   caller.
8. **`Health` does not block** and reports only in-process state; a provider
   whose key lives in a device returns `nil` unconditionally.

## Invariants

1. **Recovered plaintext only in locked pages.** `Seal` reads the caller's
   slice and wipes it on every return path; this package makes no other copy of
   the plaintext. `Open` allocates the destination first,
   with capacity exactly the plaintext length, and decrypts in place; a length
   mismatch is refused **before** decrypting. `ErrPlaintextEscaped` guards the
   (unreachable) case of the AEAD reallocating.
2. **No `Sealer` or `Sealed` mutex across a provider call.** Two
   things do span one, by design: the init slot (a one-slot semaphore acquired
   in a `select` against `ctx.Done()`) spans `UnsealRoot`, and the read lock of
   the private, per-call enclave the provider reads from or writes into (the
   DEK, or the root destination) spans every provider call. Lock order is
   init slot, then the hierarchy mutex; the mutex is held only for
   in-process work (reading, publishing, rotating), which is why rotation
   may hold it across a mint: rotation never calls the provider.
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
6. **Wrapping key and KEK rotation.** The sealer never encrypts under the
   provider's root: inside the unseal's own borrow it replaces the root with
   a wrapping key derived from it, HKDF-SHA256 under a 256-bit salt drawn for
   this sealer alone. Sealers sharing a provider — or one sealer per boot of
   a hardware root that unseals the same key every time — therefore never
   share a wrapping key, and the per-sealer bound below bounds a real key.
   A KEK generation wraps at most 2^31 DEKs — or the smaller
   crypto-period `WithKEKRotationLimit` set — then a new generation is minted
   under the wrapping key (no provider call); at most 2^31 generations, then
   seals fail with `ErrSealerExhausted`. The retired KEK's
   enclave is destroyed; its root-wrapped blob is kept so older values still
   open (one transient locked page per retired-generation open). A retired
   KEK whose `Destroy` the backend refuses is never dropped: the sealer keeps
   it until a `(*Sealer).Destroy` releases it, and the seal that rotated
   fails with a `*CleanupError`; the new generation is published, so later
   seals go on under it.
7. **`SoftwareProvider` message bound.** In `ModePerOperation` its single
   Protect key protects at most 2^31 keys, then `Protect` returns `ErrProviderMessageLimit`.
8. **Context checks.** Every provider-reaching call checks `ctx` on entry,
   again after winning the init slot (before `UnsealRoot`), and after each
   provider call returns. An already-ended context on `NewSealed` is refused
   before the process sealer is looked up, so it never installs the default.
   In `ModeRootKey`, `Open` makes no provider call and checks `ctx` on entry only.
9. **Destroy fails closed.** `(*Sealer).Destroy` takes the hierarchy's write
   lock, so it waits for in-process seals and opens, but not for a provider: an
   initialization blocked in `UnsealRoot` sees the destroyed state when it
   returns, publishes nothing and releases the root it produced. An `OpenIn`
   into a backend other than locked memory checks the sealer again after its
   `Import` returns, so a plaintext handle imported while `Destroy` ran is
   destroyed, not returned. A sealer never re-keys after `Destroy`.
10. **Process sealer is one-shot.** `SetSealer` fails with `ErrSealerInstalled`
   after any install, including the lazy default from the first `NewSealed`.
11. **`Sealed.Destroy` does not wait for opens in flight.** They complete
    against the envelope they pinned; the last one out wipes the ciphertext;
    opens starting afterwards return `ErrEnclaveDestroyed`.
12. **`OpenIn` admits one reservation, first.** An open refused **before** the
    destination is allocated — destroyed value, nil allocator, context already
    ended, budget refused — allocates nothing. Once the destination is
    allocated, the DEK page (and, for a retired generation, a KEK page) follow
    unadmitted, and a later failure (provider, authentication, context) has
    already allocated them; they are destroyed before `Open` returns. Peak use
    can therefore exceed the budget by one page (two across a retired-generation
    unwrap) per open **in flight**. That bound assumes those destroys succeed: a
    transient whose release the kernel refuses stays mapped, on the `WipeAll`
    ledger, until a later retry reclaims it.
13. **A refused handle `Destroy` is never dropped.** A key or plaintext
    handle the sealer no longer needs (a retired KEK, an import that failed or
    lacked a capability, an `OpenIn` result under a destroyed sealer) whose
    `Destroy` fails still holds its material. The sealer keeps it, the
    operation fails with a `*CleanupError`, and every `(*Sealer).Destroy`
    retries it, keeping the ones that refuse again.

## Error semantics

| Error | From | Meaning |
|---|---|---|
| `ErrSealFailed` (`*SealError`) | seal paths | AEAD, CSPRNG or provider failure (the `Cause`), or the context ended (`Cause` matches `ctx.Err()`). |
| `ErrOpenFailed` (`*OpenError`) | `Open`, `OpenIn` | The context ended, or a `ModePerOperation` provider failed with its own error (the `Cause`, reachable). It says nothing about the value, which is intact, and nothing about whether the provider's failure is transient. It can **also match** a verdict the provider returned as the context ended — `ErrSealedAuthentication`, `ErrSealerWiped`, `ErrEnclaveDestroyed` — so test those first, then inspect the provider's cause before retrying (see [Classifying an open failure](#classifying-an-open-failure)). |
| `ErrSealedAuthentication` | open paths, providers | Tampered, truncated, forged, re-paired or foreign. Deliberately indistinguishable between causes. |
| `ErrSealerWiped` (bare, or `*SealerWipedError` carrying the failure that met the sweep) | all sealing paths, `Openable` | **This sealer could not serve this operation because an enclave it was using is gone** — not, on its own, proof that the sealer is dead. See [Where `ErrSealerWiped` comes from](#where-errsealerwiped-comes-from). |
| `ErrOpenabilityUnknown` | `Openable` | A sweep ran since sealing (or during it), `ModePerOperation`, and the provider reports no health. Open the value to find out. |
| `ErrEnclaveDestroyed` | `Open`, `OpenIn`, `Openable`; seal paths | From `Openable`, and from `Open`/`OpenIn` before any work: the `Sealed` was destroyed (or is nil). From later in a seal or open: an enclave **this call** allocated was destroyed by a concurrent `WipeAll`, and the sealed value may be intact — the DEK while sealing the material under it (either mode), the open's destination or DEK while decrypting into it (either mode), or the DEK while a `ModePerOperation` provider uses it. A provider returning it is passed through too. In `ModeRootKey` the same holds for a per-call key destroyed during the wrap or unwrap under the KEK; only when a **hierarchy** key (the root or the current KEK) is dead does the failure become `ErrSealerWiped` (see below). |
| `ErrLockedMemoryUnavailable` | seal, open | Kernel refused a locked page; the sealed value survives an open failure. |
| `ErrNilAllocator` / `ErrBudgetExhausted` | `OpenIn` | Nil allocator (never falls back) / over budget. Decided before any provider call. |
| `ErrEmptyEnclave`, `ErrMaterialTooLarge` | seal | Empty input; input above AES-GCM's single-message limit, (2^32−2)·16 bytes, or whose sealed length would not fit in an `int` (about 2 GiB on 32-bit platforms). |
| `ErrSealerDestroyed` | all sealing paths, `Openable`, `SoftwareProvider` | `Destroy` ran on the sealer (or on its software provider). Permanent. |
| `ErrSealerNotConstructed` | `Seal`, `Open` | The `Sealer` was not built by `NewSealer` (e.g. a zero value). |
| `ErrInvalidProvider` | `NewSealer` | A provider option was given nil or a typed nil, or both provider options were given. |
| `ErrSealerExhausted` | `Seal` (`ModeRootKey`), as the `Cause` of a `*SealError` | A rotation would need a KEK generation past 2^31, the bound on the sealer's own wrapping key. Nothing is minted; existing values keep opening; new seals need a new `Sealer`. |
| `ErrInvalidRotationLimit` | `NewSealer` | `WithKEKRotationLimit` of zero, above 2^31, or given for `ModePerOperation`. |
| `ErrSealerInstalled`, `ErrNilSealer` | `SetSealer`, nil `(*Sealer).Seal` | One-shot install; nil sealer. |
| `ErrProviderMessageLimit` | `SoftwareProvider.Protect` | Per-key message bound reached. |
| `ErrProviderNotConstructed` | Every `SoftwareProvider` method but `Destroy` | The provider was not built by `NewSoftwareProvider` (e.g. a zero value). |
| `ErrPlaintextEscaped` | open | Defensive; unreachable while destination capacity is exact. |
| `ErrCleanupFailed` (`*CleanupError`) | `OpenIn` into an `Importer`, seals and `Destroy` of a `WithBackend` sealer | A handle the operation no longer needed refused its `Destroy` and still holds its material; the sealer keeps it for `(*Sealer).Destroy` to retry ([invariant 13](#invariants)). `Failure` is the operation's own error, reachable with `errors.Is`, or nil when only the cleanup failed; `Causes` holds what each refused `Destroy` or release returned. It is also how any failure that came with a failed cleanup is reported. |

### Context error shapes

Built by `contextFailure` in [errors.go](../../errors.go): a `*SealError` or
`*OpenError` matching `op` (`ErrSealFailed` or `ErrOpenFailed`), whose `Cause`
holds the context's error, any `context.Cause` and any provider error, each
reachable through `errors.Is`/`errors.As`. It renders as `<op>: <ctx.Err()>`,
then `: <cause>` when the cause is distinct, then `; provider: <error>`.

| Situation | Matches (`errors.Is`) |
|---|---|
| Context ended before or between provider calls | `op`, `ctx.Err()` |
| Provider returned an error wrapping `ctx.Err()` | `op`, the provider's error (and so `ctx.Err()`) |
| Provider returned some other error as the context ended | `op`, `ctx.Err()`, the provider's error — so a forgery verdict stays visible alongside the cancellation |
| `context.Cause` distinct from `ctx.Err()` | additionally the cause |
| Queued for the init slot when the context ended | `ErrSealFailed`, `ctx.Err()` |
| Successful unseal, then failed mint, context ended | `ErrSealFailed`, `ctx.Err()`, the mint failure; the root is kept |

While the context is live, a provider error passes through unwrapped when it
matches one of these sentinels, and becomes the `Cause` of a `*SealError` or
`*OpenError` otherwise
(`providerFailure` and its `providerVerdicts` table in [errors.go](../../errors.go)):

- open: `ErrSealedAuthentication`, `ErrSealerWiped`, `ErrSealerDestroyed`,
  `ErrOpenFailed`, `ErrLockedMemoryUnavailable`, `ErrEnclaveDestroyed`;
- seal: `ErrSealerWiped`, `ErrSealerDestroyed`, `ErrSealFailed`,
  `ErrLockedMemoryUnavailable`, `ErrProviderMessageLimit`, `ErrEnclaveDestroyed`.

### Where `ErrSealerWiped` comes from

It is a distinct error, not a reuse of `ErrSealedAuthentication`: a sealer
that silently re-keyed after a sweep would seal successfully and fail only on
older values, as apparent tampering, sending an operator after an attacker
who does not exist.

Three paths produce it. Paths 1 and 2 are permanent for that sealer; path 3 is
whatever the provider means by it:

1. **The hierarchy is dead** (`ModeRootKey`): the root or the current KEK was
   destroyed by a sweep, or a sweep overlapped initialization and the retained
   root was discarded. Every later seal and open that reaches the hierarchy
   fails the same way.
2. **`SoftwareProvider`'s root is dead** (a sweep destroyed it). Permanent for
   the PROVIDER: it refuses every later `Protect`, `Unprotect` and
   `UnsealRoot` rather than minting a new root. That makes it permanent for a
   `ModePerOperation` sealer using the provider, and for a `ModeRootKey`
   sealer that still needs a successful unseal. It does NOT reach a
   `ModeRootKey` sealer that is already initialized: `UnsealRoot` copied the
   root into the sealer's OWN locked root, and that sealer consults only its
   own root and KEK — if the sweep skipped those (they were borrowed) and no
   initialization or rotation overlap invalidated them, it keeps working.
3. **A provider or its `HealthReporter` returned it.** Its
   permanence is the provider's own statement; a hardware provider may use it
   for a key that is gone for good, or for a device that is merely unreachable.
   Inspect the provider's cause before acting on it.

A sweep that destroys only a **per-call** enclave — the call's own DEK, or a
retired KEK materialized for one unwrap — is not one of these paths:
`hierarchyFailure` ([hierarchy.go](../../hierarchy.go)) reports `ErrSealerWiped` only
when a hierarchy key the operation used (the root, or the current KEK) is
itself dead, and otherwise passes `ErrEnclaveDestroyed` through. That failure
is this call losing its working key, and the sealer keeps working.

A KEK being **minted** is the exception, deliberately. Any sweep that overlaps
initialization or rotation — even one that spared the root and the current KEK
because they were borrowed — wipes the whole hierarchy and reports
`ErrSealerWiped` (path 1): publishing a generation minted across a sweep would
hand back a working sealer after a `WipeAll`, the silent re-keying
`ErrSealerWiped` exists to prevent.

Path 3 is the one whose permanence the package cannot vouch for, so still
check the sealer's health before acting on `ErrSealerWiped` from a provider —
`Openable()` on a value it sealed reports it for path 1 or 2, or a health
callback's report.

### Classifying an open failure

Several sentinels can match one error, so test in this order and act on the
first match:

1. `ErrSealedAuthentication` — a forgery verdict; never retry, investigate.
2. `ErrSealerWiped` — this sealer could not serve the operation. Check
   `Openable()` before concluding anything: `ErrSealerWiped` there means the
   sealer's own keys are gone (or its health callback says so); `nil` or
   `ErrOpenabilityUnknown` means they are not known to be gone — the provider
   itself returned `ErrSealerWiped` (inspect the provider's error). A sweep
   that destroys only a per-call enclave is not reported this way; it is
   `ErrEnclaveDestroyed`. Do not retry during a shutdown sweep.
3. `ErrSealerDestroyed`, `ErrEnclaveDestroyed` — the sealer or the value was
   destroyed, or a sweep destroyed this call's working enclaves during
   shutdown; do not retry.
4. `ErrNilAllocator`, `ErrBudgetExhausted`, `ErrLockedMemoryUnavailable` —
   resource refusals; the value is intact and a later retry can succeed.
5. `ErrOpenFailed` — the context ended, or a provider failed with its own
   error. The value is intact, but `ErrOpenFailed` alone does not say the
   failure is transient: a provider's permanent errors (a deleted or disabled
   key, a revoked authorization) are wrapped under it exactly like transient
   ones, and the same error can carry a cancellation AND a provider failure
   that arrived as the context ended. Classify the provider's cause FIRST with
   `errors.Is`/`errors.As`: a permanent cause means do not retry, whatever
   else it carries; a transient one means retry. Only when no provider cause
   rules it out is a cancellation worth retrying with a live context.

### Openable

| Sealer | After no sweep | After a sweep |
|---|---|---|
| `ModeRootKey` (any provider) | `nil` | `ErrSealerWiped` if the root or current KEK was destroyed, else `nil` |
| `ModePerOperation` + `SoftwareProvider` | `nil` | `ErrSealerWiped` if the sweep destroyed the provider's root; `nil` if the root survived (it was borrowed when the sweep's context ended) or was never created |
| `ModePerOperation` + `HealthReporter` provider | `Health()` | `Health()` |
| `ModePerOperation`, no `HealthReporter` | `nil` | `ErrOpenabilityUnknown` |

After `(*Sealer).Destroy`, every row reports `ErrSealerDestroyed`.

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
| Root (`ModeRootKey`) | Once, at initialization: the HMAC state of the wrapping-key derivation (`deriveWrappingKey`) | Everything this provider's root keys, in any sealer |
| Wrapping key (`ModeRootKey`) | Every KEK mint — the first seal and each rotation (`newGeneration`) — and every open of a value under a retired generation | Everything this sealer sealed |
| `SoftwareProvider` root (`ModePerOperation`) | Once, at the first `Protect`: the HMAC state of the Protect-key derivation (`deriveProtectKey`) | Everything |
| `SoftwareProvider` Protect key (`ModePerOperation`) | Every `Protect` and `Unprotect` | Everything this provider protected |

In `ModePerOperation` with a hardware provider, the long-lived key never enters
the process, but DEK schedules still do: values sealed or opened recently remain
recoverable until their schedules' memory is reused. This is accepted rather than replacing the standard library's AES (see [architecture.md](architecture.md#rejected-alternatives)).

Measured on go1.27 linux/amd64: the `aes.NewCipher` block is 488 bytes (the
512-byte size class), one per AES operation, with the key at offset 8 —
byte-exact on the hardware path, as eight big-endian `uint32` words on the
generic path (`GODEBUG=cpu.aes=off`). Size and offset follow the block layout
and nothing depends on them; the key's presence is what matters.
`withAEAD` ([aead.go](../../aead.go)) is the only place a key leaves locked
memory. `TestSealed_KeyScheduleReachesTheHeapAsDocumented` fails if the
key stops appearing in the schedule in either form, or `NewCipher` stops
allocating; either means this section must be re-measured. Core-dump
suppression does not close the window everywhere: `RLIMIT_CORE` may be
refused, Windows has none, and a Linux `core_pattern` pipe ignores it.

### Erasure under `runtime/secret`

Built with `GOEXPERIMENT=runtimesecret` for `linux/amd64` or `linux/arm64`,
every AES operation in the package (`withAEAD`), and the derivation of a
`ModeRootKey` sealer's wrapping key from its root (`deriveWrappingKey`), runs
under `runtime/secret.Do`, which erases the operation's registers and stack when it returns
and its heap allocations — the key schedule included — once the garbage
collector finds them unreachable. No `cipher.Block` or `cipher.AEAD` outlives
the call, so nothing escapes it. In that build the table above describes a
window that closes at the next collection instead of at heap reuse.
`KeyScheduleErasure()` reports which build is running; a deployment that
relies on erasure should check it at startup.

Everywhere else (`KeyScheduleErasure() == false`) the exposure is exactly as
described above. `make test-runtimesecret` proves the claim by sweeping the
process's memory for a key after GC: a control run outside `secret.Do` must
find the schedule (so the sweep can see what it claims is erased), and the
same operations through `withAEAD` must leave nothing.

## FIPS 140-3

Three different claims, and this package makes only the first two:

1. **Approved algorithms.** Every encryption is AES-256-GCM through
   `cipher.NewGCMWithRandomNonce`, and a `ModeRootKey` sealer derives its
   wrapping key with HKDF-SHA256 (`crypto/hkdf`, a 32-byte key and salt);
   both are approved algorithms in Go's FIPS 140-3 module. There is no
   `NewGCM` fallback.
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
- Context and lock tests never sleep or race a clock: providers block on
  channels the test closes, and deadlines are contexts the test expires by
  hand, so each test fixes its interleaving.
- Counters that would take 2^31 operations to reach (KEK messages,
  generations, `SoftwareProvider`'s Protect budget) are positioned at the
  boundary by in-package tests; the integration suite cannot reach them.
- One placement has no deterministic test: the seal path translates a wrap
  failure with `hierarchyFailure` before releasing the hierarchy's read lock,
  because a rotation waiting on the write lock destroys the outgoing KEK and
  a later check would read that retirement as a sweep. No seam holds that
  window open.
- Provider behavior is checked by [provider-conformance](../provider-conformance/engineering.md),
  which `SoftwareProvider` passes in this repository's own tests.
- `make test-fips` runs the suite in FIPS strict mode (`GOFIPS140=latest`; see [FIPS 140-3](#fips-140-3)).

## Observability

No logs or metrics. `Openable`, `Sealer.Mode`, and the error shapes above are
the diagnostic surface.
