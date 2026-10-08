# Provider conformance — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-07
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

Package `providertest` (import path `github.com/jeremyhahn/go-enclave/providertest`).

| Identifier | Contract |
|---|---|
| `TestProvider(ctx context.Context, cfg Config) error` | Runs the suite. `nil` = every property was measured and held, except those `cfg` explicitly relaxed. |
| `Config.New func() (any, error)` | Returns a fresh provider. Called twice by the mode-pairing check (once per mode) and once by each other check that runs: up to 2 + 8 + 3 = 13 times when both modes are claimed. Nil or typed-nil results are failures. |
| `Config.Modes []enclave.Mode` | The modes the provider **claims**. Must be non-empty and valid. Checked in both directions. |
| `Config.SkipResidueSweep string` | Non-empty reason skips the residue sweep and accepts retention by copy as unmeasured; echoed to `Logf`. Empty, an unmeasurable sweep returns `ErrNotMeasured`. |
| `Config.SingleUseRoot string` | Non-empty reason relaxes the two `RootUnsealer` checks that need a second `UnsealRoot` call; echoed to `Logf`. |
| `Config.Logf func(format string, args ...any)` | Receives what was measured, skipped and why. Pass `t.Logf`. |
| `ErrInvalidConfig` / `*ConfigError{Field, Reason}` | `cfg` cannot be run; no provider was tested. |
| `ErrAborted` / `*AbortedError{Err}` | `ctx` ended before the run finished; unwraps to `ctx.Err()` and renders as `ErrAborted`'s text, `": "` and `Err`. Never a pass. |
| `ErrNotMeasured` / `*NotMeasuredError{Property, Reason}` | A property could not be measured on this host (residue sweep off Linux, without locked memory, or blind) and `cfg` did not accept that. Neither a pass nor a provider defect. |
| `*PropertyError{Property, Detail}` | One failed assertion; several can share a `Property`. Walk them via the joined error's `Unwrap() []error`. |

## Properties checked

| Property (as reported) | Mode | Evidence the suite collects |
|---|---|---|
| mode/interface pairing | both | The provider must implement each claimed mode's interface (and `NewSealer` must accept it through `WithKeyProtector`/`WithRootUnsealer`), and must NOT implement an unclaimed mode's. |
| Protect/Unprotect round trip | per-operation | Recovers the key (exact compare); `Protect` does not mutate its input; the blob contains no run of 8 consecutive key bytes. |
| Protect does not retain the caller's key slice | per-operation | Spy |
| Unprotect does not write into a destination the caller has finished with | per-operation | Spy, with populated-destination control |
| a later provider call does not disturb an earlier destination | per-operation | Spy |
| a blob this provider did not produce is refused | per-operation | Nil, empty, truncated, extended, random and a sample of bit-flipped blobs must fail as `ErrSealedAuthentication`; the destination must hold no run of 8 consecutive key bytes afterwards. |
| a destination of the wrong length is an authentication failure | per-operation | |
| Protect and Unprotect refuse a context that has already ended | per-operation | Already-canceled and already-expired contexts; error must match that context's error, not `ErrSealedAuthentication`; the destination must hold no run of 8 consecutive key bytes; the next call still works. |
| no copy of the key is findable in the process after Unprotect returns | per-operation | Residue sweep for the whole 32-byte key (Linux; unmeasured is `ErrNotMeasured` unless skipped with a reason; limits below) |
| UnsealRoot writes a root across the whole destination | root-key | Not a placeholder (not all-zero, not constant) |
| UnsealRoot does not retain the caller's destination | root-key | Spy (needs a second call) |
| UnsealRoot refuses a context that has already ended, and consumes nothing | root-key | Ended contexts must fail with that context's error; the destination must hold no run of 8 consecutive bytes of the root a later live call returns; that later call must succeed |

## Contract versus evidence

The provider's **contract** is what the seam requires
([sealing/engineering.md](../sealing/engineering.md#provider-contract)): retain
nothing, write nothing on a refused call, refuse every forgery, honor the
context. The suite collects **evidence** for that contract, sampled and
heuristic in places, so a pass is weaker than the contract:

- **"No key material in the destination"** is checked as "no run of 8
  consecutive bytes of the expected key" (`containsRun`). A provider that writes
  shorter fragments, or transformed key bytes, is not detected.
- **Tamper refusal** is checked for a fixed set of malformed blobs and a bounded
  sample of single-bit flips, not every forgery.
- **The residue sweep** searches, at one moment, every readable mapping in
  `/proc/self/maps` that can hold a runtime copy, for the **whole** 32-byte key,
  excluding the needle's own mapping: anonymous mappings (named or not), every
  writable mapping (private or shared, file-backed or `/dev/zero`), and memfd,
  `/dev/shm`, SysV and unlinked (`(deleted)`) mappings whatever their
  permissions. It skips unreadable mappings and read-only views of files still
  on disk (program text and rodata), stops scanning a mapping at the first read
  error, and cannot see partial copies or copies in another form. It runs only
  on Linux; a sweep that cannot run, or whose control shows it blind, returns
  `ErrNotMeasured` unless `SkipResidueSweep` accepted that.
- **Context handling** is checked only for contexts that ended before the call;
  cancellation arriving mid-call is not measured.

Deliberately out of scope, because a conforming provider cannot satisfy it:

- **Plaintext in the provider's own memory.** Every real backend decrypts into
  a fresh slice (a TPM2 RSA decrypt, a PKCS#11 wrapper, a cloud KMS HTTP
  response body), so the suite requires the transient be wiped, not that it
  never exist. Key expansion inside `crypto/aes` falls under the
  validated-module carve-out.
- **Refusing another instance's blob.** A device-backed provider shares its key
  across instances, so a blob from a second instance genuinely is its own.
- **A residue sweep for the root.** A `RootUnsealer` legitimately retains the
  root (`SoftwareProvider` holds it in a locked enclave), so only
  `KeyProtector` is swept.

The spy is the primary instrument and the residue sweep corroborates it. The
sweep is the only one that sees a retained copy, but a negative from it is
weak: bytes that transit a stack local can be stranded on a freed old stack by
stack growth, out of any wipe's reach, and a sweep whose scan buffer is not
wiped finds its own copy of the needle. The sweep therefore wipes the prefix of
its scan buffer it requested from `ReadAt` after every mapping (not the whole
1 MiB buffer, which is too slow under the race detector), sweeps
kernel-named anonymous mappings such as `[anon: Go: heap]`, and keeps the
needle only in locked memory so the suite never plants a heap copy itself.

`UnsealRoot` writing the whole destination is proved exactly: two calls into
destinations pre-filled with different canaries must agree, so every byte was
written. That equality also requires a root to be deterministic within an
instance, so two Sealers over one device hold the same root. A provider that
can unseal only once sets `SingleUseRoot`, since the seam guarantees only that a
Sealer calls `UnsealRoot` at most once.

The harness itself never copies a provider's root onto the ordinary heap.
Against a real device `UnsealRoot` hands back that device's actual root key, so
every destination, comparison snapshot and control the root checks use is a
locked enclave, borrowed across each check's observation window and destroyed
afterwards. The one exception is the destination of an ended-context call the
run may abandon: it can outlive the check, so it is an ordinary buffer holding
the caller's canary — root material appears there only if the provider broke
the contract, which is what that check reports. It is wiped by whichever side
owns it last: the check once the call has returned, or the abandoned call's
own goroutine once the provider returns, never under a running provider.

## Invariants

1. **An ended run is never a pass.** It returns an error matching `ErrAborted`,
   joined with any properties that had already failed while `ctx` was live.
2. **Never a false finding from the run's own context.** A failure recorded
   after `ctx` ended is dropped (the run reports aborted instead).
3. **Calls with an ended context run on their own goroutine**, so a provider
   that never returns cannot hold a run whose `ctx` is bounded. With an
   unbounded `ctx` such a provider hangs the run; `go test -timeout` reports it.
4. **No vacuous assertion.** Each spy check proves its setup first; the residue
   sweep proves it can see the needle before it reports a negative, and
   otherwise returns `ErrNotMeasured`.
5. **Fail closed when unmeasured.** A residue sweep that cannot run (non-Linux,
   no locked memory, blind control) returns `ErrNotMeasured`, never `nil`,
   unless `Config.SkipResidueSweep` records why that is accepted.

## Error semantics

| Return | Meaning | Caller action |
|---|---|---|
| `nil` | Every property was measured and held, except those `cfg` relaxed | Read `Logf` output for what was relaxed. |
| matches `ErrInvalidConfig` | `New` nil, `Modes` empty or invalid | Fix the test harness. |
| matches `ErrAborted` | Run incomplete | Re-run with a longer deadline; inspect any joined `*PropertyError`. |
| matches `ErrNotMeasured` | A property could not be measured on this host | Run on Linux with locked memory, or set `SkipResidueSweep` with the reason it is acceptable; inspect any joined `*PropertyError`. |
| joined `*PropertyError`s | Provider violates the seam | Fix the provider. |

Every sentinel and error type is declared in
[errors.go](../../providertest/errors.go). `AbortedError` is an alias of the
package's one cause-carrying shape, which matches its sentinel and unwraps to
`Err`. The joined findings are the only `errors.Join` the package builds
(`joinFindings`).

## Configuration and persistence

Only `Config`. Nothing persisted.

## Test strategy

The suite is itself tested in `providertest` against `SoftwareProvider` (which
must pass) and against deliberately defective providers (which each property
must catch), so a check that cannot fail is found. `make test-providertest` and
`make coverage-providertest` run it alone. In the devcontainer, the enclave
integration suite (`test/integration/enclave/provider_test.go`) runs it against
`SoftwareProvider` with the residue sweep required to run, and in a child with
`RLIMIT_MEMLOCK` at zero, where the sweep must report `ErrNotMeasured`.

## Observability

`Config.Logf` is the only output besides the returned error: what was measured,
what was skipped and why (residue sweep, single-use root, non-Linux host), and
the residue sweep's mapping counts.
