# Provider conformance — architecture

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Problem

The provider seam's signatures — `Unprotect(ctx, blob, key []byte) error`,
`UnsealRoot(ctx, dst []byte) error` — constrain where plaintext is **written**.
They say nothing about what a provider **keeps**: a provider may write into the
caller's locked slice and hold its own copy forever, and from go-enclave's side
that is indistinguishable from a conforming one. Nor can a signature say that a
provider refuses forgeries, honors its context, or implements only the modes it
really serves. Providers (TPM, HSM, cloud KMS) are written in other
repositories, so the check has to ship to them.

## Shape chosen

A subpackage, `providertest`, in the shape of `testing/fstest.TestFS`: one call,
`TestProvider(ctx, cfg)`, which returns `nil` or an error joining one
`*PropertyError` per failed **assertion**. One property can contribute several
(the tampered-blob check records one per blob it wrongly accepted), all
carrying the same `Property` name. It does not import `testing`, takes no
dependency on any provider, and nothing in go-enclave depends on it.

```mermaid
flowchart TD
  T["TestProvider(ctx, cfg)"] --> V{cfg valid?}
  V -- no --> CE["*ConfigError (ErrInvalidConfig)"]
  V -- yes --> MP["mode/interface pairing:<br/>claimed modes implemented and accepted, unclaimed not implemented"]
  MP --> KP{"claims ModePerOperation?"}
  KP -- yes --> KPC["KeyProtector checks:<br/>round trip · Protect retains no slice ·<br/>no write after caller wiped dst ·<br/>no disturbance by a later call ·<br/>tampered blob refused · wrong length refused ·<br/>ended context refused · residue sweep"]
  KP -- no --> RU
  KPC --> RU{"claims ModeRootKey?"}
  RU -- yes --> RUC["RootUnsealer checks:<br/>fills whole dst with a real root ·<br/>no disturbance by a later call ·<br/>ended context refused, nothing consumed"]
  RU -- no --> R
  RUC --> R["result: nil, or joined *PropertyError;<br/>+ *AbortedError if ctx ended"]
```

Each check calls `cfg.New` for a fresh provider — the mode-pairing check once
per mode, so twice — so one check leaving a provider in a terminal state cannot
change the meaning of the next. Checks stop
at the next boundary once `ctx` ends.

### Two instruments for retention, in this order

1. **The spy (primary, deterministic).** The suite is the caller, so it owns
   every slice it hands the provider and watches it afterwards: a `Protect`
   that filed the caller's slice instead of copying it, an `Unprotect` that
   writes into a destination the caller already wiped, a later call that
   disturbs an earlier destination. Each spy assertion has a control that fails
   first if its setup did not happen.
2. **The residue sweep (corroboration, Linux only).** The only instrument that
   can see a retained **copy**: it protects a needle that exists only in locked
   pages, recovers it into a second locked mapping, destroys that mapping, and
   searches every readable mapping that can hold a runtime copy — anonymous,
   writable, memfd, `/dev/shm`, `/dev/zero` and unlinked (via `/proc/self/maps`
   and `/proc/self/mem`) — for the whole needle outside its home; unreadable
   mappings and read-only views of on-disk files are skipped and a read error
   ends the scan of that mapping (limits:
   [engineering.md](engineering.md#contract-versus-evidence)). It first proves it *can* find the needle
   while the destination is alive, and wipes its own scan buffer after every
   mapping so it cannot plant what it looks for. A sweep that cannot run
   returns `ErrNotMeasured` unless `SkipResidueSweep` accepted that.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Require that a provider never materializes plaintext | Unsatisfiable: every real backend's decrypt returns a fresh slice (TPM2 `RSADecrypt`, PKCS#11 wrappers, HTTP response bodies from KMS APIs). The requirement is to **wipe** that transient, which the sweep measures. |
| Residue sweep as the primary instrument | A sweep that keeps its scan buffer replants its needle; and a residue claim is unfalsifiable for bytes that transit a stack local (a stack growth strands pre-wipe bytes on the freed old stack). It corroborates; the spy decides. |
| A residue sweep for `RootUnsealer` | A root unsealer legitimately retains the root — that is its job (`SoftwareProvider` keeps it in a locked enclave). It would fail every conforming implementation. |
| Trust `Config.Modes` as a description | An unclaimed mode the type happens to satisfy (a placeholder `UnsealRoot` returning a constant) would be accepted by `NewSealer` and seal everything under a fake root. The suite requires unclaimed modes to be refused. |
| Require cross-instance blob refusal | A device-backed provider hands every instance the same device key; a blob from another instance *is* its own. |
| A boolean "skip residue sweep" | A reason string is required and echoed to `Logf`, so a green run records what it did not measure. |
| Report a provider call aborted by the run's context as a provider failure | It proves only that the run stopped waiting. Reported as `ErrAborted` instead. |
| Measure mid-call cancellation | Only the provider can hold a call open; the suite measures the refusal of already-ended contexts. |

## Component boundaries

| Concern | File |
|---|---|
| `Config`, `TestProvider`, the checks | [providertest/providertest.go](../../providertest/providertest.go) |
| `ErrInvalidConfig`/`ConfigError`, `ErrAborted`/`AbortedError`, `PropertyError` | [providertest/errors.go](../../providertest/errors.go) |
| Residue sweep | [providertest/residue.go](../../providertest/residue.go), [providertest/residue_linux.go](../../providertest/residue_linux.go), [providertest/residue_other.go](../../providertest/residue_other.go) |

The provider under test is the author's; the suite runs in the author's
repository and test binary.

## Trust boundaries

A passing run is evidence about the properties the suite **could measure on
that host**, nothing more. What it could not measure goes to `Config.Logf`.

## Scope fence

Not a performance or load test; no device liveness checks; no mid-call
cancellation measurement; no check of the bulk AES key schedule, which is inside
the standard library's AES implementation, not the provider, and is out of scope.
