# Shutdown sweep — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `WipeAll(ctx context.Context) (int, error)` | Destroy every enclave on the ledger and retry every orphaned mapping; report what is still held and what was found. Never panics. |
| `SweepError{Corrupt int; Unwiped int}` | Findings of an admitted sweep. `errors.Is(err, ErrEnclaveCorrupted)` iff `Corrupt > 0`; `errors.Is(err, ErrReleasedWithoutWipe)` iff `Unwiped > 0`. |
| `ErrSweepInProgress` | This call was never admitted; it swept nothing. |

## Invariants

1. **One sweep at a time.** A second call waits for the slot only as long as its
   own `ctx` allows; a nil `ctx` only tries. A free slot is taken even under an
   already-done `ctx`.
2. **Never unmaps under a reader.** "Reader" is any holder of the enclave's lock:
   `WithBytes`, `Open`, `OpenString`, `EqualTo`, `Size`, `IsAlive`,
   `Freeze`, or a `Destroy` waiting its turn. Such an enclave is waited for while
   `ctx` is live and left mapped (and counted) when it ends. A slice returned by
   `Open` is **not** a lock holder: the sweep can unmap the pages behind it.
3. **`ctx` bounds waiting, not reclaiming.** An admitted call with a done or nil
   `ctx` still reclaims everything not currently held, including the extra passes
   reclamation pays for; it only declines to wait or retry contention.
4. **Bounded by `ctx`.** Once `ctx` ends the sweep stops waiting and stops
   retrying contention; it returns after at most the extra passes that
   reclaiming owed entries earns (finite: one per owed entry). Under
   `context.Background()` it returns once every owed enclave has been free at a
   moment the sweep could take it — never, if a borrow never ends. Constructors
   racing the sweep never extend it.
5. **Refunds ride the release.** An enclave's `Allocator` reservation is returned
   exactly when its pages go back (same predicate as `Destroy`); an orphan's
   attached refund runs once, when its mapping is released.
6. **Generation ordering.** The sweep generation is bumped (to odd) before
   anything is destroyed and bumped back (to even) on every return path of an
   admitted sweep; a call that is not admitted does not touch it.
7. **Sealing enclaves are swept like any other enclave**, in every mode: the
   plaintext enclaves `Open` returned, transient DEK and KEK enclaves of seals
   and opens in flight, and any in-process key — a `ModeRootKey` sealer's root
   and KEKs, a `SoftwareProvider` root. What that does to sealed values depends
   on which keys were **actually reclaimed** (an enclave still borrowed when
   `ctx` ends survives): a `ModeRootKey` sealer becomes permanently wiped
   (`ErrSealerWiped`) if either its root or its current KEK was destroyed, and
   keeps working only if both survived; a `SoftwareProvider` in
   `ModePerOperation` is wiped only if its root was destroyed. Sealed values
   stay openable where the needed in-process keys survived, or where the
   wrapping key is held outside the process (a device-held `ModePerOperation`
   key).
8. **Never call it from inside a borrow** — it would wait for the borrow that is
   waiting for it, until `ctx` ends.

## Return values

The **count** is what is still held when the call returns, read from the
ledgers under their lock: enclaves still borrowed when `ctx` ended, enclaves
whose release the kernel refused, enclaves registered mid-sweep and not reached,
and orphaned mappings still refused. `0` means both ledgers were empty at that
instant — not that this package holds no mapped pages: a constructor maps and
locks its pages before it registers them (registration is its last step), so a
construction in flight when the count is read is not in it. It is a snapshot,
not a diagnosis; a non-zero count is most often workers that outlived the
shutdown.

The **error**:

| Value | Meaning |
|---|---|
| `nil` | Admitted, and found nothing to report. A `ctx` ending during an admitted sweep is not an error. |
| `ErrSweepInProgress` | Not admitted. The count is still current; the running sweep reports its own findings to its own caller. |
| `*SweepError` | Admitted, and found canary corruption (`Corrupt`, counted once per entry per sweep, including every enclave whose `Destroy` reported corruption since the previous admitted sweep) and/or releases that fell back to an unwiped unmap (`Unwiped`). Never a nil `*SweepError` behind a non-nil error. |

Neither finding is a held page, so neither is in the count — except a corrupt
entry whose pages the kernel then refused to release, which is in both. A
corruption is reported again by each later sweep that retries that entry, until
its pages are reclaimed (detection is sticky while the mapping is held); once
they are, no later sweep reports it.

## Cost

Each acquisition of an enclave's lock adds two atomic adds on its `holders`
counter and one load of a package-level flag that only a sweep writes — no lock,
no allocation (`BenchmarkBorrow*`, `BenchmarkIsAliveParallel`). `registryMu`
serializes construction and destruction process-wide for one map operation each.
An enclave whose release keeps failing stays on the ledger for the process
lifetime, by design.

## Configuration and persistence

None.

## Test strategy

Package-private hooks, nil in every build except the tests that set them, make
each ordering observable without timing: `sweepWaitingForTest` (about to block on
a borrow), `sweepPassForTest` (start of each pass), `sweepParkedForTest` (after
the generation bump, before destroying), `sweepAdmissionWaitForTest` (about to
block for the slot). Release refusals and corruption are injected through the
memory seams described in
[locked-memory/engineering.md](../locked-memory/engineering.md#test-strategy).
Borrow-path cost is measured by the borrow benchmarks (`make bench`).

## Observability

The return values are the whole interface. Log the count and the error at
shutdown; a `*SweepError` with `Corrupt > 0` is a memory-safety event that has
already happened in the process.
