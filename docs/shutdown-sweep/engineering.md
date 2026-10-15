# Shutdown sweep — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `WipeAll(ctx context.Context) (int, error)` | Phase one: destroy every enclave on the ledger and retry every orphaned mapping. Phase two: call `Sweep(ctx)` on every registered non-default `Sweeper`, in name order. Report what is still held and what was found. Never panics on its own account. |
| `SweepError{Corrupt int; Unwiped int; Backends []BackendSweepFailure}` | Findings of an admitted sweep. `errors.Is(err, ErrEnclaveCorrupted)` iff `Corrupt > 0`; `errors.Is(err, ErrReleasedWithoutWipe)` iff `Unwiped > 0`. `Unwrap() []error` returns each failed backend's error, so `errors.Is`/`errors.As` reach them. |
| `BackendSweepFailure{Backend string; Err error}` | One `Sweeper` that returned an error: its registered name and that error, unchanged. |
| `ErrSweepInProgress` | This call was never admitted; it swept nothing. |

## Invariants

1. **One sweep at a time.** A second call waits for the slot only as long as its
   own `ctx` allows; a nil `ctx` only tries. A free slot is taken even under an
   already-done `ctx`. Serialization keeps the sweep generation single-writer:
   two overlapping sweeps would return it to even mid-sweep. The slot is a
   one-token channel rather than a mutex so a waiting caller can abandon it when
   its own `ctx` ends instead of inheriting the running sweep's bound.
2. **Never unmaps under a reader.** "Reader" is any holder of the enclave's lock:
   `WithBytes`, `EqualTo`, `Size`, `IsAlive`, `Freeze`, or a `Destroy` waiting
   its turn. Such an enclave is waited for while `ctx` is live and left mapped
   (and counted) when it ends. A slice kept past `WithBytes` is **not** a lock
   holder: the sweep can unmap the pages behind it.
   The sweep only ever *tries* an enclave's lock (a blocked `Lock` cannot be
   abandoned when `ctx` ends, and a pending writer stalls new readers), and it
   retries every registered entry on every pass, because a write `TryLock` loses
   to any momentary reader such as an `IsAlive` health probe. The wait is an
   event, not a sleep: the release that frees a held enclave wakes the sweep
   through a one-slot channel that coalesces wake-ups, drained at the start of
   each pass before any lock is tried, so no release is missed.
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
   admitted sweep; a call that is not admitted does not touch it. The parity is
   a sequence lock: a value sealed under an odd generation is suspect whatever
   the count later says. Bumping first means the race window yields a brief
   `ErrOpenabilityUnknown` (fail safe), never a nil from `Openable` about keys
   already destroyed.
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
   key). `Sealed` values are not swept: they own no locked pages (so
   including them would corrupt the count), destroying them under
   `ModePerOperation` would destroy data the device can still open, and a
   swept value would report `ErrEnclaveDestroyed` instead of the more accurate
   `ErrSealerWiped`.
8. **Never call it from inside a borrow** — it would wait for the borrow that is
   waiting for it, until `ctx` ends.
9. **Program-owned, never library-called.** It destroys every enclave in the
   process, including those of subsystems a library cannot know about. It is a
   cooperative teardown step, not a fault handler: it raises no panic of its
   own, and a corrupt enclave is reported and the sweep continues. A
   registered `Sweeper` that panics is the backend's own panic and is not
   recovered.
10. **Backends are swept second, outside the registry lock.** Phase two runs
    only after phase one has finished, still holding the sweep slot and with
    the generation still odd, so a backend's `Sweep` never races the
    locked-memory sweep or another `WipeAll`. It takes a snapshot of the registered `Sweeper`s
    (the default `"locked-memory"` backend excluded: phase one is its sweep)
    under the registry's read lock, releases the lock, sorts the snapshot by
    name and calls each once with the caller's `ctx`, unchanged (nil and done
    included). A `Sweep` may therefore `Register`; a backend registered after
    the snapshot waits for the next `WipeAll`. A panic in a `Sweep` is not
    recovered.

## Error semantics

The **count** is what is still held when the call returns, read from the
ledgers under their lock: enclaves still borrowed when `ctx` ended, enclaves
whose release the kernel refused, enclaves registered mid-sweep and not reached,
and orphaned mappings still refused. `0` means both ledgers were empty at that
instant — not that this package holds no mapped pages: a constructor maps and
locks its pages before it registers them (registration is its last step), so a
construction in flight when the count is read is not in it. It is a snapshot,
not a diagnosis; a non-zero count is most often workers that outlived the
shutdown. Calling again at once does not help: a live borrow is waited for
again, and an unchanged refusal is refused again. Each `Sweeper`'s held count
is added to it (a negative count counts as 0), read after its `Sweep` returns.

The **error**:

| Value | Meaning |
|---|---|
| `nil` | Admitted, and found nothing to report. A `ctx` ending during an admitted sweep is not an error. |
| `ErrSweepInProgress` | Not admitted. The count is still current; the running sweep reports its own findings to its own caller. |
| `*SweepError` | Admitted, and found canary corruption (`Corrupt`, counted once per entry per sweep, including every enclave whose `Destroy` reported corruption since the previous admitted sweep) and/or releases that fell back to an unwiped unmap (`Unwiped`), and/or registered backends whose `Sweep` failed (`Backends`, in name order). `Error()` is one line per non-zero count, then one line per failed backend: `enclave: backend "<name>" failed its sweep: <err>`. Never a nil `*SweepError` behind a non-nil error. |

Corruption is tallied by entry during the sweep, not read from the ledger: a
reclaimed corrupt entry is no longer on it, and one whose release was refused
reports corruption on every attempt.

Neither finding is a held page, so neither is in the count — except a corrupt
entry whose pages the kernel then refused to release, which is in both. A
corruption is reported again by each later sweep that retries that entry, until
its pages are reclaimed (detection is sticky while the mapping is held); once
they are, no later sweep reports it.

## Cost

Each acquisition of an enclave's lock adds two atomic adds on its `holders`
counter and one load of a package-level flag that only a sweep writes — no lock,
no allocation (`BenchmarkBorrow*`, `BenchmarkIsAliveParallel`). `registryMu`
serializes construction and destruction process-wide for one map operation each;
it is never held together with an enclave lock or across a syscall, so it cannot
deadlock against a borrow. Lock order: the sweep slot, then `registryMu`.
An enclave whose release keeps failing stays on the ledger for the process
lifetime, by design: dropping the only reference to pages the kernel still has
mapped would make them unreachable and unretryable. The same holds for the
mapping of a failed construction whose rollback was refused (the orphan ledger).
An orphan is held in an enclave no caller can reach, so the sweep releases it
through the same lock attempt and the same bookkeeping step (`settleRelease`:
refund once, note corruption, leave the ledger) as a live enclave, and
`Destroy` books its own release through that step too.

## Configuration and persistence

None.

## Test strategy

Package-private hooks, nil in every build except the tests that set them, make
each ordering observable without timing: `sweepWaitingForTest` (about to block on
a borrow), `sweepPassForTest` (start of each pass), `sweepParkedForTest` (after
the generation bump, before destroying), `sweepAdmissionWaitForTest` (about to
block for the slot). Release refusals and corruption are injected through the
memory seams described in
[memory-enclave/engineering.md](../memory-enclave/engineering.md#test-strategy).
Phase two is driven by registered fake `Sweeper`s that record their call order
and `ctx`, and one that calls `Register` from inside `Sweep`.
Borrow-path cost is measured by the borrow benchmarks (`make bench`).

## Observability

The return values are the whole interface. Log the count and the error at
shutdown; a `*SweepError` with `Corrupt > 0` is a memory-safety event that has
already happened in the process.
