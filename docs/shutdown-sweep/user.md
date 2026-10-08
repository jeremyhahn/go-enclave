# Shutdown sweep — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Who calls it

Only the program that owns the process — `main`, or its signal handler. A
library must never call `WipeAll`: it destroys every enclave in the process,
including ones other components are still using.

## Wire it into shutdown

Take the deadline **at shutdown**, inside the deferred call; one created at the
top of `main` would have expired long before it is needed.

```go
func main() {
	defer wipeAtExit()
	// ... run the program; stop workers before returning ...
}

func wipeAtExit() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	n, err := enclave.WipeAll(ctx)
	var sweep *enclave.SweepError
	switch {
	case errors.As(err, &sweep):
		log.Printf("enclave: sweep found %d corrupted, %d unwiped; %d still held",
			sweep.Corrupt, sweep.Unwiped, n)
	case errors.Is(err, enclave.ErrSweepInProgress):
		log.Printf("enclave: another sweep was running; %d still held", n)
	case n != 0:
		log.Printf("enclave: %d still held at exit", n)
	}
}
```

Order matters: stop the goroutines that read or create enclaves **before** the
sweep. An enclave still being read is waited for until the deadline and then
left mapped; one created during the sweep may be returned to its creator
already destroyed.

## Reading the results

| Result | What to do |
|---|---|
| `0, nil` | When the count was read, nothing was on the ledgers: every registered enclave and orphaned mapping had been released. A constructor still running at that instant had pages mapped but not yet registered, so stop constructing before you sweep. |
| `n > 0, nil` | `n` enclaves or mappings still held: workers outlived the shutdown (still reading or constructing), or the kernel is refusing releases. Calling again immediately rarely helps — fix the shutdown ordering. |
| `*SweepError` with `Corrupt > 0` | Something wrote into memory it did not own. Treat as a security incident. |
| `*SweepError` with `Unwiped > 0` | `mprotect` is denied in this environment; those pages were unmapped without the in-process wipe. They were locked for their whole life (never swapped), and the kernel zeroes anonymous pages before reusing them. |
| `ErrSweepInProgress` | This call swept nothing because another sweep was running and this call's context ended (or was nil). The count is current. |

## Effects on sealing

In every mode the sweep destroys enclaves that `Open` returned and any
in-process sealing key it can reclaim; an enclave still borrowed when the
sweep's context ends is skipped and survives. In `ModeRootKey` (the default)
the sealer needs **both** its root and its current KEK: if the sweep destroyed
either one, every value that sealer sealed is permanently unopenable and
further seals fail with `ErrSealerWiped`. Only if both survived does it keep
working — and a sweep that overlapped a KEK rotation in progress leaves the
sealer wiped even if the root survived it, because rotation discards its new
generation and destroys the hierarchy when it detects the overlap. A `SoftwareProvider` used in `ModePerOperation` likewise keeps working
only if its root survived. With a `ModePerOperation` provider whose key is held
by a device, sealed values stay openable. Sealed values themselves are never destroyed by the sweep and keep
reporting `IsAlive() == true`; use `Openable()` to ask. See
[sealing](../sealing/user.md#after-a-shutdown-sweep).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Shutdown hangs in `WipeAll` | `context.Background()` (or no deadline) and a goroutine is still borrowing an enclave, or `WipeAll` was called from inside a borrow | Pass a deadline; stop workers first; never call it inside `WithBytes`. |
| A crash (SIGSEGV) right after the sweep | A goroutine kept a slice past `WithBytes` and read it after the sweep unmapped it | Never retain borrowed slices; stop readers first. |
| `ErrEnclaveDestroyed` in a component after shutdown began | The sweep destroyed its enclave | Expected; stop the component before the sweep. |
| Count non-zero every time | A release the kernel keeps refusing (e.g. `vm.max_map_count` reached) | Inspect the host; the entries stay on the ledger and are retried. |

## Upgrading

Migration guidance lives in one place: [Upgrading](../README.md#upgrading).
