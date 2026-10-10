# Locked-memory budget and admission — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-09
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Who does what

- **The binary** (the code that owns `main`) sizes one budget for the whole
  process and installs it, before anything allocates.
- **A library** never builds or installs a budget. It asks for the process
  budget and allocates through it.

## In the binary: size and install the budget

```go
func main() {
	budget, err := enclave.NewAllocatorWithinRLimit(64 << 20) // 64 MiB of locked pages
	if err != nil {
		log.Fatal(err) // e.g. ErrBudgetExceedsRLimit names both figures
	}
	if err := enclave.SetAllocator(budget); err != nil {
		log.Fatal(err) // ErrAllocatorInstalled: a successful ProcessAllocator call installed the default first
	}
	// ... construct the libraries that use locked memory ...
}
```

Install before any library calls `ProcessAllocator` — the first such call that
succeeds installs a default and locks the configuration (a call whose limit
discovery fails installs nothing and leaves `SetAllocator` available). Leave headroom below the
ceiling for locked memory taken outside the budget (unbudgeted constructors,
`Sealed.Open`, sealing keys).

If you install nothing, the default budget equals the discovered ceiling, or is
unbounded when no ceiling binds. It leaves no headroom.

## Size it in pages

Every enclave costs at least one page. Size with `LockedSize`:

```go
budget, err := enclave.NewAllocator(100 * enclave.LockedSize(32)) // 100 small credentials = 100 pages
```

## Derive a budget from the host

```go
limit, err := enclave.DiscoverLockedMemoryLimit()
if err != nil {
	return err // ErrLimitDiscoveryFailed: the ceiling could not be read
}
var size int64 = 64 << 20 // from configuration
if limit.Bounded {
	size = limit.Bytes / 2 // leave half for everything else
}
log.Printf("locked-memory budget %d bytes (source: %s)", size, limit.Source)
budget, err := enclave.NewAllocatorWithinRLimit(size)
```

When `Bounded` is false — `Source` prints as `RLIMIT_MEMLOCK unlimited`,
`RLIMIT_MEMLOCK not enforced (CAP_IPC_LOCK)` or `no locked-memory limit on this
platform` — there is no number to size against; take the budget from
configuration.

## In a library: allocate through the process budget

```go
a, err := enclave.ProcessAllocator()
if err != nil {
	return err
}
key, err := a.NewSized(32)
switch {
case errors.Is(err, enclave.ErrBudgetExhausted):
	return errBusy // refuse this request, not the process
case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
	return err // admitted, but the kernel refused: the ceiling is shared
case err != nil:
	return err
}
defer key.Destroy() // returns the reservation
```

For a path that receives untrusted input before authentication, give it its own
smaller allocator funded from the process budget (`TransferTo`), so a flood is
refused there and authenticated work keeps its headroom.

## Retune at runtime

| Need | Call | On refusal |
|---|---|---|
| Raise or lower the budget | `a.SetLimit(n)` | `ErrBudgetInUse` (below reservations), `ErrBudgetExceedsRLimit` (raise above the ceiling, checked allocators) — nothing changes |
| Record a ceiling that already moved | `excess, err := a.ForceLimit(n)` | Only a negative `n` (`ErrInvalidBudget`). `excess > 0` is how far reservations exceed the new budget; a request is admitted again only once reservations fall by `excess` plus that request's page-rounded size |
| Stop admitting, keep live enclaves | `excess, _ := a.ForceLimit(0)` | Cannot fail (only a negative budget is refused); `excess` is the reservations still live. `SetLimit(0)` is **not** this: lowering a positive budget to 0 with any live reservation returns `ErrBudgetInUse` and changes nothing. (On a budget that is already 0, `SetLimit(0)` is a no-op returning `nil` — equal limits change nothing.) |
| Move headroom between two budgets | `src.TransferTo(dst, n)` | `ErrBudgetInUse` if `src` cannot spare it; `ErrInvalidTransfer` for `n <= 0`, nil or same `dst` |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ErrBudgetExhausted` | Budget full | Destroy enclaves sooner, raise the budget, or refuse the request. `BudgetError` shows requested/in-use/limit. |
| `ErrLockedMemoryUnavailable` with budget left | Something outside this allocator used the shared ceiling, or a cgroup binds below it | Leave headroom; raise `RLIMIT_MEMLOCK`; account for `Open` and sealing pages. |
| `ErrBudgetExceedsRLimit` at startup | Configured budget above `ulimit -l` | Lower the budget or raise the limit. |
| `ErrAllocatorInstalled` | `SetAllocator` after a library's `ProcessAllocator` call succeeded and installed the default | Install earlier in `main`. |
| `Available()` is 0, `InUse() > Limit()` | `ForceLimit` over-subscribed the allocator | Wait for enclaves to be destroyed, or raise the budget. |
| `ErrNilAllocator` from `New`, `NewSized` or a retune | The `*Allocator` is nil: an unset field or a skipped configuration step | Construct the allocator, or use `ProcessAllocator()`. `New` has already wiped the data. |
| `ErrAllocatorNotConstructed` from any call | An `enclave.Allocator{}` declared by value instead of built by a constructor | Use `NewAllocator`, `NewAllocatorWithinRLimit` or `ProcessAllocator()`, and pass the `*Allocator` around; a copied value shares the original's budget. |
| Budget not returned after a failed allocation | The kernel refused to unlock the rolled-back pages; the charge is kept until a `WipeAll` reclaims them | Expected; the shutdown sweep refunds it. |

## Upgrading

Migration guidance lives in one place: [Upgrading](../README.md#upgrading).
