# Backend detection — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

Design: [architecture.md](architecture.md). Code: `detection.go`, and the
`Prober` capability in `backend.go`.

## Exported surface

```go
type Prober interface {
	Backend
	Rank() int
	Probe(ctx context.Context) error
}

const CapabilityProbe Capability = "probe"

type ProbeResult struct {
	Backend string
	Rank    int
	Err     error
}

func Detect(ctx context.Context) (Backend, []ProbeResult)

var ErrBackendUnavailable error

type ProbeError struct {
	Backend string
	Cause   error
}
```

| Symbol | Contract |
|---|---|
| `Prober.Rank` | How secure the backend is; higher is more secure, and locked memory is 0. Fixed for the backend's life, never blocks, never panics. |
| `Prober.Probe` | Nil when this host can run the backend, else the backend's own typed error. It is safe to call repeatedly and concurrently, and its verdict is stable. It changes no lasting state and never panics. A nil `ctx` never ends. |
| `Detect` | Returns the usable `Prober` with the highest rank, or `DefaultBackend()` when none ranks above 0. The results hold one entry per registered backend, the default included, in byte order of name. It never fails, runs only when called and is safe for concurrent use. |
| `ProbeResult` | `Backend` is the registered name. `Rank` is the reported rank, or 0 for a backend that is no `Prober`. `Err` is nil when usable, else why the backend was passed over. |
| `ProbeError` | A `Probe` failure: `Backend` names the backend, and `Cause` is what its `Probe` returned. |
| Default backend, `Allocator` | `Prober`s of rank 0 whose `Probe` returns nil: locked memory is usable wherever the module runs, and a refused lock surfaces at the constructor. |

## Invariants

1. **Only registered backends are considered.** `Detect` reads the registry
   once and probes exactly what it holds. A backend registered during a call
   waits for the next call.
2. **Nothing probes unless `Detect` is called.** Importing and `Register` call
   no `Rank` or `Probe`.
3. **`Detect` always returns a backend.** Locked memory is always registered
   and always usable, so it is the floor.
4. **A backend is selected only if it is a `Prober`, it probed usable, and it
   ranks strictly above the current selection.** The selection starts at
   locked memory, and backends are visited in byte order of name. So a tie
   goes to locked memory, then to the first name. The result never depends on
   map order.
5. **Every registered backend gets a result**, and the probe of each gets the
   caller's `ctx` unchanged.
6. **No lock is held while probing**, so `Register`, `Lookup` and other
   `Detect` calls proceed during a slow probe.

## Error semantics

`Detect` returns no error. Each passed-over backend's reason is in its
`ProbeResult.Err`:

| `ProbeResult.Err` | Means | Matches |
|---|---|---|
| nil | Usable. If it is not the selection, it was outranked or lost a tie. | — |
| `*ProbeError` | Its `Probe` failed: the host lacks the device, firmware or permission. | `ErrBackendUnavailable`; it unwraps to `Cause`, so `errors.Is` also reaches the backend's own error. |
| `*CapabilityError` | It is no `Prober`, so it has no rank to compare. Select it by name with `Lookup`, or make it a `Prober`. | `ErrCapabilityUnsupported`; `Capability` is `CapabilityProbe`. |

Texts are the sentinel's, then the quoted backend name, then the cause's text
when there is one. Match with `errors.Is` and `errors.As`, never the text.

## Cost

One read lock to snapshot the registry, a sort of the names, and then one
`Rank` and one `Probe` per registered backend. The probes cost whatever each
backend's own check costs: a device open, a CPUID or a firmware query. Call
`Detect` once at startup, not per operation.

## Configuration and persistence

None. `Detect` keeps no state: each call probes afresh, and the selection is
returned to the caller, not stored.

## Test strategy

`detection_test.go` covers selection with only the default registered, the
higher of two usable backends, passing over an unusable higher-ranked backend
(with its `ProbeError`, cause and sentinel), and falling back when the only
others are unusable or rank below 0. It also covers a tie with locked memory
under a name that sorts first, a tie between two names (repeated), a backend
that is no `Prober`, name order of the results, probing only on the call with
the caller's `ctx` (and a nil one), concurrent `Register` and `Detect` under
`-race`, `ProbeError`'s text and `Unwrap`, and the default, an `Allocator` and
a nil allocator as rank-0 `Prober`s. `make test-backend-detection` runs them
with the rest of the root package.

`make integration-test-backend-detection` runs the `TestBackendDetection_`
tests in `test/integration/enclave`. On a plain host with no other backend
registered, detection selects locked memory, and a memory enclave made
afterwards reports that backend; this is the release criterion. With an absent higher-ranked device
and a backend that is no `Prober` registered, detection still falls back, and
each result says why.

`backendtest.TestBackend` checks a backend claiming `CapabilityProbe`: its rank
is stable, and its probe verdict is stable across calls, under a nil `ctx` and
under concurrent calls, without panicking
([backend conformance](../backend-conformance/engineering.md)).

## Observability

`Detect`'s results are the record of the choice: log each `ProbeResult` with
the selected `Backend().Name()` at startup, next to `BackendNames()` and
`HardenProcess`'s report. Each passed-over backend carries its reason in
`Err`, and the selection is the one with no error and the highest rank. Every
handle's `Backend().Name()` then says where its material is held.
