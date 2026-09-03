# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`providertest` — the conformance suite for the provider seam** (#64).
  go-enclave ships it; any implementer of `KeyProtector` or `RootUnsealer` — a
  TPM, an HSM, a cloud KMS — runs `providertest.TestProvider` against its own
  provider in its own repository. The shape is `fstest.TestFS`'s: one call, an
  error naming every property that failed, no import of `testing` and no
  dependency in either direction.

  **The property it enforces is RETENTION, not destination.**
  `Unprotect(blob, key []byte)` and `UnsealRoot(dst []byte)` constrain where the
  plaintext is written and say nothing about what the provider KEEPS. A provider
  may write into the caller's locked slice and hold its own copy forever, and
  from this package's side a conforming signature and a retaining implementation
  are indistinguishable. That is the unenforced half of `KeyProtector`'s
  "protects short key material outside this process", and it is the same gap
  that produced #33's fail-open: #33 made in-process retention *declarable*, and
  this makes it *detectable*.

  It does NOT assert that a provider never materializes plaintext. Measured
  against go-xkms's backends, every one returns a fresh `[]byte` from its
  decrypt — the native TPM2 path is `RSADecrypt(...) ([]byte, error)`, the
  PKCS#11 wrapper returns a slice, and the AWS, GCP, Azure and Vault backends
  return HTTP response bodies. No hardware decrypts into an arbitrary caller
  page, so demanding that would fail every real backend for conforming. What is
  required is the wipe of the transient, which the interface already states in
  words and the sweep below measures.

  Two instruments, ranked and not interchangeable. The **spy** is primary and
  deterministic: the suite is the caller, so it owns every slice the provider is
  handed, records the exact destination, asserts under a control that it held
  the material *at return time* — without which a later zero reading cannot be
  told apart from a destination that was never populated — and then requires
  that no later call disturbs it in either direction. The **residue sweep** is
  corroboration: it is the only instrument that can see a retained COPY, so it
  cannot be dropped, but a sweep that does not wipe its scan buffer replants its
  own needle and a sweep-based residue claim is unfalsifiable for anything
  transiting a stack local (both measured, #45). It wipes after every mapping,
  refuses to report a negative it has not first proven it could turn positive,
  and is skippable only with a recorded reason echoed into the log.

  Every property has a planted violator in the package's own tests that breaks
  exactly that property, and the test asserts the suite goes red and names it —
  including the headline control, a provider that retains a copy on purpose.
  A conformance suite that cannot fail is worse than none, because it certifies.

  `SoftwareProvider` passes the whole suite in both modes; that run is the
  positive control against the suite over-asserting.

  Two escape hatches, both taking a **reason** rather than a boolean, and both
  echoed into the log so a green run cannot hide what it did not measure:
  `SkipResidueSweep` for a transit the provider cannot reach (a cloud KMS
  receives its plaintext in an HTTP response body owned by `net/http`), and
  `SingleUseRoot` for a provider that consumes a one-shot handle on a
  successful unseal — the seam guarantees only that a `Sealer` calls
  `UnsealRoot` at most once, so a suite that calls it twice would fail a
  provider for honoring the contract.

### Changed

- **The test suite runs across `-cpu=1,2,8`** in CI and in `make test` /
  `make coverage` (#61). One direction of the retune-versus-admission race —
  a lowering that takes the contested page while `reserve` sits between its read
  of the headroom counter and the compare-and-swap that acts on it — is caught
  by contention rather than by arrangement, because giving it a test seam would
  put a branch on the lock-free admission path this type exists to keep clear of
  one. That makes the runner's core count part of the oracle. Measured against
  `reserve` regressed to read-then-subtract, 10 whole-package runs per setting
  on an 8-core host: `-cpu=1` killed it 0/10, `-cpu=2` 6/10, `-cpu=8` 10/10 —
  so a single-core or heavily-pinned runner cannot see the defect at all, and
  the list is what guarantees a multi-core run happens anyway. No production
  code changed. Cost: the CI test step goes from 74s to 195s, against a
  30-minute job timeout.

- `make lint` pins golangci-lint v2.13.2 — the floor for linting Go 1.27;
  v2.12.2's vendored analysis tools cannot parse the 1.27 standard library.
  CI already runs the same version baked into the runner image.

- **The `RLIMIT_MEMLOCK` check is now sticky: an allocator built by
  `NewAllocatorWithinRLimit` carries it for life.** (#46) `SetLimit` re-reads the
  ceiling and refuses to raise that allocator's budget above it with
  `ErrBudgetExceedsRLimit`, the same sentinel and the same `RLimitError` the
  constructor uses. `TransferTo` applies it to the allocator it CREDITS, since a
  transfer is a raise on the receiving side.

  Before this, the check bound a budget for exactly as long as it took to call
  `SetLimit`: #43 refused an over-ceiling budget at construction and #44 let the
  same allocator be raised straight back over it, so two entry points to one
  allocator disagreed about whether the kernel ceiling applied. It was never a
  safety hole — admission fails safe with `ErrLockedMemoryUnavailable` — but it
  lost the diagnostic the check exists for, which is failing at the setting that
  caused the problem rather than at peak load.

  **The ceiling is read fresh on every raise, never cached.** It moves: a
  setrlimit from any thread, a container resized underneath the process. A
  budget compared against a figure from startup would refuse a raise the kernel
  now permits, or permit one it now would not. The syscall is on a control-plane
  path that runs rarely, and it is taken outside the retune mutex so it cannot
  stall other retunes or the observability getters. **Nothing was added to the
  admission path**, which still reads no ceiling at all.

  Three boundaries, each with a test that fails without it:

  - **Opt-in.** A plain `NewAllocator` allocator is never checked, on any path.
    Applying the ceiling to every allocator would break callers who chose the
    unchecked constructor deliberately.
  - **Raises only.** A lowering is never refused on a ceiling, or an
    over-ceiling allocator could not move back towards compliance.
  - **`ForceLimit` overrides it**, as it overrides every other refusal on this
    type — it is the method that exists to do what `SetLimit` refuses. That is
    documented on the method rather than left implicit, so the contract is not
    mistaken for one that cannot be bypassed, and it is the escape hatch when
    discovery itself fails. The allocator stays bound afterwards: an override is
    not an opt-out.

  A discovery failure during a raise is reported as `ErrLimitDiscoveryFailed`
  and refuses the raise — nothing was compared, so nothing passed.

- **The package docs no longer present shipped API as future work** (#65).
  `doc.go` and `README.md` described `OpenWith` as "tracked as issue #17" and
  `Openable` as "tracked as issue #33" after both had shipped, and both files
  plus `provider.go` called the `crypto.Decrypter` composition an open
  decision after it was ruled will-not-ship (#50). These are package docs, so
  they reach `go doc` and pkg.go.dev: a reader was told a method they could
  call right now was a plan.

  The sentences were replaced rather than deleted, because each was doing real
  work — explaining why an obvious gap existed. `OpenWith` is now described as
  the admitted variant, keeping the reasoning about `Open` charging no budget;
  `Openable` is described by the four answers it returns, keeping the point
  that `IsAlive` cannot answer that question and must not try; and the
  `Decrypter` composition is stated as settled, on SCOPE — this package
  defines the seam and ships the software default, so a bridge adapting device
  backends belongs with the layer that owns them.

  The scope wording replaced an earlier draft that gave a MEMORY reason:
  that `crypto.Decrypter` returns a fresh slice and so "structurally cannot"
  decrypt into caller-locked memory. That claim is false, and `provider.go`
  itself refutes it thirty lines further down, where `KeyProtector`'s contract
  says in as many words that a provider whose underlying API returns a fresh
  slice must copy into the destination and wipe its transient. Every realistic
  backend is in exactly that position — the native TPM2 path is
  `RSADecrypt(...) ([]byte, error)`, PKCS#11 wrappers return a slice, and the
  cloud KMS backends return response bodies — so a fresh-slice return is the
  normal case the contract already accommodates, not a disqualifier. A public
  doc asserting a structural impossibility that the adjacent contract permits
  is worse than one that simply says where the code belongs.


### Added

- **The hardware-rootable two-mode sealing seam (#22): `SealedEnclave`,
  `Sealer`, `KeyProtector`/`RootUnsealer`, and `SoftwareProvider`.**
  Material sealed at rest as an envelope — a fresh
  per-value DEK generated into locked memory seals the material with
  AES-256-GCM (`NewGCMWithRandomNonce`, so nonce misuse is structurally
  impossible), and the DEK itself is protected by a PLUGGABLE crypto
  provider. go-enclave ships pure software only and defines the seam; TPM,
  HSM and cloud-KMS providers are injected from higher layers through
  `NewSealer(WithProvider, WithMode)` or the one-shot process default
  (`SetSealer`; `NewSealed` uses it, lazily installing the software default).

  **Providers must supply confidentiality AND authenticity** —
  `Unprotect`/`Open` fail for any blob the provider's own `Protect` did not
  produce, so a hardware-sealed value is unforgeable as well as unreadable. A
  bare RSA decryption key does not qualify (anyone holding its public key
  could forge an envelope — the finding that sank the earlier
  confidentiality-only design); a `FromDecrypterSigner` composition closing
  that gap with stdlib key interfaces was built, fully measured, and SPLIT
  OUT of this change during review — whether a `crypto.Decrypter` bridge
  ships at this layer at all is an owner decision, tracked as issue #50
  with the measurements attached. The wrapped-DEK blob is bound to the ciphertext as
  AAD, so a re-paired envelope — one value's blob against another's
  ciphertext, both halves individually authentic — fails the tag.

  **Two config-selected modes, same envelope** (`Mode` carries the honest
  comparison): `ModePerOperation` calls the device per seal/open, on the DEK
  only — the key that opens everything never enters the process, and a
  memory-reading adversary is bounded to values open during their window.
  `ModeRootKey` (the default) unseals a root once and runs an in-memory KEK
  hierarchy — the scale accommodation, stated plainly as such: after the
  unseal a live-memory adversary gets everything; what remains is the origin
  and gating of the root (device-held, PCR-bindable). KEK generations rotate
  at 2^31 wraps against the AES-GCM message bound; retired generations are
  retained as root-wrapped heap blobs — bytes, not locked pages — so rotation
  never strands a value.

  **A shutdown `WipeAll` destroys the hierarchy's keys and the sealer FAILS
  CLOSED with the distinct `ErrSealerWiped`** — never silent re-keying, which
  would make a lifecycle bug present as `ErrSealedAuthentication` and read as
  a security incident. Mode asymmetry stated on `WipeAll`: a device-held
  per-operation key survives a sweep, an in-process hierarchy does not.
  Recovery happens INTO caller-supplied memory throughout — `Open` decrypts
  straight into locked pages sized exactly (verified by process-memory
  sweeps), and the seam's recover-into signatures preserve that for providers.

  **Foreign sealed bytes remain out of contract** — no unmarshaller, pinned
  by an AST guard test whose rationale is rewritten from the obsolete
  forgery argument to the real one: there is no persistence contract, and an
  entry point would make the internal format accidentally permanent.

  `GOEXPERIMENT=boringcrypto` builds cannot seal, by decision (#34, closed):
  the only route would be `cipher.NewGCM` with caller-supplied nonces,
  weakening every build to serve a mechanism superseded by the native FIPS
  140-3 module. The refusal is documented in the package docs, on the
  constructor, and at the AEAD call site.

  Construction fails closed on a nil provider — typed or untyped — with
  `ErrProviderMode` rather than defaulting (which would silently swap a
  configured hardware provider for software) or panicking at the first seal
  (which is where a typed-nil provider detonated before review caught it).
  One test-infrastructure hardening came out of chasing a flake in the
  split-out adapter's doc-test: the shared process-memory sweep now WIPES
  its scan buffer on every return path, because an unwiped buffer let a
  later sweep find an earlier sweep's copy of the needle and report a heap
  residue that never existed in the code under test. (The second smear
  channel found — a control copy stranded on a freed, grown-away goroutine
  stack, unreachable by any wipe — is a runtime property recorded in the
  sweep's comments as a constraint on future sweep-based tests.) The
  dominating key exposure remains the `withAEAD` key-schedule copy that
  persists past GC in every mode with every provider.

  Supersedes the PR #16 single-process-key implementation per the adopted
  #22 design; its reviewed AEAD discipline, residency sweeps, key-schedule
  threat-model audit and locked-memory-exhaustion evidence carry forward
  into this envelope. New errors: `ErrSealFailed`,
  `ErrSealedAuthentication`, `ErrPlaintextEscaped`, `ErrMaterialTooLarge`,
  `ErrSealerWiped`, `ErrProviderMode`, `ErrInvalidMode`,
  `ErrSealerInstalled`, `ErrNilSealer`, `ErrProviderMessageLimit`.

- **`NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error)` — a constructor
  that copies without consuming its source.** `NewMemoryEnclave` takes ownership
  and wipes the caller's slice on every return path; that stays the default and
  stays right. Some callers cannot honor it — a buffer owned by someone else, a
  fixture handed back on every call, material compared against the bytes it was
  built from — and they were composing `NewMemoryEnclaveSized` + `WithBytes` +
  `Destroy`-on-error by hand instead, the same eight lines in two packages of one
  consumer already. Omitting that `Destroy` leaks a locked page on a path nobody
  tests, which is the kind of mistake a constructor should make impossible rather
  than document.

  **The result is FROZEN read-only**, matching `NewMemoryEnclave` and not
  `NewMemoryEnclaveSized`. The material is complete when the constructor returns,
  so writable pages would buy nothing and would give up the protection against a
  stray write through a retained `Open` slice. The decision is in the doc comment
  because guessing it wrong is not an error — a write through frozen pages
  **faults the process** — and because the two older constructors disagree, so a
  caller generalizes from whichever it met first.

  **What the caller accepts is stated in the doc comment, not glossed:** an
  unprotected copy of the material remains on the ordinary Go heap for as long as
  the source lives. That is exactly what this package exists to avoid, and this
  constructor does not undo it — it protects the copy it holds and makes no claim
  about the source, which nothing here can wipe later because only the caller
  knows when it is done. Material that should never touch the heap at all belongs
  in `NewMemoryEnclaveSized`.

  `NewMemoryEnclave` is now implemented as this constructor plus the wipe, so the
  two cannot drift apart in the mapping, freeze or cleanup sequence — which is the
  same divergence the duplicated hand-rolled composition was heading for.

- **`(*MemoryEnclave) Freeze() error` — restore fault-on-write once a sized
  enclave's fill is done.** `NewMemoryEnclave` freezes its pages read-only as
  the material moves in, so a write through a slice retained past its borrow
  faults. `NewMemoryEnclaveSized` cannot: pages that have to be filled cannot
  arrive read-only, and until now they stayed writable for the enclave's whole
  LIFETIME. A stray write there silently corrupted the material, which is a
  strictly worse failure than a fault, and the window was the lifetime rather
  than the fill. `Freeze` closes it — after it returns, a sized enclave has
  exactly the protection a move-constructed one has.

  It is **idempotent** and **not reversible**. A second `Freeze` is a no-op, and
  so is freezing an enclave that arrived frozen, so a caller handed an enclave
  can freeze it without knowing which constructor built it. There is
  deliberately no `Melt`: a re-mutable enclave reopens the window this closes,
  and the fill is the only reason the pages were ever writable.

  It takes the **write lock**, so it waits out in-flight borrows exactly as
  `Destroy` does. That is not incidental: under the read lock the `mprotect`
  could land between two stores of a goroutine that is still filling, and a
  method whose purpose is to turn silent corruption into a fault would be
  manufacturing the fault itself. It must therefore never be called from inside
  a borrow on the same enclave, which deadlocks like any other nested call.

  A refused `mprotect` returns `ErrLockedMemoryUnavailable` (as a
  `LockedMemoryError`) and leaves the enclave **alive, writable and otherwise
  untouched** — the caller keeps what it had and knows the property was not
  established. `NewMemoryEnclave` destroys the mapping on that same failure only
  because a constructor cannot hand back a half-built enclave; here the caller
  already owns one, and destroying it underneath them would turn a failed
  hardening step into lost key material.

  The name is `Freeze`, not `Seal`. It names the mechanism, matches the internal
  `mapping.freeze` and memguard's spelling, and does not collide with the AEAD
  `Seal` that consumers of this library have in scope at exactly the call sites
  that hold key material — the same reasoning that keeps the type from being
  called a "secret".

  What it costs, stated because it is a real trade: freezing moves the
  material's wipe at `Destroy` time BEHIND a syscall that can be refused.
  `Destroy` wipes first, before anything deniable, while the region is still
  writable; a frozen region has to be made writable again first. A denied
  `mprotect` sends any enclave down #38's unwiped-release path — pages handed
  back with a bare `munmap`, `DestroyErr` reporting `ErrReleasedWithoutWipe` —
  but **a frozen enclave is the only kind whose material is still there when it
  goes**, because `wipeAndVerify` skips its early wipe exactly when the pages are
  read-only. That is measured from inside the unmap seam, in both arms, rather
  than argued. Nothing leaks either way: the pages were `mlock`'d for their whole
  life and the kernel zeroes an anonymous page before reuse. That is already true of every enclave from
  `NewMemoryEnclave` and `NewMemoryEnclaveCopy`, and an `mprotect` refused on a
  region this process already owns is a far narrower hazard than an unbounded
  window in which a retained slice rewrites a key with nothing to announce it.

  The evidence is by execution, not by assertion: a subprocess fills a sized
  enclave, freezes it, and writes through a retained slice — it must die, and
  must not have printed its survival marker. The in-process control does the
  same write on an unfrozen enclave and requires it to SUCCEED, since an
  implementation that froze sized enclaves at construction would break every
  consumer of them. (#6)

- **`NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error)` — the
  startup check for a locked-memory budget.** It discovers the process's
  `RLIMIT_MEMLOCK` and **refuses** a budget above it, returning
  `ErrBudgetExceedsRLimit` (as an `*RLimitError`) naming both the budget and the
  discovered ceiling. A service whose budget was never satisfiable learns it
  while starting, from an error that names the number to change, instead of at
  peak load from an allocation failure several layers from the setting that
  caused it.

  It fails closed rather than warning and continuing: a guard that reports a
  problem somewhere nobody correlates with the failure it later causes is the
  pattern this package exists to remove. And it is a **constructor error**, not
  an exit — a library must never `os.Exit`, `log.Fatal` or panic over a host's
  resource configuration, so the decision stays with the application.

  `NewAllocator` is unchanged and still accepts any positive budget, so nothing
  existing changes behavior.

- **`DiscoverLockedMemoryLimit() (LockedMemoryLimit, error)`**, with
  `LimitSource` and its `String`, for **deriving** a budget from the host rather
  than guessing one — and for logging where the figure came from. "8 MiB because
  `RLIMIT_MEMLOCK` said so" and "8 MiB because nothing bounded us and the config
  asked for it" are the same number and different facts.

  Three readings are handled explicitly rather than arithmetically. `RLIM_INFINITY`
  is all-bits-set, which as an `int64` is `-1` — below every budget, so treating
  it as a number would refuse them all; it reports as unlimited, and so does a
  finite limit too large to represent as the `int64` a budget is. A process
  holding **`CAP_IPC_LOCK`** may exceed the limit outright, so the figure is
  reported as `LimitNotEnforced` and refuses nothing: failing a correctly
  configured privileged service at startup, over a number the kernel will not
  apply to it, is worse than the late failure this check exists to prevent.

  The reading is a **snapshot and an upper bound on what may be assumed**, never
  a guarantee. The ceiling is process-wide and shared, a cgroup v2 `memory.max`
  frequently binds below it in a container, and it can move afterwards.
  `ErrLockedMemoryUnavailable` remains the authority on what may actually be
  locked. It is read once, at construction, and never on the allocation path.

  The ceiling is read on **Linux and on the five BSDs**, all of which define
  `RLIMIT_MEMLOCK`. `LimitUnsupported` is reported only where a platform
  genuinely exposes none — Windows bounds a working-set size instead — because
  reporting it where a ceiling *was* readable is a fail-open guard: the budget
  was checkable, the constructor said nothing, and the failure lands later under
  allocation pressure. There the constructor refuses nothing, which is the
  deliberate contract: a diagnostic that cannot run is absent, not violated, and
  refusing every budget would push callers back to the unchecked constructor and
  delete the check where it does work. `LimitUnsupported` rather than
  `LimitUnlimited` because "we did not look" is not the same claim as "the
  kernel says there is no ceiling".

  The BSD path has no CI — this repository's runners are Linux-only. Its
  classification is shared with Linux in `classifyRlimit` and tested against
  **both** platforms' `RLIM_INFINITY` sentinels, which do not agree: the BSDs
  use the largest positive `int64` and Linux all-bits-set, so reading one with
  the other's value silently yields a bounded ceiling of nine exabytes or of
  -1. Only the syscall and the sentinel constant go unexercised, and a mistake
  there fails loudly at startup rather than quietly later.

- **`ErrLimitDiscoveryFailed` and `LimitDiscoveryError`** for a ceiling that
  could not be READ, wrapping the syscall failure and reachable with
  `errors.As`. Nothing was compared, so it is deliberately neither a verdict on
  the budget nor a shortage of locked memory.

  Resolves #11 (acceptance criterion 2 of #2).

- **`(*SealedEnclave) OpenWith(a *Allocator) (*MemoryEnclave, error)` — the
  admitted open (#17).** `Open` allocates through the UNADMITTED constructors,
  so a caller bounding locked memory through an `Allocator` had no way to bound
  what opening a credential cost. That matters here because of WHEN this type
  allocates: `NewSealed` takes locked memory once, for keys, but `Open` takes a
  fresh locked page on EVERY call — a service opening a secret per connection
  allocates a locked page per connection, entirely outside the budget it
  configured. Locked memory is a process-wide ceiling, so that is the
  request-rate-driven exhaustion an `Allocator` exists to turn into a typed
  refusal.

  **One reservation per open, taken FIRST.** The destination is the only
  admitted allocation and it is the gate: an open the budget refuses has
  allocated no locked memory and has not touched a key. The transient key pages
  an open needs on the way — the per-value DEK, and for a retired KEK
  generation that generation's key — are deliberately NOT charged, so the
  process peak can exceed the budget by up to two pages per open IN FLIGHT,
  bounded because nothing transient is allocated until a reservation has been
  granted. The allocation order changed for that reason: the destination now
  precedes the DEK, where before budgets existed the DEK came first.

  Charging the transients as additional reservations was implemented first and
  rejected, and the reason is recorded on `OpenWith` because it is the kind of
  accuracy that costs availability. Two reservations per open let concurrent
  callers fragment a budget against themselves: under a budget sized for one
  open, two callers can each take a key page and then BOTH be refused for a
  destination the budget could have covered for one of them — a flood makes
  every open fail, including the legitimate ones, which is the outcome an
  `Allocator` exists to prevent. One reservation per open makes admission a
  single atomic decision, so contention refuses only the excess.

  **`OpenWith(nil)` is refused with the new `ErrNilAllocator`** rather than
  falling back to an unadmitted allocation. A caller reaches for this method to
  bound something; quietly allocating outside the budget would deliver the
  precise outcome the call was written to prevent, on a path that keeps working
  and keeps looking bounded. The unbudgeted open is still available and spelled
  differently — call `Open`, whose contract is unchanged and now says plainly
  that it allocates outside any budget.

  Not covered, and stated as a boundary rather than an omission: the SEAL path
  is still unadmitted. There is no `SealWith`; sealing allocates once per value
  rather than once per use, so it does not scale with request rate the way
  opening does.

- **`(*SealedEnclave) Openable() error` — the openability question `IsAlive`
  cannot answer (#33).** Returns nil, `ErrSealerWiped`, or
  `ErrEnclaveDestroyed`, consulting the sealer.

  It closes a NAME COLLISION. Since #40, `MemoryEnclave.IsAlive` reports false
  once its material is wiped, so across this package `IsAlive` reads as "you
  can actually use this" — while `SealedEnclave.IsAlive` tests ciphertext
  presence, which a shutdown sweep does not touch. A swept value therefore read
  alive and yielded nothing usable, which is the shape #13 was about; a doc
  comment is a weak fix for a name that means something else next door.

  `IsAlive` is deliberately UNCHANGED — its cheap, local meaning and its lock
  profile are worth keeping — and is now documented as reporting on the
  ciphertext, with `Openable` as the openability question.

- **`WithProviderHealth(fn func() error)` and `ErrOpenabilityUnknown` — an
  out-of-package provider can now report that a sweep took its sealing key
  (#33).** `SealedEnclave.Openable` consulted an UNEXPORTED interface, which by
  Go's rules no external package can satisfy, so a third-party `KeyProtector`
  keeping its key in this process's locked memory was silently assumed healthy:
  after `WipeAll` destroyed that key, `Openable` returned nil and the following
  `Open` failed. A fail-open in a health API — and it reported
  `ErrEnclaveDestroyed` rather than `ErrSealerWiped`, the same misattribution
  the decision below argues against.

  Providers that can answer now do so precisely and their answer is
  **authoritative and terminal**: the sweep-generation fallback never overrides
  it, or a provider reporting "the device still holds this key" after a sweep
  could not express the one thing the callback exists for. The callback is
  deliberately narrow — this process's sealing state, not device liveness —
  because a probe answering both would make `Openable` mean two things
  depending on which provider was installed.

  `ErrOpenabilityUnknown` **is public API**: callers match on it, so its
  identity is part of this package's compatibility surface. Added with that
  cost weighed, not as an implementation detail.

### Changed
- **An enclave whose material has been wiped now reads as DESTROYED even while
  its pages are still held.** `IsAlive` returns false, `Size` returns 0, and
  `Open`, `WithBytes`, `EqualTo` and `EqualToErr` return `ErrEnclaveDestroyed`.

  The case is the failed release: when the wipe succeeded but the `munlock` or
  `munmap` after it was refused, the mapping is deliberately **kept** so
  `Destroy` can be retried. It then read as a perfectly ordinary live enclave —
  `IsAlive` true, a non-zero `Size`, and `Open` handing back **zeroes** from a
  region whose guard pages the release path had already left **read-write**. A
  caller that recovers from `Destroy`'s panic and reads rather than
  re-destroying would derive from an all-zero secret with the guards off, and
  nothing said so.

  "The enclave still reports itself alive, which is the truth" was true of the
  **mapping** and was never true of the **enclave**. The pages stay held for the
  retry either way; only the answers about the material changed.

  **Both branches of the release path are covered.** A frozen enclave loses its
  material to the release `mprotect`; a mutable one — a sized enclave that has not
  been frozen (#6) — loses it to the *early* wipe that runs before any
  syscall that can be refused, so its material is gone even when that `mprotect`
  is the step that fails. The two differ in fact, and the flag follows the fact:
  a genuinely refused wipe still reads as alive, because nothing was destroyed.

- **`WipeAll` will not be extended to sweep `SealedEnclave` values (#33,
  decided; no behavior change).** Three grounds, now recorded where the count is
  defined rather than left open in an issue. The COUNT means "still holding
  locked memory" and that invariant is the function's whole value; a
  `SealedEnclave` holds none — its envelope is heap ciphertext — so covering it
  would either corrupt the number or require a second one. Sweeping would also
  be WRONG rather than merely costly: in `ModePerOperation` the device still
  holds the key, so a swept value stays legitimately openable, and destroying it
  would destroy recoverable application data that this process's memory never
  protected — under a call documented for sweep-and-keep-running callers. And it
  would REGRESS diagnostics, since a swept value would report
  `ErrEnclaveDestroyed` ("you destroyed this") in place of `ErrSealerWiped` ("a
  sweep did"), sending an operator to the wrong code.

- **`Openable` now answers "I cannot tell" instead of guessing, and `WipeAll`
  bumps a sweep generation before it destroys anything (#33).** For a provider
  that reports no health, `Openable` returns nil until a sweep has run and
  `ErrOpenabilityUnknown` afterwards. Gating on a sweep having actually
  happened is what keeps it a signal: an answer that read "unknown" both before
  and after would be structurally unable to report the one event it exists to
  report, and would replace a true nil with a permanent false alarm for every
  contract-abiding hardware provider.

  The ORDER inside `WipeAll` is the correctness of this, not a detail. Bump
  then destroy leaves at worst a brief false "unknown" while a sweep is in
  flight, which is the safe direction. Destroy then bump would leave a window
  where the keys are gone and the generation still reads old, so `Openable`
  returns nil about a value that can no longer be opened — the same fail-open,
  narrowed to a race that only appears under load. Pinned by a test that PARKS
  between the two steps rather than trusting statement order to survive an
  edit, with controls asserting the seam fired and the enclave was still alive
  inside the window.

  The fallback is scoped to `ModePerOperation`. In `ModeRootKey` the hierarchy
  is this package's own enclaves and it inspects them directly, so a nil there
  is knowledge rather than ignorance and a sweep elsewhere must not downgrade
  it.

### Security

- **A release whose `mprotect` is denied now hands the pages back with a bare
  `munmap` instead of keeping them, and says so.** The wipe that precedes a
  release needs the region writable; for a FROZEN enclave that mprotect is the
  only way in, so a permanent denial — a seccomp filter, a sandbox — left the
  material resident in locked memory for the process lifetime, and retrying
  could not help. The release now falls back to unmapping directly. Nothing
  leaks: the pages were `mlock`'d for their whole life and the kernel zeroes an
  anonymous page before reuse.

  It is reported rather than silent, through the new `ErrReleasedWithoutWipe`
  (as an `UnwipedReleaseError`) and the new **`(*MemoryEnclave) DestroyErr()
  error`** — `Destroy` with its non-fatal report kept rather than discarded,
  the same relationship `EqualToErr` has to `EqualTo`. It is deliberately not
  `ErrEnclaveCorrupted` and does not panic: no memory was corrupted and no
  material outlived its enclave. What it tells an operator is that something in
  the environment is denying `mprotect`, which reaches every other enclave in
  the process. (#38)
- **`Allocator.SetLimit`, `Allocator.ForceLimit` and `Allocator.TransferTo` — a
  budget that can be retuned at runtime and rebalanced between allocators.**
  (#35) Until now `Allocator.limit` was written once in `NewAllocator` and never
  again, so a process whose locked-memory demand moved — a per-tenant seal
  barrier gaining and losing tenants, a container resized under it — could not
  adjust without rebuilding its allocators.

  The two lowering contracts are separate methods because they answer different
  questions. `SetLimit` **refuses** to shrink below the memory already reserved,
  returning a `LimitError` matching the new `ErrBudgetInUse` and changing
  nothing: the reservations belong to live enclaves that only their owners may
  destroy, and no budget decision may invalidate them. `ForceLimit` records a
  ceiling that moved regardless of what is reserved, keeps every live enclave
  working, **returns the over-subscription in bytes** so the caller is told
  rather than left to discover it, and admits nothing further until reservations
  drain beneath the new budget. Zero is a legal runtime budget — quiescing an
  allocator — even though it remains a construction-time error.

- **The admission counter now holds the REMAINING budget rather than the bytes
  used**, which is what makes a moving budget safe. Every operation reduces to
  one signed adjustment of that single word: admitting subtracts, releasing
  adds, raising the budget adds, lowering it subtracts. A budget reduction and
  an allocation therefore compete on exactly the same terms, through the same
  compare-and-swap, and one of them loses — where a limit and a usage counter in
  two separate words would have let a lowering land invisibly between an
  admission's check and its commit, over-committing locked memory the process
  cannot actually get.

  Admission is unchanged in cost and remains lock-free: one atomic word, no
  syscall on refusal. The new mutex serializes budget CHANGES only, and the
  observability getters take it shared so `InUse()` is an exact figure rather
  than a torn pair. It is never taken on the allocation or release path.

  A side benefit: the admission predicate is now `charge > free`, a comparison
  with no arithmetic between the two values, so the overflow class the previous
  `charge > limit-used` form was carefully written to avoid cannot arise at all.
  The DIAGNOSTIC path still subtracts, and `BudgetError.InUse` is now documented
  and tested as never negative: an over-subscribed allocator has a negative
  headroom counter, and a lock-free reader catching it beside a freshly raised
  limit would otherwise compute a byte count that wrapped. A wrapped count is not
  a stale reading but an impossible one, and a consumer graphing it cannot tell
  the difference. Caught by Codex on PR #44.

  `Available()` reports zero rather than a negative remainder while an allocator
  is over-subscribed, and `BudgetError.InUse` may now exceed `BudgetError.Limit`
  — both states are reachable only through `ForceLimit`, and both are what an
  over-subscribed allocator honestly looks like.

- **`Allocator.TransferTo` moves headroom between two allocators as one
  operation.** Doing it as a lowering plus a raise leaves a window in which the
  bytes are in both allocators or in neither, depending on the order; "both"
  lets each side admit against the same locked memory. The transfer debits the
  source first and credits the destination second, so the intermediate state is
  always "in neither" — conservative, recoverable by a retry, and unobservable
  to any other retune since both locks are held across it. The two locks are
  taken in a fixed total order (ascending construction id), which is what makes
  concurrent A→B and B→A transfers impossible to deadlock.

  No parent/child budget hierarchy was introduced; #35 records that as an
  architecture decision for the owner, and direct transfer does not need one.

  None of the three re-checks `RLIMIT_MEMLOCK`, exactly as `NewAllocator` does
  not. An allocator built by `NewAllocatorWithinRLimit` (#43) can be raised back
  above the ceiling that constructor refused, so that check is a startup check
  and does not carry forward; `SetLimit`'s doc comment says so. Applying it to a
  retune would be a behavior decision for the owner rather than a gap to fill
  quietly, and admission fails safe regardless — the kernel refuses the lock and
  the allocation returns `ErrLockedMemoryUnavailable`.

### Tests

- **A stale forward reference in the docs now fails the suite (#65).**
  `docs_issue_refs_test.go` classifies every issue citation in the documented
  surface — the non-test `*.go` comments, `README.md` and `CLAUDE.md` — as
  `classHistorical` (describes something already done or decided),
  `classPending` (presents the issue as unresolved future work) or
  `classExternal` (another repository's numbering).

  It is deliberately NOT "fail when the docs cite a closed issue". All 27
  citations in this package resolve to closed issues, because the docs earn
  their keep by explaining why the code is shaped as it is; that check would
  fire on everything and be suppressed the same day. What rots is the CLAIM
  around the citation, so the claim is what is recorded.

  **The ledger is keyed by a digest of the citing SENTENCE, not by file and
  issue number.** The first version keyed at `<file>#<number>` and review on
  PR #66 killed it with the obvious mutation: reword `doc.go`'s
  "`SealedEnclave.Openable` is the explicit probe (issue #33)" into "an
  openability probe is tracked as issue #33" — the exact defect this guard
  exists for — and it PASSED, because `doc.go#33` was already classified and
  nothing looked at the prose. A second sentence in the same file presenting
  the same issue as pending went through the same hole. With a sentence-level
  key a classification covers exactly the words classified: reword it and the
  old entry orphans while the new one is undeclared, so the suite fails twice
  until someone re-reads the sentence. Rewrapping a paragraph changes nothing,
  because the digest is taken after whitespace and comment markers are
  normalized away.

  Two halves, each with teeth on its own. The offline half compares the
  citations found in the tree against the ledger and fails on any difference in
  either direction. It needs no network. The online half resolves every
  `classPending` entry against Gitea and fails if the issue is closed.

  **The online half skips only for genuine transport unavailability.** A
  rejected token, a wrong repository or a malformed endpoint is a
  configuration failure and FAILS the suite rather than disabling the check
  while printing green — the second finding on PR #66, and the
  silent-instrument pattern this repository keeps catching. Setting
  `ENCLAVE_ISSUE_API` is what asks for the check; leaving it unset is the
  opt-out, so nobody's build breaks over a credential they did not ask for.

  An intermediate design warned instead of failing when nothing was
  `classPending`. It was removed after measuring that the warning could never
  be seen: a PASSING test in a non-verbose run emits nothing at all — not
  `t.Log`, not `os.Stderr`, not `os.Stdout` — and neither `ci.yml` nor
  `make test` runs `go test -v`. A state nobody can observe is not a state,
  and an invisible warning is the same defect one level up from the one this
  guard is for.

  **Merging #64 found two more extractor defects, and both were the silent
  kind.** `providertest` writes `PKCS#11` twice, which a bare `#(\d+)` reads as
  a citation of issue 11 — a guard that invents citations gets its ledger
  padded with nonsense until someone deletes the check. And `providertest`
  lives in a subdirectory, which the root-only file scan never read, so a whole
  new package's docs were excluded while the scan reported clean. A `#`
  preceded by a letter or digit is now part of a word rather than a citation
  unless the token before it looks like `owner/repo`, the file walk is
  recursive, and `TestCitationExtraction` and
  `TestDocIssueRefFilesReachesSubpackages` pin both. Walked paths are
  normalized with `filepath.ToSlash`, since the ledger is checked-in text and
  must not classify the same tree differently depending on the host separator.

  **The repository is checked on every lookup, not just the control.** The
  control proves the endpoint answers for this repository; it does not prove it
  does so for every number, and the pending loop branched on `state` alone. An
  endpoint, proxy or mistyped base serving the control correctly and a pending
  issue from elsewhere would have reported the docs verified against the wrong
  tracker — the same asymmetry as the control check, one level down. A
  wrong-repository answer is now a failure and does not count towards
  `Checked`, because it resolved nothing.

  The guard states what it CANNOT catch, in its own doc comment: it records
  the claim a human made about a sentence, not the claim the sentence makes,
  so a careless `classHistorical` defeats it; a forward reference carrying no
  issue number is invisible; and the online half is opt-in through the
  environment.

  **The online half's own policy is now tested, hermetically.** It was not,
  and that was the third finding on PR #66: with no `classPending` entries and
  `ENCLAVE_ISSUE_API` unset, the default run skipped, so the control lookup,
  the pending lookup, HTTP and auth failure, a malformed response, a closed
  pending issue, and the fatal branch of the policy itself were covered by
  nothing. A regression turning any of them fail-open would have left
  `go test ./...` green — the defect this guard exists to prevent, living
  inside the guard.

  The decision is now a VALUE: `evaluateIssueState` returns what should happen
  and why, and the test function only translates that into a skip, a log or a
  failure. `TestIssueStatePolicy` walks 18 rows against a stubbed
  `http.RoundTripper` — no network, no Gitea, no credentials, and not even a
  loopback port, since a guard whose own tests need a listening socket cannot
  run in a socket-restricted runner — asserting the action AND a fragment of
  its explanation, so a row cannot pass by producing the right verdict for the
  wrong reason. `misconfigured` remains the single place the fatal-versus-
  warn split is decided, and `TestMisconfiguredIsTheOnlyFatalWarnDecision`
  pins that every misconfiguration path routes through it.

  Two fail-open paths were found by that table and by review while writing it.
  An `ENCLAVE_ISSUE_API` with no scheme — `gitea.local/api/v1/...` — is
  accepted by `http.NewRequestWithContext` and refused by `http.Client.Do`, so
  it took the SKIP path under the very policy meant to catch it; the base URL
  is now validated up front. And narrowing "transport failure" to `net.Error`
  was not enough on its own, because `*url.Error` — which the client wraps
  EVERY failure in — implements `net.Error` itself, so the check matched
  unconditionally and classified everything as transport. The inner error is
  what is asked now. The second defect was caught by the table row written for
  the first.

  A third: the instrument check asserted only that the control issue is
  closed, which identifies no repository — measured on this server,
  go-blockstore, go-luks2, go-quicbaas and go-qrdb all have a closed #17 too,
  so a probe aimed at any of them would have passed and then resolved
  `classPending` entries against unrelated issues whose numbers merely
  collide. The control now also requires `repository.full_name` to be this
  repository, and that is verified live: pointed at go-blockstore with a valid
  token, it fails.

- **`Allocator`'s cacheline budget is asserted rather than assumed (#60).**
  This type's lock-free argument rests on `free` and `limit` sharing a line that
  nothing unrelated writes, and nothing enforced it. The slack ran out
  invisibly: the `stalled` seam (#51) costs 8 bytes and `rlimitBound` (#53)
  costs 1, but `rlimitBound` lands at offset 48 and a func pointer needs 8-byte
  alignment, so the bool drags 7 bytes of padding and the pair takes the struct
  from 56 bytes to exactly 64. Each diff looked free in isolation; the bill only
  existed in the combined struct, which came into being at a rebase, so no
  reviewer of either pull request could have been shown it. `TestAllocator_StaysWithinItsCachelineBudget`
  now fails on the next field of any size — measured: one added `bool` takes it
  to 72 bytes and the test names it — and separately fails if `free` and `limit`
  are ever split across lines.

- **The parked withdrawal no longer leaks on the handoff test's failure path
  (#60).** It parks inside `withdrawLocked` and therefore parks HOLDING `a.mu`,
  since `SetLimit`'s deferred `Unlock` has not run; a `t.Fatalf` between the park
  and the release left that goroutine blocked for the life of the process,
  holding a lock, with nothing joining it. Released through an idempotent
  `sync.Once` on `t.Cleanup` now. Exercised rather than argued: with `reserve`
  mutated to refuse every admission, the test fails on that exact line and the
  cleanup runs.

- **The retune/admission race test no longer inherits the scheduler's luck
  (#51).** `TestAllocator_Retune_RacesAdmission` ran a storm — goroutines
  allocating and destroying in a loop against goroutines raising a page and
  taking it back — and read the outcome off the counters afterwards. Which half
  of the race got to run was entirely the scheduler's to decide. Measured on one
  8-core host with no change to the code under test: `lowered=43` of 2400 idle,
  `lowered=2400` of 2400 under CPU load, and a flat
  `admitted=600 refusedAdmit=1800 lowered=2400` under `GOMAXPROCS=1` and
  `taskset -c 0`, which is not a race at all but sixteen goroutines run to
  completion in turn. On a saturated CI runner the shrinking half starved
  outright (`raised=2400 lowered=0`) and the test's own vacuity control fired on
  an unrelated pull request. **The control was right** — without it that run
  would have been a green report on a retune path that performed no lowerings —
  so the setup was fixed and the control kept, word for word.

  The contest is now ARRANGED. Each round releases a fixed cast from one line:
  actors that each attempt exactly one page-sized admission, actors that each
  destroy exactly one pre-held enclave, and one retuner that withdraws exactly
  one page. Every claim is one page and nothing loops, so supply and demand are
  known before the round opens and `min(supply, demand)` claims must be granted
  whatever order they land in — too many is the over-commit, too few is a
  starved round saying so instead of quietly proving less. Three shapes: one
  where supply covers demand (so a successful lowering is guaranteed on every
  host, which is what makes the control stop being load-sensitive), one two
  pages short (the conservation check), and one where destroys land inside the
  window. Measured 0 failures in 25 runs in each of multi-core, `GOMAXPROCS=1`,
  `taskset -c 0`, and under 16 busy loops, with `lowered` never below 546 of 600
  — against a structural floor of 400 that no scheduling can take away.

- **The linearization defect is now caught deterministically rather than a
  third of the time.** Arranging the contest fixed the vacuity, but neither form
  reliably catches the regression the test exists for: against a
  `withdrawLocked` reduced from compare-and-swap to read-then-subtract, the
  storm form went red on 3 runs in 10 and the arranged form on 0 in 10 — the
  window a racing admission must land in is two instructions wide, so entering
  it is a coin flip. `TestAllocator_Retune_LoweringLosesTheContestedPage` parks
  the withdrawal in that window through a seam on `Allocator` (`stalled`, nil in
  every build, called only from `withdrawLocked` under the retune mutex — never
  on the lock-free admission path), lands the conflicting admission by hand, and
  only then releases it. Red 25 out of 25 against that regression, multi-core
  and `GOMAXPROCS=1` alike, reporting `free = -4096` — the over-commit itself,
  by name.


## [v0.4.0-alpha] - 2026-08-26

### Added

- **`WipeAll() (int, error)` — a cooperative shutdown sweep that destroys every
  live enclave, reports how many it could not, and reports whether any of them
  were corrupt.** For an orderly exit: a signal handler, a defer in main. It is
  not a fault handler and nothing calls it for you.

  The two return values are **orthogonal, and neither implies the other**. The
  count is how many enclaves are still holding locked memory; a non-zero value
  is a shutdown-ordering bug in the caller. The error reports detected canary
  corruption and nothing else, matching `ErrEnclaveCorrupted` through
  `errors.Is` exactly as `Destroy`'s panic value does, and naming how many
  enclaves failed.

  A corrupt enclave's pages **are** reclaimed, so it is not "still held" and
  never appears in the count — which is precisely why the corruption needs a
  return value of its own. An earlier revision of this branch returned only the
  count, so a sweep that detected memory corruption reported `0` and looked like
  a clean exit: `Destroy` panics on that same condition because it matters, and
  a sweep must not abort, but non-fatal must not mean invisible either.

  This is the one thing v0.3.0-alpha's removal of memguard left a consumer
  needing. Option B deleted memguard's process-global registry because of what
  memguard did WITH it — purge the whole thing on any mapping failure, then panic
  — while a consumer had been relying on that same registry for a *cooperative*
  exit wipe. After the conversion its exit path silently stopped covering the
  key it was meant to destroy: nothing failed, nothing announced it.

  A cooperative sweep is a different mechanism wearing a similar shape.
  `WipeAll` is called explicitly rather than triggered by a fault, **never
  panics** — a sweep that aborted partway would leave every enclave after the
  failure untouched — and **never waits on a reader**: an enclave being read
  when the sweep reaches it is retried on a later pass, and only one still held
  after every pass is counted, because a shutdown that hangs behind a goroutine
  still reading a key is worse than one that reports what it could not reach.

  The registry is touched on construction, on destruction, and by `WipeAll` — and
  by **nothing on the borrow path**, which is what keeps `purgeMu` from coming
  back. Allocating inside a live borrow still works.

### Changed

- **`WipeAll` waits briefly between retry passes, so the promise it makes about
  momentary readers is actually true.** Without it the retry loop was
  temporally degenerate: all eight passes completed in about 966 **nanoseconds**,
  so "still held after every pass" meant "held for more than roughly a
  microsecond," and a realistic reader — a health probe calling `IsAlive`, a
  `Size`, an `EqualTo` — lost its enclave 20/20 times at every duration from
  20µs to 2ms.

  This is a backoff, not synchronization, and the distinction is the test:
  remove the wait and the sweep is still **correct** — the enclave simply is not
  reclaimed on that call, the count stays honest, and the documented remedy
  still works. A sleep standing in for an ordering guarantee becomes *wrong*
  when removed; that is the pattern this project bans, and this is not it. There
  is also nothing to wait on: the party being waited for is another goroutine's
  read lock, and `sync.RWMutex` exposes no "notify when free."

  Cost is milliseconds at shutdown, and only when something is genuinely still
  held. Stated as measured rather than as arithmetic: nominally 1.4ms, measured
  at **7.5ms** against a held enclave, because short sleeps overshoot.

- **`WipeAll`'s documentation no longer attributes a non-zero count solely to
  caller ordering.** A read that simply outlasts the retry budget produces the
  same number, so the count now reads as "these were still in use" rather than
  as a diagnosis — and it says plainly that `WipeAll` belongs to the **program
  that owns the process**, never to a library, since it destroys enclaves
  belonging to subsystems a library knows nothing about. Two independent
  consumers reached that conclusion on their own and declined to call it; an API
  two callers separately avoid is inviting the mistake.

- **An enclave is published to the shutdown ledger as the LAST step of its
  construction**, after every field a sweep reads has been set. `Allocator.New`
  and `Allocator.NewSized` install the reservation callback and then register;
  the constructors no longer register on their behalf.

  Registering inside the constructor put an allocator-backed enclave on the
  ledger while `Allocator.New` had not yet assigned its `release` callback. A
  `WipeAll` landing in that window read the field while it was being written — a
  data race — and destroyed the enclave with `release` still nil, handing the
  pages back to the kernel while the budget kept the charge. In the
  `WipeAll`-at-exit pattern, where the sweep is the destroyer, nothing ever
  returns that charge: an `Allocator` that sweeps and keeps running loses
  admission capacity permanently. Measured on the defective shape, 34–52 MiB of
  a 256 MiB budget was stranded per run.

  No API change; `WipeAll` and both allocator constructors behave as documented.

- **A momentary reader no longer costs an enclave its sweep.** `WipeAll` retries
  an enclave it could not lock on its next pass, instead of writing it off after
  one lost race.

  `tryReleaseMapping` takes the WRITE lock without waiting, so it loses to any
  concurrent reader — `IsAlive`, `Size`, `EqualTo`, a health probe polling an
  enclave during shutdown — not merely to a long `WithBytes` borrow. The sweep
  marked every enclave as seen when it built a pass's batch, *before* trying to
  release it, so one lost microsecond took that enclave out of the sweep
  permanently: no later pass reconsidered it, the process exited with the
  material still mapped and locked, and the returned count blamed the caller's
  shutdown ordering. That is the outcome `WipeAll` exists to prevent, reached
  through the most ordinary concurrent operation there is.

  Termination never depended on the seen-set — `maxSweepPasses` is the bound —
  so it is gone. A genuinely long borrow still outlives every pass and is
  skipped and counted, which remains correct: memory being actively read must
  not be unmapped underneath the reader.

- `tryReleaseMapping` now returns `(released bool, err error)` rather than
  `(error, bool)`, putting the error last as the conventions require.

### Documentation

- **`WipeAll` is documented in the API surface**, in both the README table and
  the package doc, where it was missing entirely.
- **The README's "enclaves are destroyed when their owner destroys them and at
  no other time" is corrected.** It became false the moment a global sweep
  existed. What remains true — and is what the sentence was protecting — is that
  nothing destroys an enclave in reaction to a *fault*.
- **`Open` names `WipeAll` as a second concurrent destroyer.** A retained `Open`
  slice segfaults if a shutdown sweep runs while the caller still holds it, and
  only this enclave's own `Destroy` was mentioned before.
- **The constructors document that a successful return can hand back an
  already-destroyed enclave** when `WipeAll` ran between publication and return.
- **The registry design note states its two costs plainly:** `registryMu`
  serializes construction and destruction process-wide (it is not `purgeMu` — it
  never touches the borrow path and is never held across a syscall or an enclave
  lock), and an enclave whose release keeps failing is retained for the process
  lifetime by design, so a later sweep can retry it.

### Tests

- **The never-panics guarantee is now pinned rather than merely documented.**
  `WipeAll`'s most prominent promise — that it does not panic, including on an
  enclave whose canary fails — had no test. A corrupt canary is now seeded into
  a batch and the whole batch is checked: no panic, every enclave wiped, the
  sweep not aborted at the failure, the corrupt enclave's reservation returned
  (a detected corruption still counts as released), and the corruption
  **reported** through the error rather than swallowed.
- **The concurrent-construction test was rebuilt to be affordable in CI.** Its
  first two versions needed a large payload (1 MiB, then 512 KiB) to widen the
  window they race for, and a sweeper that spun without yielding to sample it
  often. Both worked locally — including pinned to a single CPU — and both blew
  the test's own drain bound on the build runner, twice.

  The payload was the expensive half: under `-race`, hundreds of megabytes of
  mlock churn in a memory-capped container is a different order of problem from
  slow CPU. The width also turned out to be unnecessary — race detection needs
  the window ENTERED, not held open, and a one-page payload hits it just as
  reliably (8/8 against the defective shape) for 1/128th of the memory. The test
  now costs hundredths of a second on every machine measured.

  The strength that bought moved to the race detector, which is the reliable
  oracle for this defect and is what CI runs; the budget assertion is kept as a
  weaker second signal that needs no detector, and the doc comment says so
  rather than claiming two equal oracles. The "a live successful return is
  usable" check moved to a quiescent phase, because it is a property of
  construction rather than of the race — asserted against a live sweeper it
  failed whenever the sweeper won everything, which on one CPU was 99 times in
  100.
- **The failed-release path is pinned.** An enclave whose release fails for a
  reason that is not corruption keeps BOTH its Allocator charge and its ledger
  entry. Neither was held by any test. Refunding unconditionally would hand the
  budget back while the kernel still holds the pages, so the allocator
  over-admits against a real `RLIMIT_MEMLOCK`; deregistering would make
  `WipeAll` return **zero while the material is still mapped and locked**, and
  no later sweep could ever find it — the same class as the tallied-count
  fail-open. The shipped code was correct on both; nothing held it correct.
- **The corruption contract is pinned in both directions.** One test requires
  the error to name how many enclaves were corrupt; a control requires a clean
  sweep to report `nil`, without which both would pass against an
  implementation that reported corruption unconditionally. Every other test in
  the package now routes its sweep through a helper that fails on an unexpected
  corruption report, so the whole suite doubles as that control.

## [v0.3.0-alpha] - 2026-08-26

### Changed

- **go-enclave maps its own memory.** The backing store is no longer a memguard
  `LockedBuffer`; the package allocates, locks, guards, wipes and releases pages
  through `memcall` directly — the layer memguard itself uses.

  The layout is deliberately unchanged: an mlock'd inner region with the data
  flush against an inaccessible postguard, a random canary in the slack ahead of
  it, a second guard page in front, wipe-and-verify on release. What changed is
  the FAILURE POLICY, which could not be changed from outside memguard. memguard
  registers every buffer in a process-global list and answers any mapping failure
  with `core.Panic`: `Purge()` — destroying and UNMAPPING every live buffer in
  the process — and then a panic. go-enclave converted that panic into a typed
  error from v0.1.0-alpha, but a `recover` cannot undo a purge that already ran,
  so it also needed `purgeMu`, a process-wide lock serializing every allocation
  against every borrow.

- **`purgeMu` is gone, and with it the nested-allocation deadlock.** Allocating,
  borrowing or destroying an enclave from inside another enclave's live borrow
  now works. It previously deadlocked: allocation took the lock exclusively,
  borrows took it shared, and Go's `RWMutex` blocks new readers once a writer
  queues. That blocked an ordinary shape outright — handing borrowed key
  material to an injected interface whose implementations allocate protected
  memory of their own — because the three ways of writing the code were
  deadlock, an unprotected heap copy, or an unsynchronized read.

- **An allocation failure no longer damages unrelated enclaves.** Exhausting
  `RLIMIT_MEMLOCK` fails exactly the allocation that reached the ceiling. An
  enclave is destroyed when its owner destroys it and at no other time, so
  `ErrEnclaveDestroyed` can no longer appear spontaneously on an enclave the
  caller still holds.

- **A failed mapping releases everything it took.** Where memguard aborts and
  never unwinds, this returns an error — so the cleanup is real code, verified
  against `VmLck` and the process's VMA count over 256 induced failures.

- **The material is destroyed before any syscall that could be refused.**
  `mprotect` can be denied — a seccomp filter is the realistic case — and the
  release path used to make the region writable first and wipe afterwards, so a
  refusal returned an error having wiped nothing and left the secret resident on
  locked pages. While the inner region is writable, which it is unless a freeze
  succeeded, the material needs no syscall to destroy; it is now destroyed
  first, so the worst a refusal can cost is an empty mapping that could not be
  handed back.

- **A release that could not unmap keeps its handle.** If the region cannot be
  made writable — so it was never wiped — or cannot be unlocked or unmapped, the
  mapping is left intact and the `Allocator` reservation is NOT returned.
  Clearing the fields regardless would strand memory that is still resident,
  possibly still locked and possibly still holding material, with no reference
  left to retry through, while the budget reported those bytes as available. A
  caller that recovers from the panic can call `Destroy` again to retry.

- The `Allocator` is unchanged in shape but its rationale is narrower and
  honest: it bounds one path's consumption so an untrusted source cannot starve
  the rest of the process. It never protected against collateral purges, and
  there are no longer any to protect against.

### Added

- `CoreDumpsDisabled()` reports whether lowering `RLIMIT_CORE` at import
  succeeded. The package documented core dumps as disabled while discarding the
  result, which is a guarantee the code did not enforce and a control callers had
  no API to assert. It is best effort by nature, so it is now reported rather
  than promised — and every enclave's pages are separately marked
  `MADV_DONTDUMP` as they are locked, which **is** verified and fails the
  allocation if refused. memcall attempts the same madvise and discards its
  result, so this is the first core-dump control here that is actually checked.

- `ErrEnclaveCorrupted`, reported when the canary does not verify on release.
  `Destroy` wipes and releases everything it holds, returns the `Allocator`
  reservation, and then panics with it — see its documentation for why detected
  memory corruption is the one condition this package does not hand back as an
  error.

### Removed

- The `github.com/awnumar/memguard` dependency, and with it `golang.org/x/crypto`
  — go-enclave never called memguard's `Enclave`/`Seal` paths, but their NaCl
  secretbox sat in the build graph of every consumer, and x/crypto is where the
  ten HIGH CVEs cleared in v0.2.0-alpha came from. The module now requires
  `memcall` and `golang.org/x/sys` and nothing else.

## [v0.2.1-alpha] - 2026-08-26

### Fixed

- **`Allocator` admitted against the wrong unit.** The budget counted requested
  BYTES while the kernel charges locked PAGES, so a budget sized below
  `RLIMIT_MEMLOCK` was not actually bounded by it — the comparison the type
  exists to make could not be made. Measured against `/proc/self/status` VmLck
  on a 4 KiB-page host: a 32-byte enclave locks 4096 bytes, a **128x**
  undercount, and 200 of them charged 6400 bytes against a budget while locking
  819200. Reservations are now charged, reported and released in locked bytes,
  page-rounded as the kernel charges them.

- **A size too large to MAP reached memguard and purged the process.** memguard
  lays out the data region plus two guard pages using `int` arithmetic
  (`core.NewBuffer` asks `memcall.Alloc` for `2*pageSize + roundToPageSize(size)`),
  so past a certain size that arithmetic overflows, `mmap` refuses the nonsense
  length, and `core.Panic` destroys every live locked buffer in the process.
  Measured on v0.2.0-alpha with `n = MaxInt64-pageSize`: admission passed, the
  request reached memguard, and an unrelated canary enclave came back dead. Both
  construction paths are now gated — `Allocator.NewSized` through admission and
  `NewMemoryEnclaveSized`, which has no allocator in front of it at all.

### Added

- `LockedSize(n int) int64` — the locked memory an enclave of n bytes actually
  consumes, so a caller can size a budget instead of guessing. Returns int64 to
  match `NewAllocator`'s budget, so sizing one needs no conversion. Guard pages are
  not part of it: they are mapped PROT_NONE and never mlock'd, verified against
  the kernel's accounting rather than inferred from the mapping code.

### Changed

- `ErrInvalidSize` now reports two conditions rather than one: a non-positive
  size, and a size too large for memguard to map. Its message changed to match.
  A larger `Allocator` budget helps with neither, which is why they are not
  `ErrBudgetExhausted`.
- `Limit`, `InUse`, `Available` and `BudgetError.Requested` are documented as
  **locked bytes**, comparable to `RLIMIT_MEMLOCK`. Existing budgets therefore
  admit far fewer enclaves — which is the fix, not a regression: they admitted
  more before only by mismeasuring. A budget below one page constructs and then
  admits nothing, refusing with figures that show why.

## [v0.2.0-alpha] - 2026-08-26

### Added

- `NewMemoryEnclaveSized(n int)` and `Allocator.NewSized(n int)`: locked, zeroed
  memory of `n` bytes that the caller fills IN PLACE through the existing
  `WithBytes` borrow, so generated material — a drawn key, a derived wrapping
  key, a Shamir share — never exists on the ordinary heap, not even transiently.
  Until now the whole construction surface took existing bytes, which forced
  callers into the `make` + generate + move shape the wipe cannot fully undo.
- `ErrInvalidSize` for a non-positive size, mirroring `ErrInvalidBudget`.
  `Allocator.NewSized` refuses it at the admission gate, before memguard is
  entered.

### Changed

- `Allocator`'s admission gate is now a single `reserve` step shared by `New` and
  `NewSized`, and it refuses a non-positive reservation outright — the byte
  counter can no longer be driven below zero, which would have let a concurrent
  caller admit against an inflated budget.
- The admission predicate compares the request against the remaining budget
  instead of testing `used + n` against the limit. The addition overflows int64
  for a large enough request and wraps negative, which passed the budget test and
  admitted an allocation the budget could not cover — a fail-open into memguard,
  reachable through `NewSized` because it takes its size from the caller as a
  plain int rather than as the length of an already-allocated slice.
- Documented the one property that separates the two construction paths after
  construction: memguard freezes the pages of an enclave built from existing
  material, while a sized enclave's pages stay writable for its lifetime. `Open`
  and the package documentation previously said a write always faults.

### Security

- Bumped the indirect `golang.org/x/crypto` from v0.41.0 to v0.52.0, clearing ten
  HIGH CVEs (CVE-2025-47913, CVE-2026-39828/-39829/-39830/-39831/-39832/-39835,
  CVE-2026-42508, CVE-2026-46595, CVE-2026-46597). No go-enclave code imports the
  module — it arrives via memguard — so `govulncheck` reported them only as
  present-but-uncalled; `trivy` is module-level and does flag them.
- Added a tracked, intentionally empty `.trivyignore`, and pointed the `Makefile`'s
  `trivy` target at it. The nightly Trivy job passes `--ignorefile .trivyignore`,
  and trivy treats a missing ignore file as a FATAL flag error rather than as an
  empty list — so that job had never scanned this repository, and the CVEs above
  were behind the error it died on.

## [v0.1.0-alpha] - 2026-08-23

### Added

- Initial release. `MemoryEnclave`, a region of locked, zeroized memory for
  holding sensitive material for its whole lifetime in the process. Extracted
  from an object-storage library that had grown its own copy, so that libraries
  handling key material can share one implementation instead of each rolling
  their own.
- Error-returning locked-memory handling: an mlock failure yields a typed
  `LockedMemoryError` / `ErrLockedMemoryUnavailable` instead of memguard's
  process-wide `Purge` + panic.
- The `WithBytes` borrow window and process-wide `purgeMu` coordination, so an
  in-flight borrow survives a purge triggered elsewhere in the process.
- Admission control: `Allocator`, a lock-free bounded allocator with a typed
  `ErrBudgetExhausted` / `BudgetError`, so callers can cap unauthenticated
  locked-memory allocation below the RLIMIT_MEMLOCK ceiling that triggers a
  purge. Reservations are released on `Destroy`.

[v0.3.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.3.0-alpha
[v0.2.1-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.2.1-alpha
[v0.2.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.2.0-alpha
[v0.1.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.1.0-alpha
