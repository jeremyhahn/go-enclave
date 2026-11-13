# Plan: mac-secure-enclave (#192)

## Objective

Propose the design of a backend on the Apple Secure Enclave that implements
the backend seam, and move the SPEC row `mac-secure-enclave` from `future` to
`planned` with a link to that design. No code is written until the owner
decides the design's open questions.

## Slices

1. **Design proposal** (this slice, docs only).
   - `docs/backends/mac-secure-enclave.md`: the proposal, in the section
     structure of `docs/backends/amd-sev.md`.
   - `docs/SPEC.md`: row `mac-secure-enclave` `future` → `planned`, design link.
   - `ROADMAP.md`: the bullet moves from Future to Later with the design link.
   - `changelog.d/192-mac-secure-enclave-design.md`: an Added fragment.
   - This plan lives beside the proposal, not in `docs/plans/`: the
     feature-map gate treats every `docs/` directory as a feature.
   - Departure: the SPEC and ROADMAP edits are not in this branch: both
     files are protected, and their edit follows in a change allowed to make it.
   - Tests: `make check-changelog-assembly`, `make check-releasability`,
     `make check-buildgates`.
2. **Owner rulings.** Each answered open question replaces its options in the
   design; the document then becomes the contract for the code slices.
3. **Backend slice 1: module, typed errors, probe, refusal path.**
   - `backends/macse`, a nested module in the shape of
     `backends/armtrustzone` (Q1, the recommended option; the path is
     `macse`, not the proposal's `macsecureenclave`, as the brief names it).
   - `errors.go`: `ErrSecureEnclaveUnavailable`, `ErrSecureEnclaveOperation`,
     `ErrInvalidSignInput`, `*SecurityError{Op, Status}` wrapping its cause,
     `*PlatformError` for a build without the binding.
   - `probe.go`: the probe's sequence (one transient key, its public key, one
     signature, verified in Go) and its pure parsers (X9.63 public point,
     ASN.1 signature, `OSStatus` text).
   - `backend.go`: `New(ctx)` runs the probe; `Name` `mac-secure-enclave`,
     `Rank` 2 (Q8, recommended), `Probe`. No `Importer`, no `Sweep` yet.
   - `secure_enclave_stub.go`: every build refuses with the typed unavailable
     error naming the `create` step.
   - Makefile: `backends/macse` joins `BACKEND_MODULES` (tidy, lint, unit
     tests, cross builds), as `backends/armtrustzone` is listed.
   - Tests: the stub's refusal from `Probe` and `New`, through `Detect`'s
     ranking contract; the parsers on fixed buffers; `make test-backends`,
     `make lint`, `make cross-build`.
4. **Backend slice 2: the darwin binding** (Q2, cgo, recommended), in a
   `darwin && cgo` file, built and vetted on a Mac with the command-line
   tools; the stub then takes `//go:build !darwin || !cgo`.
5. **Later slices** (each its own brief): the signer and key-agreement
   handles and `Sweep`; the MDA identity check in the probe and attestation;
   the conformance run on a physical Mac.

## Out of scope

- Any Go code in the root module.
- A macOS runner.
- A simulator, emulator or mock device: off the hardware, only the refusal
  path and the pure parsers are tested.
- A secure-element `KeyProtector` provider on the Secure Enclave: that is the
  keyprotector-providers row's work (#264).
