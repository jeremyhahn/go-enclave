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
3. **Later slices** (each its own brief, after the rulings): the nested
   module and its darwin and stub builds; the signer and key-agreement handles;
   the probe and rank; attestation; the conformance run on a physical Mac.

## Out of scope

- Any Go code, in the root module or a backend module.
- A macOS runner, or any change to CI.
- A secure-element `KeyProtector` provider on the Secure Enclave: that is the
  keyprotector-providers row's work (#264).
