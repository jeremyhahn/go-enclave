### Changed

- Align the provider seam text in `docs/SPEC.md`, `ROADMAP.md`, `docs/sealing/hardware-providers.md` and `docs/sealing/architecture.md` with the `keyprotector-providers` row: the memory, TPM (`backends/tpm`) and TrustZone host-side (`backends/armtrustzone`) providers ship, the TrustZone TA side is pending in trusted-firmware, and the secure-element provider waits on open questions 8-11; documentation only (#338).
