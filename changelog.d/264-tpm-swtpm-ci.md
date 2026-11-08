### Added

- `make integration-test-tpm` runs the TPM provider's conformance suite (residue sweep included) and its sealed-blob length check against a throwaway swtpm on loopback (`SWTPM_PORT`, `SWTPM_CTRL_PORT`); CI's `tpm-swtpm` job runs it on the full tier (on a pull request, when the TPM paths change)

### Changed

- The TPM provider marshals `TPM2_Create` and `TPM2_Unseal` itself, in locked buffers it wipes, so no copy of the key stays in the heap after `Protect` or `Unprotect` returns; go-tpm's own marshaling left the key in clear in heap buffers it never wiped
- A context that ends while the TPM provider waits on the TPM now interrupts the exchange on a simulator socket or a pollable device, and the call returns `ctx.Err()`; the next call reopens the stream. `Close` waits up to 2 seconds for a call in progress, then interrupts it
- The TPM provider's sealed blob for a 32-byte key is 209 bytes, as the reference TPM's private area is 158 bytes; the design document's blob layout now accounts for every field
- The TPM provider opens a device path only if it is absolute and names a character device; a relative path or any other file is refused with a `DeviceError` naming the path (the `tcp:` and `unix:` swtpm forms are unchanged)
