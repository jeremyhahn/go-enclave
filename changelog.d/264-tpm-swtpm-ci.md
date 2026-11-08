### Added

- `make integration-test-tpm` runs the TPM provider's conformance suite (residue sweep included) and its sealed-blob length check against a throwaway swtpm on loopback (`SWTPM_PORT`, `SWTPM_CTRL_PORT`); CI's `tpm-swtpm` job runs it on the full tier (on a pull request, when the TPM paths change)

### Changed

- The TPM provider marshals `TPM2_Create` and `TPM2_Unseal` itself, in locked buffers it wipes, so no copy of the key stays in the heap after `Protect` or `Unprotect` returns; go-tpm's own marshaling left the key in clear in heap buffers it never wiped
- A context that ends while the TPM provider waits on the TPM now interrupts the exchange on a simulator socket or a pollable device, and the call returns `ctx.Err()`; the next call reopens the stream. `Close` waits up to 2 seconds for a call in progress, then interrupts it
- After an interrupt on `/dev/tpm0` or a simulator socket, which have no resource manager, the TPM provider reopens the stream and flushes each transient object or loaded session the interrupted call left, found with `TPM2_GetCapability` against a list the call took before its first command, within 5 seconds; a reclaim that fails stays due and the next call finishes it first. `/dev/tpmrm0` still relies on the kernel's resource manager
- `make coverage`, which CI's test stage runs, now also runs each backend module's unit tests with `-race` (`make test-backends`); the coverage floor still measures the root packages only
- The TPM provider's sealed blob for a 32-byte key is 209 bytes, as the reference TPM's private area is 158 bytes; the design document's blob layout now accounts for every field
- The TPM provider opens a device path only if it is absolute and names a character device; a relative path or any other file is refused with a `DeviceError` naming the path (the `tcp:` and `unix:` swtpm forms are unchanged)
- On Linux the TPM provider's key buffers are also excluded from forked children (`MADV_DONTFORK`), and an allocation whose core-dump or fork exclusion the kernel refuses now fails with `ErrLockedMemory` wrapping the refusal; before, a refused `MADV_DONTDUMP` was ignored and the buffer used
- A handle whose `TPM2_FlushContext` the TPM answers with an error (`TPM_RC_RETRY` after every retry, for example) is kept and flushed before the next call sends a command; the next call fails while the TPM still lists it, and `Close` tries it once more on a transport without a resource manager. Before, the provider lost track of it and repeated failures could exhaust the TPM's slots
