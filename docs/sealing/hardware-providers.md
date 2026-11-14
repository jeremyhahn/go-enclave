# Hardware KeyProtector providers — design

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-10
> Conflicts with this document are defects. The TPM provider ships in [`backends/tpm`](../../backends/tpm): the code is canonical for it, and this document is fixed to match. The secure-element provider is not shipped; it will implement the outline below once its open questions are answered.
> The design of the TPM and secure-element providers behind the [`KeyProtector` seam](engineering.md#provider-contract). The TPM provider is shipped; the secure-element provider is an outline with its open questions.

This is the design of the hardware providers of the `keyprotector-providers`
row ([SPEC](../SPEC.md)). go-enclave owns the protected-memory
primitives, the sealing envelope and the `KeyProtector` seam; four providers
sit behind it: memory (`SoftwareProvider`, shipped), TrustZone (the OP-TEE
TA's SEAL 0x3 and UNSEAL 0x4), secure element and TPM. A TPM or secure
element enters go-enclave only as a `KeyProtector` provider. go-enclave
protects key material at rest; it does not sign, decrypt or perform other key
operations with a device, which belong to a crypto library above it.

## Problem

A `ModePerOperation` sealer hands every data key (DEK) to its provider's
`Protect` and stores the blob it gets back
([Sealed envelope](engineering.md#sealed-envelope)). The memory provider
(`SoftwareProvider`) keeps its protect key in this process's locked memory,
so a sealed value is no safer at rest than the process that sealed it. A TPM
or a secure element holds a key the process can use but never read; a provider over one
makes a sealed value openable only on the device that sealed it.

The [provider contract](engineering.md#provider-contract) is fixed and this
design meets it unchanged. The blob is a
[generic provider blob](engineering.md#generic-providers): opaque to
go-enclave (contract item 4), so its layout below is the provider's own and
contract v1 gains no byte.

## TPM provider

### Module

The provider lives in its own Go module, `backends/tpm` (module path
`github.com/jeremyhahn/go-enclave/backends/tpm`), as
[`backends/armtrustzone`](../backends/arm-trustzone-design.md) does, so the
root module gains no dependency. It depends on `github.com/google/go-tpm`
(the `tpm2` package; v0.9.8 at this writing). It
is a `KeyProtector` and a `HealthReporter`, and serves `ModePerOperation`
only; it is not a `RootUnsealer`.

### Device

The provider opens `/dev/tpmrm0`, the kernel's TPM resource manager, once,
when it is made, and releases it in `Close`. `Open("")` takes that path
(`DefaultPath`); on Linux, `Open` also takes another device path such as
`/dev/tpm0`, or a simulator's command socket as `unix:<path>` or
`tcp:<host:port>` (see [Transports](#transports)). On other systems `Open`
returns an error matching `ErrUnsupportedPlatform`. The retries of
[Error mapping](#error-mapping) default to 5 attempts with a 20 ms back-off
that doubles after each attempt; `WithRetry` sets both. The resource manager gives the
provider its own transient handle space and flushes whatever the provider
left loaded when the file closes. One mutex per provider serializes the
provider's command sequences on that file (see [Concurrency](#concurrency)).
A call waiting for the provider when `Close` starts, and a call after
`Close`, returns the provider's own `ErrClosed` without reaching the device.

### Parent

Every call creates the parent with `TPM2_CreatePrimary` under the owner
hierarchy and flushes it with `TPM2_FlushContext` before it returns. The
parent is an ECC P-256 storage key in the shape of the storage template of
the [TCG EK Credential Profile](../reference/TCG_EK_Credential_Profile_for_TPM_Family_2_0_Level_0_Version_2_7_Pub.pdf)
2.7, §5.3.4 Template L-2 (see [TCG TPM 2.0](../reference/README.md#tcg-tpm-20)):

| Field | Value |
| --- | --- |
| type, nameAlg | `TPM_ALG_ECC`, `TPM_ALG_SHA256` |
| objectAttributes | `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`, `noDA`, `restricted`, `decrypt` |
| authPolicy | empty |
| symmetric | `TPM_ALG_AES`, 128 bits, `TPM_ALG_CFB` |
| scheme, curveID, kdf | `TPM_ALG_NULL`, `TPM_ECC_NIST_P256`, `TPM_ALG_NULL` |
| unique.x | SHA-256 of the label `go-enclave v1 TPM KeyProtector` (32 bytes) |
| unique.y | 32 zero bytes |

The only departure from the standard storage template is `unique.x`, which
carries the label (see [Associated data](#associated-data)). A primary key is
derived from the hierarchy's seed and its template, so the same template
yields the same parent on every call, in every process and across reboots.
No persistent handle is written: the provider changes no TPM state and needs
no owner authorization beyond the hierarchy's (empty) one. The cost is one
`TPM2_CreatePrimary` per call; ECC is chosen over RSA-2048 because an ECC
primary is derived without a prime search.

### Protect

1. Refuse an ended context with `ctx.Err()`; refuse a key that is empty or
   longer than `MAX_SYM_DATA` (128 bytes, the bound of
   `TPM2B_SENSITIVE_DATA`) with the provider's own `ErrKeySize`. Both happen
   before any device work.
2. Copy `key` into a locked transient; from here on the provider never reads
   the caller's slice again.
3. Create the parent, then start an HMAC session salted to it
   (`TPM2_StartAuthSession` with the parent as `tpmKey`, ECDH salt), with
   AES-128 CFB parameter encryption of the first command parameter
   (`decrypt` session attribute).
4. `TPM2_Create` under the parent, authorized by that session, of a sealed
   data object: a `TPM_ALG_KEYEDHASH` object with scheme `TPM_ALG_NULL`,
   nameAlg SHA-256, empty `authPolicy`, `objectAttributes` = `fixedTPM |
   fixedParent | userWithAuth | noDA`, `inSensitive.userAuth` empty and
   `inSensitive.data` = the transient. `sensitiveDataOrigin`, `sign` and
   `decrypt` stay clear: the TPM refuses a sealed data object whose
   `sensitiveDataOrigin` is set while the caller supplies the data.
5. Flush the session and the parent on every path, and wipe the transient.
   Return the blob only as the last step: a context that ended or a flush
   that failed returns `ctx.Err()` or the provider's own error, and the blob
   is discarded.

The salted session is what keeps the key off the bus in clear. An unsalted,
unbound session over empty authorization values derives its session key
from the two nonces alone, which a bus observer sees, so its parameter
encryption hides nothing.

### Blob layout

The blob is the provider's own, opaque to go-enclave
([Generic providers](engineering.md#generic-providers)). Every multi-byte
integer is big-endian, as the TPM marshals it:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | version: `tpmBlobVersion` = 1 |
| 1 | 2 | p: size of `TPMT_PUBLIC` (the `TPM2B_PUBLIC` size field) |
| 3 | p | `TPMT_PUBLIC` of the sealed object, as `TPM2_Create` returned it |
| 3 + p | 2 | q: size of the private area (the `TPM2B_PRIVATE` size field) |
| 5 + p | q | `TPM2B_PRIVATE` buffer: the integrity HMAC and the encrypted sensitive area, under the parent's seed |

The length prefixes are the TPM2B size fields themselves, so the blob is the
version byte followed by the two structures exactly as the TPM marshals them.
Nothing may follow the private area. A private area over 254 bytes, the
size for a `maxKeyBytes` (128-byte) DEK, is refused as a sealed-authentication
failure before any command reaches the TPM. For an n-byte DEK under the SHA-256,
AES-128 parent the blob is 177 + n bytes, 209 for a 32-byte DEK, and the
swtpm test pins it:

| Field | Bytes |
| --- | --- |
| version | 1 |
| `TPM2B_PUBLIC` size field | 2 |
| `TPMT_PUBLIC`: type 2, nameAlg 2, objectAttributes 4, `authPolicy` 2+0, scheme 2, `unique` 2+32 | 46 |
| `TPM2B_PRIVATE` size field | 2 |
| integrity HMAC, a `TPM2B_DIGEST` of the parent's nameAlg | 2+32 |
| outer wrap IV, a `TPM2B_IV` of the AES block | 2+16 |
| `TPM2B_SENSITIVE` size field | 2 |
| `TPMT_SENSITIVE`: sensitiveType 2, `authValue` 2+32, `seedValue` 2+32, `sensitive` 2+n | 72 + n |

The private area is the reference TPM's (and libtpms'): its outer wrap
carries the CFB IV in clear, and it pads an empty `authValue` with zeros to
the nameAlg's digest size before it encrypts the sensitive area, so the
area's size does not tell the authValue's.

### Associated data

The label `go-enclave v1 TPM KeyProtector` is bound into the parent's
`unique` field, and through it into the parent's key and seed.

The sealed object's private area is encrypted and integrity-protected under
keys derived from its parent's seed, and a storage primary's seed is derived
from the hierarchy seed and the template, `unique` included. A blob sealed
by another client of the same TPM under the standard storage key (or any
parent other than go-enclave's) therefore fails `TPM2_Load` under the
go-enclave parent with `TPM_RC_INTEGRITY`: the TPM enforces the separation,
not this process.

The alternative the row offered, the sealed object's `authPolicy`, was not
taken. With `userWithAuth` set the TPM never evaluates `authPolicy` for an
unseal, so a label there is a field this process compares after parsing the
blob; anyone writing a blob can set it. It also fills a field a later PCR
policy option needs (see [Rejected alternatives](#rejected-alternatives)).

The binding is domain separation, not authentication against a local user of
the TPM: anyone who can open the TPM and use the owner hierarchy can derive
the same parent and seal a blob the provider accepts. Access to the TPM is
the authority this provider grants, as access to the process is for
`SoftwareProvider`.

### Unprotect

1. Refuse an ended context with `ctx.Err()`, before device work.
2. Parse the blob without the device: refuse, with an error matching
   `enclave.ErrSealedAuthentication`, a version other than 1, a size field
   that runs past the end or leaves bytes after the private area, a
   `TPMT_PUBLIC` that does not unmarshal, and a public area that differs from
   the provider's sealed-object template in anything but `unique` (type,
   nameAlg, attributes, an empty `authPolicy`, the `TPM_ALG_NULL` scheme, a
   32-byte `unique`). Refuse a `key` that is empty or longer than 128 bytes the
   same way: no blob `Protect` made unseals into it.
3. Create the parent and start a session salted to it, with response
   parameter encryption (`encrypt` session attribute).
4. `TPM2_Load` the public and private areas under the parent, then
   `TPM2_Unseal` the loaded object under the session. The unsealed data is
   received into a locked transient and stays there; `key` is not touched.
5. Flush the object, the session and the parent. Every handle the call
   holds is flushed on every path, after a failure or a cancellation too,
   and each flush's result is kept.
6. Decide the result, in this order: a context that has ended returns an
   error matching `ctx.Err()`; a failed flush returns the provider's own
   error; an unsealed length other than `len(key)` returns an error matching
   `enclave.ErrSealedAuthentication`. On any of these, wipe the transient
   and return.
7. Copy the transient into `key`, wipe the transient, and return nil.

`key` is written only in step 7, the last step, after cleanup succeeded and
every check passed, so every refused call (authentication, a failed flush,
a cancellation at any point) leaves `key` untouched. The transient is wiped
on every path. The blob is read, never kept or modified.

A flush that fails after a successful unseal refuses the call, even when a
lost transport's reopen and reclaim then succeed: the call returns the
flush's failure joined with the reclaim's result. The seam
gives an error one meaning, no key material written (contract item 5), so
the call cannot both report the failure and deliver the key; and returning
nil would hide a handle the provider believes it left loaded. The refusal
costs nothing: the blob is unchanged and a later call can open it.

### Error mapping

Results are mapped by the command that returned them, so an authorization
failure on the provider's own parent is never mistaken for a bad blob.
go-tpm reports a format-one response code with its parameter, handle or
session number; the mapping compares the code with that number masked out,
except where the table names a parameter.

| Source | Result | Error |
| --- | --- | --- |
| blob parse | wrong version, bad size field, trailing bytes, public area not the template | matches `ErrSealedAuthentication` |
| `key` length | empty, over 128 bytes, or not the unsealed length | matches `ErrSealedAuthentication` |
| `TPM2_Load` | `TPM_RC_INTEGRITY` | matches `ErrSealedAuthentication` |
| `TPM2_Load` | any other format-one code on parameter 1 (`inPrivate`) or 2 (`inPublic`), such as `TPM_RC_SIZE` | matches `ErrSealedAuthentication` |
| `TPM2_Unseal` | `TPM_RC_BAD_AUTH`, `TPM_RC_AUTH_FAIL`, `TPM_RC_POLICY_FAIL` | matches `ErrSealedAuthentication` |
| any command | `TPM_RC_RETRY`, `TPM_RC_YIELDED`, `TPM_RC_TESTING` | retried with back-off; once the retries are spent, the provider's own error |
| any command | `TPM_RC_LOCKOUT` | the provider's own error |
| `TPM2_CreatePrimary`, `TPM2_StartAuthSession`, `TPM2_Create`, `TPM2_FlushContext` | any error code | the provider's own error |
| transport | open, read or write failure on `/dev/tpmrm0` | the provider's own error |
| any command | every other response code | the provider's own error |

The provider's own errors wrap the go-tpm error, so a caller can still read
the response code. `TPM2_Clear`, or anything else that changes the owner
seed, changes the parent; every blob sealed before it then fails `TPM2_Load`
with `TPM_RC_INTEGRITY` and reports `ErrSealedAuthentication`. The provider
cannot tell a cleared TPM from a forged blob.

### Contract

How the TPM provider meets each item of the
[provider contract](engineering.md#provider-contract):

| Item | How the TPM provider meets it |
| --- | --- |
| 1. Authenticated | The private area's integrity HMAC under the label-bound parent's seed; the template check, the blob framing and the length check refuse the rest, all as `ErrSealedAuthentication` ([Error mapping](#error-mapping)). |
| 2. Recover into the caller's buffer | Unseal lands in a locked transient, checked against `len(key)`, then copied into `key`. |
| 3. Retain nothing | The provider marshals `TPM2_Create` and `TPM2_Unseal` itself, so the key is in clear only in locked buffers it owns (`Protect`'s transient, the parameter and command buffers, the transport's response buffer), each wiped before the call returns, on every path, cancellation included. On Linux each buffer has its own anonymous pages, locked and excluded from core dumps and forked children (`MADV_DONTDUMP`, `MADV_DONTFORK`); an allocation whose lock or exclusion the kernel refuses fails with `ErrLockedMemory` wrapping the refusal, and the call fails before it sends its own commands; the TPM keeps no object after the flush ([Open questions](#open-questions) 4). |
| 4. Blob is opaque | Non-empty by construction; the provider parses a copy-free view of the blob and never writes it or keeps it. |
| 5. Honor the context | Refused at entry before device work and while waiting for the mutex; a context ending mid-command interrupts the exchange on a simulator socket or a pollable device (on a device without deadlines, the command in flight completes first), and the call returns `ctx.Err()` after the flushes or the abandonment of its handles, and the wipes, with `key` unwritten: `Unprotect` writes `key` only as its last step, after cleanup succeeded ([Unprotect](#unprotect), [Concurrency](#concurrency)). |
| 6. Infrastructure failures | Every result outside the authentication rows of [Error mapping](#error-mapping) is the provider's own error. |
| 7. Concurrent calls | Safe: the mutex serializes the command sequences, and each call owns its transients and handles. |
| 8. `Health` does not block | `Health` returns nil unconditionally: the key lives in the TPM. |

### Concurrency

A call holds the provider's mutex for its whole command sequence
(create parent, session, create or load and unseal, flushes), because the
sequence's transient handles are only meaningful together. The mutex is a
one-slot semaphore, so a waiting call also selects on `ctx.Done()` and
returns `ctx.Err()` without touching the device. `Close` marks the provider
closing before it waits for the mutex, so a call waiting when `Close`
starts, or one that takes the mutex after, returns `ErrClosed` without
reaching the device, and `Close` takes the mutex after at most the one call
it interrupts.

Every exchange with the device takes the call's context. The command
sequence runs on the calling goroutine, and the provider checks the context
before every command it sends. When the context ends during an exchange,
the provider sets a deadline in the past on the stream: a simulator socket,
or a device file the runtime can poll, ends the read or write at once. The
kernel cannot cancel a TPM command once it is sent, so on a device file
without deadlines the command in flight runs to completion first; a
`TPM2_CreatePrimary` may take a large part of a second on a discrete TPM.
This is the case the seam's "as far as the underlying API allows" covers.
When the context has ended:

1. no further command of the sequence is sent: only `TPM2_FlushContext` for
   each handle the call holds (object, session, parent), under a context of
   its own bounded at 5 seconds;
2. if the context ended during an exchange, the stream is out of step (the
   interrupted command's response may still arrive, and the command may
   still create a handle), so the provider reclaims instead of flushing,
   within the same 5-second bound (see Transports below);
3. the provider wipes every transient that holds key material: `Protect`'s
   copy of `key`, `Unprotect`'s unsealed transient, and the parameter,
   command and response buffers it marshals `TPM2_Create` and
   `TPM2_Unseal` in;
4. only then does the call release the mutex and return an error matching
   `ctx.Err()`.

No goroutine outlives the call, and no copy of the key survives its return.
A context that ends during a flush does not stop the remaining flushes, and
the call still returns `ctx.Err()`. A cancelled `Unprotect` never writes
`key`, even when `TPM2_Unseal` completed or the context ended only during
the flushes: the context is checked after cleanup and before the copy (step
6 of [Unprotect](#unprotect)), and the unsealed transient is wiped, not
copied.

`Close` waits up to 2 seconds for the call in progress, then interrupts its
exchange the same way and waits for it to return: at once on a socket or a
pollable device, and on a device file without deadlines within the kernel's
TPM command timeout. The interrupted call's reclaim then takes at most 5
seconds more, and without a resource manager the reclaim `Close` finishes
before it closes the stream at most 5 seconds after that.

Calls on different providers over the same TPM are serialized by the TPM
itself; the resource manager keeps their handles apart.

#### Transports

The reclaim depends on the transport:

- **`/dev/tpmrm0`**, or a link to it: the kernel's resource manager flushes
  every handle a closed stream held. After an interrupt the provider closes
  the stream and opens a fresh one, and lists no handles.
- **`/dev/tpm0` and a simulator socket** (`unix:` or `tcp:`): nothing
  flushes a closed stream's handles, and an interrupted command may still
  create one in the TPM. The provider must be the TPM's only user. Before
  its first command, a call lists the TPM's transient objects and loaded
  sessions with `TPM2_GetCapability` (`TPM_CAP_HANDLES`). After an interrupt
  the provider reopens the stream, lists them again, and flushes each handle
  the first list lacks; it never flushes a handle that list holds. The TPM
  runs one command at a time, so the second list follows the interrupted
  command. A reclaim the TPM refuses, or that runs past the 5-second bound,
  stays due: the next call finishes it before it sends a command, and fails
  if it cannot. With no next call, `Close` finishes it within 5 seconds
  before it closes the stream, which it closes whatever the reclaim returns,
  and returns the reclaim's failure.

On every transport, a `TPM2_FlushContext` the TPM answers with an error
(`TPM_RC_RETRY` after every retry, or any other response code) leaves its
handle loaded on a stream still in step. The call returns its error and the
provider keeps the handle: the next call flushes it before it sends a
command, and fails while the TPM still lists it; one the TPM no longer lists
is gone. Without a resource manager, `Close` flushes it within the same
5 seconds as the reclaim, since closing the stream does not drop the handle,
and returns a failure; behind one, a reopen or `Close`
drops it. The provider keeps only handles it made.

The interrupted call returns an error matching `ctx.Err()` either way.

### Test plan

- **Unit tests, pure functions, every platform:** the blob framing (round
  trip; each truncation; a wrong version; trailing bytes; a size field past
  the end; each template field changed), and the result-code mapping (each
  row of the [error mapping](#error-mapping), including a format-one code on
  a handle or session number, which must not count as a parameter).
- **Mid-command cancellation, unit test, every platform:** `providertest`
  refuses only a context already ended at entry, so the provider's own test
  measures the rest. A fake go-tpm transport blocks inside a chosen command
  until the test releases it; the test cancels the context while it blocks,
  then releases it. For `Protect` and `Unprotect`, and for each command of
  their sequences in turn, the test checks that the call does not return
  before every key-bearing transient is wiped (the fake observes the wipe
  through the provider's transient allocator), that no command but the
  `TPM2_FlushContext` of the held handles reaches the transport after the
  blocked one, that the error matches `ctx.Err()`, and that a cancelled
  `Unprotect` leaves `key` holding the canary bytes the test filled it with.
  The blocked command includes each `TPM2_FlushContext` after a successful
  `TPM2_Unseal`: a cancel during a flush still sends the remaining flushes,
  returns `ctx.Err()` and leaves `key` unchanged. A fake flush that fails
  after a successful unseal, with the context live, returns the provider's
  own error and also leaves `key` unchanged.
- **Interrupted exchange, unit test, Linux:** over a socket that accepts
  commands and never answers, `Protect` and `Unprotect` return `ctx.Err()`
  within 2 seconds of the context's end, `Close` interrupts a call stuck
  with a live context, and the goroutine count returns to its value before
  the test.
- **Residue, unit test, Linux:** a fake TPM checks the session HMACs,
  decrypts `TPM2_Create`'s `inSensitive` and encrypts `TPM2_Unseal`'s
  response; after each call the test sweeps this process's anonymous and
  writable mappings through `/proc/self/mem` for the key, which may remain
  only in the fake's own locked buffer.
- **Conformance against a software TPM:** `providertest.TestProvider` with
  `Modes` = `ModePerOperation`, against `swtpm` in a CI fixture job under a
  build tag of its own, as the OP-TEE job runs the arm-trustzone suite. The
  `Forge` hook seals a key with the same TPM under the standard storage
  template (no label), and `Unprotect` must refuse that blob with
  `ErrSealedAuthentication`: the suite thereby measures the label binding.
- **No hardware TPM in CI.** A hardware TPM is a manual check, documented in
  the provider's user doc.

## Secure-element provider (outline)

A PKCS#11 provider in its own module, `backends/pkcs11` (module path
`github.com/jeremyhahn/go-enclave/backends/pkcs11`), so the root module
gains no dependency. Nothing here is decided beyond the shape; the
[open questions](#open-questions) must be answered before it is built.

- **Key:** one AES-256 secret key in the token, `CKA_TOKEN`, `CKA_SENSITIVE`,
  `CKA_ENCRYPT` and `CKA_DECRYPT` true, `CKA_EXTRACTABLE` false, found by its
  `CKA_ID`. The provider uses the key; it never reads it.
- **Protect:** `C_EncryptInit` with `CKM_AES_GCM` (a 96-bit nonce, a 128-bit
  tag, the label `go-enclave v1 PKCS#11 KeyProtector` as AAD), then
  `C_Encrypt` of the key.
- **Unprotect:** `C_DecryptInit` and `C_Decrypt` into a locked transient,
  copied into `key` only when the tag verified and the length is `len(key)`.
  A tag failure (`CKR_ENCRYPTED_DATA_INVALID`), a `CKA_ID` the token does not
  hold, a wrong version byte and a malformed blob match
  `ErrSealedAuthentication`; every other `CKR_` code is the provider's own
  error.
- **Health:** nil unconditionally.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | version = 1 |
| 1 | 1 | k: length of the key's `CKA_ID` |
| 2 | k | the key's `CKA_ID` |
| 2 + k | 12 | GCM nonce |
| 14 + k | n + 16 | ciphertext of the n-byte key, then the GCM tag |

## Rejected alternatives

- **A persistent SRK handle** (`TPM2_EvictControl` to `0x81000001`). It
  writes TPM NV state, needs owner authorization, takes a scarce persistent
  slot, and collides with whatever provisioning already put a key at the
  well-known handle. The per-call primary is deterministic, so it loses
  nothing a persistent handle would keep; it costs one `TPM2_CreatePrimary`
  per call.
- **Sealing under a PCR policy by default.** It ties every blob to one boot
  state: a firmware, bootloader or kernel update changes the PCRs and makes
  every sealed value unopenable unless a re-seal or a `TPM2_PolicyAuthorize`
  signing key was set up first. Which PCRs, and who holds that key, is a
  product decision the caller owns. A PCR policy may come later as an opt-in
  option; the default seals to the TPM alone.
- **The TPM provider in the root module.** It would make go-tpm a dependency
  of every go-enclave consumer, including those that never touch a TPM. The
  nested-module pattern of `backends/armtrustzone` keeps the root clean.
- **The label in the sealed object's `authPolicy`.** Not enforced by the TPM
  under `userWithAuth`; see [Associated data](#associated-data).
- **An RSA-2048 parent.** Deriving an RSA primary searches for primes, which
  takes seconds on some TPMs, on every call.
- **A password session for `TPM2_Unseal`.** The key would cross the bus in
  clear.
- **Wrapping with a TPM-resident AES key** (`TPM2_EncryptDecrypt2`). The
  command is optional and absent from some TPMs; sealed data objects are
  mandatory.

## Open questions

1. **Owner hierarchy authorization: resolved.** The provider takes no
   owner-auth option: it authorizes `TPM2_CreatePrimary` under the owner
   hierarchy with an empty password (`backends/tpm/protector.go:536`), as
   Linux distributions ship the hierarchy. A TPM whose owner auth is set
   refuses the command with `TPM_RC_BAD_AUTH`, which the provider returns as
   its own error (`ErrCommandFailed`), so no credential enters its
   configuration. An owner-auth option would be an addition to the API.
2. **An active bus interposer.** The salted session hides the key from a
   passive observer. An attacker who can rewrite TPM responses can hand the
   provider a parent public key of its own and read the salt. Binding the
   session to an endorsement-key-certified key closes that, at the cost of an
   EK certificate chain; it is not in this design.
3. **The parent's lifetime: resolved.** The parent is created per call:
   `Protect` and `Unprotect` each create it in `parentAndSession`
   (`backends/tpm/protector.go:381`) and flush it with the call's other
   handles in `cleanup` (`backends/tpm/protector.go:408`) before the call
   returns. The provider keeps no parent loaded between calls, so a
   resource-manager restart or a context swap cannot leave it a stale handle;
   the cost is one `TPM2_CreatePrimary` per call.
4. **Residual copy in go-tpm's buffers: resolved.** go-tpm v0.9.8 marshals
   `TPM2_Create`'s `inSensitive` in clear into heap buffers before it applies
   parameter encryption, and decrypts `TPM2_Unseal`'s response in place in a
   heap buffer it does not hand back or wipe. A heap sweep over a fake TPM
   found the key resident after both calls. The provider therefore marshals
   those two commands itself, in locked buffers it wipes, and uses only the
   session's exported `Encrypt`, `Decrypt`, `Authorize` and `Validate`, which
   work in place on the provider's buffers and hash only ciphertext. The
   other commands carry no key material and stay on go-tpm. The unit sweep
   (`residue_linux_test.go`) and `providertest`'s residue sweep on `swtpm`
   run with no skip.
5. **Departure: the label binds through the parent.** The row offered the
   sealed object's `authPolicy` or its own unique or name derivation. A
   sealed data object's `unique` is computed by the TPM from its sensitive
   area and its name is a digest of its public area, so neither carries a
   label the TPM checks at load; the parent's `unique` does. This design
   binds through the parent ([Associated data](#associated-data)).
6. **Departure: TPM2_Load parameter errors.** The row mapped only
   `TPM_RC_INTEGRITY` among load failures to `ErrSealedAuthentication`. A
   tampered blob can also fail to load with another format-one code on its
   own parameters (`TPM_RC_SIZE`, for example), and contract item 1 requires
   that refusal too to match `ErrSealedAuthentication`. This design maps
   every format-one code on `TPM2_Load`'s parameters 1 and 2, and checks the
   public area against the template before device work.
7. **Departure: sealed object attributes.** The row's attribute set is kept;
   the design adds that `sensitiveDataOrigin` must stay clear, which
   [TPM 2.0 Part 3](../reference/TCG_TPM2_r1p59_Part3_Commands_pub.pdf)
   (`TPM2_Create`) requires when the caller supplies the sealed data.
8. **Secure element: cgo.** A PKCS#11 binding loads a C library: the common
   Go bindings need cgo, and go-enclave builds without it today. Options: a
   cgo binding in the nested module only; a pure-Go loader; or a separate
   helper process. Open.

   Proposed answer (for owner sign-off): a pure-Go loader in the nested
   module `backends/pkcs11` only, so the provider builds with
   `CGO_ENABLED=0` as `backends/armtrustzone` does and the root module
   gains nothing; a helper process is rejected because the key would cross
   an IPC boundary the provider does not control, and a cgo binding would
   bring a C toolchain into the static and cross builds. Whether a
   third-party pure-Go loader dependency is preferable to cgo confined to
   the nested module is the owner's taste.
9. **Secure element: test fixture.** SoftHSM in a CI fixture job, as `swtpm`
   for the TPM, is the obvious choice; whether its GCM behaviour matches the
   tokens the provider targets is not established. Open.

   Proposed answer (for owner sign-off): SoftHSM v2, at its latest release,
   in a CI fixture job that runs `providertest` (the residue sweep
   included, with no skip) as `swtpm` does for the TPM; it is a real
   PKCS#11 token driven through the same library interface, not a mock in
   the provider's code. The suite asserts only the contract and the blob
   layout, not token-specific GCM behaviour, so a difference on another
   token shows as a failing run on that token; which hardware token, if
   any, gets a recurring run is the owner's choice.
10. **Secure element: nonce and limits.** A random 96-bit nonce bounds a key
    at 2^32 encryptions (NIST SP 800-38D), a count no single process can
    enforce across processes; and some tokens in FIPS mode refuse a
    caller-supplied GCM nonce and generate their own. Whether the provider
    asks the token for the nonce, and how the limit is enforced, is open.

    Proposed answer (for owner sign-off): the provider supplies a random
    96-bit nonce from `crypto/rand` and does not enforce the limit; the
    limit is documented as the operator's, met by provisioning a new key
    under a new `CKA_ID` well before 2^32 seals, and old blobs still open
    because each names its key. This keeps the provider stateless across
    processes, as the TPM provider writes no NV state; the blob already
    stores the nonce, so token-generated nonces can be added later without
    a layout change. Whether FIPS-mode tokens that refuse a caller nonce
    are a target for the first code slice is the owner's call.
11. **Secure element: key provisioning and login.** Who creates the token key
    (the provider on first use, or an operator beforehand), and where the
    user PIN comes from without a credential in configuration.

    Proposed answer (for owner sign-off): an operator provisions the key
    beforehand, and the provider never creates one; at construction it
    checks the key's attributes against the outline and refuses a key that
    is extractable or not sensitive. The caller hands the user PIN to the
    constructor in a locked buffer the provider wipes after `C_Login`, and
    a token with a protected authentication path logs in with no PIN, so
    no credential enters the provider's configuration, as the TPM provider
    takes no owner-auth option (question 1). Whether the PIN arrives as a
    locked buffer or through a caller callback is the owner's taste.
