// Package armtrustzone is go-enclave's arm-trustzone backend: random bytes
// from a trusted application in OP-TEE, the secure world of Arm TrustZone,
// delivered into memory enclave handles.
//
// It is pure Go over the Linux TEE subsystem's ioctl interface on /dev/tee0
// (include/uapi/linux/tee.h) with the GP TEE Client API's semantics, so it
// builds with CGO_ENABLED=0 into a static linux/arm64 binary. On other
// platforms it compiles, and [Connect] returns a [PlatformError].
//
// [Connect] opens a session with the trusted application
// (interface version 1) and checks its interface with GET_INFO;
// [Backend.Random] fills a handle with GET_RANDOM. Register a [Connector] with
// [enclave.Register] to make the backend discoverable by name:
//
//	if err := enclave.Register(armtrustzone.Connector{}); err != nil { ... }
//	b, err := armtrustzone.Connect("/dev/tee0")
//	h, err := b.Random(ctx, 32)
//
// The design is docs/backends/arm-trustzone-design.md.
package armtrustzone
