package imxele

import (
	"context"
	"encoding/binary"
	"fmt"
)

// DefaultEndpoint is the TEE device the backend opens when given no path.
const DefaultEndpoint = "/dev/tee0"

// The generic TEE subsystem ABI of the kernel's tee.h; nothing here is
// specific to the i.MX 95.
const (
	// teeVersionSize is sizeof(struct tee_ioctl_version_data): impl_id,
	// impl_caps and gen_caps, three __u32.
	teeVersionSize = 12
	// teeGenCapGP is TEE_GEN_CAP_GP: the driver is a GlobalPlatform client.
	teeGenCapGP uint32 = 1 << 0
	// teeIOCVersion is TEE_IOC_VERSION, _IOR(TEE_IOC_MAGIC 0xa4,
	// TEE_IOC_BASE + 0, struct tee_ioctl_version_data).
	teeIOCVersion = 2<<30 | teeVersionSize<<16 | 0xa4<<8
)

// teeVersion is struct tee_ioctl_version_data.
type teeVersion struct {
	ImplID, ImplCaps, GenCaps uint32
}

// parseVersion decodes the buffer TEE_IOC_VERSION fills, native-endian as
// the kernel writes it.
func parseVersion(b []byte) (teeVersion, error) {
	if len(b) < teeVersionSize {
		return teeVersion{}, fmt.Errorf("imxele: TEE version data is %d bytes, want %d", len(b), teeVersionSize)
	}
	return teeVersion{
		ImplID:   binary.NativeEndian.Uint32(b[0:]),
		ImplCaps: binary.NativeEndian.Uint32(b[4:]),
		GenCaps:  binary.NativeEndian.Uint32(b[8:]),
	}, nil
}

// checkVersion refuses a driver that is not a GlobalPlatform client. It does
// not pin the implementation ID: the doc leaves trusted-imx95's secure world
// open ("CONFIG_OPTEE if it is OP-TEE"), and the session step identifies the
// trusted application itself.
func checkVersion(v teeVersion) error {
	if v.GenCaps&teeGenCapGP == 0 {
		return ErrNotGlobalPlatform
	}
	return nil
}

// probe runs the detection probe of docs/backends/imx-edgelock-enclave.md
// Q4, the recommended option: check ctx, open the device, check
// TEE_IOC_VERSION, open a session to the trusted application, run the
// version command, check the ABI version, and close everything, making no
// key. Each refusal is a typed error naming its step.
func probe(ctx context.Context, path string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		path = DefaultEndpoint
	}
	if err := probeDevice(path); err != nil {
		return err
	}
	// The session and version-command steps need trusted-imx95's published
	// trusted application UUID and command ABI; until then the backend
	// refuses here rather than probe usable.
	return &TEESessionError{Cause: errTAUnpublished}
}
