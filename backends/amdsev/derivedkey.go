package amdsev

import "encoding/binary"

// sevGuestDevice is the SNP guest device the sev-guest driver creates when
// SNP is active. SEV and SEV-ES guests have none.
const sevGuestDevice = "/dev/sev-guest"

// The SNP_GET_DERIVED_KEY messages, as the SEV-SNP firmware ABI defines
// MSG_KEY_REQ and MSG_KEY_RSP and Linux's include/uapi/linux/sev-guest.h
// carries them: a 32-byte request and a 64-byte response whose STATUS word
// is at offset 0 and whose DERIVED_KEY is the last 32 bytes.
const (
	keyRequestSize       = 32
	keyResponseSize      = 64
	keyResponseKeyOffset = 0x20
	derivedKeySize       = keyResponseSize - keyResponseKeyOffset
)

// ROOT_KEY_SELECT: the key the firmware derives from.
const (
	// rootKeyVCEK is the chip's versioned key: material sealed under it
	// opens on this chip only.
	rootKeyVCEK uint32 = 0
	// rootKeyVMRK is the migration agent's VM root key.
	rootKeyVMRK uint32 = 1
)

// GUEST_FIELD_SELECT: the guest fields the firmware mixes into the key.
const (
	fieldPolicy      uint64 = 1 << 0
	fieldImageID     uint64 = 1 << 1
	fieldFamilyID    uint64 = 1 << 2
	fieldMeasurement uint64 = 1 << 3
	fieldGuestSVN    uint64 = 1 << 4
	fieldTCBVersion  uint64 = 1 << 5
)

// keyRequest is MSG_KEY_REQ.
type keyRequest struct {
	rootKey    uint32
	fields     uint64
	vmpl       uint32
	guestSVN   uint32
	tcbVersion uint64
}

// sealKeyRequest is the request [Backend.UnsealRoot] sends: a key from the
// chip's VCEK bound to the guest's policy and launch measurement, at VMPL 0.
// The same image under the same policy on the same chip derives the same
// key; another image, policy or chip does not.
var sealKeyRequest = keyRequest{rootKey: rootKeyVCEK, fields: fieldPolicy | fieldMeasurement}

// encode lays the request out little-endian, reserved bytes zero.
func (r keyRequest) encode() [keyRequestSize]byte {
	var b [keyRequestSize]byte
	binary.LittleEndian.PutUint32(b[0:], r.rootKey)
	binary.LittleEndian.PutUint64(b[8:], r.fields)
	binary.LittleEndian.PutUint32(b[16:], r.vmpl)
	binary.LittleEndian.PutUint32(b[20:], r.guestSVN)
	binary.LittleEndian.PutUint64(b[24:], r.tcbVersion)
	return b
}

// decodeKeyResponse copies the response's DERIVED_KEY into dst, which is
// [derivedKeySize] bytes, or returns a [*FirmwareError] carrying a nonzero
// STATUS and writes nothing.
func decodeKeyResponse(resp *[keyResponseSize]byte, dst []byte) error {
	if s := binary.LittleEndian.Uint32(resp[0:]); s != 0 {
		return &FirmwareError{Status: s}
	}
	copy(dst, resp[keyResponseKeyOffset:])
	return nil
}

// firmwareError splits the ioctl's exitinfo2 into the firmware's error word
// (the low half) and the hypervisor's (the high half).
func firmwareError(exitInfo2 uint64, errno error) *FirmwareError {
	return &FirmwareError{
		FWError:  uint32(exitInfo2), //nolint:gosec // G115: the low half, by definition
		VMMError: uint32(exitInfo2 >> 32),
		Errno:    errno,
	}
}
