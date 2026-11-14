package armtrustzone

import "encoding/binary"

// The GP TEE Client API's semantics this client reimplements over the TEE
// ioctls instead of inheriting them from libteec: TEEC_UUID and its byte
// order, and the TEEC_Result and TEEC_ORIGIN values it reports. The calls
// themselves (TEEC_InitializeContext, TEEC_OpenSession, TEEC_InvokeCommand)
// are client_linux.go's.

// TEEC_Result values this client acts on.
const (
	teecSuccess     = 0x00000000
	teecErrorCancel = 0xffff0002
)

// TEEC_ORIGIN values, for reading a [SessionError] or [CommandError].
const (
	OriginAPI        = 1 // TEEC_ORIGIN_API: the Client API
	OriginComms      = 2 // TEEC_ORIGIN_COMMS: the transport to the TEE
	OriginTEE        = 3 // TEEC_ORIGIN_TEE: the TEE itself
	OriginTrustedApp = 4 // TEEC_ORIGIN_TRUSTED_APP: the trusted application
)

// uuidLen is the length of a UUID in octets.
const uuidLen = 16

// teecUUID is TEEC_UUID: the RFC 9562 fields of a UUID.
type teecUUID struct {
	TimeLow          uint32
	TimeMid          uint16
	TimeHiAndVersion uint16
	ClockSeqAndNode  [8]byte
}

// parseUUID reads the RFC 9562 string form (8-4-4-4-12 hex digits) into a
// TEEC_UUID.
func parseUUID(text string) (teecUUID, error) {
	var octets [uuidLen]byte
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return teecUUID{}, &UUIDError{Text: text}
	}
	// Read the 16 digit pairs at their fixed offsets, so a dash in a
	// digit position is refused rather than skipped.
	i := 0
	for j := range octets {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			i++
		}
		hi, ok1 := hexDigit(text[i])
		lo, ok2 := hexDigit(text[i+1])
		if !ok1 || !ok2 {
			return teecUUID{}, &UUIDError{Text: text}
		}
		octets[j] = hi<<4 | lo
		i += 2
	}
	return teecUUID{
		TimeLow:          uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3]),
		TimeMid:          uint16(octets[4])<<8 | uint16(octets[5]),
		TimeHiAndVersion: uint16(octets[6])<<8 | uint16(octets[7]),
		ClockSeqAndNode:  [8]byte(octets[8:]),
	}, nil
}

// octets returns u in the byte order the TEE driver reads it: RFC 9562's
// network order, each field big-endian, as libteec's uuid_to_octets writes it.
func (u teecUUID) octets() [uuidLen]byte {
	var o [uuidLen]byte
	binary.BigEndian.PutUint32(o[0:4], u.TimeLow)
	binary.BigEndian.PutUint16(o[4:6], u.TimeMid)
	binary.BigEndian.PutUint16(o[6:8], u.TimeHiAndVersion)
	copy(o[8:], u.ClockSeqAndNode[:])
	return o
}

// hexDigit returns the value of one hex digit, either case.
func hexDigit(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
