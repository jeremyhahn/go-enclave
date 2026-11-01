package armtrustzone

import (
	"errors"
	"testing"
)

// TestTEECUUIDByteOrder checks the TA's UUID against RFC 9562: its fields,
// its version and variant, and the network byte order the driver reads.
func TestTEECUUIDByteOrder(t *testing.T) {
	u, err := parseUUID(taUUID)
	if err != nil {
		t.Fatalf("parseUUID(%q): %v", taUUID, err)
	}
	want := teecUUID{
		TimeLow:          0x23751b49,
		TimeMid:          0x3a76,
		TimeHiAndVersion: 0x4e49,
		ClockSeqAndNode:  [8]byte{0xb6, 0x3c, 0xe5, 0x85, 0x37, 0x42, 0xfa, 0x1f},
	}
	if u != want {
		t.Fatalf("parseUUID(%q) = %+v, want %+v", taUUID, u, want)
	}
	if v := u.TimeHiAndVersion >> 12; v != 4 {
		t.Errorf("version = %d, want 4 (RFC 9562 §5.4)", v)
	}
	if variant := u.ClockSeqAndNode[0] >> 6; variant != 0b10 {
		t.Errorf("variant = %02b, want 10 (RFC 9562 §4.1)", variant)
	}
	octets := [uuidLen]byte{
		0x23, 0x75, 0x1b, 0x49, 0x3a, 0x76, 0x4e, 0x49,
		0xb6, 0x3c, 0xe5, 0x85, 0x37, 0x42, 0xfa, 0x1f,
	}
	if got := u.octets(); got != octets {
		t.Errorf("octets() = % x, want % x", got, octets)
	}
	upper, err := parseUUID("23751B49-3A76-4E49-B63C-E5853742FA1F")
	if err != nil || upper != u {
		t.Errorf("upper-case form = %+v, %v; want %+v", upper, err, u)
	}
}

func TestParseUUIDRefusesMalformedText(t *testing.T) {
	for _, text := range []string{
		"",
		"23751b49-3a76-4e49-b63c-e5853742fa1",
		"23751b49-3a76-4e49-b63c-e5853742fa1f0",
		"23751b493a764e49b63ce5853742fa1f",
		"23751b49_3a76-4e49-b63c-e5853742fa1f",
		"23751b49-3a76-4e49-b63c-e5853742fa1g",
		"{3751b49-3a76-4e49-b63c-e5853742fa1f",
	} {
		_, err := parseUUID(text)
		var ue *UUIDError
		if !errors.Is(err, ErrInvalidUUID) || !errors.As(err, &ue) || ue.Text != text {
			t.Errorf("parseUUID(%q) = %v, want a UUIDError for it", text, err)
		}
	}
}
