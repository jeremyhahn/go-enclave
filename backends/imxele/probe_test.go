package imxele

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// versionBuf lays out struct tee_ioctl_version_data (impl_id, impl_caps,
// gen_caps; three native-endian __u32) as TEE_IOC_VERSION fills it.
func versionBuf(implID, implCaps, genCaps uint32) []byte {
	b := make([]byte, teeVersionSize)
	binary.NativeEndian.PutUint32(b[0:], implID)
	binary.NativeEndian.PutUint32(b[4:], implCaps)
	binary.NativeEndian.PutUint32(b[8:], genCaps)
	return b
}

func TestParseVersion(t *testing.T) {
	v, err := parseVersion(versionBuf(1, 0x3, teeGenCapGP|0x4))
	if err != nil {
		t.Fatalf("parseVersion = %v", err)
	}
	if v.ImplID != 1 || v.ImplCaps != 0x3 || v.GenCaps != teeGenCapGP|0x4 {
		t.Errorf("parseVersion = %+v", v)
	}
	if _, err := parseVersion(make([]byte, teeVersionSize-1)); err == nil {
		t.Errorf("parseVersion accepted a short buffer")
	}
}

func TestCheckVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		genCaps uint32
		ok      bool
	}{
		{"gp client", teeGenCapGP, true},
		{"gp client with more caps", teeGenCapGP | 0x6, true},
		{"not gp", 0x6, false},
		{"no caps", 0, false},
	} {
		v, err := parseVersion(versionBuf(2, 0, tc.genCaps))
		if err != nil {
			t.Fatalf("%s: parseVersion = %v", tc.name, err)
		}
		err = checkVersion(v)
		if tc.ok != (err == nil) {
			t.Errorf("%s: checkVersion = %v, want ok %v", tc.name, err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, ErrNotGlobalPlatform) {
			t.Errorf("%s: checkVersion = %v, want ErrNotGlobalPlatform", tc.name, err)
		}
	}
}

func TestProbeHonoursCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx, DefaultEndpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe(canceled ctx) = %v, want context.Canceled", err)
	}
}
