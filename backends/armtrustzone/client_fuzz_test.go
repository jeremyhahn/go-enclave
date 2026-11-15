package armtrustzone

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// wellFormedUUID is the oracle for parseUUID, written without it: 36 bytes,
// dashes at 8, 13, 18 and 23, and a hex digit at every other position.
func wellFormedUUID(text string) bool {
	if len(text) != 36 {
		return false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", rune(c)) {
				return false
			}
		}
	}
	return true
}

func FuzzParseUUID(f *testing.F) {
	for _, seed := range []string{
		taUUID,
		strings.ToUpper(taUUID),
		"",
		"23751b49-3a76-4e49-b63c-e5853742fa1",
		"23751b49-3a76-4e49-b63c-e5853742fa1f0",
		"23751b493a764e49b63ce5853742fa1f",
		"23751b49_3a76-4e49-b63c-e5853742fa1f",
		"23751b49-3a76-4e49-b63c-e5853742fa1g",
		"{3751b49-3a76-4e49-b63c-e5853742fa1f",
		// Dashes where digits belong: the parser must not skip them.
		"--751b49-3a76-4e49-b63c-e5853742fa1f",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		u, err := parseUUID(text)
		if wellFormedUUID(text) {
			if err != nil {
				t.Fatalf("parseUUID(%q): %v, want it accepted", text, err)
			}
			o := u.octets()
			got := hex.EncodeToString(o[:])
			want := strings.ToLower(strings.ReplaceAll(text, "-", ""))
			if got != want {
				t.Fatalf("parseUUID(%q).octets() = %s, want %s", text, got, want)
			}
			return
		}
		var ue *UUIDError
		if !errors.Is(err, ErrInvalidUUID) || !errors.As(err, &ue) || ue.Text != text {
			t.Fatalf("parseUUID(%q) = %+v, %v, want a UUIDError for it", text, u, err)
		}
	})
}

func TestHexDigit(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := byte(i)
		got, ok := hexDigit(c)
		want, perr := strconv.ParseUint(string(c), 16, 8)
		if perr != nil {
			if ok {
				t.Errorf("hexDigit(%#02x) = %d, true, want ok false", c, got)
			}
			continue
		}
		if !ok || uint64(got) != want {
			t.Errorf("hexDigit(%q) = %d, %v, want %d, true", c, got, ok, want)
		}
	}
}
