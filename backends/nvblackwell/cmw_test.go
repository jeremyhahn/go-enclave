package nvblackwell

import (
	"errors"
	"testing"
)

func TestEncodeCMWRecord(t *testing.T) {
	got, err := encodeCMW(cmwCollection{
		"a": cmwRecord{Type: mediaTypePEMChain, Value: []byte{0xfb, 0xff}, Ind: cmwIndEvidence},
	})
	if err != nil {
		t.Fatalf("encodeCMW: %v", err)
	}
	// base64url without padding: 0xfb 0xff is "-_8", never "+/8=".
	want := `{"a":["application/pem-certificate-chain","-_8",4]}`
	if string(got) != want {
		t.Fatalf("encodeCMW = %s, want %s", got, want)
	}
}

func TestEncodeCMWOmitsZeroInd(t *testing.T) {
	got, err := encodeCMW(cmwCollection{"a": cmwRecord{Type: "text/plain", Value: []byte{0x01}}})
	if err != nil {
		t.Fatalf("encodeCMW: %v", err)
	}
	if want := `{"a":["text/plain","AQ"]}`; string(got) != want {
		t.Fatalf("encodeCMW = %s, want %s", got, want)
	}
}

func TestEncodeCMWNestsAndSortsLabels(t *testing.T) {
	got, err := encodeCMW(cmwCollection{
		"gpu0": cmwCollection{"report": cmwRecord{Type: "text/plain", Value: []byte("r"), Ind: cmwIndEvidence}},
		"cpu":  cmwRecord{Type: "text/plain", Value: []byte("c"), Ind: cmwIndEvidence},
	})
	if err != nil {
		t.Fatalf("encodeCMW: %v", err)
	}
	want := `{"cpu":["text/plain","Yw",4],"gpu0":{"report":["text/plain","cg",4]}}`
	if string(got) != want {
		t.Fatalf("encodeCMW = %s, want %s", got, want)
	}
}

func TestEncodeCMWRefusesMalformedMembers(t *testing.T) {
	rec := cmwRecord{Type: "text/plain", Value: []byte("x")}
	for name, c := range map[string]cmwCollection{
		"empty collection":  {},
		"empty nested":      {"a": cmwCollection{}},
		"empty label":       {"": rec},
		"reserved label":    {cmwCollectionTypeLabel: rec},
		"empty type":        {"a": cmwRecord{Value: []byte("x")}},
		"empty value":       {"a": cmwRecord{Type: "text/plain"}},
		"nil member":        {"a": nil},
		"nested empty type": {"a": cmwCollection{"b": cmwRecord{Value: []byte("x")}}},
	} {
		if _, err := encodeCMW(c); !errors.Is(err, errMalformedCMW) {
			t.Errorf("%s: encodeCMW error = %v, want errMalformedCMW", name, err)
		}
	}
}
