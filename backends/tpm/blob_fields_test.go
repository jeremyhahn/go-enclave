package tpm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// TestSized drives the size-prefixed field reader directly, on every
// boundary of its two length checks.
func TestSized(t *testing.T) {
	cases := []struct {
		name        string
		in          []byte
		field, rest []byte
		ok          bool
	}{
		{name: "empty", in: nil},
		{name: "one_byte", in: []byte{0x00}},
		{name: "zero_length_field", in: []byte{0x00, 0x00, 0x07}, field: []byte{}, rest: []byte{0x07}, ok: true},
		{name: "field_fills_input", in: []byte{0x00, 0x02, 0x0a, 0x0b}, field: []byte{0x0a, 0x0b}, rest: []byte{}, ok: true},
		{name: "length_one_past_input", in: []byte{0x00, 0x03, 0x0a, 0x0b}},
		{name: "length_ffff_short_input", in: []byte{0xff, 0xff, 0x0a}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, rest, ok := sized(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				if field != nil || rest != nil {
					t.Fatalf("refused read returned field %x, rest %x; want nil", field, rest)
				}
				return
			}
			if !bytes.Equal(field, tc.field) || !bytes.Equal(rest, tc.rest) {
				t.Fatalf("got field %x rest %x, want field %x rest %x", field, rest, tc.field, tc.rest)
			}
		})
	}
}

// TestCheckPublic names each reason checkPublic refuses a public area for,
// and accepts the sealed template it marshals itself.
func TestCheckPublic(t *testing.T) {
	const (
		unmarshal = "the public area does not unmarshal"
		notSealed = "the public area is not a sealed-data object"
		badUnique = "the public area's unique is not a SHA-256 digest"
		template  = "the public area is not the sealed-object template"
	)
	cases := []struct {
		name   string
		public []byte
		reason string
	}{
		{name: "does_not_unmarshal", public: []byte{0x00, 0x08, 0x00}, reason: unmarshal},
		{name: "empty", public: nil, reason: unmarshal},
		{name: "type_ecc", public: tpm2.Marshal(storageTemplate(make([]byte, 32))), reason: notSealed},
		{name: "unique_31", public: tpm2.Marshal(sealedTemplate(make([]byte, 31))), reason: badUnique},
		{name: "unique_33", public: tpm2.Marshal(sealedTemplate(make([]byte, 33))), reason: badUnique},
		{name: "attribute_decrypt_set", public: testPublic(t, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Decrypt = true }), reason: template},
		{name: "name_alg_sha384", public: testPublic(t, func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgSHA384 }), reason: template},
		{name: "auth_policy_non_empty", public: testPublic(t, func(p *tpm2.TPMTPublic) {
			p.AuthPolicy = tpm2.TPM2BDigest{Buffer: make([]byte, 32)}
		}), reason: template},
		{name: "trailing_byte", public: append(testPublic(t, nil), 0), reason: template},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPublic(tc.public)
			var ae *authError
			if !errors.As(err, &ae) {
				t.Fatalf("got %v, want an *authError", err)
			}
			if ae.reason != tc.reason {
				t.Fatalf("reason %q, want %q", ae.reason, tc.reason)
			}
			requireAuth(t, err)
		})
	}

	t.Run("sealed_template_accepted", func(t *testing.T) {
		if err := checkPublic(testPublic(t, nil)); err != nil {
			t.Fatalf("checkPublic refused the sealed template: %v", err)
		}
	})
}
