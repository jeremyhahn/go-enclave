package macse

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
)

// probeMessage is what the probe's transient key signs.
var probeMessage = []byte("go-enclave mac-secure-enclave probe")

// errBadSignature is the probe's signature failing under its own key's
// public point.
var errBadSignature = errors.New("the signature does not verify under the key's public point")

// probe is the check the proposal's "Shape proposed" names: one transient
// key in the Secure Enclave, its public point, one signature, verified here
// in Go. Every failure matches [ErrSecureEnclaveUnavailable] and names its
// step, except an ended ctx, which returns ctx.Err(). A nil ctx never ends.
//
// The Managed Device Attestation identity check (OpIdentity) joins the probe
// with attestation, in a later slice; until then a Mac that can hold keys but
// cannot attest still probes usable.
func probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	k, err := createKey(ctx)
	if err != nil {
		return err
	}
	defer k.release()

	pub, status := k.publicX963()
	if status != 0 {
		return unavailableError(OpPublic, status, nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	digest := sha256.Sum256(probeMessage)
	sig, status := k.sign(digest[:])
	if status != 0 {
		return unavailableError(OpSign, status, nil)
	}
	return checkProbeSignature(pub, digest[:], sig)
}

// checkProbeSignature verifies sig, ASN.1 DER ECDSA, over digest under pub,
// an X9.63 uncompressed P-256 point. A failure is a [*SecurityError] at
// OpVerify matching [ErrSecureEnclaveUnavailable].
func checkProbeSignature(pub, digest, sig []byte) error {
	k, err := parsePublicX963(pub)
	if err != nil {
		return unavailableError(OpVerify, 0, err)
	}
	if !ecdsa.VerifyASN1(k, digest, sig) {
		return unavailableError(OpVerify, 0, errBadSignature)
	}
	return nil
}

// parsePublicX963 parses the external representation of a Secure Enclave
// public key: 65 bytes, 0x04 || X || Y, a point on P-256.
func parsePublicX963(b []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
}
