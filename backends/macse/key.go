package macse

// seKey is one transient P-256 key in the Secure Enclave, as the platform's
// createKey made it (SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
// and no kSecAttrIsPermanent): it lives as long as the reference and leaves
// nothing in the keychain.
type seKey interface {
	// publicX963 returns the public key's external representation, the
	// X9.63 uncompressed point 0x04 || X || Y.
	publicX963() ([]byte, error)
	// sign returns the ASN.1 DER ECDSA signature of a SHA-256 digest
	// (kSecKeyAlgorithmECDSASignatureDigestX962SHA256).
	sign(digest []byte) ([]byte, error)
	// release drops the reference, after which the key is gone.
	release()
}
