package macse

// seKey is one transient P-256 key in the Secure Enclave, as the platform's
// createKey made it (SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
// and no kSecAttrIsPermanent): it lives as long as the reference and leaves
// nothing in the keychain. Each call returns the OSStatus of the Security
// framework call it makes, 0 on success.
type seKey interface {
	// publicX963 returns the public key's external representation, the
	// X9.63 uncompressed point 0x04 || X || Y.
	publicX963() ([]byte, int32)
	// sign returns the ASN.1 DER ECDSA signature of a SHA-256 digest
	// (kSecKeyAlgorithmECDSASignatureDigestX962SHA256).
	sign(digest []byte) ([]byte, int32)
	// release drops the reference, after which the key is gone.
	release()
}
