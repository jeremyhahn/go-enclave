// Package tpm is go-enclave's TPM 2.0 KeyProtector provider.
//
// A [KeyProtector] seals each data-encryption key into a TPM sealed-data
// object under a transient ECC P-256 storage primary whose template carries
// the label "go-enclave v1 TPM KeyProtector", so only a parent derived for
// go-enclave can load the blob. The provider serves
// [enclave.ModePerOperation] only:
//
//	tp, err := tpm.Open("") // /dev/tpmrm0
//	if err != nil {
//		return err
//	}
//	defer tp.Close()
//	sealer, err := enclave.NewSealer(enclave.WithKeyProtector(tp))
//
// The TPM keeps no object and no persistent handle: every call derives the
// parent from the owner hierarchy's seed and flushes it before it returns.
// Clearing the TPM changes the seed, and every blob sealed before then is
// refused with an error matching [enclave.ErrSealedAuthentication].
//
// The provider lives in its own module, so the go-enclave root module gains
// no dependency on go-tpm.
package tpm
