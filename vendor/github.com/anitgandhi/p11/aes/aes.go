// package aes implements AES encryption using an HSM via PKCS11

package aes

import (
	"crypto/cipher"

	"github.com/anitgandhi/p11"
	"github.com/miekg/pkcs11"
)

// BlockSize is the the AES block size in bytes
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key identifier in the HSM
// and the CKM_AES_ECB mechanism
// It implements the cipher.Block interface
type aesCipher struct {
	*p11.Context
	oh   pkcs11.ObjectHandle
	mech []*pkcs11.Mechanism
}

// NewCipher creates and returns a new cipher.Block.
// oh is a PKCS11 Object Handle that refers to a
func NewCipher(ctx *p11.Context, oh pkcs11.ObjectHandle) (cipher.Block, error) {
	block := aesCipher{
		Context: ctx,
		oh:      oh,
	}

	block.mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}

	return &block, nil
}

func (c *aesCipher) BlockSize() int {
	return BlockSize
}

// If an error occurs, Encrypt will panic.
// Typically a function like this would return the error,
// but the cipher.Block interface function signatures
// don't allow for that.
func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}

	var err error

	// Initialize for single-part ECB encryption
	err = c.HSM.EncryptInit(c.Session, c.mech, c.oh)
	if err != nil {
		panic(err)
	}

	// Execute single-part ECB encryption of src
	retSlice, err := c.HSM.Encrypt(c.Session, src)

	// Since the pkcs11 Encrypt function returns a new slice, need to copy into dst
	copy(dst, retSlice)

	if err != nil {
		panic(err)
	}
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}

	// Initialize for single-part ECB decryption
	c.HSM.DecryptInit(c.Session, c.mech, c.oh)

	// Execute single-part ECB decryption of src
	var err error
	retSlice, err := c.HSM.Decrypt(c.Session, src)

	// Since the pkcs11 Decrypt function returns a new slice, need to copy into dst
	copy(dst, retSlice)

	if err != nil {
		panic(err)
	}
}
