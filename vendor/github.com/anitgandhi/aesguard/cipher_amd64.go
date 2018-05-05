// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aesguard

import (
	"crypto/cipher"

	"golang.org/x/sys/cpu"
)

// defined in asm_amd64.s
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)
func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)
func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

type aesCipherAsm struct {
	aesCipher
}

var useAsm = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ

func newCipher(key []byte) (cipher.Block, error) {
	if !useAsm {
		return newCipherGeneric(key)
	}

	keyBuffer, encScheduleBuffer, decScheduleBuffer, encScheduleUint32, decScheduleUint32, err := prepareMemguard(key)
	if err != nil {
		return nil, err
	}

	c := aesCipherAsm{}
	c.enc = encScheduleUint32
	c.dec = decScheduleUint32
	c.encLockedBuffer = encScheduleBuffer
	c.decLockedBuffer = decScheduleBuffer

	rounds := 10
	switch len(keyBuffer.Buffer()) {
	case 128 / 8:
		rounds = 10
	case 192 / 8:
		rounds = 12
	case 256 / 8:
		rounds = 14
	}

	expandKeyAsm(rounds, &keyBuffer.Buffer()[0], &c.enc[0], &c.dec[0])

	err = finalizeMemguard(keyBuffer, encScheduleBuffer, decScheduleBuffer)
	if err != nil {
		return nil, err
	}

	if hasGCMAsm() {
		return &aesCipherGCM{c}, nil
	}

	return &c, nil
}

func (c *aesCipherAsm) BlockSize() int { return BlockSize }

func (c *aesCipherAsm) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	encryptBlockAsm(len(c.enc)/4-1, &c.enc[0], &dst[0], &src[0])
}

func (c *aesCipherAsm) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	decryptBlockAsm(len(c.dec)/4-1, &c.dec[0], &dst[0], &src[0])
}

// Destroy destroys the encryption and decryption key schedule LockedBuffers
func (c *aesCipherAsm) Destroy() {
	c.encLockedBuffer.Destroy()
	c.decLockedBuffer.Destroy()
}

// expandKey is used by BenchmarkExpand to ensure that the asm implementation
// of key expansion is used for the benchmark when it is available.
func expandKey(key []byte, enc, dec []uint32) {
	if useAsm {
		rounds := 10 // rounds needed for AES128
		switch len(key) {
		case 192 / 8:
			rounds = 12
		case 256 / 8:
			rounds = 14
		}
		expandKeyAsm(rounds, &key[0], &enc[0], &dec[0])
	} else {
		expandKeyGo(key, enc, dec)
	}
}
