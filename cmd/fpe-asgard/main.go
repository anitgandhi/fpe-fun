package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/capitalone/fpe/ff1"

	"github.com/anitgandhi/asgard"
)

func main() {

	// Key and tweak should be byte arrays. Put your key and tweak here.
	var key = [16]byte{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}

	// Create an AES block from the key, using asgard to protect the key in memory
	// This will be used to create the FF1 cipher
	aesBlock, err := asgard.NewCipher(key[:])
	if err != nil {
		log.Println(err)
		return
	}

	tweak, err := hex.DecodeString("")
	if err != nil {
		log.Println(err)
		return
	}

	// Create a new FF1 cipher "object" using the asgard AES block we already made
	// 10 is the radix/base, and 8 is the max tweak length.
	FF1, err := ff1.NewCipherWithBlock(aesBlock, 10, 8, tweak)
	if err != nil {
		log.Println(err)
		return
	}

	original := "0123456789"

	// Call the encryption function on an example SSN
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		log.Println(err)
		return
	}

	if ciphertext != "2433477484" {
		panic("ciphertext incorrect")
	}

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		log.Println(err)
		return
	}

	err = asgard.DestroyCipher(aesBlock)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Original:", original)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)
}
