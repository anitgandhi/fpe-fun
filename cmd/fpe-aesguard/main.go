package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/capitalone/fpe/ff1"

	"github.com/anitgandhi/aesguard"
)

func main() {

	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		log.Println(err)
		return
	}

	// Create an AES block from the key, using aesguard to protect the key in memory
	// This will be used to create the FF1 cipher
	aesBlock, err := aesguard.NewCipher(key)
	if err != nil {
		log.Println(err)
		return
	}

	tweak, err := hex.DecodeString("")
	if err != nil {
		log.Println(err)
		return
	}

	// Create a new FF1 cipher "object" using the aesguard AES block we already made
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

	err = aesguard.DestroyCipher(aesBlock)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Original:", original)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)
}
