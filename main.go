package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/capitalone/fpe/ff1"

	"github.com/anitgandhi/p11"
	"github.com/anitgandhi/p11/aes"
	"github.com/miekg/pkcs11"
)

var (
	p11Ctx *p11.Context
)

// createKey creates an AES session key with a CKA_LABEL=keyid
func createKey(key []byte, keyid string) (pkcs11.ObjectHandle, error) {
	// This is an AES key with a known value
	aesKeyTemplate := []*pkcs11.Attribute{

		// create it as a temporary session key only
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyid),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyid),

		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),

		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
	}

	return p11Ctx.HSM.CreateObject(p11Ctx.Session, aesKeyTemplate)
}

func deleteKey(oh pkcs11.ObjectHandle) error {
	return p11Ctx.HSM.DestroyObject(p11Ctx.Session, oh)
}

func main() {

	lib := "/usr/local/lib/softhsm/libsofthsm2.so"
	pin := "1234"

	var err error

	p11Ctx, err = p11.New(lib, pin, 1)
	defer p11Ctx.Destroy()
	if err != nil {
		log.Println(err)
		return
	}

	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		log.Println(err)
		return
	}

	// create the temporary key object in the HSM
	oh, err := createKey(key, "19")
	// defer deleteKey(oh)
	if err != nil {
		log.Println(err)
		return
	}

	aesBlock, err := aes.NewCipher(p11Ctx, oh)
	if err != nil {
		log.Println(err)
		return
	}

	tweak, err := hex.DecodeString("")
	if err != nil {
		log.Println(err)
		return
	}

	// Create a new FF1 cipher "object" using the HSM-backed AES block we already made
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

	fmt.Println("Original:", original)
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Plaintext:", plaintext)
}
