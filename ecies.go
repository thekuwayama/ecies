package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	// Generate ephemeral key
	ek, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	// Derive shared secret
	ss, err := ek.Encapsulate(pubkey)
	if err != nil {
		return nil, err
	}

	// AES keygen
	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	// PKCS7 padding
	plaintext := pkcs7Pad(msg, block.BlockSize())

	// IV is zeros
	// https://github.com/bcgit/bc-java/blob/738dfc0132323d66ad27e7ec366666ed3e0638ab/cor[…]src/main/java/org/bouncycastle/crypto/modes/CBCBlockCipher.java
	// If an IV isn't passed as part of the parameter, the IV will be all zeros.
	iv := make([]byte, 16)
	// zeroPad(iv, 16)

	// AES encryption
	aescbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	aescbc.CryptBlocks(ciphertext, plaintext)

	return append(ek.PublicKey.Bytes(false), ciphertext...), nil
}
