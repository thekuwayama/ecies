package ecies

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KDF to use SHA256 digest
func kdf(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}

	return key, nil
}

func zeroPad(b []byte, leigth int) []byte {
	for i := 0; i < leigth-len(b); i++ {
		b = append([]byte{0x00}, b...)
	}

	return b
}

func pkcs7Pad(msg []byte, blockSize int) []byte {
	msgLen := len(msg)
	mod := msgLen % blockSize

	plaintext := make([]byte, msgLen+mod)
	copy(plaintext, msg)

	for i := 0; i < mod; i++ {
		plaintext[msgLen+i] = byte(mod)
	}

	return plaintext
}
