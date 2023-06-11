package ecies

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

// PrivateKey is an instance of secp384r1 private key with nested public key
type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// GenerateKey generates secp384r1 key pair
func GenerateKey() (*PrivateKey, error) {
	curve := getCurve()

	p, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(p),
	}, nil
}

// can be safely used as encryption key
func (k *PrivateKey) Encapsulate(pub *PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(k.PublicKey.Bytes(false))

	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())
	secret.Write([]byte{0x04})

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(pub.Curve.Params().P.Bytes())
	secret.Write(zeroPad(sx.Bytes(), l))
	secret.Write(zeroPad(sy.Bytes(), l))

	return kdf(secret.Bytes())
}
