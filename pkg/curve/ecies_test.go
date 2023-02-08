package curve

import (
	"encoding/hex"
	"math/big"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/stretchr/testify/assert"
)

func UnmarshalPrivateKey(b []byte) (*ecies.PrivateKey, error) {
	x, y := BLS12381().ScalarBaseMult(b)
	return &ecies.PrivateKey{
		PublicKey: &ecies.PublicKey{
			Curve: BLS12381(),
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(b),
	}, nil
}

func TestECIES(t *testing.T) {
	kb, err := hex.DecodeString("63e5cd2c608861a712f003254d6bf5f5f5921651e323162bea78d0f5e7d77225")
	assert.NoError(t, err)
	k, err := UnmarshalPrivateKey(kb)
	assert.NoError(t, err)
	ciphertext, err := ecies.Encrypt(k.PublicKey, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	t.Logf("plaintext encrypted: %v\n", ciphertext)

	plaintext, err := ecies.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	t.Logf("ciphertext decrypted: %s\n", string(plaintext))
}
