package curve

import (
	"github.com/suutaku/bls12381"
	"golang.org/x/crypto/blake2b"
)

func parseFr(data []byte) *bls12381.Fr {
	return bls12381.NewFr().FromBytes(data)
}

func f2192() *bls12381.Fr {
	return &bls12381.Fr{0, 0, 0, 1}
}

func frToRepr(fr *bls12381.Fr) *bls12381.Fr {
	frRepr := bls12381.NewFr()
	frRepr.Mul(fr, &bls12381.Fr{1})

	return frRepr
}

func frFromOKM(message []byte) *bls12381.Fr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message)
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := bls12381.NewFr().FromBytes(append(emptyEightBytes, okm[:okmMiddle]...))
	elm.Mul(elm, f2192())

	fr := bls12381.NewFr().FromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm.Add(elm, fr)

	return elm
}
