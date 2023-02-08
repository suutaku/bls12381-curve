package curve

import (
	"crypto/elliptic"
	"math/big"

	"github.com/suutaku/bls12381"
)

var (
	g2        = bls12381.NewG2()
	CurveName = "BLS12-381"
)

var bls12381Instance = Bls12381Curve{
	param: &elliptic.CurveParams{
		P:       hexToBig("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"),
		B:       big.NewInt(4),
		N:       hexToBig("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001"),
		Gx:      hexToBig("17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB"),
		Gy:      hexToBig("08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1"),
		BitSize: 381,
		Name:    CurveName,
	},
}

func BLS12381() elliptic.Curve {
	return &bls12381Instance
}

type Bls12381Curve struct {
	param *elliptic.CurveParams
}

// Params returns the parameters for the curve.
func (curve *Bls12381Curve) Params() *elliptic.CurveParams {
	return curve.param
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
//
// Note: this is a low-level unsafe API. For ECDH, use the crypto/ecdh
// package. The NewPublicKey methods of NIST curves in crypto/ecdh accept
// the same encoding as the Unmarshal function, and perform on-curve checks.
func (curve *Bls12381Curve) IsOnCurve(x, y *big.Int) bool {
	pointG2, err := BigToG2(x, y)
	if err != nil {
		return false
	}
	return g2.IsOnCurve(pointG2)
}

// Add returns the sum of (x1,y1) and (x2,y2).
//
// Note: this is a low-level unsafe API.
func (curve *Bls12381Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	g2p1, _ := BigToG2(x1, y1)
	g2p2, _ := BigToG2(x2, y2)
	ret := g2.New()
	g2.Add(ret, g2p1, g2p2)
	return G2ToBig(ret)
}

// Double returns 2*(x,y).
//
// Note: this is a low-level unsafe API.
func (curve *Bls12381Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p, _ := BigToG2(x, y)
	ret := g2.New()
	g2.Double(ret, p)
	return G2ToBig(ret)
}

// ScalarMult returns k*(x,y) where k is an integer in big-endian form.
//
// Note: this is a low-level unsafe API. For ECDH, use the crypto/ecdh
// package. Most uses of ScalarMult can be replaced by a call to the ECDH
// methods of NIST curves in crypto/ecdh.
func (curve *Bls12381Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	p, err := BigToG2(x1, y1)
	if err != nil {
		panic(err)
	}
	e := bls12381.NewFr()
	ret := g2.New()
	e.FromBytes(k)
	g2.MulScalar(ret, p, e)
	return G2ToBig(ret)
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
//
// Note: this is a low-level unsafe API. For ECDH, use the crypto/ecdh
// package. Most uses of ScalarBaseMult can be replaced by a call to the
// PrivateKey.PublicKey method in crypto/ecdh.
func (curve *Bls12381Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	base := g2.One()
	kfr := parseFr(k)
	g2.MulScalar(base, base, frToRepr(kfr))
	return G2ToBig(g2.Affine(base))
}

func hexToBig(hex string) *big.Int {
	n, ok := big.NewInt(0).SetString(hex, 16)
	if !ok {
		panic("invlaid n")
	}
	return n
}

func BigToG2(x, y *big.Int) (*bls12381.PointG2, error) {
	tmp := append(x.Bytes(), y.Bytes()...)
	return g2.FromBytes(tmp)
}

func G2ToBig(p *bls12381.PointG2) (*big.Int, *big.Int) {
	g2.Affine(p)
	tmp := g2.ToBytes(p)
	return new(big.Int).SetBytes(tmp[:96]), new(big.Int).SetBytes(tmp[96:])
}
