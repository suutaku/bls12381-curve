package curve

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurve(t *testing.T) {
	d := hexToBig("63e5cd2c608861a712f003254d6bf5f5f5921651e323162bea78d0f5e7d77225")
	assert.Equal(t, 32, len(d.Bytes()))
	t.Logf("fr byts 0x%x", d)
	curv := BLS12381()
	x, y := curv.ScalarBaseMult(d.Bytes())
	assert.NotNil(t, x)
	assert.NotNil(t, y)
	assert.Equal(t, 96, len(x.Bytes()))
	t.Logf("0x%x\n", x.Bytes())
	t.Logf("0x%x\n", y)
}
