package ed_ristretto

import (
	"testing"
	"github.com/stretchr/testify/assert"
	r255 "github.com/gtank/ristretto255"
)

func TestScalarOne(t *testing.T){
	one1 := ScalarOne()

	var twoBytes [32]byte
	twoBytes[0] = 2
	two, _ := BytesReduceToScalar(twoBytes[:])

	twoCal := new(r255.Scalar).Add(one1, one1)
	rlt := two.Equal(twoCal)

	assert.True(t, (rlt == 1), "failed")
}

func TestBytesReduceToScalar(t *testing.T){
	rndBytes, _ := NewRandomScalarBytes()
	_, err := BytesReduceToScalar(rndBytes[:])
	assert.Nil(t, err, "must be nil")
}

func TestNewRandomScalarBytes(t *testing.T) {
	rndBytes, err := NewRandomScalarBytes()
	t.Log(rndBytes, err)
}
