package ed_ristretto

import (
	"bytes"
	"testing"

	r255 "github.com/gtank/ristretto255"
	"github.com/stretchr/testify/assert"
)

func TestScModInverse(t *testing.T){
	var a [32]byte
	a[0] = 1
	aInv := ScModInverse(a)

	var aScalar = new(r255.Scalar)
	aScalar.Decode(a[:])
	var aInvScalar = new(r255.Scalar)
	aInvScalar.Decode(aInv[:])

	mul := new(r255.Scalar).Multiply(aScalar, aInvScalar)

	assert.Equal(t, mul.Equal(ScalarOne()), 1, "failed")
}

func TestScReduce(t *testing.T){
	var inBytes [64]byte
	var outBytes, outCalBytes [32]byte

	inBytes[0] = 50
	outBytes[0] = 50

	ScReduce(&outCalBytes, &inBytes)

	assert.True(t, bytes.Equal(outBytes[:], outCalBytes[:]), "failed")
}

func TestScMul(t *testing.T){
	var aBytes, bBytes, cBytes, cCalBytes [32]byte
	
	aBytes[0] = 2
	bBytes[0] = 5
	cBytes[0] = 10
	
	ScMul(&cCalBytes, &bBytes, &aBytes)

	assert.True(t, bytes.Equal(cBytes[:], cCalBytes[:]), "failed")
}

func TestScAdd(t *testing.T){
	var aBytes, bBytes, cBytes, cCalBytes [32]byte
	
	aBytes[0] = 2
	bBytes[0] = 5
	cBytes[0] = 7
	
	ScAdd(&cCalBytes, &bBytes, &aBytes)

	assert.True(t, bytes.Equal(cBytes[:], cCalBytes[:]), "failed")
}

func TestScSub(t *testing.T){
	var aBytes, bBytes, cBytes, cCalBytes [32]byte
	
	aBytes[0] = 5
	bBytes[0] = 2
	cBytes[0] = 3
	
	ScSub(&cCalBytes, &aBytes, &bBytes)

	assert.True(t, bytes.Equal(cBytes[:], cCalBytes[:]), "failed")
}

func TestScMulAdd(t *testing.T){
	var aBytes, bBytes, cBytes, outBytes, outCalBytes [32]byte
	
	aBytes[0] = 2
	bBytes[0] = 5
	cBytes[0] = 10
	outBytes[0] = 20
	
	ScMulAdd(&outCalBytes, &aBytes, &bBytes, &cBytes)

	assert.True(t, bytes.Equal(outBytes[:], outCalBytes[:]), "failed")
}

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
