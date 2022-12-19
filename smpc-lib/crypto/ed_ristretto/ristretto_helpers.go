package ed_ristretto

import (
	"crypto/rand"
	"errors"
	"fmt"
	r255 "github.com/gtank/ristretto255"
)

var maxTryTimes = 10
var oneBytes = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func ScModInverse(a [32]byte) [32]byte {
	aScalar, _ := BytesReduceToScalar(a[:])
	aInv := new(r255.Scalar).Invert(aScalar)
	var aInvBytes [32]byte
	aInv.Encode(aInvBytes[:0])
	return aInvBytes
}

// out = a * b + c
func ScMulAdd(out, a, b, c *[32]byte){
	aScalar, _ := BytesReduceToScalar((*a)[:])
	bScalar, _ := BytesReduceToScalar((*b)[:])
	cScalar, _ := BytesReduceToScalar((*c)[:])

	outScalar := new(r255.Scalar).Multiply(aScalar, bScalar)
	outScalar = new(r255.Scalar).Add(outScalar, cScalar)
	outScalar.Encode((*out)[:0])
}

func ScReduce(out *[32]byte, in *[64]byte){
	outScalar, _ := BytesReduceToScalar((*in)[:])
	outScalar.Encode((*out)[:0])
}

func ScAdd(out, a, b *[32]byte){
	aScalar, _ := BytesReduceToScalar((*a)[:])
	bScalar, _ := BytesReduceToScalar((*b)[:])

	sum := new(r255.Scalar).Add(aScalar, bScalar)
	sum.Encode((*out)[:0])
}

func ScSub(out, a, b *[32]byte){
	aScalar, _ := BytesReduceToScalar((*a)[:])
	bScalar, _ := BytesReduceToScalar((*b)[:])

	sum := new(r255.Scalar).Subtract(aScalar, bScalar)
	sum.Encode((*out)[:0])
}

func ScMul(out, a, b *[32]byte){
	aScalar, _ := BytesReduceToScalar((*a)[:])
	bScalar, _ := BytesReduceToScalar((*b)[:])

	mul := new(r255.Scalar).Multiply(aScalar, bScalar)
	mul.Encode((*out)[:0])
}

func ScalarOne() *r255.Scalar {
	one, _ := BytesReduceToScalar(oneBytes[:])
	return one
}

func BytesReduceToScalar(in []byte) (*r255.Scalar, error) {
	if len(in) != 64 && len(in) != 32 {
		return nil, errors.New("error, input byte array must be 32 or 64 length.")
	}

	var barr [64]byte
	copy(barr[:], in[:])

	rlt := new(r255.Scalar).FromUniformBytes(barr[:])
	return rlt, nil
}

func NewRandomScalar() (*r255.Scalar, error) { 
	for i := 0; i < maxTryTimes; i++ {
		s := [64]byte{}
		_, err := rand.Read(s[:])
		if err != nil {
			continue
		}

		sc, err := BytesReduceToScalar(s[:])
		if err != nil || sc.Equal(r255.NewScalar()) == 1 {
			continue
		}

		return sc, nil
	}
	return nil, fmt.Errorf("error in generating new random scalar after try %d times", maxTryTimes)
}

func NewRandomScalarBytes() ([32]byte, error) { 
	var rlt [32]byte
	rndScalar, err := NewRandomScalar()

	if err == nil {
		rndScalar.Encode(rlt[:0])
		return rlt, nil
	}
	return rlt, err
}
