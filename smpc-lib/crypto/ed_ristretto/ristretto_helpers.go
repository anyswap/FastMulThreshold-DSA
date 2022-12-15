package ed_ristretto

import (
	"crypto/rand"
	"errors"
	"fmt"
	r255 "github.com/gtank/ristretto255"
)

var maxTryTimes = 10
var oneBytes = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

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
