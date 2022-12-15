package ed_ristretto

import (
	"crypto/sha512"
	r255 "github.com/gtank/ristretto255"
)

var message = []byte("hello thresholdeddsa")

func calChallenge(RBytes []byte, X []byte) (*r255.Scalar, error) {
	// hash by sha512
	var eDigest [64]byte

	h := sha512.New()
	h.Write(RBytes[:])
	h.Write(message[:])
	h.Write(X[:])
	h.Write(message[:])
	h.Sum(eDigest[:0])

	e, err := BytesReduceToScalar(eDigest[:])
	if err != nil {
		return nil, err
	}
	return e, nil
}

func Prove2(sk [32]byte) ([64]byte,error) {
	var defaultRlt [64]byte

	rndScalar, err := NewRandomScalar()
	if err != nil {
		return defaultRlt, err
	}
	
	R := r255.NewElement().ScalarBaseMult(rndScalar)
	var RBytes [32]byte
	R.Encode(RBytes[:0])

	skScalar, err := BytesReduceToScalar(sk[:])
	if err != nil {
		return defaultRlt, err
	}
	X := new(r255.Element).ScalarBaseMult(skScalar)
	var XBytes [32]byte
	X.Encode(XBytes[:0])

	e, err := calChallenge(RBytes[:], XBytes[:])
	if err != nil {
		return defaultRlt, err
	}

	s := new(r255.Scalar).Multiply(e, skScalar)
	s = new(r255.Scalar).Add(rndScalar, s)

	var signature [64]byte
	e.Encode(signature[:0])
	s.Encode(signature[:32])

	return signature,nil
}

func VerifyZk2(signature [64]byte, pk [32]byte) bool {
	s, err := BytesReduceToScalar(signature[32:])
	if err != nil {
		return false
	}
	sG := new(r255.Element).ScalarBaseMult(s)

	e, err := BytesReduceToScalar(signature[:32])
	if err != nil {
		return false
	}

	eNeg := new(r255.Scalar).Negate(e)

	X := new(r255.Element)
	X.Decode(pk[:])
	eNegX := new(r255.Element).ScalarMult(eNeg, X)
	
	RCal := new(r255.Element).Add(eNegX, sG)
	var RCalBytes [32]byte
	RCal.Encode(RCalBytes[:0])

	eCal, err := calChallenge(RCalBytes[:], pk[:])
	if err != nil {
		return false
	}

	if eCal.Equal(e) == 1 {
		return true
	}
	return false
}

