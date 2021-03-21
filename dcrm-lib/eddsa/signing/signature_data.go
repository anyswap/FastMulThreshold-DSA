package signing 

import (
	"math/big"
	//"strings"
	//"fmt"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	"crypto/sha512"
	"bytes"
)

type InputVerify struct {
	FinalR  [32]byte
	FinalS  [32]byte
	Message []byte
	FinalPk [32]byte
}

func EdVerify(input InputVerify) bool {
	// 1. calculate k
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	_,err := h.Write(input.FinalR[:])
	if err != nil {
	    return false
	}

	_,err = h.Write(input.FinalPk[:])
	if err != nil {
	    return false
	}

	_,err = h.Write(input.Message[:])
	if err != nil {
	    return false
	}

	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2. verify the equation
	var R, pkB, sB, sBCal ed.ExtendedGroupElement
	pkB.FromBytes(&(input.FinalPk))
	R.FromBytes(&(input.FinalR))

	ed.GeScalarMult(&sBCal, &k, &pkB)
	ed.GeAdd(&sBCal, &R, &sBCal)

	ed.GeScalarMultBase(&sB, &(input.FinalS))

	var sBBytes, sBCalBytes [32]byte
	sB.ToBytes(&sBBytes)
	sBCal.ToBytes(&sBCalBytes)

	pass := bytes.Equal(sBBytes[:], sBCalBytes[:])

	return pass
}

type EdSignData struct {
    Rx string
    Sx string
}

//TODO
type PrePubData struct {
	K1 *big.Int
	R *big.Int
	Ry *big.Int
	Sigma1 *big.Int
}

