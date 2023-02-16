/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package signing

import (
	"math/big"
	"bytes"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	r255 "github.com/gtank/ristretto255"
	tsslib "github.com/anyswap/FastMulThreshold-DSA/tss-lib/common"
)

// InputVerify  Ed algorithm validation data 
type InputVerify struct {
	KeyType string
	FinalR  [32]byte
	FinalS  [32]byte
	Message []byte
	FinalPk [32]byte
}

// EdVerify check (R,S)
func EdVerify(input InputVerify, keytype string) bool {
	// 1. calculate k
	k, err := tsslib.CalKValue(input.KeyType, input.Message[:], input.FinalPk[:], input.FinalR[:])
	if err != nil {
		fmt.Printf("error in EdVerify CalKValue function. \n")
		return false
	}

	// 2. verify the equation

	var sBBytes, sBCalBytes [32]byte
	if keytype == smpc.SR25519 {
		var(
			R = new(r255.Element)
			pkB = new(r255.Element)
			sB = new(r255.Element)
			sBCal = new(r255.Element)
			kScalar = new(r255.Scalar)
			finalSScalar = new(r255.Scalar)
		)
		pkB.Decode(input.FinalPk[:])
		R.Decode(input.FinalR[:])
		kScalar.Decode(k[:])
		finalSScalar.Decode(input.FinalS[:])

		sBCal = new(r255.Element).ScalarMult(kScalar, pkB)
		sBCal = new(r255.Element).Add(R, sBCal)

		sB = new(r255.Element).ScalarBaseMult(finalSScalar)
		
		sB.Encode(sBBytes[:0])
		sBCal.Encode(sBCalBytes[:0])
	}else {
		var R, pkB, sB, sBCal ed.ExtendedGroupElement
		pkB.FromBytes(&(input.FinalPk))
		R.FromBytes(&(input.FinalR))
	
		ed.GeScalarMult(&sBCal, &k, &pkB)
		ed.GeAdd(&sBCal, &R, &sBCal)
	
		ed.GeScalarMultBase(&sB, &(input.FinalS))
		
		sB.ToBytes(&sBBytes)
		sBCal.ToBytes(&sBCalBytes)
	}
	
	pass := bytes.Equal(sBBytes[:], sBCalBytes[:])

	return pass
}

// EdSignData ed sign result (r,s)
type EdSignData struct {
	Rx [32]byte
	Sx [32]byte
}

// PrePubData pre-sign data 
type PrePubData struct {
	K1     *big.Int
	R      *big.Int
	Ry     *big.Int
	Sigma1 *big.Int
}
