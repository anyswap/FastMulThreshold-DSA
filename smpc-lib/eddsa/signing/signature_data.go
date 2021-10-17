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
	"crypto/sha512"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"strconv"
	edlib "crypto/ed25519"
)

// InputVerify  Ed algorithm validation data 
type InputVerify struct {
	FinalR  [32]byte
	FinalS  [32]byte
	Message []byte
	FinalPk [32]byte
}

// EdVerify check (R,S)
func EdVerify(input InputVerify) bool {
	// 1. calculate k
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	_, err := h.Write(input.FinalR[:])
	if err != nil {
		return false
	}

	_, err = h.Write(input.FinalPk[:])
	if err != nil {
		return false
	}

	_, err = h.Write(input.Message[:])
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

// Verify solane ed lib verify
func Verify(publicKey edlib.PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != 32 {
		fmt.Printf("================= ed25519: bad public key length: " + strconv.Itoa(l) + " ==================\n")
		return false
	}

	if len(sig) != 64 || sig[63]&224 != 0 {
		fmt.Printf("===================ed lib verify fail,sig len error =========================\n")
		return false
	}

	var A ed.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		fmt.Printf("===================ed lib verify fail,pubkey format error =========================\n")
		return false
	}
	ed.FeNeg(&A.X, &A.X)
	ed.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	ed.ScReduce(&hReduced, &digest)

	var R ed.ProjectiveGroupElement
	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !ed.ScMinimal(&s) {
		fmt.Printf("===================ed lib verify fail,check ScMinimal fail =========================\n")
		return false
	}

	ed.GeDoubleScalarMultVartime(&R, &hReduced, &A, &s)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}
