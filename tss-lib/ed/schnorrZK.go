/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  xing.chang@anyswap.exchange
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

package ed

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
)

// Prove  Generate SK zero knowledge proof data 
func Prove(sk [32]byte) ([64]byte,error) {
	rand := cryptorand.Reader
	var rndNum [32]byte
	if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")

		var ret [64]byte
		return ret,err
	}
	var one, zero [32]byte
	one[0] = 1

	ScMulAdd(&rndNum, &rndNum, &one, &zero)

	var R ExtendedGroupElement
	var RBytes [32]byte
	GeScalarMultBase(&R, &rndNum)
	R.ToBytes(&RBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eDigest [64]byte
	var e [32]byte

	h := sha512.New()
	h.Write(RBytes[:])
	h.Write(message[:])
	h.Sum(eDigest[:0])
	ScReduce(&e, &eDigest)

	var s [32]byte
	ScMulAdd(&s, &e, &sk, &rndNum)

	var signature [64]byte
	copy(signature[:32], e[:])
	copy(signature[32:], s[:])

	return signature,nil
}

// VerifyZk verify SK zero knowledge proof data
func VerifyZk(signature [64]byte, pk [32]byte) bool {

	var sG, X, eX, RCal ExtendedGroupElement

	var sTem [32]byte
	copy(sTem[:], signature[32:])
	GeScalarMultBase(&sG, &sTem)

	X.FromBytes(&pk)
	FeNeg(&X.X, &X.X)
	FeNeg(&X.T, &X.T)

	var eTem [32]byte
	copy(eTem[:], signature[:32])
	GeScalarMult(&eX, &eTem, &X)

	GeAdd(&RCal, &sG, &eX)
	var RCalBytes [32]byte
	RCal.ToBytes(&RCalBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eCalDigest [64]byte
	var eCal [32]byte

	h := sha512.New()
	h.Write(RCalBytes[:])
	h.Write(message[:])

	h.Sum(eCalDigest[:0])

	ScReduce(&eCal, &eCalDigest)

	if bytes.Equal(eCal[:], eTem[:]) {
		return true
	}

	return false
}

//-----------------------------------------------------------------
// fixed: Weak Fiat-Shamir transformation in Schnorr’s ZKP
// This transformation is known to be insecure if the calculation of the hash does not include the public value g^sk.

// Prove2  Generate SK zero knowledge proof data,include pk 
func Prove2(sk [32]byte,pk [32]byte) ([64]byte,error) {
	rand := cryptorand.Reader
	var rndNum [32]byte
	if _, err := io.ReadFull(rand, rndNum[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, rndNum[:])")
		var ret [64]byte
		return ret,err 
	}

	var one, zero [32]byte
	one[0] = 1

	ScMulAdd(&rndNum, &rndNum, &one, &zero)

	var R ExtendedGroupElement
	var RBytes [32]byte
	GeScalarMultBase(&R, &rndNum)
	R.ToBytes(&RBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eDigest [64]byte
	var e [32]byte

	h := sha512.New()
	h.Write(RBytes[:])
	h.Write(message[:])

	// fixed: Weak Fiat-Shamir transformation in Schnorr’s ZKP
	// This transformation is known to be insecure if the calculation of the hash does not include the public value g^sk.
	h.Write(pk[:])
	h.Write(message[:])
	h.Sum(eDigest[:0])
	ScReduce(&e, &eDigest)

	var s [32]byte
	ScMulAdd(&s, &e, &sk, &rndNum)

	var signature [64]byte
	copy(signature[:32], e[:])
	copy(signature[32:], s[:])

	return signature,nil
}

// VerifyZk2 verify SK zero knowledge proof data,include pk
func VerifyZk2(signature [64]byte, pk [32]byte) bool {

	var sG, X, eX, RCal ExtendedGroupElement

	var sTem [32]byte
	copy(sTem[:], signature[32:])
	GeScalarMultBase(&sG, &sTem)

	X.FromBytes(&pk)
	FeNeg(&X.X, &X.X)
	FeNeg(&X.T, &X.T)

	var eTem [32]byte
	copy(eTem[:], signature[:32])
	GeScalarMult(&eX, &eTem, &X)

	GeAdd(&RCal, &sG, &eX)
	var RCalBytes [32]byte
	RCal.ToBytes(&RCalBytes)

	message := []byte("hello thresholdeddsa")

	// hash by sha512
	var eCalDigest [64]byte
	var eCal [32]byte

	h := sha512.New()
	h.Write(RCalBytes[:])
	h.Write(message[:])

	// fixed: Weak Fiat-Shamir transformation in Schnorr’s ZKP
	// This transformation is known to be insecure if the calculation of the hash does not include the public value g^sk.
	h.Write(pk[:])
	h.Write(message[:])
	h.Sum(eCalDigest[:0])
	ScReduce(&eCal, &eCalDigest)

	if bytes.Equal(eCal[:], eTem[:]) {
		return true
	}

	return false
}


