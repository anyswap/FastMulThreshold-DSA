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

package ec2

import (
	"math/big"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
)

// Commitment commitment data
type Commitment struct {
	C *big.Int
	D []*big.Int
}

// Commit  Generate commitment data by secrets
func (commitment *Commitment) Commit(secrets ...*big.Int) *Commitment {
	if len(secrets) == 0 {
	    return nil
	}

	// Generate the random num
	rnd := random.GetRandomInt(256)
	if rnd == nil {
		return nil
	}

	// First, hash with the keccak256
	sha3256 := sha3.New256()
	//keccak256 := sha3.NewKeccak256()

	sha3256.Write(rnd.Bytes())

	for _, secret := range secrets {
	    sha3256.Write([]byte("hello multichain"))
	    sha3256.Write(secret.Bytes())
	}

	digestKeccak256 := sha3256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256.Write(digestKeccak256)
	digest := sha3256.Sum(nil)

	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)

	D := []*big.Int{rnd}
	D = append(D, secrets...)

	commitment.C = digestBigInt
	commitment.D = D

	return commitment
}

// Verify  Verify commitment data 
func (commitment *Commitment) Verify() bool {
	C := commitment.C
	D := commitment.D

	if C == nil {
	    return false
	}

	if len(D) < 1 { // at least rnd number
	    return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(D[0].Bytes())
	
	for _, secret := range D[1:] {
	    sha3256.Write([]byte("hello multichain"))
	    sha3256.Write(secret.Bytes())
	}
	digestKeccak256 := sha3256.Sum(nil)
	sha3256.Write(digestKeccak256)
	computeDigest := sha3256.Sum(nil)

	computeDigestBigInt := new(big.Int).SetBytes(computeDigest)

	if computeDigestBigInt.Cmp(C) != 0 {
		return false
	}

	// Check whether the point is on the curve
	if !checkPointOnCurve(D[1:]) {
		return false
	}

	return true
}

// DeCommit get commitment data secrets
func (commitment *Commitment) DeCommit() (bool, []*big.Int) {
	if commitment.Verify() {
		return true, commitment.D[1:]
	}
	
	return false, nil

}

//-----------------------------------------------------------

// checkCommitmentGammaGOnCurve Check whether the point is on the curve
func checkPointOnCurve(secrets []*big.Int) bool {
	if len(secrets) == 0 || (len(secrets)%2) != 0 {
		return false
	}

	l := (len(secrets) / 2)
	for i := 0; i < l; i++ {
		x := secrets[2*i]
		y := secrets[2*i+1]
		if x == nil || y == nil || !secp256k1.S256().IsOnCurve(x, y) {
			return false
		}
	}

	return true
}


