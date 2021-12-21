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

package ec2

import (
	"encoding/json"
	"fmt"
	"errors"
	"math/big"
)

// SquareFreeProof 
// add for GG20: keygen phase 3. Each player Pi proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30]
// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1  
type SquareFreeProof struct {
	Y *big.Int
}

//------------------------------------------------------------------------------------

// CalcX 
// random Input: x belong to ZN*
func CalcX(n *big.Int,id *big.Int) *big.Int {
	if n == nil || id == nil || zero.Cmp(n) != -1 {
		return nil
	}

	//fmt.Printf("[SquareFree] calc x, n = %v,id = %v\n",n,id)
	
	try := n	
	for {
		try = Sha512_256(try,id)
		try = new(big.Int).Mod(try,n)
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}

	//fmt.Printf("[SquareFree] success get x = %v\n",try)
	return try
}

//---------------------------------------------------------------------------------

// SquareFreeProve 
// prover compute M = N^-1 mod OuLa(N) and output y = x^M mod N
func SquareFreeProve(n *big.Int,l *big.Int,uid *big.Int) *SquareFreeProof {
	if n == nil || l == nil || uid == nil {
	    return nil
	}

	x := CalcX(n,uid)
	if x == nil {
	    return nil
	}

	M := new(big.Int).ModInverse(n,l)
	y := new(big.Int).Exp(x,M,n)

	return &SquareFreeProof{Y: y}
}

// SquareFreeVerify
// verifier check y^N = x mod N
func SquareFreeVerify(n *big.Int,uid *big.Int,proof *SquareFreeProof) bool {
	if n == nil || uid == nil || proof == nil || proof.Y == nil {
	    return false 
	}

	// check y
	// y != nil
	// y mod N != 0
	// y mod N != 1
	// gcd(y,N) = 1
	one := big.NewInt(1)
	ymn := new(big.Int).Mod(proof.Y,n)
	if ymn.Cmp(zero) == 0 || ymn.Cmp(one) == 0 {
	    return false 
	}
	gcd := big.NewInt(0)
	if gcd.GCD(nil,nil,proof.Y,n).Cmp(one) != 0 {
	    return false
	}

	x := CalcX(n,uid)
	if x == nil {
	    return false 
	}

	yn := new(big.Int).Exp(proof.Y,n,n)
	xn := new(big.Int).Mod(x,n)
	if yn.Cmp(xn) != 0 {
	    fmt.Printf("check that a zero-knowledge proof that paillier.N is a square-free integer fail\n")
	    return false
	}

	return true
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal SquareFreeProof to json bytes
func (sfpf *SquareFreeProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Y string `json:"Y"`
	}{
		Y: fmt.Sprintf("%v", sfpf.Y),
	})
}

// UnmarshalJSON unmarshal raw to SquareFreeProof
func (sfpf *SquareFreeProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		Y string `json:"Y"`
	}
	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	sfpf.Y, _ = new(big.Int).SetString(zk.Y, 10)

	if sfpf.Y == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}


