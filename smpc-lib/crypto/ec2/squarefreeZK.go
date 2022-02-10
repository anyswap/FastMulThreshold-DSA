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
	"strings"
	"math/big"
)

const ( 
    m = 7 // default value is 7, recommend is m = T k/log2a T ,  a = 65537, k = 128
	// m = 8, ceiling of above result
)

var (
    alpha = 65537
)

// SquareFreeProof 
// add for GG20: keygen phase 3. Each player Pi proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30]
// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1 
type SquareFreeProof struct {
	Sigma []*big.Int
}

//------------------------------------------------------------------------------------

// CalcX 
// return m random int: Xi belong to ZN*
// len(Xi) == n.BitLen()
// n is the paillier pubKey.N
func CalcX(n *big.Int,num *big.Int) []*big.Int {
	if n == nil || zero.Cmp(n) != -1 || num == nil || num.Cmp(zero) < 0 {
		return nil
	}

	num = new(big.Int).Mod(num,n)
	l := len(n.Bytes())

	str := "productoftwoprimesproof"
	strnum := new(big.Int).SetBytes([]byte(str))
	roh := make([]*big.Int,m)
	for i:= 0;i<m;i++ { // use multi-thread?
	    tmp := make([]*big.Int,0)
	    inlen := 0
	    try := n
	    diff := 0
	    for {
		// find short x
		for {
			try = Sha512_256(try,num,strnum,big.NewInt(int64(i)))
			try = new(big.Int).Mod(try,n) // no need mod
			if IsNumberInMultiplicativeGroup(n, try) { // no need to check and for loop
				break
			}
		}
		//

		if (inlen + len(try.Bytes())) > l {
		    diff = l - inlen
		    if diff > 0 {
			break
		    }

		    return nil
		}
		
		tmp = append(tmp,try)
		inlen += len(try.Bytes())
		if inlen == l {
		    break
		}
	    }

	    X := joinInt(tmp,diff)
	    if X == nil {
		return nil
	    }

		// check if X is in In Multiplicative Group
	    roh[i] = X
	}

	return roh 
}

//---------------------------------------------------------------------------------

// SquareFreeProve
// chooses m random value Xi belong to ZN*
// prover compute M = N^-1 mod OuLa(N) and output sigmai = Xi^M mod N for every Xi
func SquareFreeProve(n *big.Int,num *big.Int,l *big.Int) *SquareFreeProof {
	if n == nil || l == nil || num == nil || num.Cmp(zero) < 0 {
	    return nil
	}

	X := CalcX(n,num)
	if X == nil {
	    return nil
	}

	M := new(big.Int).ModInverse(n,l)
	if M == nil {
	    return nil
	}

	sigma := make([]*big.Int,0)
	for _,v := range X {
	    y := new(big.Int).Exp(v,M,n)
	    sigma = append(sigma,y)
	}

	return &SquareFreeProof{Sigma: sigma}
}

// SquareFreeVerify
// check:
// N > 0 , N mod p != 0, p is prime, p < alpha
// N > sigmai > 0 
// verifier check sigmai^N = Xi (mod N)
func SquareFreeVerify(n *big.Int,num *big.Int,proof *SquareFreeProof) bool {
	if n == nil || proof == nil || proof.Sigma == nil || num == nil || num.Cmp(zero) < 0 {
	    return false
	}
	if len(proof.Sigma) != m {
	    return false
	}

	X := CalcX(n,num)
	if X == nil {
	    return false 
	}

	// check N > 0 , N/p != 0, p is prime, p < alpha
	if n.Cmp(zero) <= 0 {
	    return false
	}

	for i:=2;i< alpha;i++ {
	    ii := big.NewInt(int64(i))
	    if ii.ProbablyPrime(PrimeTestTimes) {
		qua := new(big.Int).Mod(n,ii)
		if qua.Cmp(zero) == 0 {
		    return false
		}
	    }
	}

	// check N > sigmai > 0
	for _,v := range proof.Sigma {
	    if v.Cmp(zero) <= 0 || v.Cmp(n) >= 0 {
		return false
	    }
	}

	for k,v := range X {
	    // check sigmai^N = Xi (mod N)
	    yn := new(big.Int).Exp(proof.Sigma[k],n,n)
	    xn := new(big.Int).Mod(v,n)
	    if yn.Cmp(xn) != 0 {
		fmt.Printf("check that a zero-knowledge proof that paillier.N is a square-free integer fail\n")
		return false
	    }
	}

	return true
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal SquareFreeProof to json bytes
func (sfpf *SquareFreeProof) MarshalJSON() ([]byte, error) {
    	tmp := make([]string,0)
	for _,v := range sfpf.Sigma {
	    tmp = append(tmp,fmt.Sprintf("%v",v))
	}

	sigma := strings.Join(tmp,":")
	return json.Marshal(struct {
		Y string `json:"Y"`
	}{
		Y: sigma,
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

	tmp := strings.Split(zk.Y,":")
	sigma := make([]*big.Int,0)
	for _,v := range tmp {
	    y, _ := new(big.Int).SetString(v, 10)
	    if y == nil {
		return fmt.Errorf("get sigma fail")
	    }

	    sigma = append(sigma,y)
	}

	sfpf.Sigma = sigma
	return nil
}


