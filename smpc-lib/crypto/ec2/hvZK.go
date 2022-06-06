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
	"math"
	"sync"
	"strings"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

const ( 
    //HoeffdingBoundParam = 128 
    HoeffdingBoundParam = 1 //TODO
)

// GetHoeffdingBound get hoeffding bound
// m = T κ·32·ln2 T
// k default set 128
func GetHoeffdingBound() *big.Int {
    m := HoeffdingBoundParam*32*math.Log(2)
    m = math.Ceil(m)
    mInt,_ := new(big.Int).SetString(fmt.Sprintf("%v",m),10)
    return mInt
}

// HvProof 
// see Paper:   Attacking Threshold Wallets*   JP Aumasson and Omer Shlomovits   Taurus Group, Switzerland   ZenGo X, Israel   section 5  The Golden Shoe Attack
// Mitigation: The fix is simple: Ntilde,h1,h2 must be validated on the receiving end.For Ntilde,the sender must attach a proof that Ntilde is a valid RSA modulus from two safe primes.For h1,h2, there is a nice trick in [FO97]: pick h1 at random and h2 = h1^alpha and prove to the receiver the knowledge of alpha with respect to h1, h2.
// see Paper : Efficient Noninteractive Certification of RSA Moduli and Beyond   Sharon Goldberg*, Leonid Reyzin*, Omar Sagga*, and Foteini Baldimtsi      Boston University, Boston, MA, USA  George Mason University, Fairfax, VA, USA foteini@gmu.edu   October 3, 2019     section 3.4  HVZK Proof for a Product of Two Primes
type HvProof struct {
	Sigma []*big.Int
}

//------------------------------------------------------------------------------------

type RohData struct {
    Index int64
    Roh *big.Int
}

// CalcRoh 
// return m random int: ROHi belong to JN
// len(ROHi) = n.BitLen()
// n is the paillier pubKey.N or Ntilde ....
func CalcRoh(n *big.Int,num *big.Int) []*big.Int {
	if n == nil || zero.Cmp(n) != -1 || num == nil || num.Cmp(zero) < 0 {
		return nil
	}

	num = new(big.Int).Mod(num,n)
	l := len(n.Bytes())

	mm := GetHoeffdingBound()
	m := mm.Int64()
	if m > math.MaxInt64 {
	    fmt.Printf("get hoeffding bound fail,the maximum value of Int64 has been exceeded")
	    return nil
	}

	if m <= 0 {
	    return nil
	}

	str := "productoftwoprimesproof"
	strnum := new(big.Int).SetBytes([]byte(str))
	
	data := make(chan RohData,m)
	tmp2 := common.NewSafeMap(10)
	var wg sync.WaitGroup
	for i:=0;int64(i) < m;i++ {
	    wg.Add(1)
	    go func(index int64) {
		defer wg.Done()
		
		tmp := make([]*big.Int,0)
		inlen := 0
		try := n
		diff := 0
		for {
		    // find short roh
		    try = Sha512_256(try,num,strnum,big.NewInt(index))
		    //try = new(big.Int).Mod(try,n)
		    //
		    
		    if (inlen + len(try.Bytes())) > l {
			diff = l - inlen
			if diff > 0 {
			    roh := joinInt(tmp,diff)
			    if roh == nil {
				tmp = make([]*big.Int,0)
				inlen = 0
				diff = 0
				continue
			    }

			    roh = new(big.Int).Mod(roh,n)

			    if !IsNumberInMultiplicativeGroup(n, roh) {
				tmp = make([]*big.Int,0)
				inlen = 0
				diff = 0
				continue
			    }
			    
			    // Jacobi-symbol (roh,N) = 1,so roh in JN
			    sym := big.Jacobi(roh,n)
			    if sym != 1 {
				tmp = make([]*big.Int,0)
				inlen = 0
				diff = 0
				continue
			    }

			    _,exsit := tmp2.ReadMap(strings.ToLower(fmt.Sprintf("%v",roh)))
			    if exsit {
				fmt.Printf("calc roh fail\n")
				return
			    }

			    tmp2.WriteMap(strings.ToLower(fmt.Sprintf("%v",roh)),"ok")
			    rd := RohData{Index:index,Roh:roh}
			    data <-rd

			    break
			}

			fmt.Printf("calc roh fail\n")
			return
		    }
		    
		    tmp = append(tmp,try)
		    inlen += len(try.Bytes())
		    if inlen == l {
			roh := joinInt(tmp,diff)
			if roh == nil {
			    tmp = make([]*big.Int,0)
			    inlen = 0
			    diff = 0
			    continue
			}
			
			roh = new(big.Int).Mod(roh,n)

			if !IsNumberInMultiplicativeGroup(n, roh) {
			    tmp = make([]*big.Int,0)
			    inlen = 0
			    diff = 0
			    continue
			}
			
			// Jacobi-symbol (roh,N) = 1,so roh in JN
			sym := big.Jacobi(roh,n)
			if sym != 1 {
			    tmp = make([]*big.Int,0)
			    inlen = 0
			    diff = 0
			    continue
			}

			_,exsit := tmp2.ReadMap(strings.ToLower(fmt.Sprintf("%v",roh)))
			if exsit {
			    fmt.Printf("calc roh fail\n")
			   return
			}

			tmp2.WriteMap(strings.ToLower(fmt.Sprintf("%v",roh)),"ok")
			rd := RohData{Index:index,Roh:roh}
			data <-rd

			break
		    }
		}
	    }(int64(i))
	}
	wg.Wait()

	l = len(data)
	if int64(l) != m {
	    return nil
	}

	rohs := make([]*big.Int,m)
	for i := 0; i < l; i++ {
	    rd := <-data
	    rohs[rd.Index] = rd.Roh 
	}

	//fmt.Printf("====================CalcRoh,get rohs success, n = %v,m = %v,num = %v======================\n",n,m,num)
	return rohs 
}

//---------------------------------------------------------------------------------

// HvProve
// get quadratic residue x for ROH1,ROH2,ROH3 ..... ROHm
// For every ROHj belong to QRn,the Prover sends back xj(belong to Z*) such that xj^2 mod N = ROHj, Of the four square roots, the Prover chooses one at random. For other ROHj,the prover sends back 0.
func HvProve(n *big.Int,num *big.Int,p *big.Int,q *big.Int) *HvProof {
	if n == nil || num == nil || num.Cmp(zero) < 0 || p == nil || q == nil {
	    return nil
	}

	ROH := CalcRoh(n,num)
	if ROH == nil {
	    return nil
	}

	sigma := make([]*big.Int,len(ROH))
	for k,v := range ROH {
	    var x *big.Int
	    if p.Cmp(q) >= 0 {
		x,_,_,_ = GetTheQuadraticResidueInt(v,n,p,q)
	    } else {
		x,_,_,_ = GetTheQuadraticResidueInt(v,n,q,p)
	    }

	    if x != nil {
		x2 := new(big.Int).Mul(x,x)
		x2 = new(big.Int).Mod(x2,n)
		if x2.Cmp(v) == 0 {
		    sigma[k] = new(big.Int).Abs(x) // Select the x value greater than or equal to 0 
		    continue
		}
	    }

	    sigma[k] = big.NewInt(0)
	}

	return &HvProof{Sigma: sigma}
}

// HvVerify
// for N = p*q
// verifier check:
// 1. Ni > 0
// 2. Ni is a positive odd integer and is not a prime or a prime power
// 3. the count of xij != 0 >= 3*m/8
// 4. xij^2 = ROHij (mod Ni) for every xij != 0  (j = 1,2,...m)   (i = 0,1,2,3,4) 5 nodes for example.
func HvVerify(n *big.Int,num *big.Int,proof *HvProof) bool {
	if n == nil || proof == nil || proof.Sigma == nil || num == nil || num.Cmp(zero) < 0 {
	    return false
	}
	
	ROH := CalcRoh(n,num)
	if ROH == nil {
	    return false 
	}

	if len(proof.Sigma) != len(ROH) {
	    fmt.Printf("====================HvVerify verify len fail,n = %v,num = %v,sigma len = %v, roh len = %v====================\n",n,num,len(proof.Sigma),len(ROH))
	    return false
	}

	if !CheckPrime(n) {
	    fmt.Printf("==============HvVerify,check prime fail,n = %v,num = %v,=================\n",n,num)
	    return false 
	}

	count := 0
	for kk,vv := range proof.Sigma {
	    if vv.Sign() == 0 {
		continue
	    }

	    count++

	    t := new(big.Int).Mul(vv,vv)
	    t = new(big.Int).Mod(t,n)
	    if t.Cmp(ROH[kk]) != 0 {
		fmt.Printf("==============HvVerify,check sigma fail,n = %v,num = %v,k = %v,sigma = %v=================\n",n,num,kk,vv)
		return false
	    }
	}
	
	mm := GetHoeffdingBound()
	m := mm.Int64()
	if m > math.MaxInt64 {
	    fmt.Printf("get hoeffding bound fail,the maximum value of Int64 has been exceeded")
	    return false
	}

	if m <= 0 {
	    return false
	}

	// t = 3*m/8
	t := (3*m)/8 
	if int64(count) < t {
	    fmt.Printf("==============HvVerify,check count fail,n = %v,num = %v,m = %v,t = %v,count = %v=================\n",n,num,m,t,count)
	    return false 
	}
	
	return true
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal HvProof to json bytes
func (hvpf *HvProof) MarshalJSON() ([]byte, error) {
    	tmp := make([]string,0)
	for _,v := range hvpf.Sigma {
	    tmp = append(tmp,fmt.Sprintf("%v",v))
	}

	sigma := strings.Join(tmp,":")
	return json.Marshal(struct {
		Y string `json:"Y"`
	}{
		Y: sigma,
	})
}

// UnmarshalJSON unmarshal raw to HvProof
func (hvpf *HvProof) UnmarshalJSON(raw []byte) error {
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

	hvpf.Sigma = sigma
	return nil
}


