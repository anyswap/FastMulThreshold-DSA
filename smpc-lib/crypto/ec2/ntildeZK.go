// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package ec2 

import (
	"fmt"
	"math/big"

	"strings"
	"errors"
	"crypto"
	"encoding/binary"
	"encoding/json"
	"crypto/rand"
	//"github.com/binance-chain/tss-lib/common"
	//cmts "github.com/binance-chain/tss-lib/crypto/commitments"
)

const (
	Iterations = 128
	mustGetRandomIntMaxBits = 5000
	hashInputDelimiter = byte('$')
)

type (
	NtildeProof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

func NewNtildeProof(h1, h2, x, p, q, N *big.Int) *NtildeProof {
	pMulQ := new(big.Int).Mul(p, q)
	modN, modPQ := ModInt(N), ModInt(pMulQ)
	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = GetRandomPositiveInt(pMulQ)
		alpha[i] = modN.Exp(h1, a[i])
		//fmt.Printf("==========================NewNtildeProof,i = %v,alphai = %v==========================\n",i,alpha[i])
	}
	msg := append([]*big.Int{h1, h2, N}, alpha[:]...)
	//fmt.Printf("==================NewNtildeProof, h1 = %v, h2 = %v, N = %v, alpha len = %v, alpha[0] = %v, alpha[end] = %v ====================\n",h1,h2,N,len(alpha),alpha[0],alpha[len(alpha)-1])
	c := SHA512_256i(msg...)
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range t {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		t[i] = modPQ.Add(a[i], modPQ.Mul(cIBI, x))
		//fmt.Printf("==========================NewNtildeProof,i = %v,ti = %v==========================\n",i,t[i])
	}
	return &NtildeProof{alpha, t}
}

func (p *NtildeProof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}
	modN := ModInt(N)
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	//fmt.Printf("==================NtildeProof.Verify, h1 = %v, h2 = %v, N = %v, alpha len = %v, alpha[0] = %v, alpha[end] = %v ====================\n",h1,h2,N,len(p.Alpha),p.Alpha[0],p.Alpha[len(p.Alpha)-1])
	c := SHA512_256i(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
		    //fmt.Printf("==========================NtildeProof.Verify,pai = %v,pti = %v========================\n",p.Alpha[i],p.T[i])
			return false
		}
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := modN.Exp(h1, p.T[i])
		h2ExpCi := modN.Exp(h2, cIBI)
		alphaIMulH2ExpCi := modN.Mul(p.Alpha[i], h2ExpCi)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
		    //fmt.Printf("==========================NtildeProof.Verify,i = %v,alphaIMulH2ExpCi = %v,h1ExpTi = %v========================\n",i,alphaIMulH2ExpCi,h1ExpTi)
			return false
		}
	}
	return true
}

//-------------------------------------------------------------------------------

func (p *NtildeProof) MarshalJSON() ([]byte, error) {
    l := len(p.Alpha)
    var alpha string
    for k,v := range p.Alpha {
	alpha += fmt.Sprintf("%v",v)
	if k != (l-1) {
	    alpha += "|"
	}
    }

    var t string
    for k,v := range p.T {
	t += fmt.Sprintf("%v",v)
	if k != (l-1) {
	    t += "|"
	}
    }

    return json.Marshal(struct {
		Alpha string `json:"Alpha"`
		T string `json:"T"`
	}{
		Alpha: alpha,
		T: t,
	})
}

func (p *NtildeProof) UnmarshalJSON(raw []byte) error {
	var pf struct {
		Alpha string `json:"Alpha"`
		T string `json:"T"`
	}
	if err := json.Unmarshal(raw, &pf); err != nil {
		return err
	}

	al := strings.Split(pf.Alpha,"|")
	fmt.Printf("====================NtildeProof.UnmarshalJSON, pf.Alpha = %v, pf.T = %v, len al = %v ======================\n",pf.Alpha,pf.T,len(al))

	if len(al) != Iterations {
	    return errors.New("unmarshal ntilde zk proof alpha json data fail.")
	}
	
	var alpha [Iterations]*big.Int
	for k,v := range al {
	    alpha[k],_ = new(big.Int).SetString(v,10)
	    fmt.Printf("====================NtildeProof.UnmarshalJSON, alpha[k] = %v, k = %v, v = %v ======================\n",alpha[k],k,v)
	}
	
	tt := strings.Split(pf.T,"|")
	if len(tt) != Iterations {
	    return errors.New("unmarshal ntilde zk proof t json data fail.")
	}
	
	var t [Iterations]*big.Int
	for k,v := range tt {
	    t[k],_ = new(big.Int).SetString(v,10)
	    fmt.Printf("====================NtildeProof.UnmarshalJSON, t[k] = %v, k = %v, v = %v ======================\n",t[k],k,v)
	}

	p.Alpha = alpha
	p.T = t
	return nil
}

//-------------------------------------------------------------------------------------------

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

func (mi *modInt) Neg(x *big.Int) *big.Int {
	i := new(big.Int)
	i.Neg(x)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Inverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) Sqrt(x *big.Int) *big.Int {
	return new(big.Int).ModSqrt(x, mi.i())
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

//-----------------------------------------------------------------------------------------------------

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(fmt.Errorf("rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

func GetRandomPositiveInt(upper *big.Int) *big.Int {
	if upper == nil || zero.Cmp(upper) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(upper.BitLen())
		if try.Cmp(upper) < 0 && try.Cmp(zero) >= 0 {
			break
		}
	}
	return try
}

func GetRandomPrimeInt(bits int) *big.Int {
	if bits <= 0 {
		return nil
	}
	try, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//  Return a random generator of RQn with high probability.
//  THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

//---------------------------------------------------------------------------------------------------------

// SHA-512/256 is protected against length extension attacks and is more performant than SHA-256 on 64-bit architectures.
// https://en.wikipedia.org/wiki/Template:Comparison_of_SHA_functions
func SHA512_256(in ...[]byte) []byte {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	bzSize := 0
	// prevent hash collisions with this prefix containing the block count
	inLenBz := make([]byte, 64/8)
	// converting between int and uint64 doesn't change the sign bit, but it may be interpreted as a larger value.
	// this prefix is never read/interpreted, so that doesn't matter.
	binary.LittleEndian.PutUint64(inLenBz, uint64(inLen))
	for _, bz := range in {
		bzSize += len(bz)
	}
	data = make([]byte, 0, len(inLenBz)+bzSize+inLen)
	data = append(data, inLenBz...)
	for _, bz := range in {
		data = append(data, bz...)
		data = append(data, hashInputDelimiter) // safety delimiter
	}
	// n < len(data) or an error will never happen.
	// see: https://golang.org/pkg/hash/#Hash and https://github.com/golang/go/wiki/Hashing#the-hashhash-interface
	if _, err := state.Write(data); err != nil {
		fmt.Printf("SHA512_256 Write() failed: %v\n",err)
		return nil
	}
	return state.Sum(nil)
}

func SHA512_256i(in ...*big.Int) *big.Int {
	var data []byte
	state := crypto.SHA512_256.New()
	inLen := len(in)
	if inLen == 0 {
		return nil
	}
	bzSize := 0
	// prevent hash collisions with this prefix containing the block count
	inLenBz := make([]byte, 64/8)
	// converting between int and uint64 doesn't change the sign bit, but it may be interpreted as a larger value.
	// this prefix is never read/interpreted, so that doesn't matter.
	binary.LittleEndian.PutUint64(inLenBz, uint64(inLen))
	ptrs := make([][]byte, inLen)
	for i, n := range in {
	    if n == nil {
		fmt.Printf("===================SHA512_256i, n is nil, i = %v, inLen = %v, ==================\n",i,inLen)
		continue
	    }

	    ptrs[i] = n.Bytes()
	    bzSize += len(ptrs[i])
	}
	data = make([]byte, 0, len(inLenBz)+bzSize+inLen)
	data = append(data, inLenBz...)
	for i := range in {
		data = append(data, ptrs[i]...)
		data = append(data, hashInputDelimiter) // safety delimiter
	}
	// n < len(data) or an error will never happen.
	// see: https://golang.org/pkg/hash/#Hash and https://github.com/golang/go/wiki/Hashing#the-hashhash-interface
	if _, err := state.Write(data); err != nil {
		fmt.Printf("SHA512_256i Write() failed: %v\n",err)
		return nil
	}
	return new(big.Int).SetBytes(state.Sum(nil))
}

func SHA512_256iOne(in *big.Int) *big.Int {
	var data []byte
	state := crypto.SHA512_256.New()
	if in == nil {
		return nil
	}
	data = in.Bytes()
	// n < len(data) or an error will never happen.
	// see: https://golang.org/pkg/hash/#Hash and https://github.com/golang/go/wiki/Hashing#the-hashhash-interface
	if _, err := state.Write(data); err != nil {
		//Logger.Errorf("SHA512_256iOne Write() failed: %v", err)
		fmt.Printf("SHA512_256iOne Write() failed: %v\n",err)
		return nil
	}
	return new(big.Int).SetBytes(state.Sum(nil))
}


