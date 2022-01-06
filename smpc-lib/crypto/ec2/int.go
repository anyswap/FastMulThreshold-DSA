// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package ec2 

import (
	"math/big"
	"fmt"
	"crypto/rand"
	"github.com/pkg/errors"
	"crypto"
	"encoding/binary"
	"sync"
	"strings"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
)

const (
	mustGetRandomIntMaxBits = 5000
	hashInputDelimiter = byte('$')
)

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

//----------------------------------------------------------

// Sha512_256 get a hash value with input and add the custom domain separator to hash computations.
func Sha512_256(in ...*big.Int) *big.Int {
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
		fmt.Errorf("SHA512_256 Write() failed: %v", err)
		return nil
	}
	return new(big.Int).SetBytes(state.Sum(nil))
}

//------------------------------------------------------

// GetRandomPositiveRelativelyPrimeInt Generate a random element in the group of all the elements in Z/nZ that
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

//--------------------------------------------------

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
		return nil
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
		return nil
	}
	return n
}

//-------------------------------------------------------

// IsNumberInMultiplicativeGroup judge weather gcd(n,v) = 1
func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//--------------------------------------------------------

// GetRandomPositiveInt get a random number in (0,upper)
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

//---------------------------------------------------------------
// Ntilde = p*q, p and q are odd prime.
// Z = {0,1,2,.....,Ntilde - 1}
// Z* = {x| the element in Z that such as gcd(x,Ntilde) = 1}
// JN = {a1,a2,a3,.....,ak,....}, the element in Z* that such as Jacobi-Symbol (ai/Ntilde) = 1   (i = 1,2,3...)
// QRn = {b1,b2,...,bk....}, the element in JN that such as x^2 = bi (mod Ntilde) has solution,this is equivalent to Legendre-Symbol (bi/p) = 1 and (bi/q) = 1      (i = 1,2,3...)


// GetTheQuadraticResidueInt get the roots of x^2 = roh (mod N)
// N = p*q , p and q are odd prime, p >= q 
// gcd(roh,N) = 1, 1 <= roh < N
// return 4 roots: (x,-x,y,-y)
// x^2 = roh (mod p) ------------->  r
// x^2 = roh (mod q) ------------->  s
// get g,c,d by Euclidean Algorithm,such as: g = gcd(p,q),pc + qd = g
// so:
// x = r*d*q + s*c*p
// y = r*d*q − s*c*p
func GetTheQuadraticResidueInt(roh *big.Int,N *big.Int,p *big.Int,q *big.Int) (*big.Int,*big.Int,*big.Int,*big.Int) {
    if roh == nil || N == nil || p == nil || q == nil || p.Cmp(q) < 0 {
	return nil,nil,nil,nil
    }

    one,_ := new(big.Int).SetString("1",10)
    MinusOne := big.NewInt(-1)

    // x^2 = roh (mod p)
    r := new(big.Int).ModSqrt(roh,p)
    if r == nil {
	return nil,nil,nil,nil
    }

    // x^2 = roh (mod q)
    s := new(big.Int).ModSqrt(roh,q)
    if s == nil {
	return nil,nil,nil,nil
    }

    // g = gcd(p,q) and pc + qd = g
    // p >= q, c,d are integer
    g,c,d := EuclideanAlgorithm(p,q)
    if g.Cmp(one) != 0 {
	return nil,nil,nil,nil
    }

    tmp1 := new(big.Int).Mul(q,d)
    tmp1 = new(big.Int).Mul(tmp1,r)

    tmp2 := new(big.Int).Mul(p,c)
    tmp2 = new(big.Int).Mul(tmp2,s)

    // x = r*d*q + s*c*p
    x := new(big.Int).Add(tmp1,tmp2)
    x = new(big.Int).Mod(x,N)

    // negx = -x
    negx := new(big.Int).Mul(x,MinusOne)
    negx = new(big.Int).Mod(negx,N)

    // y = r*d*q − s*c*p
    y := new(big.Int).Sub(tmp1,tmp2)
    y = new(big.Int).Mod(y,N)

    // negy = -y
    negy := new(big.Int).Mul(y,MinusOne)
    negy = new(big.Int).Mod(negy,N)

    return x,negx,y,negy
}

//--------------------------------------------------------------

// EuclideanAlgorithm get (d,x,y) such as: d = gcd(a,b) and ax + by = d
// a >= b, x and y are integer
func EuclideanAlgorithm(a *big.Int,b *big.Int) (*big.Int,*big.Int,*big.Int) {
    if a == nil || b == nil || a.Cmp(b) < 0 {
	return nil,nil,nil
    }

    zero,_ := new(big.Int).SetString("0",10)
    one,_ := new(big.Int).SetString("1",10)
    
    if b.Cmp(zero) == 0 {
	return a,one,zero
    }

    x2 := one
    x1 := zero
    y2 := zero
    y1 := one
    for {
	if b.Cmp(zero) <= 0 {
	    break
	}

	q := new(big.Int).Div(a,b)
	qb := new(big.Int).Mul(q,b)
	r := new(big.Int).Sub(a,qb)
	qx1 := new(big.Int).Mul(q,x1)
	x := new(big.Int).Sub(x2,qx1)
	qy1 := new(big.Int).Mul(q,y1)
	y := new(big.Int).Sub(y2,qy1)
	a = b
	b = r
	x2 = x1
	x1 = x
	y2 = y1
	y1 = y
    }

    return a,x2,y2
}

//---------------------------------------------------------------

// GetRandomValuesFromJN get m random values from JN
func GetRandomValuesFromJN(N *big.Int) []*big.Int {
    if N == nil || N.Cmp(big.NewInt(1)) <= 0 {
	return nil
    }

    m := GetHoeffdingBound()
    mint := int(m.Int64())
    
    data := make(chan *big.Int,mint)
    
    tmp := common.NewSafeMap(10)
    var wg sync.WaitGroup
    for i:=0;i<mint;i++ {
	wg.Add(1)
	go func() {
	    defer wg.Done()
	    
	    for {
		// roh in Z*
		roh := GetRandomPositiveRelativelyPrimeInt(N)
		if roh == nil {
		    continue
		}

		// Jacobi-symbol (roh,N) = 1,so roh in JN
		sym := big.Jacobi(roh,N)
		if sym != 1 {
		    continue
		}

		_,exsit := tmp.ReadMap(strings.ToLower(fmt.Sprintf("%v",roh)))
		if exsit {
		    continue
		}

		tmp.WriteMap(strings.ToLower(fmt.Sprintf("%v",roh)),"ok")
		data <-roh
		break
	    }
	}()
    }

    wg.Wait()
    
    var ret []*big.Int = make([]*big.Int,0)
    l := len(data)
    for i := 0; i < l; i++ {
	roh := <-data
	//fmt.Printf("==========================GetRandomValuesFromJN,i = %v,l = %v,roh = %v,N = %v=========================\n",i,l,roh,N)
	ret = append(ret, roh)
    }

    return ret
}

//------------------------------------------------------

// CheckPrime Check Ntilde:
// 1. Ntilde > 0
// 2. Ntilde is odd
// 3. Ntilde is not a prime
// 4. Ntilde is not a prime perfect power
func CheckPrime(Ntilde *big.Int) bool {
    if Ntilde == nil {
	return false
    }

    // Ntilde > 0 ??
    zero,_ := new(big.Int).SetString("0",10)
    if Ntilde.Cmp(zero) <= 0 {
	return false
    }

    // Ntilde % 2 != 0 ??
    two,_ := new(big.Int).SetString("2",10)
    t := new(big.Int).Mod(Ntilde,two)
    if t.Cmp(zero) == 0 {
	return false
    }

    // Ntilde is not a prime ??
    if Ntilde.ProbablyPrime(PrimeTestTimes) {
	return false
    }

    // Ntilde is not a prime perfect power ??
    return !IsPerfectPowerOfPrime(Ntilde)
}

//-------------------------------------------------------

// IsPerfectPower find two integers a and b,such as: Ntilde = a ^ b,and return a  ( 2 =< b <= logNtilde )
// if not found a,return nil
func IsPerfectPower(Ntilde *big.Int) *big.Int {
    if Ntilde == nil {
	return nil
    }

    log2n := big.NewInt(int64(Ntilde.BitLen()))

    for b:= big.NewInt(2);b.Cmp(log2n) <= 0;b.Add(b,big.NewInt(1)) {
	low := big.NewInt(1) 
	high := new(big.Int).Div(log2n,b)
	
	for {
	    ho := new(big.Int).Sub(high,big.NewInt(1))
	    if low.Cmp(ho) >= 0 {
		break
	    }

	    sum := new(big.Int).Add(low,high)
	    mid := new(big.Int).Div(sum,big.NewInt(2))
	    ab := new(big.Int).Exp(big.NewInt(2),mid,nil)
	    ab = new(big.Int).Exp(ab,b,nil)
	    if ab.Cmp(Ntilde) > 0 {
		high = mid
	    } else if ab.Cmp(Ntilde) < 0 {
		low = mid
	    } else {
		// check Ntilde = (2 ^ mid) ^ b
		a := new(big.Int).Exp(big.NewInt(2),mid,nil)
		T := new(big.Int).Exp(a,b,nil)
		if T.Cmp(Ntilde) == 0 {
		    fmt.Printf("===============IsPerfectPower,check success,a = %v,b = %v,Ntilde = %v=====================",a,b,Ntilde)
		    return a
		}
		
		break
	    }
	}
    }

    return nil
}

// Ntilde == p ^ k ?? 
// p is prime
// 2 <= k <= logNtilde
func IsPerfectPowerOfPrime(Ntilde *big.Int) bool {
    a := IsPerfectPower(Ntilde)
    if a == nil {
	return false
    }

    if a.ProbablyPrime(PrimeTestTimes) {
	return true
    }
    
     return IsPerfectPowerOfPrime(a)
}

//----------------------------------------------------------------------------------

// ContainsDuplicate judge weather contain duplicate element in ids array
func ContainsDuplicate(ids []*big.Int) (bool,error) {
    if ids == nil || len(ids) == 0 {
	return false,errors.New("input param error")
    }
    
    numMap:=make(map[string]int)
    for _,v := range ids {
        numMap[strings.ToLower(fmt.Sprintf("%v",v))] = 1
    }

    if len(numMap) != len(ids) {
       return true,nil 
    }

    return false,nil
}

//------------------------------------------------------------------------------

// joinInt join short x to X
// len(X) == n.BitLen()
// n is the paillier pubKey.N or ntilde ....
func joinInt(in []*big.Int,diff int) *big.Int {
    inLen := len(in)
    if inLen == 0 {
	return nil
    }
    
    bzSize := 0
    ptrs := make([][]byte, inLen)
    for i, n := range in {
	ptrs[i] = n.Bytes()
	bzSize += len(ptrs[i])
    }

    data := make([]byte, 0, bzSize+diff)
    for i := range in {
	data = append(data, ptrs[i]...)
    }

    //fmt.Printf("============================joinInt,inlen = %v,bzSize byte = %v,data.Len byte = %v===============================\n",inLen,bzSize,len(data))
    return new(big.Int).SetBytes(data[:])
}



