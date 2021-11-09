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
	"math"
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

// Sha512_256i get a hash value with input  
func Sha512_256i(in ...*big.Int) *big.Int {
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
		fmt.Errorf("SHA512_256i Write() failed: %v", err)
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
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
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
func GetTheQuadraticResidueInt(roh *big.Int,N *big.Int,p *big.Int,q *big.Int) (*big.Int,*big.Int,*big.Int,*big.Int) {
    if roh == nil || N == nil || p == nil || q == nil || p.Cmp(q) < 0 {
	return nil,nil,nil,nil
    }

    one,_ := new(big.Int).SetString("1",10)
    MinusOne := big.NewInt(-1)
    r := new(big.Int).ModSqrt(roh,p)
    if r == nil {
	return nil,nil,nil,nil
    }

    s := new(big.Int).ModSqrt(roh,q)
    if s == nil {
	return nil,nil,nil,nil
    }

    g,c,d := EuclideanAlgorithm(p,q)
    if g.Cmp(one) != 0 {
	return nil,nil,nil,nil
    }

    tmp1 := new(big.Int).Mul(q,d)
    tmp1 = new(big.Int).Mul(tmp1,r)

    tmp2 := new(big.Int).Mul(p,c)
    tmp2 = new(big.Int).Mul(tmp2,s)

    x := new(big.Int).Add(tmp1,tmp2)
    x = new(big.Int).Mod(x,N)

    negx := new(big.Int).Mul(x,MinusOne)
    negx = new(big.Int).Mod(negx,N)

    y := new(big.Int).Sub(tmp1,tmp2)
    y = new(big.Int).Mod(y,N)

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

// GetHoeffdingBound get hoeffding bound
func GetHoeffdingBound(k float64) *big.Int {
    m := k*32*math.Log(2)
    m = math.Ceil(m)
    mInt,_ := new(big.Int).SetString(fmt.Sprintf("%v",m),10)
    return mInt
}

// GetRandomValuesFromJN get m random values from JN
func GetRandomValuesFromJN(N *big.Int) []*big.Int {
    m := GetHoeffdingBound(128)
    mint := int(m.Int64())
    
    data := make(chan *big.Int,mint)
    
    tmp := common.NewSafeMap(10)
    var wg sync.WaitGroup
    for i:=0;i<mint;i++ {
	wg.Add(1)
	go func() {
	    defer wg.Done()
	    
	    for {
		roh := GetRandomPositiveRelativelyPrimeInt(N)
		if roh == nil {
		    continue
		}

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
	    fmt.Printf("==========================GetRandomValuesFromJN,i = %v,l = %v,roh = %v,N = %v=========================\n",i,l,roh,N)
	    ret = append(ret, roh)
    }

    return ret
}

//------------------------------------------------------

func CheckPrime(Ntilde *big.Int) bool {
    if Ntilde == nil {
	return false
    }

    zero,_ := new(big.Int).SetString("0",10)
    if Ntilde.Cmp(zero) <= 0 {
	return false
    }

    two,_ := new(big.Int).SetString("2",10)
    t := new(big.Int).Mod(Ntilde,two)
    if t.Cmp(zero) == 0 {
	return false
    }

    return !Ntilde.ProbablyPrime(PrimeTestTimes)
}


