package ec2

import (
	"math/big"
	//"fmt"
	//"encoding/json"

	"time"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
)

const (
    PrimeTestTimes = 30
)

var (
	SafePrimeCh = make(chan SafePrime, 4)
)

type SafePrime struct {
    q *big.Int
    p *big.Int // p = 2q+1
}

func (sp *SafePrime) Prime() *big.Int {
	return sp.q
}

func (sp *SafePrime) SafePrime() *big.Int {
	return sp.p
}

func (sp *SafePrime) CheckValidate() bool {
	return probablyPrime(sp.q) &&
		getSafePrime(sp.q).Cmp(sp.p) == 0 &&
		probablyPrime(sp.p)
}

func getSafePrime(p *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(p, two)
	i.Add(i, one)
	return i
}

func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(PrimeTestTimes)
}

//------------------------------------------------------

func GenRandomSafePrime() {
     for {
         if len(SafePrimeCh) < 4 {
             q,p := random.GetSafeRandomPrimeInt()
	     if q != nil && p != nil {
		 //check p < 2^(L/2),   L = 2048
		two := big.NewInt(2)
		lhalf := big.NewInt(1024)
		 m := new(big.Int).Exp(two,lhalf,nil)
		 if p.Cmp(m) < 0 {
		    common.Info("================================Success Generate Safe Random Prime.==============================")
		    SafePrimeCh <- SafePrime{q:q,p:p}
		 }
	     }
         }
	
	if len(SafePrimeCh) == 4 {
		break
 	}
	 
	time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
     }
}


