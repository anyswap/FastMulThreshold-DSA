package ec2

import (
	"math/big"
	//"fmt"
	//"encoding/json"

	"time"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

const (
    PrimeTestTimes = 30
)

var (
	SafePrimeCh = make(chan SafePrime, 1000)
	RndInt    = make(chan *big.Int, 1000)
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

//=============================================

func GenRandomSafePrime(length int) {
	for {
		if len(SafePrimeCh) < 4 { /////TODO  tmp:1000-->4
			rndInt := <-RndInt
			p := random.GetSafeRandomPrimeInt2(length/2, rndInt)
			if p != nil {
			    sp := SafePrime{q:rndInt,p:p}
			    SafePrimeCh <- sp
			    time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
			}
		}

		////TODO tmp:1000-->4
		if len(SafePrimeCh) == 4 {
			break
		}
		//////
	}
}

func GenRandomInt(length int) {

	for {
		if len(RndInt) < 1000 {
			////TODO tmp:1000-->4
			if len(SafePrimeCh) == 4 {
				break
			}
			//////
			p := random.GetSafeRandomInt(length / 2)
			RndInt <- p

			time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
		}
	}
}

