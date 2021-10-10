package ec2

import (
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"math/big"
	"time"
)

const (
	PrimeTestTimes = 30
)

var (
	SafePrimeCh = make(chan SafePrime, 4)
	zero        = big.NewInt(0)
	one         = big.NewInt(1)
	two         = big.NewInt(2)
)

type SafePrime struct {
	q *big.Int
	p *big.Int // p = 2q+1
}

func (sp *SafePrime) Q() *big.Int {
	return sp.q
}

func (sp *SafePrime) P() *big.Int {
	return sp.p
}

func (sp *SafePrime) SetQ(q *big.Int) {
	sp.q = q
}

func (sp *SafePrime) SetP(p *big.Int) {
	sp.p = p
}

func (sp *SafePrime) CheckValidate() bool {
	if sp.p == nil || sp.q == nil {
		return false
	}

	//check p < 2^(L/2),   L = 2048
	lhalf := big.NewInt(1024)
	m := new(big.Int).Exp(two, lhalf, nil)
	if sp.p.Cmp(m) < 0 {
		return probablyPrime(sp.q) &&
			GetP(sp.q).Cmp(sp.p) == 0 &&
			probablyPrime(sp.p)
	}

	return false
}

func GetP(q *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(q, two)
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
			q, p := random.GetSafeRandomPrimeInt()
			sp := SafePrime{q: q, p: p}
			if sp.CheckValidate() {
				fmt.Printf("=============================Success Generate Safe Random Prime.=============================\n")
				SafePrimeCh <- sp
			}
		}

		if len(SafePrimeCh) == 4 {
			break
		}

		time.Sleep(time.Duration(1000000)) //1000 000 000 == 1s
	}
}

//add for go test
func GetRandomPrime() (*big.Int, *big.Int) {
	q, p := random.GetSafeRandomPrimeInt()
	sp := SafePrime{q: q, p: p}
	if sp.CheckValidate() {
		return q, p
	}

	return nil, nil
}
