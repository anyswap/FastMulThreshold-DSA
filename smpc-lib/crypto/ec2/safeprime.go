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
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"math/big"
	"time"
)

const (
        // PrimeTestTimes the times to try to juede weather is prime
	PrimeTestTimes = 30
)

var (
        // SafePrimeCh the channel to save safeprime
	SafePrimeCh = make(chan SafePrime, 4)

	zero        = big.NewInt(0)
	one         = big.NewInt(1)
	two         = big.NewInt(2)
)

// SafePrime prime 
type SafePrime struct {
	q *big.Int
	p *big.Int // p = 2q+1
}

// Q get q
func (sp *SafePrime) Q() *big.Int {
	return sp.q
}

// P get p
func (sp *SafePrime) P() *big.Int {
	return sp.p
}

// SetQ set q
func (sp *SafePrime) SetQ(q *big.Int) {
	sp.q = q
}

// SetP set p
func (sp *SafePrime) SetP(p *big.Int) {
	sp.p = p
}

// CheckValidate check p < 2^(L/2) ?
// p = 2*q + 1
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

// GetP get p
func GetP(q *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(q, two)
	i.Add(i, one)
	return i
}

// probablyPrime judge weather is prime
func probablyPrime(prime *big.Int) bool {
	return prime != nil && prime.ProbablyPrime(PrimeTestTimes)
}

//------------------------------------------------------

// GenRandomSafePrime  Generate 4 random large host primes 
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

// GetRandomPrime add for go test
func GetRandomPrime() (*big.Int, *big.Int) {
	q, p := random.GetSafeRandomPrimeInt()
	sp := SafePrime{q: q, p: p}
	if sp.CheckValidate() {
		return q, p
	}

	return nil, nil
}
