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

	"encoding/json"
	"errors"
	"strings"
)

const (
    	// Iterations iter times
	Iterations              = 128
)

type (
    	// NtildeProof ntilde zk proof
	NtildeProof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

// NewNtildeProof create ntilde proof
func NewNtildeProof(h1, h2, x, p, q, N *big.Int) *NtildeProof {
	pMulQ := new(big.Int).Mul(p, q)
	modN, modPQ := ModInt(N), ModInt(pMulQ)
	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = GetRandomPositiveInt(pMulQ)
		alpha[i] = modN.Exp(h1, a[i])
	}
	msg := append([]*big.Int{h1, h2, N}, alpha[:]...)
	c := Sha512_256i(msg...)
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range t {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		t[i] = modPQ.Add(a[i], modPQ.Mul(cIBI, x))
	}
	return &NtildeProof{alpha, t}
}

// Verify Verify ntilde proof
func (p *NtildeProof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}

	// check
	zero := big.NewInt(0)
	one := big.NewInt(1)
	h1modn := new(big.Int).Mod(h1,N)
	h2modn := new(big.Int).Mod(h2,N)
	if h1modn.Cmp(zero) == 0 || h2modn.Cmp(zero) == 0 {
	    return false
	}

	if h1modn.Cmp(one) == 0 || h2modn.Cmp(one) == 0 {
	    return false
	}

	if h1modn.Cmp(h2modn) == 0 {
		return false
	}
	//

	modN := ModInt(N)
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	c := Sha512_256i(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := modN.Exp(h1, p.T[i])
		h2ExpCi := modN.Exp(h2, cIBI)
		alphaIMulH2ExpCi := modN.Mul(p.Alpha[i], h2ExpCi)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
			return false
		}
	}
	return true
}

//-------------------------------------------------------------------------------

// MarshalJSON marshal NtildeProof to json bytes
func (p *NtildeProof) MarshalJSON() ([]byte, error) {
	l := len(p.Alpha)
	var alpha string
	for k, v := range p.Alpha {
		alpha += fmt.Sprintf("%v", v)
		if k != (l - 1) {
			alpha += "|"
		}
	}

	var t string
	for k, v := range p.T {
		t += fmt.Sprintf("%v", v)
		if k != (l - 1) {
			t += "|"
		}
	}

	return json.Marshal(struct {
		Alpha string `json:"Alpha"`
		T     string `json:"T"`
	}{
		Alpha: alpha,
		T:     t,
	})
}

// UnmarshalJSON unmarshal raw to NtildeProof
func (p *NtildeProof) UnmarshalJSON(raw []byte) error {
	var pf struct {
		Alpha string `json:"Alpha"`
		T     string `json:"T"`
	}
	if err := json.Unmarshal(raw, &pf); err != nil {
		return err
	}

	al := strings.Split(pf.Alpha, "|")

	if len(al) != Iterations {
		return errors.New("unmarshal ntilde zk proof alpha json data fail")
	}

	var alpha [Iterations]*big.Int
	for k, v := range al {
		alpha[k], _ = new(big.Int).SetString(v, 10)
	}

	tt := strings.Split(pf.T, "|")
	if len(tt) != Iterations {
		return errors.New("unmarshal ntilde zk proof t json data fail")
	}

	var t [Iterations]*big.Int
	for k, v := range tt {
		t[k], _ = new(big.Int).SetString(v, 10)
	}

	p.Alpha = alpha
	p.T = t
	return nil
}


