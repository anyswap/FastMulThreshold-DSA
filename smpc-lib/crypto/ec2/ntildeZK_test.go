// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package ec2_test 

import (
    	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"math/big"
)

const (
	testPrimeTestTimes = 30
)

func checkH1H2(H1 *big.Int,H2 *big.Int) bool {
    if H1 != nil && H2 != nil && H1.Cmp(H2) != 0 {
	return true
    }

    return false
}

func TestNtildeVerify(t *testing.T) {
	nt,alpha,beta,p,q := ec2.CreateNt(testNtildeLength)
	assert.NotZero(t, nt)
	assert.NotZero(t, alpha)
	assert.NotZero(t, beta)
	assert.NotZero(t, p)
	assert.NotZero(t, q)
	ret := checkH1H2(nt.H1,nt.H2)
	assert.True(t, ret, "must be true")
	ntildeProof1 := ec2.NewNtildeProof(nt.H1, nt.H2, alpha, p, q, nt.Ntilde)
	ntildeProof2 := ec2.NewNtildeProof(nt.H2, nt.H1, beta, p, q, nt.Ntilde)

	ret1 := ntildeProof1.Verify(nt.H1, nt.H2, nt.Ntilde)
	assert.True(t, ret1, "must be true")
	ret2 := ntildeProof2.Verify(nt.H2, nt.H1, nt.Ntilde)
	assert.True(t, ret2, "must be true")
}



