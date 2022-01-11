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

package ec2_test

import (
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

const (
	testPrimeTestTimes = 30
)

func checkH1H2(H1 *big.Int, H2 *big.Int) bool {
	if H1 != nil && H2 != nil && H1.Cmp(H2) != 0 {
		return true
	}

	return false
}

func TestNtildeVerify(t *testing.T) {
	nt, alpha, beta, p, q := ec2.CreateNt(testNtildeLength)
	assert.NotZero(t, nt)
	assert.NotZero(t, alpha)
	assert.NotZero(t, beta)
	assert.NotZero(t, p)
	assert.NotZero(t, q)
	ret := checkH1H2(nt.H1, nt.H2)
	assert.True(t, ret, "must be true")
	ntildeProof1 := ec2.NewNtildeProof(nt.H1, nt.H2, alpha, p, q, nt.Ntilde)
	ntildeProof2 := ec2.NewNtildeProof(nt.H2, nt.H1, beta, p, q, nt.Ntilde)

	ret1 := ntildeProof1.Verify(nt.H1, nt.H2, nt.Ntilde)
	assert.True(t, ret1, "must be true")
	ret2 := ntildeProof2.Verify(nt.H2, nt.H1, nt.Ntilde)
	assert.True(t, ret2, "must be true")
}
