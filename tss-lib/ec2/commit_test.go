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

func TestVerify(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	com := new(ec2.Commitment).Commit(zero, one)
	succ := com.Verify()
	//assert.True(t, succ, "success")
	assert.False(t, succ, "fail")
}

func TestDeCommit(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	com := new(ec2.Commitment).Commit(zero, one)
	succ, u1G := com.DeCommit()
	//assert.True(t, succ, "success")
	//assert.NotZero(t, len(u1G), "len(u1G) must be non-zero")
	assert.False(t, succ, "fail")
	assert.Zero(t, len(u1G), "len(u1G) must be zero")
}
