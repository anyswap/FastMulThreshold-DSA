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
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
)

//------------------------------------------------------------------------------------

func TestZkUProveVerify(t *testing.T) {
	u1 := random.GetRandomIntFromZn(secp256k1.S256(keytype).N)
	u1zkUProof := ec2.ZkUProve(u1)
	assert.NotZero(t, u1zkUProof)
	u1Gx, u1Gy := secp256k1.S256(keytype).ScalarBaseMult(u1.Bytes())
	u1Secrets := make([]*big.Int, 0)
	u1Secrets = append(u1Secrets, u1Gx)
	u1Secrets = append(u1Secrets, u1Gy)

	_, u1PolyG, err := ec2.Vss2Init(u1, 3)
	assert.NoError(t, err)

	for i := 1; i < len(u1PolyG.PolyG); i++ {
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
	}
	commitU1G := new(ec2.Commitment).Commit(u1Secrets...)
	ret, u1G := commitU1G.DeCommit()
	assert.True(t, ret)
	ret = ec2.ZkUVerify(u1G, u1zkUProof)
	assert.True(t, ret)
}

func TestZkXiProveVerify(t *testing.T) {
	sk := random.GetRandomIntFromZn(secp256k1.S256(keytype).N)
	u1zkXiProof := ec2.ZkXiProve(sk)
	assert.NotZero(t, u1zkXiProof)
	xGx, xGy := secp256k1.S256(keytype).ScalarBaseMult(sk.Bytes())
	u1Secrets := make([]*big.Int, 0)
	u1Secrets = append(u1Secrets, xGx)
	u1Secrets = append(u1Secrets, xGy)

	_, u1PolyG, err := ec2.Vss2Init(sk, 3)
	assert.NoError(t, err)

	for i := 1; i < len(u1PolyG.PolyG); i++ {
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
	}
	commitXiG := new(ec2.Commitment).Commit(u1Secrets...)
	ret, xiG := commitXiG.DeCommit()
	assert.True(t, ret)
	ret = ec2.ZkXiVerify(xiG, u1zkXiProof)
	assert.True(t, ret)
}

