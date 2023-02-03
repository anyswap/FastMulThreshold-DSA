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

// Package ec2_test test ec2
package ec2_test

import (
	"testing"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/stretchr/testify/assert"
)

var (
	testNtildeLength      = 2048
	testPaillierKeyLength = 2048
)

func TestMtAZK1Verify_nhh(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	u1K := random.GetRandomIntFromZn(secp256k1.S256(keytype).N)
	nt, _, _, _, _ := ec2.CreateNt(testNtildeLength)
	assert.NotZero(t, nt)
	u1KCipher, u1R, _ := publicKey.Encrypt(u1K)
	u1u1MtAZK1Proof := ec2.MtAZK1Prove_nhh(u1K, u1R, publicKey, nt)
	assert.NotZero(t, u1u1MtAZK1Proof)
	u1rlt1 := u1u1MtAZK1Proof.MtAZK1Verify_nhh(u1KCipher, publicKey, nt)
	assert.True(t, u1rlt1, "u1rlt1 must be true")
}
