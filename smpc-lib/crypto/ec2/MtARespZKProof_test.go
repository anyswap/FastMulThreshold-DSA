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
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
)

var (
	testNtildeLength      = 2048
	testPaillierKeyLength = 2048
)

func TestMtAZK2Verify_nhh(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	nt, _, _, _, _ := ec2.CreateNt(testNtildeLength)
	assert.NotZero(t, nt)
	NSalt := new(big.Int).Lsh(big.NewInt(1), uint(testPaillierKeyLength-testPaillierKeyLength/10))
	NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
	NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
	beta1U1Star := random.GetRandomIntFromZn(NSubN2)
	beta1U1StarCipher, u1BetaR1, _ := publicKey.Encrypt(beta1U1Star)
	u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)
	u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
	u1KCipher, _, _ := publicKey.Encrypt(u1K)
	u1KGamma1Cipher := publicKey.HomoMul(u1KCipher, u1Gamma)
	u1KGamma1Cipher = publicKey.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher)
	u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(u1Gamma, beta1U1Star, u1BetaR1, u1KCipher, publicKey, nt)
	assert.NotZero(t, u1u1MtAZK2Proof)
	ret := u1u1MtAZK2Proof.MtAZK2Verify_nhh(u1KCipher, u1KGamma1Cipher, publicKey, nt)
	assert.True(t, ret, "must be true")
}
