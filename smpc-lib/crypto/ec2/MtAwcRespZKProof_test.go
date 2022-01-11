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
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/stretchr/testify/assert"
	"math/big"
	"sort"
	"testing"
)

var (
	testNtildeLength      = 2048
	testPaillierKeyLength = 2048
)

func TestMtAZK3Verify_nhh(t *testing.T) {
	threshold := 3
	var idsign smpclib.SortableIDSSlice
	enodes := []string{"524da89d8bd8f051e9b24660941e772f60e2e7a4ab0c48d1671ecfb9844e9cf1f0a9ef697be8118fe7bc9f2782a5a2bad912856bcb3a4dfda0aafcbdc9c282af", "8908863d56914eaa420afca83f43206f65ff56e42faeecb9e24f77740838819313f789bf7c4941b162e696147df409e47eb95ea351eac016ce8b7bf38fd269b2", "ee10b450a564e9cda30b37b9497a11ede5583e8964ba01ae85bbba7b421e403b1ab710f87d5b93c700ca459661b889412b9d781fbef8094ee282b46f4a90508b"}
	for i := 0; i < threshold; i++ {
		uid := big.NewInt(i+1)  // n/n
		idsign = append(idsign, uid)
	}
	sort.Sort(idsign)

	sku1, _ := new(big.Int).SetString("85882607790290383937047822609170818719033435222563352179424534763546477097862", 10)
	self := idsign[0]
	lambda1 := big.NewInt(1)

	for k, v := range idsign {
		if k == 0 {
			continue
		}

		sub := new(big.Int).Sub(v, self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256().N)
		assert.NotZero(t, subInverse)
		times := new(big.Int).Mul(subInverse, v)
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
	}
	w1 := new(big.Int).Mul(lambda1, sku1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256().N)

	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	nt, _, _, _, _ := ec2.CreateNt(testNtildeLength)
	assert.NotZero(t, nt)

	NSalt := new(big.Int).Lsh(big.NewInt(1), uint(testPaillierKeyLength-testPaillierKeyLength/10))
	NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
	NSubN2 = new(big.Int).Sub(NSalt, NSubN2)

	v1U1Star := random.GetRandomIntFromZn(NSubN2)

	u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
	u1KCipher, _, _ := publicKey.Encrypt(u1K)
	u1Kw1Cipher := publicKey.HomoMul(u1KCipher, w1)
	v1U1StarCipher, u1VR1, _ := publicKey.Encrypt(v1U1Star)
	u1Kw1Cipher = publicKey.HomoAdd(u1Kw1Cipher, v1U1StarCipher)

	u1u1MtAZK3Proof := ec2.MtAZK3Prove_nhh(w1, v1U1Star, u1VR1, u1KCipher, publicKey, nt)
	assert.NotZero(t, u1u1MtAZK3Proof)
	ret := u1u1MtAZK3Proof.MtAZK3Verify_nhh(u1KCipher, u1Kw1Cipher, publicKey, nt)
	assert.True(t, ret, "must be true")
}

