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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	cipher, rndstar, err := publicKey.Encrypt(big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	assert.NotZero(t, rndstar)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	m := big.NewInt(50)
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	cipher, _, err := publicKey.Encrypt(m)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cipher)
	assert.NoError(t, err)
	assert.Equal(t, 0, m.Cmp(ret),
		"wrong decryption ", ret, " is not ", m)
}

func TestHomoAdd(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	five := big.NewInt(5)
	seven := big.NewInt(7)

	enc1, _, _ := publicKey.Encrypt(five)
	enc2, _, _ := publicKey.Encrypt(seven)
	homoadd := publicKey.HomoAdd(enc1, enc2)
	tmp, _ := privateKey.Decrypt(homoadd)
	assert.Equal(t, new(big.Int).Add(five, seven), tmp)
}

func TestHomoMul(t *testing.T) {
	publicKey, privateKey := ec2.CreatPair(testPaillierKeyLength)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	five, _, err := publicKey.Encrypt(big.NewInt(5))
	assert.NoError(t, err)
	seven := big.NewInt(7)

	cm := publicKey.HomoMul(five, seven)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	exp := int64(35)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

