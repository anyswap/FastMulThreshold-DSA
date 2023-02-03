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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
)

// ErrMessageTooLong error info to print
var ErrMessageTooLong = errors.New("[ERROR]: message is too long")

// PublicKey the paillier pubkey
type PublicKey struct {
	Length string   `json:"Length"`
	N      *big.Int `json:"N"`  // n = p*q, where p and q are prime
	G      *big.Int `json:"G"`  // in practical, G = N + 1
	N2     *big.Int `json:"N2"` // N2 = N * N
}

// PrivateKey the paillier private key
type PrivateKey struct {
	Length string `json:"Length"`
	PublicKey
	L *big.Int `json:"L"` // (p-1)*(q-1)
	U *big.Int `json:"U"` // L^-1 mod N
}

// GenerateKeyPair create paillier pubkey and private key
func GenerateKeyPair(length int) (*PublicKey, *PrivateKey,*big.Int,*big.Int) {
    	if length <= 0 {
	    return nil,nil,nil,nil
	}

	one := big.NewInt(1)

	sp1 := <-SafePrimeCh
	p := sp1.p
	sp2 := <-SafePrimeCh
	q := sp2.p

	if p == nil || q == nil {
		return nil, nil,nil,nil
	}

	SafePrimeCh <- sp1
	SafePrimeCh <- sp2

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, one)

	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)

	l := new(big.Int).Mul(pMinus1, qMinus1)
	u := new(big.Int).ModInverse(l, n)
	if u == nil {
		return nil, nil,nil,nil
	}

	publicKey := &PublicKey{Length: strconv.Itoa(length), N: n, G: g, N2: n2}
	privateKey := &PrivateKey{Length: strconv.Itoa(length), PublicKey: *publicKey, L: l, U: u}

	return publicKey, privateKey,p,q
}

// Encrypt paillier encrypt by public key
func (publicKey *PublicKey) Encrypt(mBigInt *big.Int) (*big.Int, *big.Int, error) {
    	if mBigInt == nil {
	    return nil,nil,errors.New("param error")
	}

	if mBigInt.Cmp(publicKey.N) > 0 {
		return nil, nil, ErrMessageTooLong
	}

	rndStar := random.GetRandomIntFromZnStar(publicKey.N)

	// G^m mod N2
	Gm := new(big.Int).Exp(publicKey.G, mBigInt, publicKey.N2)
	// R^N mod N2
	RN := new(big.Int).Exp(rndStar, publicKey.N, publicKey.N2)
	// G^m * R^n
	GmRN := new(big.Int).Mul(Gm, RN)
	// G^m * R^n mod N2
	cipher := new(big.Int).Mod(GmRN, publicKey.N2)

	return cipher, rndStar, nil
}

// Decrypt paillier decrypt by private key
func (privateKey *PrivateKey) Decrypt(cipherBigInt *big.Int) (*big.Int, error) {
    	if privateKey == nil || cipherBigInt == nil {
	    return nil,errors.New("param error")
	}

	one := big.NewInt(1)

	if cipherBigInt.Cmp(privateKey.N2) > 0 {
		return nil, ErrMessageTooLong
	}

	// c^L mod N2
	cL := new(big.Int).Exp(cipherBigInt, privateKey.L, privateKey.N2)
	// c^L - 1
	cLMinus1 := new(big.Int).Sub(cL, one)
	// (c^L - 1) / N
	cLMinus1DivN := new(big.Int).Div(cLMinus1, privateKey.N)
	// (c^L - 1) / N * U
	cLMinus1DivNMulU := new(big.Int).Mul(cLMinus1DivN, privateKey.U)
	// (c^L - 1) / N * U mod N
	mBigInt := new(big.Int).Mod(cLMinus1DivNMulU, privateKey.N)

	return mBigInt, nil
}

// HomoAdd  Homomorphic addition 
func (publicKey *PublicKey) HomoAdd(c1, c2 *big.Int) *big.Int {
    	if publicKey == nil || c1 == nil || c2 == nil {
	    return nil
	}

	// c1 * c2
	c1c2 := new(big.Int).Mul(c1, c2)
	// c1 * c2 mod N2
	newCipher := new(big.Int).Mod(c1c2, publicKey.N2)

	return newCipher
}

// HomoMul  Homomorphic multiplication 
func (publicKey *PublicKey) HomoMul(cipher, k *big.Int) *big.Int {
    	if publicKey == nil || cipher == nil || k == nil {
	    return nil
	}

	// cipher^k mod N2
	newCipher := new(big.Int).Exp(cipher, k, publicKey.N2)

	return newCipher
}

//------------------------------------------------------------------------------

// MarshalJSON marshal PublicKey to json bytes
func (publicKey *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Length string `json:"Length"`
		N      string `json:"N"`
		G      string `json:"G"`
		N2     string `json:"N2"`
	}{
		Length: publicKey.Length,
		N:      fmt.Sprintf("%v", publicKey.N),
		G:      fmt.Sprintf("%v", publicKey.G),
		N2:     fmt.Sprintf("%v", publicKey.N2),
	})
}

// UnmarshalJSON unmarshal raw to PublicKey
func (publicKey *PublicKey) UnmarshalJSON(raw []byte) error {
	var pub struct {
		Length string `json:"Length"`
		N      string `json:"N"`
		G      string `json:"G"`
		N2     string `json:"N2"`
	}
	if err := json.Unmarshal(raw, &pub); err != nil {
		return err
	}

	publicKey.Length = pub.Length
	publicKey.N, _ = new(big.Int).SetString(pub.N, 10)
	publicKey.G, _ = new(big.Int).SetString(pub.G, 10)
	publicKey.N2, _ = new(big.Int).SetString(pub.N2, 10)

	l,err := strconv.Atoi(publicKey.Length)
	if err != nil {
	    return err
	}

	if l <= 0 {
	    return errors.New("unmarshal length error")
	}

	if publicKey.N == nil || publicKey.G == nil || publicKey.N2 == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}

//--------------------------------------------------------------------------

// MarshalJSON marshal PrivateKey to json bytes
func (privateKey *PrivateKey) MarshalJSON() ([]byte, error) {
	pk, err := (&(privateKey.PublicKey)).MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct {
		Length    string `json:"Length"`
		PublicKey string `json:"PublicKey"`
		L         string `json:"L"`
		U         string `json:"U"`
	}{
		Length:    privateKey.Length,
		PublicKey: string(pk),
		L:         fmt.Sprintf("%v", privateKey.L),
		U:         fmt.Sprintf("%v", privateKey.U),
	})
}

// UnmarshalJSON unmarshal raw to PrivateKey
func (privateKey *PrivateKey) UnmarshalJSON(raw []byte) error {
	var pri struct {
		Length    string `json:"Length"`
		PublicKey string `json:"PublicKey"`
		L         string `json:"L"`
		U         string `json:"U"`
	}
	if err := json.Unmarshal(raw, &pri); err != nil {
		return err
	}

	privateKey.Length = pri.Length
	l,err := strconv.Atoi(privateKey.Length)
	if err != nil {
	    return err
	}

	if l <= 0 {
	    return errors.New("unmarshal length error")
	}

	pub := &PublicKey{}
	err = pub.UnmarshalJSON([]byte(pri.PublicKey))
	if err != nil {
		return err
	}

	privateKey.PublicKey = *pub
	privateKey.L, _ = new(big.Int).SetString(pri.L, 10)
	privateKey.U, _ = new(big.Int).SetString(pri.U, 10)
	if privateKey.L == nil || privateKey.U == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}

//-----------------------------------------------------------------------

// CreatPair create paillier pubkey/private key
func CreatPair(length int) (*PublicKey, *PrivateKey) {
    	if length <= 0 {
	    return nil,nil
	}

	one := big.NewInt(1)

	_, p := GetRandomPrime()
	_, q := GetRandomPrime()

	if p == nil || q == nil {
		return nil, nil
	}

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, one)

	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)

	l := new(big.Int).Mul(pMinus1, qMinus1)
	u := new(big.Int).ModInverse(l, n)
	if u == nil {
		return nil, nil
	}

	publicKey := &PublicKey{Length: strconv.Itoa(length), N: n, G: g, N2: n2}
	privateKey := &PrivateKey{Length: strconv.Itoa(length), PublicKey: *publicKey, L: l, U: u}

	return publicKey, privateKey
}

