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

package ec2

import (
	"encoding/json"
	"fmt"
	"errors"
	"math/big"

	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

// ZK proof of knowledge of sigma_i, l_i such that T_i = g^sigma_i, h^l_i (GG20)
type TProof struct {
	AlphaX *big.Int
	AlphaY *big.Int
	T     *big.Int
	U     *big.Int
}

//------------------------------------------------------------------------------------

// TProve create T1 Prove
func TProve(t1X *big.Int, t1Y *big.Int,  Gx *big.Int, Gy *big.Int, sigma1 *big.Int,l1 *big.Int) *TProof {
	if t1X == nil || t1Y == nil || Gx == nil || Gy == nil || sigma1 == nil || l1 == nil {
	    return nil
	}

	a := random.GetRandomIntFromZn(secp256k1.S256().N)
	b := random.GetRandomIntFromZn(secp256k1.S256().N)

	aGx,aGy := secp256k1.S256().ScalarBaseMult(a.Bytes())
	bGx,bGy := secp256k1.S256().ScalarMult(Gx,Gy,b.Bytes())
	alphaX,alphaY := secp256k1.S256().Add(aGx,aGy,bGx,bGy)

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(t1X.Bytes())
	sha3256.Write(t1Y.Bytes())
	sha3256.Write(Gx.Bytes())
	sha3256.Write(Gy.Bytes())
	sha3256.Write(alphaX.Bytes())
	sha3256.Write(alphaY.Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)
	e = new(big.Int).Mod(e, secp256k1.S256().N)

	t := new(big.Int).Add(a, new(big.Int).Mul(e, sigma1))
	t = new(big.Int).Mod(t, secp256k1.S256().N)
	u := new(big.Int).Add(b, new(big.Int).Mul(e, l1))
	u = new(big.Int).Mod(u, secp256k1.S256().N)
	return &TProof{AlphaX: alphaX,AlphaY: alphaY,T: t,U: u}
}

// TVerify verify TProof
func TVerify(t1X *big.Int, t1Y *big.Int,  Gx *big.Int, Gy *big.Int, proof *TProof) bool {

	if t1X == nil || t1Y == nil || Gx == nil || Gy == nil || proof == nil {
	    return false 
	}

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(t1X.Bytes())
	sha3256.Write(t1Y.Bytes())
	sha3256.Write(Gx.Bytes())
	sha3256.Write(Gy.Bytes())
	sha3256.Write(proof.AlphaX.Bytes())
	sha3256.Write(proof.AlphaY.Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)
	e = new(big.Int).Mod(e, secp256k1.S256().N)

	tGx,tGy := secp256k1.S256().ScalarBaseMult(proof.T.Bytes())
	uGx,uGy := secp256k1.S256().ScalarMult(Gx,Gy,proof.U.Bytes())
	tGuX,tGuY := secp256k1.S256().Add(tGx,tGy,uGx,uGy)

	et1X,et1Y := secp256k1.S256().ScalarMult(t1X,t1Y,e.Bytes())
	ateX,ateY := secp256k1.S256().Add(proof.AlphaX,proof.AlphaY,et1X,et1Y)
	
	if tGuX.Cmp(ateX) != 0 || tGuY.Cmp(ateY) != 0 {
		return false
	}
	
	return true
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal TProof to json bytes
func (tpf *TProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AlphaX string `json:"AlphaX"`
		AlphaY string `json:"AlphaY"`
		T string `json:"T"`
		U string `json:"U"`
	}{
		AlphaX: fmt.Sprintf("%v", tpf.AlphaX),
		AlphaY: fmt.Sprintf("%v", tpf.AlphaY),
		T: fmt.Sprintf("%v", tpf.T),
		U: fmt.Sprintf("%v", tpf.U),
	})
}

// UnmarshalJSON unmarshal raw to TProof
func (tpf *TProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		AlphaX string `json:"AlphaX"`
		AlphaY string `json:"AlphaY"`
		T string `json:"T"`
		U string `json:"U"`
	}
	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	tpf.AlphaX, _ = new(big.Int).SetString(zk.AlphaX, 10)
	tpf.AlphaY, _ = new(big.Int).SetString(zk.AlphaY, 10)
	tpf.T, _ = new(big.Int).SetString(zk.T, 10)
	tpf.U, _ = new(big.Int).SetString(zk.U, 10)

	if tpf.AlphaX == nil || tpf.AlphaY == nil || tpf.T == nil || tpf.U == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}


