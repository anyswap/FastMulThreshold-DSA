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
	"fmt"
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

// ZkUProof zku proof
type ZkUProof struct {
	E *big.Int
	S *big.Int
}

// ZkABProof zkab proof
type ZkABProof struct {
	Alpha []*big.Int
	Beta  []*big.Int
	T     *big.Int
	U     *big.Int
}

//------------------------------------------------------------------------------------

// ZkUProve create ZkUProof
func ZkUProve(u *big.Int) *ZkUProof {
	r := random.GetRandomIntFromZn(s256.S256().N)
	rGx, rGy := s256.S256().ScalarBaseMult(r.Bytes())
	uGx, uGy := s256.S256().ScalarBaseMult(u.Bytes())

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write(uGx.Bytes())
	sha3256.Write(uGy.Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	s := new(big.Int).Mul(e, u)
	s = new(big.Int).Add(r, s)
	s = new(big.Int).Mod(s, s256.S256().N)

	zkUProof := &ZkUProof{E: e, S: s}
	return zkUProof
}

// ZkUVerify verify ZkUProof
func ZkUVerify(uG []*big.Int, zkUProof *ZkUProof) bool {
	sGx, sGy := s256.S256().ScalarBaseMult(zkUProof.S.Bytes())

	minusE := new(big.Int).Mul(big.NewInt(-1), zkUProof.E)
	minusE = new(big.Int).Mod(minusE, s256.S256().N)

	eUx, eUy := s256.S256().ScalarMult(uG[0], uG[1], minusE.Bytes())
	rGx, rGy := s256.S256().Add(sGx, sGy, eUx, eUy)

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(rGx.Bytes())
	sha3256.Write(rGy.Bytes())
	sha3256.Write(uG[0].Bytes())
	sha3256.Write(uG[1].Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)

	e := new(big.Int).SetBytes(eBytes)

	if e.Cmp(zkUProof.E) == 0 {
		return true
	}
	
	return false
}

//-----------------------------------------------------------------------------------------

// ZkABProve create ZkABProof 
func ZkABProve(a *big.Int, b *big.Int, s *big.Int, R []*big.Int) *ZkABProof {
	ra := random.GetRandomIntFromZn(s256.S256().N)
	rb := random.GetRandomIntFromZn(s256.S256().N)

	alphax, alphay := s256.S256().ScalarMult(R[0], R[1], ra.Bytes())
	rbGx, rbGy := s256.S256().ScalarBaseMult(rb.Bytes())
	alphax, alphay = s256.S256().Add(alphax, alphay, rbGx, rbGy)

	aGx, aGy := s256.S256().ScalarBaseMult(a.Bytes())
	betax, betay := s256.S256().ScalarMult(aGx, aGy, rb.Bytes())

	bAx, bAy := s256.S256().ScalarMult(aGx, aGy, b.Bytes())

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(alphax.Bytes())
	sha3256.Write(alphay.Bytes())
	sha3256.Write(betax.Bytes())
	sha3256.Write(betay.Bytes())

	sha3256.Write(aGx.Bytes())
	sha3256.Write(aGy.Bytes())
	sha3256.Write(bAx.Bytes())
	sha3256.Write(bAy.Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	t := new(big.Int).Mul(e, s)
	t = new(big.Int).Add(t, ra)
	t = new(big.Int).Mod(t, s256.S256().N)

	u := new(big.Int).Mul(e, b)
	u = new(big.Int).Add(u, rb)
	u = new(big.Int).Mod(u, s256.S256().N)

	zkABProof := &ZkABProof{Alpha: []*big.Int{alphax, alphay}, Beta: []*big.Int{betax, betay}, T: t, U: u}
	return zkABProof
}

// ZkABVerify verify zkABProof
func ZkABVerify(A []*big.Int, B []*big.Int, V []*big.Int, R []*big.Int, zkABProof *ZkABProof) bool {

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	sha3256.Write(zkABProof.Alpha[0].Bytes())
	sha3256.Write(zkABProof.Alpha[1].Bytes())
	sha3256.Write(zkABProof.Beta[0].Bytes())
	sha3256.Write(zkABProof.Beta[1].Bytes())

	sha3256.Write(A[0].Bytes())
	sha3256.Write(A[1].Bytes())
	sha3256.Write(B[0].Bytes())
	sha3256.Write(B[1].Bytes())
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	RtGux, RtGuy := s256.S256().ScalarMult(R[0], R[1], zkABProof.T.Bytes())
	Gux, Guy := s256.S256().ScalarBaseMult(zkABProof.U.Bytes())
	RtGux, RtGuy = s256.S256().Add(RtGux, RtGuy, Gux, Guy)

	alphaVex, alphaVey := s256.S256().ScalarMult(V[0], V[1], e.Bytes())
	alphaVex, alphaVey = s256.S256().Add(alphaVex, alphaVey, zkABProof.Alpha[0], zkABProof.Alpha[1])

	if RtGux.Cmp(alphaVex) != 0 {
		return false
	}

	if RtGuy.Cmp(alphaVey) != 0 {
		return false
	}

	Aux, Auy := s256.S256().ScalarMult(A[0], A[1], zkABProof.U.Bytes())

	betaBex, betaBey := s256.S256().ScalarMult(B[0], B[1], e.Bytes())
	betaBex, betaBey = s256.S256().Add(betaBex, betaBey, zkABProof.Beta[0], zkABProof.Beta[1])

	if Aux.Cmp(betaBex) != 0 {
		return false
	}

	if Auy.Cmp(betaBey) != 0 {
		return false
	}

	return true
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal ZkUProof to json bytes
func (zku *ZkUProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		E string `json:"E"`
		S string `json:"S"`
	}{
		E: fmt.Sprintf("%v", zku.E),
		S: fmt.Sprintf("%v", zku.S),
	})
}

// UnmarshalJSON unmarshal raw to ZkUProof
func (zku *ZkUProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		E string `json:"E"`
		S string `json:"S"`
	}
	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	zku.E, _ = new(big.Int).SetString(zk.E, 10)
	zku.S, _ = new(big.Int).SetString(zk.S, 10)
	return nil
}
