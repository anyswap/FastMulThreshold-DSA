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
	"errors"
	"math/big"

	s256 "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
)

//-------------------------------------------------------------------------------

// ZkUProof the ZK that he knows u using Schnorr’s protocol
type ZkUProof struct {
	E *big.Int
	S *big.Int
}

// ZkUProve create ZkUProof
func ZkUProve(keytype string,u *big.Int) *ZkUProof {
    	// R = r*G
	r := random.GetRandomIntFromZn(s256.S256(keytype).N1())
	rGx, rGy := s256.S256(keytype).ScalarBaseMult(r.Bytes())

	// U = u*G
	uGx, uGy := s256.S256(keytype).ScalarBaseMult(u.Bytes())

	// e = HASH(R||U)
	e := Sha512_256(rGx,rGy,uGx,uGy)

	// s = r + e*u mod q
	s := new(big.Int).Mul(e, u)
	s = new(big.Int).Add(r, s)
	s = new(big.Int).Mod(s, s256.S256(keytype).N1())

	// send (U,e,s) to verifier
	zkUProof := &ZkUProof{E: e, S: s}
	return zkUProof
}

// ZkUVerify verify ZkUProof
func ZkUVerify(keytype string,uG []*big.Int, zkUProof *ZkUProof) bool {
    	if uG == nil || len(uG) == 0 || zkUProof == nil || zkUProof.E == nil || zkUProof.S == nil {
	    return false
	}

	// Check whether the point is on the curve
	if !checkPointOnCurve(keytype,uG) {
		return false
	}

	// s*G
	sGx, sGy := s256.S256(keytype).ScalarBaseMult(zkUProof.S.Bytes())

	// -e*U
	minusE := new(big.Int).Mul(big.NewInt(-1), zkUProof.E)
	minusE = new(big.Int).Mod(minusE, s256.S256(keytype).N1())
	eUx, eUy := s256.S256(keytype).ScalarMult(uG[0], uG[1], minusE.Bytes())

	// R = s*G - eU
	rGx, rGy := s256.S256(keytype).Add(sGx, sGy, eUx, eUy)

	// HASH(R||U)
	e := Sha512_256(rGx,rGy,uG[0],uG[1])

	// check HASH(R||U) == e ??
	if e.Cmp(zkUProof.E) == 0 {
		return true
	}
	
	return false
}

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

	if zku.E == nil || zku.S == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}

//------------------------------------------------------------------------------------

// ZkXiProof the ZK that he knows xi using Schnorr’s protocol
type ZkXiProof struct {
	E *big.Int
	S *big.Int
}

// ZkXiProve create ZkXiProof
func ZkXiProve(keytype string,sku1 *big.Int) *ZkXiProof {
    	// R = r*G
	r := random.GetRandomIntFromZn(s256.S256(keytype).N1())
	rGx, rGy := s256.S256(keytype).ScalarBaseMult(r.Bytes())

	// X = x*G
	xGx, xGy := s256.S256(keytype).ScalarBaseMult(sku1.Bytes())

	// e = HASH(R||X)
	e := Sha512_256(rGx,rGy,xGx,xGy)

	// s = r + e*x
	s := new(big.Int).Mul(e, sku1)
	s = new(big.Int).Add(r, s)
	s = new(big.Int).Mod(s, s256.S256(keytype).N1())

	// send (X,e,s) to verifier
	zkxiProof := &ZkXiProof{E: e, S: s}
	return zkxiProof
}

// ZkXiVerify verify ZkXiProof
func ZkXiVerify(keytype string,xiG []*big.Int, zkXiProof *ZkXiProof) bool {
	if xiG == nil || len(xiG) == 0 || zkXiProof == nil || zkXiProof.E == nil || zkXiProof.S == nil {
	    return false
	}

	// Check whether the point is on the curve
	if !checkPointOnCurve(keytype,xiG) {
		return false
	}

	// s*G
	sGx, sGy := s256.S256(keytype).ScalarBaseMult(zkXiProof.S.Bytes())

	// -e*X
	minusE := new(big.Int).Mul(big.NewInt(-1), zkXiProof.E)
	minusE = new(big.Int).Mod(minusE, s256.S256(keytype).N1())
	eUx, eUy := s256.S256(keytype).ScalarMult(xiG[0],xiG[1], minusE.Bytes())

	// R = s*G - e*X
	rGx, rGy := s256.S256(keytype).Add(sGx, sGy, eUx, eUy)

	// HASH(R||X)
	e := Sha512_256(rGx,rGy,xiG[0],xiG[1])

	// check HASH(R||X) == e ??
	if e.Cmp(zkXiProof.E) == 0 {
		return true
	}

	return false
}

// MarshalJSON marshal ZkXiProof to json bytes
func (zkx *ZkXiProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		E string `json:"E"`
		S string `json:"S"`
	}{
		E: fmt.Sprintf("%v", zkx.E),
		S: fmt.Sprintf("%v", zkx.S),
	})
}

// UnmarshalJSON unmarshal raw to ZkXiProof
func (zkx *ZkXiProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		E string `json:"E"`
		S string `json:"S"`
	}
	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	zkx.E, _ = new(big.Int).SetString(zk.E, 10)
	zkx.S, _ = new(big.Int).SetString(zk.S, 10)

	if zkx.E == nil || zkx.S == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}


