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
	"crypto/sha256"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// ZK proof of knowledge of sigma_i, l_i such that T_i = g^sigma_i, h^l_i (GG20)
type TProof struct {
	AlphaX *big.Int
	AlphaY *big.Int
	T     *big.Int
	U     *big.Int
}

//------------------------------------------------------------------------------------

// CalcHPoint returns a shared point of unknown discrete logarithm for the curve
// Mimics the KZen-networks/curv impl: https://git.io/JfwSa
// Not so efficient due to 3x sha256 but it's only used once during a signing round.
func CalcHPoint() (*big.Int,*big.Int,error) {
    minRounds := 3 // minimum to generate a curve point for secp256k1
    bz := secp256k1.S256().Marshal(secp256k1.S256().Gx,secp256k1.S256().Gy)

    var hx *big.Int
    var hy *big.Int
    for i := 0; i < minRounds || (hx == nil && hy == nil); i++ {
	    if i >= 10 {
		return nil,nil,errors.New("too many rounds (max: 10)")
	    }
	    sum := sha256.Sum256(bz)
	    bz = sum[:]
	    if i >= minRounds-1 {
		    hx,hy, _ = decompressPoint(new(big.Int).SetBytes(bz), 0x2)
	    }
    }

    return hx,hy,nil
}

func decompressPoint(x *big.Int, sign byte) (*big.Int,*big.Int, error) {
	params := secp256k1.S256().Params()

	// secp256k1: y^2 = x^3 + 7
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	y2 := x3.Add(x3, big.NewInt(7))

	// find the sq root mod P
	y := new(big.Int).ModSqrt(y2,params.P)
	if y == nil {
	    return nil,nil,errors.New("invalid point")
	}
	if y.Bit(0) != uint(sign)&1 {
	    i := new(big.Int)
	    i.Neg(y)
	    y = new(big.Int).Mod(i,params.P)
	}

	return x,y,nil
}

//---------------------------------------------------------------------------------

// TProve create T1 Prove
func TProve(t1X *big.Int, t1Y *big.Int,  hx *big.Int, hy *big.Int, sigma1 *big.Int,l1 *big.Int) *TProof {
	if t1X == nil || t1Y == nil || hx == nil || hy == nil || sigma1 == nil || l1 == nil {
	    return nil
	}

	a := random.GetRandomIntFromZn(secp256k1.S256().N)
	b := random.GetRandomIntFromZn(secp256k1.S256().N)

	aGx,aGy := secp256k1.S256().ScalarBaseMult(a.Bytes())
	bHx,bHy := secp256k1.S256().ScalarMult(hx,hy,b.Bytes())
	alphaX,alphaY := secp256k1.S256().Add(aGx,aGy,bHx,bHy)

	Gx,Gy := secp256k1.S256().ScalarBaseMult(one.Bytes())
	e := Sha512_256i(t1X,t1Y,hx,hy,Gx,Gy,alphaX,alphaY)
	e = new(big.Int).Mod(e, secp256k1.S256().N)

	t := new(big.Int).Add(a, new(big.Int).Mul(e, sigma1))
	t = new(big.Int).Mod(t, secp256k1.S256().N)
	u := new(big.Int).Add(b, new(big.Int).Mul(e, l1))
	u = new(big.Int).Mod(u, secp256k1.S256().N)
	return &TProof{AlphaX: alphaX,AlphaY: alphaY,T: t,U: u}
}

// TVerify verify TProof
func TVerify(t1X *big.Int, t1Y *big.Int,  hx *big.Int, hy *big.Int, proof *TProof) bool {

	if t1X == nil || t1Y == nil || hx == nil || hy == nil || proof == nil {
	    return false 
	}

    // Check whether the point is on the curve
    var tmp = []*big.Int{proof.AlphaX,proof.AlphaY,t1X,t1Y,hx,hy}
    if !checkPointOnCurve(tmp) {
	    return false
    }

    if smpc.IsInfinityPoint(proof.AlphaX,proof.AlphaY) || smpc.IsInfinityPoint(t1X,t1Y) || smpc.IsInfinityPoint(hx,hy) {
	return false
    }

    mt := new(big.Int).Mod(proof.T,secp256k1.S256().N)
    mu := new(big.Int).Mod(proof.U,secp256k1.S256().N)
    if mt.Cmp(big.NewInt(0)) == 0 || mt.Cmp(big.NewInt(1)) == 0 || mu.Cmp(big.NewInt(0)) == 0 || mu.Cmp(big.NewInt(1)) == 0 {
	return false
    }

	Gx,Gy := secp256k1.S256().ScalarBaseMult(one.Bytes())
	e := Sha512_256i(t1X,t1Y,hx,hy,Gx,Gy,proof.AlphaX,proof.AlphaY)
	e = new(big.Int).Mod(e, secp256k1.S256().N)

	tGx,tGy := secp256k1.S256().ScalarBaseMult(proof.T.Bytes())
	uHx,uHy := secp256k1.S256().ScalarMult(hx,hy,proof.U.Bytes())
	tGuX,tGuY := secp256k1.S256().Add(tGx,tGy,uHx,uHy)

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


