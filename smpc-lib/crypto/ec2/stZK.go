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
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// ZK proof for knowledge of sigma_i, l_i such that S_i = R^sigma_i, T_i = g^sigma_i h^l_i (GG20)
type STProof struct {
    AlphaX *big.Int
    AlphaY *big.Int
    BetaX *big.Int
    BetaY *big.Int
    T     *big.Int
    U     *big.Int
}

//------------------------------------------------------------------------------------

// NewSTProof new STProof
func NewSTProof(T1X *big.Int,T1Y *big.Int,S1X *big.Int,S1Y *big.Int,Rx *big.Int,Ry *big.Int,hGx *big.Int,hGy *big.Int,sigma1 *big.Int,l1 *big.Int) *STProof {
    if T1X == nil || T1Y == nil || S1X == nil || S1Y == nil || Rx == nil || Ry == nil || hGx == nil || hGy == nil || sigma1 == nil || l1 == nil {
	return nil
    }
    
    Gx,Gy := secp256k1.S256().ScalarBaseMult(one.Bytes())
    a := random.GetRandomIntFromZn(secp256k1.S256().N)
    b := random.GetRandomIntFromZn(secp256k1.S256().N)
    alphax,alphay := secp256k1.S256().ScalarMult(Rx,Ry,a.Bytes())
    aGx,aGy := secp256k1.S256().ScalarBaseMult(a.Bytes())
    bHGx,bHGy := secp256k1.S256().ScalarMult(hGx,hGy,b.Bytes())
    betaX,betaY := secp256k1.S256().Add(aGx,aGy,bHGx,bHGy)
    
    e := Sha512_256(T1X, T1Y, S1X,S1Y,Rx,Ry,hGx, hGy, Gx, Gy, alphax, alphay, betaX, betaY)
    e = new(big.Int).Mod(e, secp256k1.S256().N)

    t, u := calculateTAndU(secp256k1.S256().N, a, e, sigma1, b, l1)
    
    return &STProof{AlphaX: alphax, AlphaY:alphay, BetaX: betaX, BetaY:betaY, T: t, U: u}
}

func STVerify(S1X *big.Int,S1Y *big.Int,T1X *big.Int,T1Y *big.Int,Rx *big.Int,Ry *big.Int,hGx *big.Int,hGy *big.Int,stpf *STProof) bool {
    if S1X == nil || S1Y == nil || T1X == nil || T1Y == nil || Rx == nil || Ry == nil || hGx == nil || hGy == nil || stpf == nil {
	return false
    }
    
    // Check whether the point is on the curve
    var tmp = []*big.Int{S1X,S1Y,T1X,T1Y,Rx,Ry,hGx,hGy,stpf.AlphaX,stpf.AlphaY,stpf.BetaX,stpf.BetaY}
    if !checkPointOnCurve(tmp) {
	    return false
    }

    if smpc.IsInfinityPoint(S1X,S1Y) || smpc.IsInfinityPoint(T1X,T1Y) || smpc.IsInfinityPoint(Rx,Ry) || smpc.IsInfinityPoint(hGx,hGy) || smpc.IsInfinityPoint(stpf.AlphaX,stpf.AlphaY) || smpc.IsInfinityPoint(stpf.BetaX, stpf.BetaY) {
	return false
    }

    mt := new(big.Int).Mod(stpf.T,secp256k1.S256().N)
    mu := new(big.Int).Mod(stpf.U,secp256k1.S256().N)
    if mt.Cmp(big.NewInt(0)) == 0 || mt.Cmp(big.NewInt(1)) == 0 || mu.Cmp(big.NewInt(0)) == 0 || mu.Cmp(big.NewInt(1)) == 0 {
	return false
    }

    Gx,Gy := secp256k1.S256().ScalarBaseMult(one.Bytes())
    e := Sha512_256(T1X, T1Y, S1X,S1Y,Rx,Ry,hGx, hGy, Gx, Gy, stpf.AlphaX, stpf.AlphaY, stpf.BetaX, stpf.BetaY)
    e = new(big.Int).Mod(e, secp256k1.S256().N)
    
    tRx,tRy := secp256k1.S256().ScalarMult(Rx,Ry,stpf.T.Bytes())
    eSx,eSy := secp256k1.S256().ScalarMult(S1X,S1Y,e.Bytes())
    aScx,aScy := secp256k1.S256().Add(stpf.AlphaX,stpf.AlphaY,eSx,eSy)
    if tRx.Cmp(aScx) != 0 || tRy.Cmp(aScy) != 0 {
	return false
    }
    
    tGx,tGy := secp256k1.S256().ScalarBaseMult(stpf.T.Bytes())
    uHGx,uHGy := secp256k1.S256().ScalarMult(hGx,hGy,stpf.U.Bytes())
    eT1x,eT1y := secp256k1.S256().ScalarMult(T1X,T1Y,e.Bytes())
    tGuHx,tGuHy := secp256k1.S256().Add(tGx,tGy,uHGx,uHGy)
    betaTx,betaTy := secp256k1.S256().Add(stpf.BetaX,stpf.BetaY,eT1x,eT1y)
    if betaTx.Cmp(tGuHx) != 0 || betaTy.Cmp(tGuHy) != 0 {
	return false
    }

    return true
}

func calculateTAndU(q *big.Int, a *big.Int, e *big.Int, sigma1 *big.Int, b *big.Int, l1 *big.Int) (t *big.Int, u *big.Int) {
    	if q == nil || a == nil || e == nil || sigma1 == nil || b == nil || l1 == nil {
	    return
	}

	modQ := ModInt(q)
	t = modQ.Add(a, new(big.Int).Mul(e, sigma1))
	u = modQ.Add(b, new(big.Int).Mul(e, l1))
	return
}

//----------------------------------------------------------------------------------

// MarshalJSON marshal STProof to json bytes
func (stpf *STProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AlphaX string `json:"AlphaX"`
		AlphaY string `json:"AlphaY"`
		BetaX string `json:"BetaX"`
		BetaY string `json:"BetaY"`
		T string `json:"T"`
		U string `json:"U"`
	}{
		AlphaX: fmt.Sprintf("%v", stpf.AlphaX),
		AlphaY: fmt.Sprintf("%v", stpf.AlphaY),
		BetaX: fmt.Sprintf("%v", stpf.BetaX),
		BetaY: fmt.Sprintf("%v", stpf.BetaY),
		T: fmt.Sprintf("%v", stpf.T),
		U: fmt.Sprintf("%v", stpf.U),
	})
}

// UnmarshalJSON unmarshal raw to STProof
func (stpf *STProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		AlphaX string `json:"AlphaX"`
		AlphaY string `json:"AlphaY"`
		BetaX string `json:"BetaX"`
		BetaY string `json:"BetaY"`
		T string `json:"T"`
		U string `json:"U"`
	}

	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	stpf.AlphaX, _ = new(big.Int).SetString(zk.AlphaX, 10)
	stpf.AlphaY, _ = new(big.Int).SetString(zk.AlphaY, 10)
	stpf.BetaX, _ = new(big.Int).SetString(zk.BetaX, 10)
	stpf.BetaY, _ = new(big.Int).SetString(zk.BetaY, 10)
	stpf.T, _ = new(big.Int).SetString(zk.T, 10)
	stpf.U, _ = new(big.Int).SetString(zk.U, 10)

	if stpf.AlphaX == nil || stpf.AlphaY == nil || stpf.BetaX == nil || stpf.BetaY == nil || stpf.T == nil || stpf.U == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}


