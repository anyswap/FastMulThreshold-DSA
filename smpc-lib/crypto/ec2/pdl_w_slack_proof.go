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
	"math/big"

	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

type (
	PDLwSlackStatement struct {
		CipherText     *big.Int
		PK             *PublicKey
		K1RX 		*big.Int //Q
		K1RY		*big.Int
		Rx		*big.Int //G
		Ry		*big.Int
		H1, H2, NTilde *big.Int
	}

	PDLwSlackWitness struct {
		K1, K1Ra *big.Int // X R
		SK   *PrivateKey
	}

	PDLwSlackProof struct {
		Z  *big.Int
		U1X  *big.Int
		U1Y  *big.Int
		U2, U3,
		S1, S2, S3 *big.Int
	}
)

const (
	PDLwSlackMarshalledParts = 11
)

//------------------------------------------------------------------------------------

// NewPDLwSlackProof new PDLwSlackProof
func NewPDLwSlackProof(wit *PDLwSlackWitness, st *PDLwSlackStatement) *PDLwSlackProof {
    if wit == nil || st == nil {
	return nil
    }

    q3 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
    q3.Mul(q3, secp256k1.S256().N)
    qNTilde := new(big.Int).Mul(secp256k1.S256().N, st.NTilde)
    q3NTilde := new(big.Int).Mul(q3, st.NTilde)

    alpha := random.GetRandomIntFromZn(q3)
    alpha = new(big.Int).Mod(alpha,secp256k1.S256().N)

    nSubOne := new(big.Int).Add(st.PK.N, one)
    tmp := random.GetRandomIntFromZn(nSubOne)
    tmp = new(big.Int).Mod(tmp,secp256k1.S256().N)
    beta := new(big.Int).Add(one,tmp)
    
    rho := random.GetRandomIntFromZn(qNTilde)
    rho = new(big.Int).Mod(rho,secp256k1.S256().N)
    
    gamma := random.GetRandomIntFromZn(q3NTilde)
    gamma = new(big.Int).Mod(gamma,secp256k1.S256().N)

    z := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, wit.K1, rho)
    u1Gx,u1Gy := secp256k1.S256().ScalarMult(st.Rx,st.Ry,alpha.Bytes())
    nOne := new(big.Int).Add(st.PK.N, one)
    u2 := commitmentUnknownOrder(nOne, beta, st.PK.N2, alpha, st.PK.N)
    u3 := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, alpha, gamma)

    e := Sha512_256i(st.Rx, st.Ry, st.K1RX, st.K1RY, st.CipherText, z, u1Gx, u1Gy, u2, u3)
    e = new(big.Int).Mod(e, secp256k1.S256().N)
    if e == nil {
	return nil
    }

    s1 := new(big.Int).Mul(e, wit.K1)
    s3 := new(big.Int).Mul(e, rho)
    s1.Add(s1, alpha)
    s2 := commitmentUnknownOrder(wit.K1Ra, beta, st.PK.N, e, one)
    s3.Add(s3, gamma)

    return &PDLwSlackProof{z, u1Gx, u1Gy, u2, u3, s1, s2, s3}

}

// commitmentUnknownOrder https://github.com/KZen-networks/multi-party-ecdsa/blob/gg20/src/utilities/zk_pdl_with_slack/mod.rs#L175
func commitmentUnknownOrder(h1, h2, NTilde, x, r *big.Int) (com *big.Int) {
    modNTilde := ModInt(NTilde)
	h1X := modNTilde.Exp(h1, x)
	h2R := modNTilde.Exp(h2, r)
	com = modNTilde.Mul(h1X, h2R)
	return
}

// Hash256Sum make a 256 hash
func Hash256Sum(in ...*big.Int) *big.Int {

    	if len(in) == 0 {
	    return nil
	}

	hellomulti := "hello multichain"
	sha3256 := sha3.New256()
	for _,n := range in {
	    sha3256.Write(n.Bytes())
	}
	sha3256.Write([]byte(hellomulti))
	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)
	e = new(big.Int).Mod(e, secp256k1.S256().N)

	return e
}

//----------------------------------------------------------------------------------

// PDLwSlackVerify verify PDLwSlackProof
func PDLwSlackVerify(st *PDLwSlackStatement,p *PDLwSlackProof) bool {
    if st == nil || p == nil {
	return false
    }

    e := Sha512_256i(st.Rx, st.Ry, st.K1RX, st.K1RY, st.CipherText, p.Z, p.U1X, p.U1Y, p.U2, p.U3)
    e = new(big.Int).Mod(e, secp256k1.S256().N)
    
    tmp := new(big.Int).Mod(p.S1,secp256k1.S256().N)
    gS1X,gS1Y := secp256k1.S256().ScalarMult(st.Rx, st.Ry,tmp.Bytes())
    eFeNeg := new(big.Int).Sub(secp256k1.S256().N, e)
    yMinusEX,yMinusEY := secp256k1.S256().ScalarMult(st.K1RX, st.K1RY,eFeNeg.Bytes())
    u1TestX,u1TestY := secp256k1.S256().Add(gS1X,gS1Y,yMinusEX,yMinusEY)
    if !secp256k1.S256().IsOnCurve(u1TestX,u1TestY) {
	return false
    }

    nOne, eNeg := new(big.Int).Add(st.PK.N, one), new(big.Int).Neg(e)
    u2TestTmp := commitmentUnknownOrder(nOne, p.S2, st.PK.N2, p.S1, st.PK.N)
    u2Test := commitmentUnknownOrder(u2TestTmp, st.CipherText, st.PK.N2, one, eNeg)
    u3TestTmp := commitmentUnknownOrder(st.H1, st.H2, st.NTilde, p.S1, p.S3)
    u3Test := commitmentUnknownOrder(u3TestTmp, p.Z, st.NTilde, one, eNeg)

    return p.U1X.Cmp(u1TestX) == 0 &&
    	   p.U1Y.Cmp(u1TestY) == 0 &&
	    p.U2.Cmp(u2Test) == 0 &&
	    p.U3.Cmp(u3Test) == 0

}

//----------------------------------------------------------------------------------

// MarshalJSON marshal PDLwSlackProof to json bytes
func (p *PDLwSlackProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Z string `json:"Z"`
		U1X string `json:"U1X"`
		U1Y string `json:"U1Y"`
		U2 string `json:"U2"`
		U3 string `json:"U3"`
		S1 string `json:"S1"`
		S2 string `json:"S2"`
		S3 string `json:"S3"`
	}{
		Z: fmt.Sprintf("%v", p.Z),
		U1X: fmt.Sprintf("%v", p.U1X),
		U1Y: fmt.Sprintf("%v", p.U1Y),
		U2: fmt.Sprintf("%v", p.U2),
		U3: fmt.Sprintf("%v", p.U3),
		S1: fmt.Sprintf("%v", p.S1),
		S2: fmt.Sprintf("%v", p.S2),
		S3: fmt.Sprintf("%v", p.S3),
	})
}

// UnmarshalJSON unmarshal raw to PDLwSlackProof
func (p *PDLwSlackProof) UnmarshalJSON(raw []byte) error {
	var zk struct {
		Z string `json:"Z"`
		U1X string `json:"U1X"`
		U1Y string `json:"U1Y"`
		U2 string `json:"U2"`
		U3 string `json:"U3"`
		S1 string `json:"S1"`
		S2 string `json:"S2"`
		S3 string `json:"S3"`
	}
	if err := json.Unmarshal(raw, &zk); err != nil {
		return err
	}

	p.Z, _ = new(big.Int).SetString(zk.Z, 10)
	p.U1X, _ = new(big.Int).SetString(zk.U1X, 10)
	p.U1Y, _ = new(big.Int).SetString(zk.U1Y, 10)
	p.U2, _ = new(big.Int).SetString(zk.U2, 10)
	p.U3, _ = new(big.Int).SetString(zk.U3, 10)
	p.S1, _ = new(big.Int).SetString(zk.S1, 10)
	p.S2, _ = new(big.Int).SetString(zk.S2, 10)
	p.S3, _ = new(big.Int).SetString(zk.S3, 10)
	return nil
}


