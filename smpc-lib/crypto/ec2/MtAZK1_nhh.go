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

// Package ec2  MPC gg18 algorithm 
package ec2

import (
	"encoding/json"
	"fmt"
	"math/big"

	s256 "github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
)

// MtAZK1Proofnhh mtazk1 zk proof 
type MtAZK1Proofnhh struct {
	Z  *big.Int
	U  *big.Int
	W  *big.Int
	S  *big.Int
	S1 *big.Int
	S2 *big.Int
}

// MtAZK1Provenhh  Generate zero knowledge proof data mtazk1proof_ nhh 
func MtAZK1Provenhh(m *big.Int, r *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) *MtAZK1Proofnhh {
	N3Ntilde := new(big.Int).Mul(s256.S256().N3(), ntildeH1H2.Ntilde)
	NNtilde := new(big.Int).Mul(s256.S256().N, ntildeH1H2.Ntilde)

	alpha := random.GetRandomIntFromZn(s256.S256().N3())
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZn(N3Ntilde)
	rho := random.GetRandomIntFromZn(NNtilde)

	z := new(big.Int).Exp(ntildeH1H2.H1, m, ntildeH1H2.Ntilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(ntildeH1H2.H2, rho, ntildeH1H2.Ntilde))
	z = new(big.Int).Mod(z, ntildeH1H2.Ntilde)

	u := new(big.Int).Exp(publicKey.G, alpha, publicKey.N2)
	u = new(big.Int).Mul(u, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	u = new(big.Int).Mod(u, publicKey.N2)

	w := new(big.Int).Exp(ntildeH1H2.H1, alpha, ntildeH1H2.Ntilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(ntildeH1H2.H2, gamma, ntildeH1H2.Ntilde))
	w = new(big.Int).Mod(w, ntildeH1H2.Ntilde)

	sha3256 := sha3.New256()
	sha3256.Write(z.Bytes())
	sha3256.Write(u.Bytes())
	sha3256.Write(w.Bytes())

	sha3256.Write([]byte("hello multichain"))

	sha3256.Write(publicKey.N.Bytes()) //MtAZK1 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, s256.S256().N)

	s := new(big.Int).Exp(r, e, publicKey.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, publicKey.N)

	s1 := new(big.Int).Mul(e, m)
	s1 = new(big.Int).Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, gamma)

	mtAZKProof := &MtAZK1Proofnhh{Z: z, U: u, W: w, S: s, S1: s1, S2: s2}
	return mtAZKProof
}

// MtAZK1Verifynhh  Verify zero knowledge proof data mtazk1proof_ nhh 
func (mtAZKProof *MtAZK1Proofnhh) MtAZK1Verifynhh(c *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) bool {
	if mtAZKProof.S1.Cmp(s256.S256().N3()) > 0 {
		return false
	}

	if mtAZKProof.Z.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZKProof.W.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZKProof.U.Cmp(publicKey.N2) >= 0 {
	    return false
	}

	if c.Cmp(publicKey.N2) >= 0 {
	    return false
	}

	if mtAZKProof.S.Cmp(publicKey.N) >= 0 {
	    return false
	}

	zm := new(big.Int).Mod(mtAZKProof.Z,ntildeH1H2.Ntilde)
	wm := new(big.Int).Mod(mtAZKProof.W,ntildeH1H2.Ntilde)
	um := new(big.Int).Mod(mtAZKProof.U,publicKey.N2)
	cm := new(big.Int).Mod(c,publicKey.N2)
	sm := new(big.Int).Mod(mtAZKProof.S,publicKey.N)
	if zm.Cmp(zero) == 0 || zm.Cmp(one) == 0 || wm.Cmp(zero) == 0 || wm.Cmp(one) == 0 || um.Cmp(zero) == 0 || um.Cmp(one) == 0 || cm.Cmp(zero) == 0 || cm.Cmp(one) == 0 || sm.Cmp(zero) == 0 || sm.Cmp(one) == 0 {
	    return false
	}

	if mtAZKProof.S1.Cmp(zero) == 0 || mtAZKProof.S1.Cmp(one) == 0 {
	    return false
	}

	if mtAZKProof.S2.Cmp(zero) == 0 || mtAZKProof.S2.Cmp(one) == 0 {
	    return false
	}

	sha3256 := sha3.New256()
	sha3256.Write(mtAZKProof.Z.Bytes())
	sha3256.Write(mtAZKProof.U.Bytes())
	sha3256.Write(mtAZKProof.W.Bytes())

	sha3256.Write([]byte("hello multichain"))
	sha3256.Write(publicKey.N.Bytes()) //MtAZK1 question 2

	eBytes := sha3256.Sum(nil)
	e := new(big.Int).SetBytes(eBytes)

	e = new(big.Int).Mod(e, s256.S256().N)

	u2 := new(big.Int).Exp(publicKey.G, mtAZKProof.S1, publicKey.N2)
	u2 = new(big.Int).Mul(u2, new(big.Int).Exp(mtAZKProof.S, publicKey.N, publicKey.N2))
	u2 = new(big.Int).Mod(u2, publicKey.N2)
	// *****
	ce := new(big.Int).Exp(c, e, publicKey.N2)
	ceU := new(big.Int).Mul(ce, mtAZKProof.U)
	ceU = new(big.Int).Mod(ceU, publicKey.N2)

	if ceU.Cmp(u2) != 0 {
		return false
	}

	w2 := new(big.Int).Exp(ntildeH1H2.H1, mtAZKProof.S1, ntildeH1H2.Ntilde)
	w2 = new(big.Int).Mul(w2, new(big.Int).Exp(ntildeH1H2.H2, mtAZKProof.S2, ntildeH1H2.Ntilde))
	w2 = new(big.Int).Mod(w2, ntildeH1H2.Ntilde)
	// *****
	ze := new(big.Int).Exp(mtAZKProof.Z, e, ntildeH1H2.Ntilde)
	zeW := new(big.Int).Mul(mtAZKProof.W, ze)
	zeW = new(big.Int).Mod(zeW, ntildeH1H2.Ntilde)

	if zeW.Cmp(w2) != 0 {
		return false
	}

	return true
}

// MarshalJSON marshal MtAZK1Proofnhh to json bytes
func (mtAZKProof *MtAZK1Proofnhh) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Z  string `json:"Z"`
		U  string `json:"U"`
		W  string `json:"W"`
		S  string `json:"S"`
		S1 string `json:"S1"`
		S2 string `json:"S2"`
	}{
		Z:  fmt.Sprintf("%v", mtAZKProof.Z),
		U:  fmt.Sprintf("%v", mtAZKProof.U),
		W:  fmt.Sprintf("%v", mtAZKProof.W),
		S:  fmt.Sprintf("%v", mtAZKProof.S),
		S1: fmt.Sprintf("%v", mtAZKProof.S1),
		S2: fmt.Sprintf("%v", mtAZKProof.S2),
	})
}

// UnmarshalJSON unmarshal raw to MtAZK1Proofnhh
func (mtAZKProof *MtAZK1Proofnhh) UnmarshalJSON(raw []byte) error {
	var proof struct {
		Z  string `json:"Z"`
		U  string `json:"U"`
		W  string `json:"W"`
		S  string `json:"S"`
		S1 string `json:"S1"`
		S2 string `json:"S2"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return err
	}

	mtAZKProof.Z, _ = new(big.Int).SetString(proof.Z, 10)
	mtAZKProof.U, _ = new(big.Int).SetString(proof.U, 10)
	mtAZKProof.W, _ = new(big.Int).SetString(proof.W, 10)
	mtAZKProof.S, _ = new(big.Int).SetString(proof.S, 10)
	mtAZKProof.S1, _ = new(big.Int).SetString(proof.S1, 10)
	mtAZKProof.S2, _ = new(big.Int).SetString(proof.S2, 10)
	return nil
}
