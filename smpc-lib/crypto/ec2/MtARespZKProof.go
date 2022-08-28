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

// MtARespZKProof GG18 A.3 Respondent ZK Proof for MtA
type MtARespZKProof struct {
	Z    *big.Int
	ZBar *big.Int
	T    *big.Int
	V    *big.Int
	W    *big.Int
	S    *big.Int
	S1   *big.Int
	S2   *big.Int
	T1   *big.Int
	T2   *big.Int
}

// MtARespZKProofProve GG18 A.3 Respondent ZK Proof for MtA 
// This proof is run by Bob (the responder) in the MtA protocol where Bob only proves that x is small (without proving that it is the discrete log of any public value).
// The input for this proof is a Paillier public key (N,G) and two values c1 , c2 ∈ ZN2.
// The Prover knows x ∈ Zq , y ∈ ZN and r ∈ Z*,such that c2 = c1^x*G^y*r^N mod N^2, where q is the order of the DSA group.
// At the end of the protocol the Verifier is convinced of the above and that x ∈ [−q^3 , q^3].
func MtARespZKProofProve(keytype string,x *big.Int, y *big.Int, r *big.Int, c1 *big.Int, c2 *big.Int,publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) *MtARespZKProof {
	q3Ntilde := new(big.Int).Mul(s256.S256(keytype).N3(), ntildeH1H2.Ntilde)
	qNtilde := new(big.Int).Mul(s256.S256(keytype).N1(), ntildeH1H2.Ntilde)

	alpha := random.GetRandomIntFromZn(s256.S256(keytype).N3())
	rho := random.GetRandomIntFromZn(qNtilde)
	rhoBar := random.GetRandomIntFromZn(q3Ntilde)
	sigma := random.GetRandomIntFromZn(qNtilde)
	beta := random.GetRandomIntFromZnStar(publicKey.N)
	gamma := random.GetRandomIntFromZnStar(publicKey.N)
	delta := random.GetRandomIntFromZn(qNtilde)

	z := new(big.Int).Exp(ntildeH1H2.H1, x, ntildeH1H2.Ntilde)
	z = new(big.Int).Mul(z, new(big.Int).Exp(ntildeH1H2.H2, rho, ntildeH1H2.Ntilde))
	z = new(big.Int).Mod(z, ntildeH1H2.Ntilde)

	zBar := new(big.Int).Exp(ntildeH1H2.H1, alpha, ntildeH1H2.Ntilde)
	zBar = new(big.Int).Mul(zBar, new(big.Int).Exp(ntildeH1H2.H2, rhoBar, ntildeH1H2.Ntilde))
	zBar = new(big.Int).Mod(zBar, ntildeH1H2.Ntilde)

	t := new(big.Int).Exp(ntildeH1H2.H1, y, ntildeH1H2.Ntilde)
	t = new(big.Int).Mul(t, new(big.Int).Exp(ntildeH1H2.H2, sigma, ntildeH1H2.Ntilde))
	t = new(big.Int).Mod(t, ntildeH1H2.Ntilde)

	v := new(big.Int).Exp(publicKey.G, gamma, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(beta, publicKey.N, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)
	v = new(big.Int).Mul(v, new(big.Int).Exp(c1, alpha, publicKey.N2))
	v = new(big.Int).Mod(v, publicKey.N2)

	w := new(big.Int).Exp(ntildeH1H2.H1, gamma, ntildeH1H2.Ntilde)
	w = new(big.Int).Mul(w, new(big.Int).Exp(ntildeH1H2.H2, delta, ntildeH1H2.Ntilde))
	w = new(big.Int).Mod(w, ntildeH1H2.Ntilde)

	e := Sha512_256(z,zBar,t,v,w,c1,c2,publicKey.N)
	e = new(big.Int).Mod(e, s256.S256(keytype).N1())

	s := new(big.Int).Exp(r, e, publicKey.N)
	s = new(big.Int).Mul(s, beta)
	s = new(big.Int).Mod(s, publicKey.N)

	s1 := new(big.Int).Mul(e, x)
	s1 = new(big.Int).Add(s1, alpha)

	s2 := new(big.Int).Mul(e, rho)
	s2 = new(big.Int).Add(s2, rhoBar)

	t1 := new(big.Int).Mul(e, y)
	t1 = new(big.Int).Add(t1, gamma)

	t2 := new(big.Int).Mul(e, sigma)
	t2 = new(big.Int).Add(t2, delta)

	mtAZK2Proof := &MtARespZKProof{Z: z, ZBar: zBar, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	return mtAZK2Proof
}

// MtARespZKProofVerify GG18 A.3 Respondent ZK Proof for MtA 
// This proof is run by Bob (the responder) in the MtA protocol where Bob only proves that x is small (without proving that it is the discrete log of any public value).
// The input for this proof is a Paillier public key (N,G) and two values c1 , c2 ∈ ZN2.
// The Prover knows x ∈ Zq , y ∈ ZN and r ∈ Z*,such that c2 = c1^x*G^y*r^N mod N^2, where q is the order of the DSA group.
// At the end of the protocol the Verifier is convinced of the above and that x ∈ [−q^3 , q^3].
// The Verifier checks that s1 ≤ q^3, h1^s1*h2^s2 = z^e*zBar mod Ntilde, h1^t1*h2^t2 = t^e*w mode Ntilde, c1^s1*s^N*G^t1 = c2^e*v mod N^2 
func (mtAZK2Proof *MtARespZKProof) MtARespZKProofVerify(keytype string,c1 *big.Int, c2 *big.Int, publicKey *PublicKey, ntildeH1H2 *NtildeH1H2) bool {
	if c1 == nil || c2 == nil || publicKey == nil || ntildeH1H2 == nil || mtAZK2Proof == nil || mtAZK2Proof.S1 == nil || mtAZK2Proof.Z == nil || mtAZK2Proof.ZBar == nil || mtAZK2Proof.T == nil || mtAZK2Proof.W == nil || mtAZK2Proof.V == nil || mtAZK2Proof.S == nil {
	    return false
	}

	if publicKey.N2.Cmp(new(big.Int).Mul(publicKey.N,publicKey.N)) != 0 {
	    return false
	}

	if publicKey.G.Cmp(new(big.Int).Add(publicKey.N,big.NewInt(1))) != 0 {
	    return false
	}
	
	if mtAZK2Proof.S1.Cmp(s256.S256(keytype).N3()) > 0 {
		return false
	}

	if mtAZK2Proof.Z.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZK2Proof.ZBar.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZK2Proof.T.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZK2Proof.W.Cmp(ntildeH1H2.Ntilde) >= 0 {
	    return false
	}

	if mtAZK2Proof.V.Cmp(publicKey.N2) >= 0 {
	    return false
	}

	if c1.Cmp(publicKey.N2) >= 0 {
	    return false
	}

	if c2.Cmp(publicKey.N2) >= 0 {
	    return false
	}

	if mtAZK2Proof.S.Cmp(publicKey.N) >= 0 {
	    return false
	}

	c1m := new(big.Int).Mod(c1,publicKey.N2)
	c2m := new(big.Int).Mod(c2,publicKey.N2)
	zm := new(big.Int).Mod(mtAZK2Proof.Z,ntildeH1H2.Ntilde)
	zbarm := new(big.Int).Mod(mtAZK2Proof.ZBar,ntildeH1H2.Ntilde)
	tm := new(big.Int).Mod(mtAZK2Proof.T,ntildeH1H2.Ntilde)
	vm := new(big.Int).Mod(mtAZK2Proof.V,publicKey.N2)
	wm := new(big.Int).Mod(mtAZK2Proof.W,ntildeH1H2.Ntilde)
	sm := new(big.Int).Mod(mtAZK2Proof.S,publicKey.N)
	if c1m.Cmp(zero) == 0 || c1m.Cmp(one) == 0 || c2m.Cmp(zero) == 0 || c2m.Cmp(one) == 0 || zm.Cmp(zero) == 0 || zm.Cmp(one) == 0 || zbarm.Cmp(zero) == 0 || zbarm.Cmp(one) == 0 || tm.Cmp(zero) == 0 || tm.Cmp(one) == 0 || vm.Cmp(zero) == 0 || vm.Cmp(one) == 0 || wm.Cmp(zero) == 0 || wm.Cmp(one) == 0 || sm.Cmp(zero) == 0 || sm.Cmp(one) == 0 {
	    return false
	}

	if mtAZK2Proof.S1.Cmp(zero) == 0 || mtAZK2Proof.S1.Cmp(one) == 0 || mtAZK2Proof.S2.Cmp(zero) == 0 || mtAZK2Proof.S2.Cmp(one) == 0 || mtAZK2Proof.T1.Cmp(zero) == 0 || mtAZK2Proof.T1.Cmp(one) == 0 || mtAZK2Proof.T2.Cmp(zero) == 0 || mtAZK2Proof.T2.Cmp(one) == 0 {
	    return false
	}

	//paillier pubkey.G
	G := new(big.Int).Add(publicKey.N,big.NewInt(1))
	//paillier pubkey.N2
	N2 := new(big.Int).Mul(publicKey.N,publicKey.N)

	e := Sha512_256(mtAZK2Proof.Z,mtAZK2Proof.ZBar,mtAZK2Proof.T,mtAZK2Proof.V,mtAZK2Proof.W,c1,c2,publicKey.N)
	e = new(big.Int).Mod(e, s256.S256(keytype).N1())

	s12 := new(big.Int).Exp(ntildeH1H2.H1, mtAZK2Proof.S1, ntildeH1H2.Ntilde)
	s12 = new(big.Int).Mul(s12, new(big.Int).Exp(ntildeH1H2.H2, mtAZK2Proof.S2, ntildeH1H2.Ntilde))
	s12 = new(big.Int).Mod(s12, ntildeH1H2.Ntilde)

	zzbar := new(big.Int).Exp(mtAZK2Proof.Z, e, ntildeH1H2.Ntilde)
	zzbar = new(big.Int).Mul(zzbar, mtAZK2Proof.ZBar)
	zzbar = new(big.Int).Mod(zzbar, ntildeH1H2.Ntilde)

	if s12.Cmp(zzbar) != 0 {
		return false
	}

	h12 := new(big.Int).Exp(ntildeH1H2.H1, mtAZK2Proof.T1, ntildeH1H2.Ntilde)
	h12 = new(big.Int).Mul(h12, new(big.Int).Exp(ntildeH1H2.H2, mtAZK2Proof.T2, ntildeH1H2.Ntilde))
	h12 = new(big.Int).Mod(h12, ntildeH1H2.Ntilde)

	tw := new(big.Int).Exp(mtAZK2Proof.T, e, ntildeH1H2.Ntilde)
	tw = new(big.Int).Mul(tw, mtAZK2Proof.W)
	tw = new(big.Int).Mod(tw, ntildeH1H2.Ntilde)

	if h12.Cmp(tw) != 0 {
		return false
	}

	cs := new(big.Int).Exp(G, mtAZK2Proof.T1, N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(mtAZK2Proof.S, publicKey.N, N2))
	cs = new(big.Int).Mod(cs, N2)
	cs = new(big.Int).Mul(cs, new(big.Int).Exp(c1, mtAZK2Proof.S1, N2))
	cs = new(big.Int).Mod(cs, N2)

	cv := new(big.Int).Exp(c2, e, N2)
	cv = new(big.Int).Mul(cv, mtAZK2Proof.V)
	cv = new(big.Int).Mod(cv, N2)

	if cs.Cmp(cv) != 0 {
		return false
	}

	return true
}

// MarshalJSON marshal MtARespZKProof to json bytes
func (mtAZK2Proof *MtARespZKProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Z    string `json:"Z"`
		ZBar string `json:"ZBar"`
		T    string `json:"T"`
		V    string `json:"V"`
		W    string `json:"W"`
		S    string `json:"S"`
		S1   string `json:"S1"`
		S2   string `json:"S2"`
		T1   string `json:"T1"`
		T2   string `json:"T2"`
	}{
		Z:    fmt.Sprintf("%v", mtAZK2Proof.Z),
		ZBar: fmt.Sprintf("%v", mtAZK2Proof.ZBar),
		T:    fmt.Sprintf("%v", mtAZK2Proof.T),
		V:    fmt.Sprintf("%v", mtAZK2Proof.V),
		W:    fmt.Sprintf("%v", mtAZK2Proof.W),
		S:    fmt.Sprintf("%v", mtAZK2Proof.S),
		S1:   fmt.Sprintf("%v", mtAZK2Proof.S1),
		S2:   fmt.Sprintf("%v", mtAZK2Proof.S2),
		T1:   fmt.Sprintf("%v", mtAZK2Proof.T1),
		T2:   fmt.Sprintf("%v", mtAZK2Proof.T2),
	})
}

// UnmarshalJSON unmarshal raw to MtARespZKProof
func (mtAZK2Proof *MtARespZKProof) UnmarshalJSON(raw []byte) error {
	var proof struct {
		Z    string `json:"Z"`
		ZBar string `json:"ZBar"`
		T    string `json:"T"`
		V    string `json:"V"`
		W    string `json:"W"`
		S    string `json:"S"`
		S1   string `json:"S1"`
		S2   string `json:"S2"`
		T1   string `json:"T1"`
		T2   string `json:"T2"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return err
	}

	mtAZK2Proof.Z, _ = new(big.Int).SetString(proof.Z, 10)
	mtAZK2Proof.ZBar, _ = new(big.Int).SetString(proof.ZBar, 10)
	mtAZK2Proof.T, _ = new(big.Int).SetString(proof.T, 10)
	mtAZK2Proof.V, _ = new(big.Int).SetString(proof.V, 10)
	mtAZK2Proof.W, _ = new(big.Int).SetString(proof.W, 10)
	mtAZK2Proof.S, _ = new(big.Int).SetString(proof.S, 10)
	mtAZK2Proof.S1, _ = new(big.Int).SetString(proof.S1, 10)
	mtAZK2Proof.S2, _ = new(big.Int).SetString(proof.S2, 10)
	mtAZK2Proof.T1, _ = new(big.Int).SetString(proof.T1, 10)
	mtAZK2Proof.T2, _ = new(big.Int).SetString(proof.T2, 10)

	if mtAZK2Proof.Z == nil || mtAZK2Proof.ZBar == nil || mtAZK2Proof.T == nil || mtAZK2Proof.V == nil || mtAZK2Proof.W == nil || mtAZK2Proof.S == nil || mtAZK2Proof.S1 == nil || mtAZK2Proof.S2 == nil || mtAZK2Proof.T1 == nil || mtAZK2Proof.T2 == nil {
	    return errors.New("unmarshal json error")
	}

	return nil
}

