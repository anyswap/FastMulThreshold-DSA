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

package signing

import (
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"math/big"
)

// Start verify MtAZK2Proof,paillier Decrypt,calc delta1
func (round *round5) Start() error {
	if round.started {
		fmt.Printf("============= round5.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	oldindex := -1
	for k, v := range round.save.IDs {
		if v.Cmp(round.save.CurDNodeID) == 0 {
			oldindex = k
			break
		}
	}

	alpha1 := make([]*big.Int, round.threshold)
	uu1 := make([]*big.Int, round.threshold)

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		u1PaillierPk := round.save.U1PaillierPk[oldindex]
		u1nt := round.save.U1NtildeH1H2[index]
		msg4, _ := round.temp.signRound4Messages[k].(*SignRound4Message)
		rlt111 := msg4.U1u1MtAZK2Proof.MtARespZKProofVerify(round.temp.ukc, msg4.U1KGamma1Cipher, u1PaillierPk, u1nt)
		if !rlt111 {
			return errors.New("verify mkg fail")
		}

		// add for GG18 A.2 Respondent ZK Proof for MtAwc
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
		deCommit := &ec2.Commitment{C: msg1.ComWiC, D: msg3.ComWiD}
		_,xG := deCommit.DeCommit()

		msg41, _ := round.temp.signRound4Messages1[k].(*SignRound4Message1)
		rlt112 := msg41.U1u1MtAZK3Proof.MtAwcRespZKProofVefify(xG,round.temp.ukc, msg41.U1Kw1Cipher, u1PaillierPk, u1nt)
		if !rlt112 {
			return errors.New("verify mkw fail")
		}

		alpha1U1, _ := round.save.U1PaillierSk.Decrypt(msg4.U1KGamma1Cipher)
		alpha1[k] = alpha1U1
		u1U1, _ := round.save.U1PaillierSk.Decrypt(msg41.U1Kw1Cipher)
		uu1[k] = u1U1
	}
	round.temp.alpha1 = alpha1
	round.temp.uu1 = uu1

	delta1 := alpha1[0]
	for i := 0; i < round.threshold; i++ {
		if i == 0 {
			continue
		}
		delta1 = new(big.Int).Add(delta1, alpha1[i])
	}
	for i := 0; i < round.threshold; i++ {
		delta1 = new(big.Int).Add(delta1, round.temp.betaU1[i])
	}
	delta1 = new(big.Int).Mod(delta1, secp256k1.S256().N)
	round.temp.delta1 = delta1

	sigma1 := uu1[0]
	for i := 0; i < round.threshold; i++ {
		if i == 0 {
			continue
		}
		sigma1 = new(big.Int).Add(sigma1, uu1[i])
	}
	for i := 0; i < round.threshold; i++ {
		sigma1 = new(big.Int).Add(sigma1, round.temp.vU1[i])
	}
	sigma1 = new(big.Int).Mod(sigma1, secp256k1.S256().N)
	round.temp.sigma1 = sigma1

	// gg20: calculate T_i = g^sigma_i * h^l_i = sigma_i*G + l_i*h*G
	l1 := random.GetRandomIntFromZn(secp256k1.S256().N)
	hx,hy,err := ec2.CalcHPoint()
	if err != nil {
	    fmt.Printf("calc h point fail, err = %v",err)
	    return err
	}

	l1Gx,l1Gy := secp256k1.S256().ScalarMult(hx,hy,l1.Bytes())
	sigmaGx,sigmaGy := secp256k1.S256().ScalarBaseMult(sigma1.Bytes())
	t1X,t1Y := secp256k1.S256().Add(sigmaGx,sigmaGy,l1Gx,l1Gy)
	// gg20: generate the ZK proof of T_i
	tProof := ec2.TProve(t1X,t1Y,hx,hy,sigma1,l1)
	if tProof == nil {
	    return errors.New("prove Ti proof fail")
	}
	//

	round.temp.t1X = t1X
	round.temp.t1Y = t1Y
	round.temp.l1 = l1

	srm := &SignRound5Message{
		SignRoundMessage: new(SignRoundMessage),
		Delta1:           delta1,
		T1X:		t1X,
		T1Y:		t1Y,
		Tpf:		tProof,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound5Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round5.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.signRound5Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}

	return true, nil
}

// NextRound enter next round
func (round *round5) NextRound() smpc.Round {
	round.started = false
	return &round6{round}
}
