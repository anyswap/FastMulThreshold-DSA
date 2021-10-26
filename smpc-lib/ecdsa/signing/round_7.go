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
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

// Start verify commitment,zkuproof,calc R
func (round *round7) Start() error {
	if round.started {
		fmt.Printf("============= round7.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var GammaGSumx *big.Int
	var GammaGSumy *big.Int
	for k := range round.idsign {
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
		deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
		if !deCommit.Verify() {
			return errors.New("verify commit fail")
		}

		_, u1GammaG := deCommit.DeCommit()
		if !ec2.ZkUVerify(u1GammaG, msg6.U1GammaZKProof) {
			return errors.New("verify zkuproof fail")
		}

		if k == 0 {
			GammaGSumx = u1GammaG[0]
			GammaGSumy = u1GammaG[1]
		}
	}

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
		deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
		_, u1GammaG := deCommit.DeCommit()
		GammaGSumx, GammaGSumy = secp256k1.S256().Add(GammaGSumx, GammaGSumy, u1GammaG[0], u1GammaG[1])
	}
	
	deltaSumInverse := new(big.Int).ModInverse(round.temp.deltaSum, secp256k1.S256().N)
	deltaGammaGx, deltaGammaGy := secp256k1.S256().ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

	// 4. get r = deltaGammaGx
	r := deltaGammaGx
	zero, _ := new(big.Int).SetString("0", 10)
	if r.Cmp(zero) == 0 {
		return errors.New("r == 0")
	}

	if r == nil || deltaGammaGy == nil {
		return errors.New("calc r fail")
	}

	round.temp.deltaGammaGx = deltaGammaGx
	round.temp.deltaGammaGy = deltaGammaGy

	// gg20: compute ZK proof of consistency between R_i and E_i(k_i) 
	bigRK1Gx,bigRK1Gy := secp256k1.S256().ScalarMult(deltaGammaGx,deltaGammaGy,round.temp.u1K.Bytes())

	oldindex := -1
	for k, v := range round.save.IDs {
		if v.Cmp(round.save.CurDNodeID) == 0 {
			oldindex = k
			break
		}
	}

	if oldindex == -1 {
		return errors.New("error old index")
	}

	u1PaillierPk := round.save.U1PaillierPk[oldindex]
	if u1PaillierPk == nil {
		return errors.New("error paillier pk for current node")
	}
	
	u1NT := round.save.U1NtildeH1H2[oldindex]
	if u1NT == nil {
		return errors.New("error ntilde for current node")
	}

	pdlWSlackStatement := &ec2.PDLwSlackStatement{
		PK:         u1PaillierPk,
		CipherText: round.temp.ukc,
		K1RX:	bigRK1Gx,
		K1RY:   bigRK1Gy,
		Rx:     deltaGammaGx,
		Ry:     deltaGammaGy,
		H1:         u1NT.H1,
		H2:         u1NT.H2,
		NTilde:     u1NT.Ntilde,
	}
	pdlWSlackWitness := &ec2.PDLwSlackWitness{
		SK: round.save.U1PaillierSk,
		K1:  round.temp.u1K,
		K1Ra:  round.temp.ukc2,
	}
	pdlWSlackPf := ec2.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)
	if pdlWSlackPf == nil {
	    return errors.New("compute ZK proof of consistency between R_i and E_i(k_i) fail")
	}
	
	srm := &SignRound7Message{
		SignRoundMessage: new(SignRoundMessage),
		K1RX:              bigRK1Gx,
		K1RY:   bigRK1Gy,
		PdlwSlackPf: pdlWSlackPf,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound7Messages[curIndex] = srm
	round.out <- srm
	//

	//round.end <- PrePubData{K1: round.temp.u1K, R: r, Ry: deltaGammaGy, Sigma1: round.temp.sigma1}

	//fmt.Printf("============= round7.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round7) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round7) Update() (bool, error) {
	for j, msg := range round.temp.signRound7Messages {
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
func (round *round7) NextRound() smpc.Round {
	round.started = false
	return &round8{round}
}
