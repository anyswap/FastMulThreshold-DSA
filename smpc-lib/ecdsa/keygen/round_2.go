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

package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

const (
	paillierBitsLen = 2048
)

// Start send vss data to corresponding peer
func (round *round2) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIDs()
	if err != nil {
		return err
	}
	round.Save.IDs = ids
	round.Save.CurDNodeID, _ = new(big.Int).SetString(round.dnodeid, 10)

	//check paillier.N bitlen
	for _,msg := range round.temp.kgRound1Messages {
		m,ok := msg.(*KGRound1Message)
		if !ok {
			return errors.New("error kg round1 message")
		}

		paiPk := m.U1PaillierPk
		if paiPk == nil {
			return errors.New("error kg round1 message")
		}

		if paiPk.N.BitLen() != paillierBitsLen {
			return errors.New("got paillier N with not enough bits")
		}
	}
	//

	// add for GG20: keygen phase 3. Each player Pi proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30]
	// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1
	num := ec2.MustGetRandomInt(round.Save.U1PaillierSk.N.BitLen())
	if num == nil {
	    return errors.New("get random int fail")
	}

	sfProof := ec2.SquareFreeProve(round.Save.U1PaillierSk.N,num,round.Save.U1PaillierSk.L)
	if sfProof == nil {
	    return errors.New("get square free proof fail")
	}

	srm := &KGRound2Message2{
		KGRoundMessage: new(KGRoundMessage),
		Num:		num,
		SfPf:		sfProof,
	}
	srm.SetFromID(round.dnodeid)
	srm.SetFromIndex(curIndex)

	round.temp.kgRound2Messages2[curIndex] = srm
	round.out <- srm

	dul,err := ec2.ContainsDuplicate(ids)
	if err != nil || dul || len(ids) > round.dnodecount {
	    return errors.New("node id error")
	}

	u1Shares, err := round.temp.u1Poly.Vss2(ids)
	if err != nil {
		return err
	}

	round.temp.u1Shares = u1Shares

	for k, id := range ids {
		for _, v := range u1Shares {
			kg := &KGRound2Message{
				KGRoundMessage: new(KGRoundMessage),
				ID:             v.ID,
				Share:          v.Share,
			}
			kg.SetFromID(round.dnodeid)
			kg.SetFromIndex(curIndex)

			vv := ec2.GetSharesID(v)
			if vv != nil && vv.Cmp(id) == 0 && k == curIndex {
				round.temp.kgRound2Messages[k] = kg
				break
			} else if vv != nil && vv.Cmp(id) == 0 {
				kg.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
				round.out <- kg
				break
			}
		}
	}

	kg := &KGRound2Message1{
		KGRoundMessage: new(KGRoundMessage),
		C1:             round.temp.c1,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)
	round.temp.kgRound2Messages1[curIndex] = kg
	round.out <- kg

	//fmt.Printf("============ round2 send msg to peer success, c1 for bip32 = %v ============\n", kg.C1)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound2Message); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.(*KGRound2Message1); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round2) Update() (bool, error) {
	for j, msg := range round.temp.kgRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2Messages1[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		msg22 := round.temp.kgRound2Messages2[j]
		if msg22 == nil || !round.CanAccept(msg22) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

// NextRound enter next round
func (round *round2) NextRound() smpc.Round {
	round.started = false
	return &round3{round}
}
