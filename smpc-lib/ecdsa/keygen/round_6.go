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
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// Start verify commitment and zku proof data
func (round *round6) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 6
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIDs()
	if err != nil {
		return errors.New("round.Start get ids fail")
	}

	for k := range ids {
		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("round.Start get round3 msg fail")
		}

		//verify commitment
		msg1, ok := round.temp.kgRound1Messages[k].(*KGRound1Message)
		if !ok {
			return errors.New("round.Start get round1 msg fail")
		}

		deCommit := &ec2.Commitment{C: msg1.ComC, D: msg3.ComU1GD}
		_, u1G := deCommit.DeCommit()
		msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
			return errors.New("round.Start get round5 msg fail")
		}

		if !ec2.ZkUVerify(u1G, msg5.U1zkUProof) {
			fmt.Printf("========= round6 verify zku fail, k = %v ==========\n", k)
			return errors.New("verify zku fail")
		}
	}

	// add HVZK Proof for a Product of Two Primes
	// for Ntilde = p*q
	// get quadratic residue x for roh1,roh2,roh3 ..... rohm that receiving from the verifier
	zero,_ := new(big.Int).SetString("0",10)
	ntilde := round.temp.kgRound4Messages[curIndex].(*KGRound4Message).U1NtildeH1H2.Ntilde

	for k,id := range ids {
	    msg51, ok := round.temp.kgRound5Messages1[k].(*KGRound5Message1)
	    if !ok {
		return errors.New("round.Start get round 5-1 msg fail")
	    }

	    qua := make([]*big.Int,len(msg51.Roh))
	    for kk,vv := range msg51.Roh {
		var x *big.Int
		if round.temp.p1.Cmp(round.temp.p2) >= 0 {
		    x,_,_,_ = ec2.GetTheQuadraticResidueInt(vv,ntilde,round.temp.p1,round.temp.p2)
		} else {
		    x,_,_,_ = ec2.GetTheQuadraticResidueInt(vv,ntilde,round.temp.p2,round.temp.p1)
		}

		if x != nil {
		    x2 := new(big.Int).Mul(x,x)
		    x2 = new(big.Int).Mod(x2,ntilde)
		    if x2.Cmp(vv) == 0 {
			qua[kk] = new(big.Int).Abs(x) // Select the x value greater than or equal to 0 
			continue
		    }
		}

		qua[kk] = zero

		//fmt.Printf("===========================round 6, k = %v,kk = %v, roh = %v,x = %v, N = %v===========================\n",k,kk,vv,qua[kk],ntilde)
	    }
	    
	    kg := &KGRound6Message1{
		    KGRoundMessage: new(KGRoundMessage),
		    Qua:    qua,
	    }
	    kg.SetFromID(round.dnodeid)
	    kg.SetFromIndex(curIndex)

	    if k == curIndex {
		round.temp.kgRound6Messages1[k] = kg
	    } else {
		kg.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
		round.out <- kg
	    }
	}
	///////////

	round.temp.p1 = nil
	round.temp.p2 = nil 

	kg := &KGRound6Message{
		KGRoundMessage:      new(KGRoundMessage),
		CheckPubkeyStatus: true,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)

	round.temp.kgRound6Messages[curIndex] = kg
	round.out <- kg

	//fmt.Printf("========= round6 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round6) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound6Message); ok {
		return msg.IsBroadcast()
	}
	
	if _, ok := msg.(*KGRound6Message1); ok {
		return !msg.IsBroadcast()
	}
	
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round6) Update() (bool, error) {
	for j, msg := range round.temp.kgRound6Messages1 {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg6 := round.temp.kgRound6Messages[j]
		if msg6 == nil || !round.CanAccept(msg6) {
			return false, nil
		}
		round.ok[j] = true
	}
	
	return true, nil
}

// NextRound enter next round
func (round *round6) NextRound() smpc.Round {
	round.started = false
	return &round7{round}
}
