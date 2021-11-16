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
)

const (
	ntildeBitsLen = 2048
)

// Start broacast zku proof data
func (round *round5) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	//check Ntilde bitlen
	for _,msg := range round.temp.kgRound4Messages {
		m,ok := msg.(*KGRound4Message)
		if !ok {
			return errors.New("error kg round4 message")
		}

		ntilde := m.U1NtildeH1H2
		if ntilde == nil || ntilde.Ntilde == nil {
			return errors.New("error kg round4 message")
		}

		if ntilde.Ntilde.BitLen() != ntildeBitsLen {
			return errors.New("got ntilde with not enough bits")
		}
	}
	//

	// add HVZK Proof for a Product of Two Primes
	// for Ntilde = p*q
	// pick m random values send to prover first
	for k,id := range round.Save.IDs {
	    msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		return errors.New("round.Start get round4 msg fail")
	    }

	    roh := ec2.GetRandomValuesFromJN(msg4.U1NtildeH1H2.Ntilde)
	    round.temp.roh[k] = roh

	    kg := &KGRound5Message1{
		    KGRoundMessage: new(KGRoundMessage),
		    Roh:    roh,
	    }
	    kg.SetFromID(round.dnodeid)
	    kg.SetFromIndex(curIndex)

	    if k == curIndex {
		round.temp.kgRound5Messages1[k] = kg
	    } else {
		kg.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
		round.out <- kg
	    }
	}

	u1zkUProof := ec2.ZkUProve(round.temp.u1)
	if u1zkUProof == nil {
		return errors.New("zku prove fail")
	}

	kg := &KGRound5Message{
		KGRoundMessage: new(KGRoundMessage),
		U1zkUProof:     u1zkUProof,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)

	round.temp.kgRound5Messages[curIndex] = kg
	round.out <- kg

	//fmt.Printf("========= round5 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound5Message); ok {
		return msg.IsBroadcast()
	}
	
	if _, ok := msg.(*KGRound5Message1); ok {
		return !msg.IsBroadcast()
	}
	
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.kgRound5Messages1 {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg5 := round.temp.kgRound5Messages[j]
		if msg5 == nil || !round.CanAccept(msg5) {
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
