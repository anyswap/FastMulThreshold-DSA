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

// Start verify commitment and zku proof data
func (round *round6) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 6
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIds()
	if err != nil {
		return errors.New("round.Start get ids fail.")
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
			return errors.New("verify zku fail.")
		}
	}

	kg := &KGRound6Message{
		KGRoundMessage:      new(KGRoundMessage),
		Check_Pubkey_Status: true,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(cur_index)

	round.temp.kgRound6Messages[cur_index] = kg
	round.out <- kg

	fmt.Printf("========= round6 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round6) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round6) Update() (bool, error) {
	for j, msg := range round.temp.kgRound6Messages {
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
func (round *round6) NextRound() smpc.Round {
	round.started = false
	return &round7{round}
}
