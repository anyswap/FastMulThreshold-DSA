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

package reshare

import (
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
)

var (
	zero = big.NewInt(0)
)

func newRound0(save *keygen.LocalDNodeSaveData, temp *localTempData, out chan<- smpc.Message, end chan<- keygen.LocalDNodeSaveData, dnodeid string, dnodecount int, threshold int, paillierkeylength int, oldnode bool,oldindex int,keytype string) smpc.Round {
	return &round0{
		&base{save, temp, out, end, make([]bool, dnodecount), false, 0, dnodeid, dnodecount, threshold, paillierkeylength, oldnode,oldindex, nil,keytype}}
}

// Start  Broadcast current dnode ID to other nodes 
func (round *round0) Start() error {
	if round.started {
		fmt.Printf("============= round0.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 0
	round.started = true
	round.ResetOK()

	re := &ReRound0Message{
		ReRoundMessage: new(ReRoundMessage),
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(-1)

	round.temp.reshareRound0Messages = append(round.temp.reshareRound0Messages, re)
	round.out <- re
	//fmt.Printf("============= round0.start success, current node id = %v =======\n", round.dnodeid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round0) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound0Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round0) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound0Messages {
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
func (round *round0) NextRound() smpc.Round {
	round.started = false
	return &round1{round}
}
