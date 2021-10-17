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
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// Start broacast success status to other nodes
func (round *round5) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	idtmp, ok := new(big.Int).SetString(round.dnodeid, 10)
	if !ok {
		return errors.New("get id big number fail")
	}

	curIndex := -1
	for k, v := range round.Save.IDs {
		if v.Cmp(idtmp) == 0 {
			curIndex = k
			break
		}
	}

	if curIndex < 0 {
		return errors.New("get cur index fail")
	}

	re := &ReRound5Message{
		ReRoundMessage: new(ReRoundMessage),
		NewSkOk:             "TRUE",
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(curIndex)

	round.temp.reshareRound5Messages[curIndex] = re
	round.out <- re

	//fmt.Printf("========= round5 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound5Message); ok {
		return msg.IsBroadcast()
	}

	return false
}

// Update  is the message received and ready for the next round? 
func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound5Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}

		round.ok[j] = true

		// add for reshare only
		if j == (len(round.temp.reshareRound5Messages) - 1) {
			for jj := range round.ok {
				round.ok[jj] = true
			}
		}
		//
	}

	return true, nil
}

// NextRound enter next round
func (round *round5) NextRound() smpc.Round {
	round.started = false
	return &round6{round}
}
