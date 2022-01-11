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
)

// Start broacast DR
func (round *round3) Start() error {
	if round.started {
		fmt.Printf("============= round3.start fail =======\n")
		return errors.New("ed sign,round3 already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	srm := &SignRound3Message{
		SignRoundMessage: new(SignRoundMessage),
		DR:               round.temp.DR,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound3Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= ed sign,round3.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round3) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round3) Update() (bool, error) {
	for j, msg := range round.temp.signRound3Messages {
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
func (round *round3) NextRound() smpc.Round {
	round.started = false
	return &round4{round}
}
