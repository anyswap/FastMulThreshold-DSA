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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

// Start get vss data and send to corresponding peer
func (round *round2) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	if !round.oldnode {
		ids, err := round.GetIDs()
		if err != nil {
			return errors.New("round.Start get ids fail")
		}
		round.Save.IDs = ids
		round.Save.CurDNodeID, _ = new(big.Int).SetString(round.dnodeid, 10)

		return nil
	}

	ids, err := round.GetIDs()
	if err != nil {
		return errors.New("round.Start get ids fail")
	}
	round.Save.IDs = ids
	round.Save.CurDNodeID, _ = new(big.Int).SetString(round.dnodeid, 10)

	skP1Shares, err := round.temp.skP1Poly.Vss2(ids)
	if err != nil {
		return err
	}

	round.temp.skP1Shares = skP1Shares

	curIndexReshare, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	curIndex := -1
	for k, v := range round.Save.IDs {
		if v.Cmp(round.Save.CurDNodeID) == 0 {
			curIndex = k
			break
		}
	}

	if curIndex < 0 {
		return errors.New("get current node index fail")
	}

	for k, id := range ids {
		for _, v := range skP1Shares {
			re := &ReRound2Message{
				ReRoundMessage: new(ReRoundMessage),
				ID:                  v.ID,
				Share:               v.Share,
			}
			re.SetFromID(round.dnodeid)
			re.SetFromIndex(curIndexReshare)

			vv := ec2.GetSharesID(v)
			if vv != nil && vv.Cmp(id) == 0 && k == curIndex {
				fmt.Printf("=========== round2, it is self. share struct id = %v, share = %v, k = %v ===========\n", v.ID, v.Share, k)
				round.temp.reshareRound2Messages[curIndexReshare] = re
				break
			} else if vv != nil && vv.Cmp(id) == 0 {
				fmt.Printf("=========== round2, share struct id = %v, share = %v, k = %v ===========\n", v.ID, v.Share, k)
				re.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
				round.out <- re
				//fmt.Printf("============ round2 send msg to peer = %v ============\n",id)
				break
			}
		}
	}

	re := &ReRound2Message1{
		ReRoundMessage: new(ReRoundMessage),
		ComD:                round.temp.comd,
		SkP1PolyG:           round.temp.skP1PolyG,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(curIndexReshare)
	round.temp.reshareRound2Messages1[curIndexReshare] = re
	round.out <- re

	//fmt.Printf("============ round2 send msg to peer success ============\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound2Message); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.(*ReRound2Message1); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round2) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.reshareRound2Messages1[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true

		//add for reshare only
		if j == (len(round.temp.reshareRound2Messages) - 1) {
			for jj := range round.ok {
				round.ok[jj] = true
			}
		}
		//
	}
	return true, nil
}

// NextRound enter next round
func (round *round2) NextRound() smpc.Round {
	round.started = false
	return &round3{round}
}
