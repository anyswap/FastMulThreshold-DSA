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

// Start send vss data to corresponding peer
func (round *round2) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	ids, err := round.GetIds()
	if err != nil {
		return errors.New("round.Start get ids fail.")
	}
	round.Save.Ids = ids
	round.Save.CurDNodeID, _ = new(big.Int).SetString(round.dnodeid, 10)

	u1Shares, err := round.temp.u1Poly.Vss2(ids)
	if err != nil {
		return err
	}

	round.temp.u1Shares = u1Shares

	cur_index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	for k, id := range ids {
		for _, v := range u1Shares {
			kg := &KGRound2Message{
				KGRoundMessage: new(KGRoundMessage),
				Id:             v.Id,
				Share:          v.Share,
			}
			kg.SetFromID(round.dnodeid)
			kg.SetFromIndex(cur_index)

			vv := ec2.GetSharesId(v)
			if vv != nil && vv.Cmp(id) == 0 && k == cur_index {
				fmt.Printf("=========== round2, it is self. share struct id = %v, share = %v, k = %v ===========\n", v.Id, v.Share, k)
				round.temp.kgRound2Messages[k] = kg
				break
			} else if vv != nil && vv.Cmp(id) == 0 {
				fmt.Printf("=========== round2, share struct id = %v, share = %v, k = %v ===========\n", v.Id, v.Share, k)
				kg.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
				round.out <- kg
				//fmt.Printf("============ round2 send msg to peer = %v ============\n",id)
				break
			}
		}
	}

	kg := &KGRound2Message1{
		KGRoundMessage: new(KGRoundMessage),
		C1:             round.temp.c1,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(cur_index)
	round.temp.kgRound2Messages1[cur_index] = kg
	round.out <- kg

	fmt.Printf("============ round2 send msg to peer success, c1 for bip32 = %v ============\n", kg.C1)
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
		round.ok[j] = true
	}
	return true, nil
}

// NextRound enter next round
func (round *round2) NextRound() smpc.Round {
	round.started = false
	return &round3{round}
}
