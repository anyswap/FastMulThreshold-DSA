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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start broacast zkPk 
func (round *round2) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 2
	round.started = true
	round.ResetOK()

	ids, err := round.GetIDs()
	if err != nil {
		return err
	}
	round.Save.IDs = ids

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}
	round.Save.CurDNodeID = ids[curIndex]

	kg := &KGRound2Message{
		KGRoundMessage: new(KGRoundMessage),
		ZkPk:           round.temp.zkPk,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)
	
	if round.tee {
	    s := &socket.EDKGRound2Msg{}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round2 start,marshal KGRound2 error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
	    msgmap := make(map[string]string)
	    err = json.Unmarshal([]byte(kgs), &msgmap)
	    if err != nil {
		log.Error("round0 start,unmarshal KGRound0 return data error","err",err)
		return err
	    }
	   
	    kg.SetTeeValidateData(msgmap["TeeValidateData"])
	}
	////
	round.temp.kgRound2Messages[curIndex] = kg
	round.out <- kg

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound2Message); ok {
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
		round.ok[j] = true
	}
	return true, nil
}

// NextRound enter next round
func (round *round2) NextRound() smpc.Round {
	round.started = false
	return &round3{round}
}
