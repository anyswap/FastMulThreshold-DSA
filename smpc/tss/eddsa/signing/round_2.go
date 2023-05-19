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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// Start broacast zkR 
func (round *round2) Start() error {
	if round.started {
		fmt.Printf("============= round2.start fail =======\n")
		return errors.New("ed sign,round2 already started")
	}
	round.number = 2
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	srm := &SignRound2Message{
		SignRoundMessage: new(SignRoundMessage),
		ZkR:              round.temp.zkR,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)
	
	if round.tee {
	    s := &socket.EDSigningRound2Msg{}
	    s.Base.SetBase(round.keyType,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round2 start,marshal Signing Round2 error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round2 start,unmarshal SigningRound2 return data error","err",err)
		return err
	    }
	   
	    srm.SetTeeValidateData(msgmap["TeeValidateData"])
	}
	////

	round.temp.signRound2Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= ed sign,round2.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round2) Update() (bool, error) {
	for j, msg := range round.temp.signRound2Messages {
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
