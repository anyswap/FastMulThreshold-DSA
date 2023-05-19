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

// Start broacast DR
func (round *round3) Start() error {
	if round.started {
		fmt.Printf("============= round3.start fail =======\n")
		return errors.New("ed sign,round3 already started")
	}
	round.number = 3
	round.started = true
	round.ResetOK()

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
	
	if round.tee {
	    s := &socket.EDSigningRound3Msg{}
	    s.Base.SetBase(round.keyType,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round3 start,marshal Signing Round3 error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round3 start,unmarshal SigningRound3 return data error","err",err)
		return err
	    }
	   
	    srm.SetTeeValidateData(msgmap["TeeValidateData"])
	}
	////

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
