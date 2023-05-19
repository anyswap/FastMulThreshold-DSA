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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// Start broacast Kc
func (round *round3) Start() error {
	if round.started {
	    log.Error("============= round3.start fail =======")
	    return errors.New("round already started")
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
		Kc:               round.temp.ukc,
		ComWiD:		round.temp.commitwiG.D, // add for GG18 A.2 Respondent ZK Proof for MtAwc
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)
	////
	if round.tee {
	    s := &socket.SigningRound3Msg{}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round3 start,marshal SignRound3 error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round3 start,unmarshal SignRound3 return data error","err",err)
		return err
	    }
	   
	    srm.SetTeeValidateData(msgmap["TeeValidateData"])
	}
	////


	round.temp.signRound3Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round3.start success, current node id = %v =======\n", round.kgid)
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
