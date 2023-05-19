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

	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	r255 "github.com/gtank/ristretto255"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	tsslib "github.com/anyswap/FastMulThreshold-DSA/tss-lib/common"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// Start verify CR DR xkR,calc lambda1 s
func (round *round4) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round4.start fail =======\n")
		return errors.New("ed sign,round4 already started")
	}
	round.number = 4
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	if round.tee {
	    return round.ExecTee(curIndex)
	}

	var FinalRBytes [32]byte

	if round.temp.keyType == smpc.SR25519 {
		FinalR := new(r255.Element)
		for k := range round.idsign {
			msg1, ok := round.temp.signRound1Messages[k].(*SignRound1Message)
			if !ok {
				return errors.New("get cr fail")
			}

			msg3, ok := round.temp.signRound3Messages[k].(*SignRound3Message)
			if !ok {
				return errors.New("get dr fail")
			}

			CRFlag := ed.Verify(msg1.CR, msg3.DR)
			if !CRFlag {
				fmt.Printf("error: commitment(r) not pass at user: %v\n", round.save.CurDNodeID)
				return errors.New("smpc back-end internal error:commitment verification fail in ed sign")
			}

			msg2, ok := round.temp.signRound2Messages[k].(*SignRound2Message)
			if !ok {
				return errors.New("get zkr fail")
			}

			var temR [32]byte
			copy(temR[:], msg3.DR[32:])

			zkRFlag := ed_ristretto.VerifyZk2(msg2.ZkR, temR)
			if !zkRFlag {
				fmt.Printf("Error: ZeroKnowledge Proof (R) Not Pass at User: %v\n", round.save.CurDNodeID)
				return errors.New("smpc back-end internal error:zeroknowledge verification fail in ed sign")
			}

			var temRBytes [32]byte
			copy(temRBytes[:], msg3.DR[32:])
			temR2 := new(r255.Element)
			temR2.Decode(temRBytes[:])
			
			if k == 0 {
				FinalR = temR2
			} else {
				FinalR = new(r255.Element).Add(FinalR, temR2)
			}
		}
		FinalR.Encode(FinalRBytes[:0])
	}else {
		var FinalR, temR2 ed.ExtendedGroupElement
		for k := range round.idsign {
			msg1, ok := round.temp.signRound1Messages[k].(*SignRound1Message)
			if !ok {
				return errors.New("get cr fail")
			}

			msg3, ok := round.temp.signRound3Messages[k].(*SignRound3Message)
			if !ok {
				return errors.New("get dr fail")
			}

			CRFlag := ed.Verify(msg1.CR, msg3.DR)
			if !CRFlag {
				fmt.Printf("error: commitment(r) not pass at user: %v\n", round.save.CurDNodeID)
				return errors.New("smpc back-end internal error:commitment verification fail in ed sign")
			}

			msg2, ok := round.temp.signRound2Messages[k].(*SignRound2Message)
			if !ok {
				return errors.New("get zkr fail")
			}

			var temR [32]byte
			copy(temR[:], msg3.DR[32:])

			zkRFlag := ed.VerifyZk2(msg2.ZkR, temR)
			if !zkRFlag {
				fmt.Printf("Error: ZeroKnowledge Proof (R) Not Pass at User: %v\n", round.save.CurDNodeID)
				return errors.New("smpc back-end internal error:zeroknowledge verification fail in ed sign")
			}

			var temRBytes [32]byte
			copy(temRBytes[:], msg3.DR[32:])
			temR2.FromBytes(&temRBytes)
			if k == 0 {
				FinalR = temR2
			} else {
				ed.GeAdd(&FinalR, &FinalR, &temR2)
			}
		}
		FinalR.ToBytes(&FinalRBytes)
	}

	round.temp.FinalRBytes = FinalRBytes

	k, err := tsslib.CalKValue(round.temp.keyType, round.temp.message, round.temp.pkfinal[:], FinalRBytes[:])
	if err != nil {
		fmt.Printf("error in Round 4 CalKValue: %v\n", round.save.CurDNodeID)
		return err
	}

	// 2.7 calculate lambda1
	var lambda [32]byte
	lambda[0] = 1
	order := ed.GetBytesOrder()

	var curByte [32]byte
	copy(curByte[:], round.save.CurDNodeID.Bytes())

	for kk, vv := range round.idsign {
		if kk == curIndex {
			continue
		}

		var indexByte [32]byte
		copy(indexByte[:], vv.Bytes())

		var time [32]byte
		t := indexByte //round.temp.uids[oldindex]
		tt := curByte  //round.temp.uids[cur_oldindex]

		if round.temp.keyType == smpc.SR25519 {
			ed_ristretto.ScSub(&time, &t, &tt)
			time = ed_ristretto.ScModInverse(time)
		}else {
			ed.ScSub(&time, &t, &tt)
			time = ed.ScModInverse(time, order)
		}
		count := 0
		for index:=0;index<32;index++ {
		    if time[index] == byte('0') {
			count++
		    }
		}
		if count == 32 {
		    return errors.New("calc time mod inverse fail")
		}

		if round.temp.keyType == smpc.SR25519 {
			ed_ristretto.ScMul(&time, &time, &t)
			ed_ristretto.ScMul(&lambda, &lambda, &time)
		}else {
			ed.ScMul(&time, &time, &t)
			ed.ScMul(&lambda, &lambda, &time)
		}
	}

	var s [32]byte
	var sBBytes [32]byte

	if round.temp.keyType == smpc.SR25519 {
		ed_ristretto.ScMul(&s, &lambda, &round.temp.tsk)

		//stmp := hex.EncodeToString(s[:])
		ed_ristretto.ScMul(&s, &s, &k)
		ed_ristretto.ScAdd(&s, &s, &round.temp.r)

		// 2.9 calculate sBBytes
		var sScalar = new(r255.Scalar)
		sScalar.Decode(s[:])
		sB := new(r255.Element).ScalarBaseMult(sScalar)
		sB.Encode(sBBytes[:0])
	}else {
		ed.ScMul(&s, &lambda, &round.temp.tsk)

		//stmp := hex.EncodeToString(s[:])
		ed.ScMul(&s, &s, &k)
		ed.ScAdd(&s, &s, &round.temp.r)

		// 2.9 calculate sBBytes
		var sB ed.ExtendedGroupElement
		ed.GeScalarMultBase(&sB, &s)
		sB.ToBytes(&sBBytes)
	}

	// 2.10 commit(sBBytes)
	CSB, DSB,err := ed.Commit(sBBytes)
	if err != nil {
	    return err
	}

	round.temp.DSB = DSB
	round.temp.sBBytes = sBBytes
	round.temp.s = s

	srm := &SignRound4Message{
		SignRoundMessage: new(SignRoundMessage),
		CSB:              CSB,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound4Messages[curIndex] = srm
	round.out <- srm

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.signRound4Messages {
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
func (round *round4) NextRound() smpc.Round {
	round.started = false
	return &round5{round}
}

//----------------------------------------

type EDSigningRound4ReturnValue struct {
    FinalRBytes [32]byte
    S [32]byte
    SBBytes [32]byte
    CSB [32]byte
    DSB [64]byte
    TeeValidateData string
}

func (round *round4) ExecTee(curIndex int) error {
    CRs := make([][32]byte,len(round.idsign))
    DRs := make([][64]byte,len(round.idsign))
    ZkRs := make([][64]byte,len(round.idsign))

    for k,_ := range round.idsign {
	msg1, ok := round.temp.signRound1Messages[k].(*SignRound1Message)
	if !ok {
		return errors.New("get cr fail")
	}

	msg3, ok := round.temp.signRound3Messages[k].(*SignRound3Message)
	if !ok {
		return errors.New("get dr fail")
	}

	msg2, ok := round.temp.signRound2Messages[k].(*SignRound2Message)
	if !ok {
		return errors.New("get zkr fail")
	}

	CRs[k] = msg1.CR
	DRs[k] = msg3.DR
	ZkRs[k] = msg2.ZkR
    }

    s := &socket.EDSigningRound4Msg{CRs:CRs,DRs:DRs,ZkRs:ZkRs,Message:round.temp.message,Pkfinal:round.temp.pkfinal,CurDNodeID:round.save.CurDNodeID,IdSign:round.idsign,Index:curIndex,TSk:round.temp.tskEnc,R:round.temp.r}
    s.Base.SetBase(round.keyType,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round1 start,marshal KGRound1 error","err",err)
	return err
    }
   
    kgs := <-round.teeout
	bytesMap := make(map[string][]byte)
	err = json.Unmarshal([]byte(kgs), &bytesMap)
	msgmap := common.BytesMap2StringMap(bytesMap)
    if err != nil {
	log.Error("round1 start,unmarshal KGRound1 return data error","err",err)
	return err
    }

    if msgmap["Msg4CheckRes"] == "FALSE" {
	return errors.New("ed round4 check fail")
    }

    ret := &EDSigningRound4ReturnValue{}
    err = json.Unmarshal([]byte(msgmap["Ret"]),ret)
    if err != nil {
	return err
    }

    round.temp.FinalRBytes = ret.FinalRBytes
    round.temp.DSB = ret.DSB
    round.temp.sBBytes = ret.SBBytes
    round.temp.s = ret.S

    srm := &SignRound4Message{
	    SignRoundMessage: new(SignRoundMessage),
	    CSB:              ret.CSB,
    }
    srm.SetFromID(round.kgid)
    srm.SetFromIndex(curIndex)
    srm.SetTeeValidateData(ret.TeeValidateData)

    round.temp.signRound4Messages[curIndex] = srm
    round.out <- srm
    return nil
}



