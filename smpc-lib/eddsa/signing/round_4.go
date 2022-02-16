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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ed"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"crypto/sha512"
)

// Start verify CR DR xkR,calc lambda1 s
func (round *round4) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round4.start fail =======\n")
		return errors.New("ed sign,round4 already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var FinalR, temR2 ed.ExtendedGroupElement
	var FinalRBytes [32]byte

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
	round.temp.FinalRBytes = FinalRBytes

	// 2.6 calculate k=H(FinalRBytes||pk||M)
	var k [32]byte
	var kDigest [64]byte

	h := sha512.New()
	_, err = h.Write(FinalRBytes[:])
	if err != nil {
		return err
	}
	_, err = h.Write([]byte("hello multichain"))
	if err != nil {
		return err
	}

	_, err = h.Write(round.temp.pkfinal[:])
	if err != nil {
		return err
	}
	_, err = h.Write([]byte("hello multichain"))
	if err != nil {
		return err
	}

	_, err = h.Write(([]byte(round.temp.message))[:])
	if err != nil {
		return err
	}
	_, err = h.Write([]byte("hello multichain"))
	if err != nil {
		return err
	}

	h.Sum(kDigest[:0])
	ed.ScReduce(&k, &kDigest)

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
		ed.ScSub(&time, &t, &tt)
		time = ed.ScModInverse(time, order)
		count := 0
		for index:=0;index<32;index++ {
		    if time[index] == byte('0') {
			count++
		    }
		}
		if count == 32 {
		    return errors.New("calc time mod inverse fail")
		}

		ed.ScMul(&time, &time, &t)
		ed.ScMul(&lambda, &lambda, &time)
	}

	var s [32]byte
	ed.ScMul(&s, &lambda, &round.temp.tsk)

	//stmp := hex.EncodeToString(s[:])

	ed.ScMul(&s, &s, &k)
	ed.ScAdd(&s, &s, &round.temp.r)

	// 2.9 calculate sBBytes
	var sBBytes [32]byte
	var sB ed.ExtendedGroupElement
	ed.GeScalarMultBase(&sB, &s)
	sB.ToBytes(&sBBytes)

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
