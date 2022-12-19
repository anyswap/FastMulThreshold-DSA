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
	"bytes"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	r255 "github.com/gtank/ristretto255"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ed"
)

// Start verify CSB DSB commitment data,broacast current node s to other nodes
func (round *round6) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round6.start fail =======\n")
		return errors.New("ed sign,round already started")
	}
	round.number = 6
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var sBBytes2 [32]byte

	if round.temp.keyType == smpc.SR25519 {
		sB2 := new(r255.Element)

		for k := range round.idsign {
			msg4, ok := round.temp.signRound4Messages[k].(*SignRound4Message)
			if !ok {
				return errors.New("get csb fail")
			}

			msg5, ok := round.temp.signRound5Messages[k].(*SignRound5Message)
			if !ok {
				return errors.New("get dsb fail")
			}

			CSBFlag := ed.Verify(msg4.CSB, msg5.DSB)
			if !CSBFlag {
				fmt.Printf("Error: Commitment(SB) Not Pass at User: %v", round.kgid)
				return errors.New("smpc back-end internal error:commitment(CSB) not pass")
			}

			var temSBBytes [32]byte
			copy(temSBBytes[:], msg5.DSB[32:])
			var temSB = new(r255.Element)
			temSB.Decode(temSBBytes[:])

			if k == 0 {
				sB2 = temSB
			} else {
				sB2 = new(r255.Element).Add(sB2, temSB)
			}
		}
		sB2.Encode(sBBytes2[:0])
	}else {
		var sB2, temSB ed.ExtendedGroupElement
		for k := range round.idsign {
			msg4, ok := round.temp.signRound4Messages[k].(*SignRound4Message)
			if !ok {
				return errors.New("get csb fail")
			}

			msg5, ok := round.temp.signRound5Messages[k].(*SignRound5Message)
			if !ok {
				return errors.New("get dsb fail")
			}

			CSBFlag := ed.Verify(msg4.CSB, msg5.DSB)
			if !CSBFlag {
				fmt.Printf("Error: Commitment(SB) Not Pass at User: %v", round.kgid)
				return errors.New("smpc back-end internal error:commitment(CSB) not pass")
			}

			var temSBBytes [32]byte
			copy(temSBBytes[:], msg5.DSB[32:])
			temSB.FromBytes(&temSBBytes)

			if k == 0 {
				sB2 = temSB
			} else {
				ed.GeAdd(&sB2, &sB2, &temSB)
			}
		}
		sB2.ToBytes(&sBBytes2)
	}

	k2, err := CalKValue(round.temp.keyType, round.temp.message, round.temp.pkfinal[:], round.temp.FinalRBytes[:])
	if err != nil {
		fmt.Printf("error in Round 6 CalKValue: %v\n", round.save.CurDNodeID)
		return err
	}

	// 3.6 calculate sBCal
	var sBCalBytes [32]byte

	if round.temp.keyType == smpc.SR25519 {
		var FinalR2 = new(r255.Element)
		var sBCal = new(r255.Element) 
		var FinalPkB = new(r255.Element)
		var k2Scalar = new(r255.Scalar)
		k2Scalar.Decode(k2[:])

		FinalR2.Decode(round.temp.FinalRBytes[:])
		FinalPkB.Decode(round.temp.pkfinal[:])
		sBCal = new(r255.Element).ScalarMult(k2Scalar, FinalPkB)
		sBCal = new(r255.Element).Add(sBCal, FinalR2)

		sBCal.Encode(sBCalBytes[:0])
	}else {
		var FinalR2, sBCal, FinalPkB ed.ExtendedGroupElement
		FinalR2.FromBytes(&round.temp.FinalRBytes)
		FinalPkB.FromBytes(&round.temp.pkfinal)
		ed.GeScalarMult(&sBCal, &k2, &FinalPkB)
		ed.GeAdd(&sBCal, &sBCal, &FinalR2)

		sBCal.ToBytes(&sBCalBytes)
	}

	// 3.7 verify equation
	if !bytes.Equal(sBBytes2[:], sBCalBytes[:]) {
		fmt.Printf("Error: Not Pass Verification (SB = SBCal) at User: %v, message = %v,msg str = %v, pk = %v,RBytes = %v  \n", round.kgid, round.temp.message, hex.EncodeToString(round.temp.message[:]), round.temp.pkfinal[:], round.temp.FinalRBytes[:])
		return errors.New("error: not pass verification (sb = sbcal)")
	}

	srm := &SignRound6Message{
		SignRoundMessage: new(SignRoundMessage),
		S:                round.temp.s,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound6Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= ed sign,round6.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round6) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round6) Update() (bool, error) {
	for j, msg := range round.temp.signRound6Messages {
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
func (round *round6) NextRound() smpc.Round {
	round.started = false
	return &round7{round}
}
