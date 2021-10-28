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
	"encoding/hex"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"crypto/sha512"
)

// Start verify cPk dPk zkPk,calc vss 
func (round *round4) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIDs()
	if err != nil {
		return errors.New("round.start get ids fail")
	}

	fmt.Printf("==================round 4 start===============\n")
	var PkSet []byte

	for k, id := range ids {
		msg1, ok := round.temp.kgRound1Messages[k].(*KGRound1Message)
		if !ok {
			return errors.New("round.Start get round1 msg fail")
		}

		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("round.Start get round3 msg fail")
		}

		CPkFlag := ed.Verify(msg1.CPk, msg3.DPk)
		if !CPkFlag {
			fmt.Printf("Error: Commitment(PK) Not Pass at User: %v, k = %v \n", id, k)
			return errors.New("smpc back-end internal error:commitment check fail in req ed pubkey")
		}

		msg2, ok := round.temp.kgRound2Messages[k].(*KGRound2Message)
		if !ok {
			return errors.New("round.Start get round2 msg fail")
		}

		var t [32]byte
		copy(t[:], msg3.DPk[32:])
		zkPkFlag := ed.VerifyZk2(msg2.ZkPk, t)
		if !zkPkFlag {
			fmt.Printf("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %v \n", id)
			return errors.New("smpc back-end internal error:zeroknowledge check fail")
		}

		PkSet = append(PkSet[:], (msg3.DPk[32:])...)
	}

	fmt.Printf("================round 4, ZeroKnowledge Proof Pass================\n")

	// 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
	var a [32]byte
	var aDigest [64]byte

	msg3, ok := round.temp.kgRound3Messages[curIndex].(*KGRound3Message)
	if !ok {
		return errors.New("round get msg3 fail")
	}

	h := sha512.New()
	_, err = h.Write(msg3.DPk[32:])
	if err != nil {
		return errors.New("smpc back-end internal error:write dpk fail in calcing SHA256(PkU1, {PkU2, PkU3}")
	}

	_, err = h.Write(PkSet)
	if err != nil {
		return errors.New("smpc back-end internal error:write pkset fail in calcing SHA256(PkU1, {PkU2, PkU3}")
	}

	h.Sum(aDigest[:0])
	ed.ScReduce(&a, &aDigest)

	// 2.6 calculate ask
	var ask [32]byte
	var temSk2 [32]byte
	copy(temSk2[:], round.temp.sk[:32])
	ed.ScMul(&ask, &a, &temSk2)

	// 2.7 calculate vss

	var uids [][32]byte
	for _, v := range ids {
		var tem [32]byte
		tmp := v.Bytes()
		copy(tem[:], tmp[:])
		if len(v.Bytes()) < 32 {
			l := len(v.Bytes())
			for j := l; j < 32; j++ {
				tem[j] = byte(0x00)
			}
		}
		uids = append(uids, tem)
	}
	round.temp.uids = uids

	_, cfsBBytes, shares := ed.Vss(ask, uids, round.threshold, round.dnodecount)
	round.temp.cfsBBytes = cfsBBytes

	for k, id := range ids {
		kg := &KGRound4Message{
			KGRoundMessage: new(KGRoundMessage),
			Share:          shares[k],
		}
		kg.SetFromID(round.dnodeid)
		kg.SetFromIndex(curIndex)

		if k == curIndex {
			round.temp.kgRound4Messages[k] = kg
		} else {

			var tmp [32]byte
			copy(tmp[:], id.Bytes())
			idtmp := hex.EncodeToString(tmp[:])
			kg.AppendToID(idtmp) //id-->dnodeid
			round.out <- kg
		}
	}

	fmt.Printf("========= round4 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound4Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.kgRound4Messages {
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
