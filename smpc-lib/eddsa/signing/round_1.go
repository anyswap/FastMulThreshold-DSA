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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
	"crypto/sha512"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
)

var (
	zero = big.NewInt(0)
)

func newRound1(temp *localTempData, save *keygen.LocalDNodeSaveData, idsign smpc.SortableIDSSlice, out chan<- smpc.Message, end chan<- EdSignData, kgid string, threshold int, paillierkeylength int, txhash *big.Int) smpc.Round {
	finalize_endCh := make(chan *big.Int, threshold)
	return &round1{
		&base{temp, save, idsign, out, end, make([]bool, threshold), false, 0, kgid, threshold, paillierkeylength, nil, txhash, finalize_endCh}}
}

// Start get sk pkfinal R
func (round *round1) Start() error {
	if round.started {
		fmt.Printf("============= ed sign,round1.start fail =======\n")
		return errors.New("ed sign,round1 already started")
	}
	round.number = 1
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var sk [64]byte
	copy(sk[:], round.save.Sk[:64])
	var tsk [32]byte
	copy(tsk[:], round.save.TSk[:32])
	var pkfinal [32]byte
	copy(pkfinal[:], round.save.FinalPkBytes[:32])

	var uids [][32]byte
	for _, v := range round.save.Ids {
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

	round.temp.sk = sk
	round.temp.tsk = tsk
	round.temp.pkfinal = pkfinal

	if round.txhash == nil {
		return errors.New("no unsign hash")
	}

	tmpstr := hex.EncodeToString(round.txhash.Bytes())
	round.temp.message, _ = hex.DecodeString(tmpstr)
	fmt.Printf("===============ed sign,round1.start, message = %v, msg str = %v ======================\n", round.temp.message, tmpstr)

	// [Notes]
	// 1. calculate R
	var r [32]byte
	var RBytes [32]byte
	var rDigest [64]byte

	h := sha512.New()
	_, err = h.Write(sk[32:])
	if err != nil {
		return errors.New("smpc back-end internal error:write sk fail in caling R")
	}

	_, err = h.Write([]byte(round.temp.message))
	if err != nil {
		return errors.New("smpc back-end internal error:write message fail in caling R")
	}

	h.Sum(rDigest[:0])
	ed.ScReduce(&r, &rDigest)

	var R ed.ExtendedGroupElement
	ed.GeScalarMultBase(&R, &r)

	// 2. commit(R)
	R.ToBytes(&RBytes)
	CR, DR := ed.Commit(RBytes)

	// 3. zkSchnorr(rU1)
	zkR := ed.Prove(r)

	round.temp.DR = DR
	round.temp.zkR = zkR
	round.temp.r = r

	srm := &SignRound1Message{
		SignRoundMessage: new(SignRoundMessage),
		CR:               CR,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound1Messages[cur_index] = srm
	round.out <- srm

	fmt.Printf("============= ed sign,round1.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}

	return false
}

// Update  is the message received and ready for the next round? 
func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.signRound1Messages {
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
func (round *round1) NextRound() smpc.Round {
	round.started = false
	return &round2{round}
}
