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

package reshare

import (
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
)

// Start calc w1 and get commitment data
func (round *round1) Start() error {
	if round.started {
		fmt.Printf("============ round1 start error,already started============\n")
		return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.ResetOK()

	if !round.oldnode {
		return nil
	}

	if round.threshold <= 1 || round.threshold > round.dnodecount {
	    return errors.New("threshold value error")
	}

	index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		fmt.Printf("============round1 start,get dnode id index fail,uid = %v,err = %v ===========\n", round.dnodeid,err)
		return err
	}

	var self *big.Int
	lambda1 := big.NewInt(1)
	for k, v := range round.idreshare {
		if k == index {
			self = v
			break
		}
	}

	if self == nil {
		return errors.New("round start fail,self uid is nil")
	}

	for k, v := range round.idreshare {
		if k == index {
			continue
		}

		sub := new(big.Int).Sub(v, self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256(round.keytype).N1())
		if subInverse == nil {
		    return errors.New("calc times fail")
		}

		times := new(big.Int).Mul(subInverse, v)
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256(round.keytype).N1())
	}
	w1 := new(big.Int).Mul(lambda1, round.Save.SkU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256(round.keytype).N1())

	round.temp.w1 = w1

	skP1Poly, skP1PolyG, _ := ec2.Vss2Init(round.keytype,w1, round.threshold)
	skP1Gx, skP1Gy := secp256k1.S256(round.keytype).ScalarBaseMult(w1.Bytes())
	u1CommitValues := make([]*big.Int, 0)
	u1CommitValues = append(u1CommitValues, skP1Gx)
	u1CommitValues = append(u1CommitValues, skP1Gy)
	for i := 1; i < len(skP1PolyG.PolyG); i++ {
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][0])
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][1])
	}
	commitSkP1G := new(ec2.Commitment).Commit(u1CommitValues...)
	if commitSkP1G == nil {
		return errors.New(" Error generating commitment data in reshare round 1")
	}

	round.temp.comd = commitSkP1G.D
	round.temp.skP1Poly = skP1Poly
	round.temp.skP1PolyG = skP1PolyG.PolyG

	re := &ReRound1Message{
		ReRoundMessage: new(ReRoundMessage),
		ComC:                commitSkP1G.C,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(index)

	round.temp.reshareRound1Messages[index] = re
	round.out <- re

	//fmt.Printf("============ round1 start success ============\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true

		//add for reshare only
		if j == (len(round.temp.reshareRound1Messages) - 1) {
			for jj := range round.ok {
				round.ok[jj] = true
			}
		}
		//
	}

	return true, nil
}

// NextRound enter next round
func (round *round1) NextRound() smpc.Round {
	round.started = false
	return &round2{round}
}
