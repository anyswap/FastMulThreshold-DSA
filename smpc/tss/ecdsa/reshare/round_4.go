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
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
)

// Start create ntilde 
func (round *round4) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	
	round.number = 4
	round.started = true
	round.ResetOK()

	idtmp, ok := new(big.Int).SetString(round.dnodeid, 10)
	if !ok {
		return errors.New("get id big number fail")
	}

	curIndex := -1
	for k, v := range round.Save.IDs {
		if v.Cmp(idtmp) == 0 {
			curIndex = k
			break
		}
	}

	if curIndex < 0 {
		return errors.New("get cur index fail")
	}

	// zk of paillier key
	var u1NtildeH1H2 *ec2.NtildeH1H2
	var alpha *big.Int
	var beta *big.Int
	var p *big.Int
	var q *big.Int

	if round.oldnode && round.oldindex != -1 {
	    u1NtildeH1H2 = round.Save.U1NtildeH1H2[round.oldindex]
	    alpha = round.Save.U1NtildePrivData.Alpha
	    beta = round.Save.U1NtildePrivData.Beta
	    p = round.Save.U1NtildePrivData.Q1
	    q = round.Save.U1NtildePrivData.Q2
	} else {
	    NtildeLength := 2048
	    u1NtildeH1H2, alpha, beta, p, q,_,_ = ec2.GenerateNtildeH1H2(NtildeLength)
	    if u1NtildeH1H2 == nil {
		    return errors.New("gen ntilde h1 h2 fail")
	    }

	}

	ntildeProof1 := ec2.NewNtildeProof(u1NtildeH1H2.H1, u1NtildeH1H2.H2, alpha, p, q, u1NtildeH1H2.Ntilde)
	ntildeProof2 := ec2.NewNtildeProof(u1NtildeH1H2.H2, u1NtildeH1H2.H1, beta, p, q, u1NtildeH1H2.Ntilde)

	re := &ReRound4Message{
		ReRoundMessage: new(ReRoundMessage),
		U1NtildeH1H2:        u1NtildeH1H2,
		NtildeProof1:        ntildeProof1,
		NtildeProof2:        ntildeProof2,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(curIndex)

	round.temp.u1NtildeH1H2 = u1NtildeH1H2
	round.temp.u1NtildePrivData = &ec2.NtildePrivData{Alpha:alpha,Beta:beta,Q1:p,Q2:q}
	round.temp.reshareRound4Messages[curIndex] = re
	round.out <- re

	//fmt.Printf("========= round4 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}

		round.ok[j] = true

		//add for reshare only
		if j == (len(round.temp.reshareRound4Messages) - 1) {
			for jj := range round.ok {
				round.ok[jj] = true
			}
		}
		//
	}

	return true, nil
}

// NextRound enter next round
func (round *round4) NextRound() smpc.Round {
	round.started = false
	return &round5{round}
}
