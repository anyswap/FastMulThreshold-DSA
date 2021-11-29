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
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// Start broacast commitment D 
func (round *round3) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	// add for GG20: keygen phase 3. Each player Pi proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30]
	// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1
	// compute M = N^-1 mod OuLa(N) and output y = x^M mod N 
	for k,id := range round.Save.IDs {
		msg22, ok := round.temp.kgRound2Messages2[k].(*KGRound2Message2)
		if !ok {
		    return errors.New("round.Start get round2 msg 2 fail")
		}

		// check x
		// x != nil 
		// x mod N != 0
		// x mod N != 1
		// gcd(x,N) = 1
		if msg22.X == nil {
		    return errors.New("get msg2-2 fail,x is nil")
		}
		one := big.NewInt(1)
		xmn := new(big.Int).Mod(msg22.X,round.Save.U1PaillierSk.N)
		if xmn.Cmp(zero) == 0 || xmn.Cmp(one) == 0 {
		    return errors.New("x mod N == 0 or 1")
		}
		gcd := big.NewInt(0)
		if gcd.GCD(nil,nil,msg22.X,round.Save.U1PaillierSk.N).Cmp(one) != 0 {
		    return errors.New("gcd(x,N) != 1")
		}

		M := new(big.Int).ModInverse(round.Save.U1PaillierSk.N, round.Save.U1PaillierSk.L)
		y := new(big.Int).Exp(msg22.X,M,round.Save.U1PaillierSk.N)

		kg := &KGRound3Message1{
			KGRoundMessage: new(KGRoundMessage),
			Y:    y,
		}
		kg.SetFromID(round.dnodeid)
		kg.SetFromIndex(curIndex)

		if k == curIndex {
		    round.temp.kgRound3Messages1[k] = kg
		} else {
		    kg.AppendToID(fmt.Sprintf("%v", id)) //id-->dnodeid
		    round.out <- kg
		}
	}
	//
	
	kg := &KGRound3Message{
		KGRoundMessage: new(KGRoundMessage),
		ComU1GD:        round.temp.commitU1G.D,
		ComC1GD:        round.temp.commitC1G.D,
		U1PolyGG:       round.temp.u1PolyG.PolyG,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)
	round.temp.kgRound3Messages[curIndex] = kg
	round.out <- kg

	//fmt.Printf("========= round3 start success, u1polygg = %v, k = %v ==========\n", round.temp.u1PolyG.PolyG, curIndex)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round3) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	if _, ok := msg.(*KGRound3Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round3) Update() (bool, error) {
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg31 := round.temp.kgRound3Messages1[j]
		if msg31 == nil || !round.CanAccept(msg31) {
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
