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
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

var (
	zero = big.NewInt(0)
)

func newRound1(temp *localTempData, save *keygen.LocalDNodeSaveData, idsign smpc.SortableIDSSlice, out chan<- smpc.Message, end chan<- PrePubData, kgid string, threshold int, paillierkeylength int) smpc.Round {
	finalizeendCh := make(chan *big.Int, threshold)
	return &round1{
		&base{temp, save, idsign, out, end, make([]bool, threshold), false, 0, kgid, threshold, paillierkeylength, nil, nil, finalizeendCh}}
}

// Start calc w1 and u1Gamma k1
func (round *round1) Start() error {
	if round.started {
		fmt.Printf("============= round1.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var self *big.Int
	lambda1 := big.NewInt(1)
	for k, v := range round.idsign {
		if k == curIndex {
			self = v
			break
		}
	}

	if self == nil {
		return errors.New("round start fail,self uid is nil")
	}

	for k, v := range round.idsign {
		if k == curIndex {
			continue
		}

		sub := new(big.Int).Sub(v, self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256().N)
		if subInverse == nil {
		    return errors.New("calc times fail")
		}

		times := new(big.Int).Mul(subInverse, v)
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
	}
	w1 := new(big.Int).Mul(lambda1, round.save.SkU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256().N)

	round.temp.w1 = w1

	u1K := random.GetRandomIntFromZn(secp256k1.S256().N)
	u1Gamma := random.GetRandomIntFromZn(secp256k1.S256().N)

	u1GammaGx, u1GammaGy := secp256k1.S256().ScalarBaseMult(u1Gamma.Bytes())
	commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)
	if commitU1GammaG == nil {
		return errors.New(" Error generating commitment data in signing round 1")
	}

	round.temp.u1K = u1K
	round.temp.u1Gamma = u1Gamma
	round.temp.commitU1GammaG = commitU1GammaG

	srm := &SignRound1Message{
		SignRoundMessage: new(SignRoundMessage),
		C11:              commitU1GammaG.C,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound1Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round1.start success, current node id = %v =======\n", round.kgid)
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
