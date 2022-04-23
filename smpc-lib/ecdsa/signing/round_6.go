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
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
)

// Start broacast zkuproof and commitment D
func (round *round6) Start() error {
	if round.started {
		fmt.Printf("============= round6.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 6
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	msg5, _ := round.temp.signRound5Messages[0].(*SignRound5Message)
	deltaSum := msg5.Delta1

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg5, _ := round.temp.signRound5Messages[k].(*SignRound5Message)
		deltaSum = new(big.Int).Add(deltaSum, msg5.Delta1)
	}
	deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)
	round.temp.deltaSum = deltaSum

	u1GammaZKProof := ec2.ZkUProve(round.temp.u1Gamma)

	srm := &SignRound6Message{
		SignRoundMessage: new(SignRoundMessage),
		CommU1D:          round.temp.commitU1GammaG.D,
		U1GammaZKProof:   u1GammaZKProof,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound6Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round6.start success, current node id = %v =============\n", round.kgid)

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
