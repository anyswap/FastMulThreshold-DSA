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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
)

// Start return save data 
func (round *round7) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.ResetOK()
	
	ids, err := round.GetIDs()
	if err != nil {
		return err
	}

	for k := range ids {
		msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
			return errors.New("round.Start get round5 msg fail")
		}

		msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
		if !ok {
			return errors.New("round.Start get round4 msg fail")
		}

		deCommit := &ec2.Commitment{C: msg4.ComXiC, D: msg5.ComXiGD}
		_, xiG := deCommit.DeCommit()

		msg6, ok := round.temp.kgRound6Messages[k].(*KGRound6Message)
		if !ok {
			return errors.New("round.Start get round6 msg fail")
		}

		if !ec2.ZkXiVerify(xiG, msg6.U1zkXiProof) {
			fmt.Printf("========= round7 verify zkx fail, k = %v ==========\n", k)
			return errors.New("verify zkx fail")
		}
	}

	round.end <- *round.Save

	//fmt.Printf("========= round7 start success ==========\n")
	return nil
}

// CanAccept end keygen
func (round *round7) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end keygen
func (round *round7) Update() (bool, error) {
	return false, nil
}

// NextRound end keygen
func (round *round7) NextRound() smpc.Round {
	return nil
}
