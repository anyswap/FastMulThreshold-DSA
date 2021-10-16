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
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// Start return save data 
func (round *round7) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()

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
