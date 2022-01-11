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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
)

// Start get S
func (round *round11) Start() error {
	if round.started {
		fmt.Printf("============= round11.start fail =======\n")
		return errors.New("round already started")
	}
	
	round.number = 11
	round.started = true
	round.resetOK()

	msg9, _ := round.temp.signRound9Messages[0].(*SignRound9Message)
	s := msg9.Us1

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg9, _ := round.temp.signRound9Messages[k].(*SignRound9Message)
		s = new(big.Int).Add(s, msg9.Us1)
	}
	s = new(big.Int).Mod(s, secp256k1.S256().N)

	round.finalizeend <- s
	//fmt.Printf("============= round9.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept end signing
func (round *round11) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end signing
func (round *round11) Update() (bool, error) {
	return false, nil
}

// NextRound end signing
func (round *round11) NextRound() smpc.Round {
	return nil
}


