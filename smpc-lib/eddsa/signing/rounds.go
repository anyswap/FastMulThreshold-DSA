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
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
	"strings"
)

type (
	base struct {
		temp              *localTempData
		save              *keygen.LocalDNodeSaveData
		idsign            smpc.SortableIDSSlice
		out               chan<- smpc.Message
		end               chan<- EdSignData
		ok                []bool
		started           bool
		number            int
		kgid              string
		threshold         int
		paillierkeylength int
		predata           *PrePubData
		txhash            *big.Int
		finalizeend      chan<- *big.Int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5
	}
	round7 struct {
		*round6
	}

	//finalize TODO
)

// ----- //

func (round *base) RoundNumber() int {
	return round.number
}

func (round *base) CanProceed() bool {
	if !round.started {
		fmt.Printf("=========== round.CanProceed,not start, round.number = %v ============\n", round.number)
		return false
	}

	for _, ok := range round.ok {
		if !ok {
			//fmt.Printf("=========== round.CanProceed,not ok, round.number = %v ============\n", round.number)
			return false
		}
	}

	return true
}

// GetIDs get from all nodes
func (round *base) GetIDs() (smpc.SortableIDSSlice, error) {
	return round.idsign, nil
}

// GetDNodeIDIndex get current dnode index by id
func (round *base) GetDNodeIDIndex(id string) (int, error) {
	if id == "" {
		return -1, nil
	}

	for k, v := range round.idsign {
		var id2 [32]byte
		copy(id2[:], v.Bytes())
		if strings.EqualFold(hex.EncodeToString(id2[:]), id) {
			return k, nil
		}

	}

	return -1, errors.New("get dnode index fail,no found in kgRound0Messages")
}

func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}
