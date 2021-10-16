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
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
	"sort"
)

type (
	base struct {
		Save       *LocalDNodeSaveData
		temp       *localTempData
		out        chan<- smpc.Message
		end        chan<- LocalDNodeSaveData
		ok         []bool
		started    bool
		number     int
		dnodeid    string
		dnodecount int
		threshold  int
	}
	round0 struct {
		*base
	}
	round1 struct {
		*round0
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

// GetIds get from all nodes
func (round *base) GetIds() (smpc.SortableIDSSlice, error) {
	var ids smpc.SortableIDSSlice
	for _, v := range round.temp.kgRound0Messages {
		uidtmp, _ := hex.DecodeString(v.GetFromID())
		uid := new(big.Int).SetBytes(uidtmp[:])
		ids = append(ids, uid)
	}

	sort.Sort(ids)
	return ids, nil
}

// GetDNodeIDIndex get current node index by id
func (round *base) GetDNodeIDIndex(id string) (int, error) {
	if id == "" || len(round.temp.kgRound0Messages) != round.dnodecount {
		return -1, nil
	}

	ids, err := round.GetIds()
	if err != nil {
		return -1, err
	}

	uidtmp, _ := hex.DecodeString(id)
	uid := new(big.Int).SetBytes(uidtmp[:])
	for k, v := range ids {
		if v.Cmp(uid) == 0 {
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
