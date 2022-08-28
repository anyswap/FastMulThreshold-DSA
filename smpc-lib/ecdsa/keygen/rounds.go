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
	"math/big"
	"sort"
	"encoding/hex"
)

type (
	base struct {
		Save              *LocalDNodeSaveData
		temp              *localTempData
		out               chan<- smpc.Message
		end               chan<- LocalDNodeSaveData
		ok                []bool
		started           bool
		number            int
		dnodeid           string
		dnodecount        int
		threshold         int
		paillierkeylength int
		keytype           string
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
	round7 struct {
		*round6
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

// GetIDs get uid with *big.Int format
func (round *base) GetIDs() (smpc.SortableIDSSlice, error) {
	var ids smpc.SortableIDSSlice
	for _, v := range round.temp.kgRound0Messages {
		uidtmp, err := hex.DecodeString(v.GetFromID())
		if err != nil {
		    return nil,err
		}

		uid,_ := new(big.Int).SetString(string(uidtmp[:]),10)
		ids = append(ids, uid)
	}

	sort.Sort(ids)
	return ids, nil
}

func (round *base) GetDNodeIDIndex(id string) (int, error) {
	if id == "" || len(round.temp.kgRound0Messages) != round.dnodecount {
		return -1, nil
	}

	uidtmp, err := hex.DecodeString(id)
	if err != nil {
	    return -1,err
	}

	idtmp,_ := new(big.Int).SetString(string(uidtmp[:]),10)

	// fixed bug: get wrong index by id
	for i:=0;i<round.dnodecount;i++ {
	    v := big.NewInt(int64(i+1))
	    if v.Cmp(idtmp) == 0 {
		return i,nil
	    }
	}

	/*ids, err := round.GetIDs()
	if err != nil {
		return -1, err
	}

	for k, v := range ids {
		if v.Cmp(idtmp) == 0 {
			return k, nil
		}
	}*/

	return -1, errors.New("get dnode index fail,no found in kgRound0Messages")
}

func (round *base) ResetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

