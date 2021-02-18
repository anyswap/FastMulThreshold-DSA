package keygen 

import (
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"math/big"
	"errors"
	"sort"
	"fmt"
    )

type (
	base struct {
		Save   *dcrm.LocalDNodeSaveData 
		temp    *localTempData
		out     chan<- dcrm.Message 
		end     chan<- dcrm.LocalDNodeSaveData
		ok      []bool
		started bool
		number  int
		dnodeid string
		dnodecount int
		threshold int
		paillierkeylength int
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
	    fmt.Printf("=========== round.CanProceed,not start, round.number = %v ============\n",round.number)
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			fmt.Printf("=========== round.CanProceed,not ok, round.number = %v ============\n",round.number)
			return false
		}
	}
	return true
}

func (round *base) GetIds() (dcrm.SortableIDSSlice,error) {
    var ids dcrm.SortableIDSSlice
    for _,v := range round.temp.kgRound0Messages {
	uid,ok := new(big.Int).SetString(v.GetFromID(),10)
	if !ok {
	    return nil,errors.New("get uid fail")
	}

	ids = append(ids, uid)
    }
    
    sort.Sort(ids)
    return ids,nil
}

func (round *base) GetDNodeIDIndex(id string) (int,error) {
    if id == "" || len(round.temp.kgRound0Messages) != round.dnodecount {
	return -1,nil
    }

    idtmp,ok := new(big.Int).SetString(id,10)
    if !ok {
	return -1,errors.New("get id big number fail.")
    }

    ids,err := round.GetIds()
    if err != nil {
	return -1,err
    }

    for k,v := range ids {
	if v.Cmp(idtmp) == 0 {
	    return k,nil
	}
    }

    return -1,errors.New("get dnode index fail,no found in kgRound0Messages")
}

func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

