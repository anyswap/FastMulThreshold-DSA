package reshare 

import (
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	"math/big"
	"errors"
	"sort"
	"fmt"
    )

type (
	base struct {
		Save   *keygen.LocalDNodeSaveData 
		temp    *localTempData
		out     chan<- smpc.Message 
		end     chan<- keygen.LocalDNodeSaveData
		ok      []bool
		started bool
		number  int
		dnodeid string
		dnodecount int
		threshold int
		paillierkeylength int
		oldnode bool
		//add for check msg0
		idreshare smpc.SortableIDSSlice
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

//get from all nodes
func (round *base) GetIds() (smpc.SortableIDSSlice,error) {
    var ids smpc.SortableIDSSlice
    for _,v := range round.temp.reshareRound0Messages {
	uid,ok := new(big.Int).SetString(v.GetFromID(),10)
	if !ok {
	    return nil,errors.New("get uid fail")
	}

	ids = append(ids, uid)
    }
    
    sort.Sort(ids)
    return ids,nil
}

//get from threshold group
func (round *base) GetDNodeIDIndex(id string) (int,error) {
    if id == "" {
	return -1,nil
    }

    idtmp,ok := new(big.Int).SetString(id,10)
    if !ok {
	return -1,errors.New("get id big number fail.")
    }

    for k,v := range round.idreshare {
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

