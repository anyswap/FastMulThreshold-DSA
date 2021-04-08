package signing 

import (
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	"math/big"
	"errors"
	"strings"
	"fmt"
	"encoding/hex"
    )

type (
	base struct {
		temp    *localTempData
		save   *keygen.LocalDNodeSaveData
		idsign smpc.SortableIDSSlice
		out     chan<- smpc.Message 
		end     chan<- EdSignData
		ok      []bool
		started bool
		number  int
		kgid string
		threshold int
		paillierkeylength int
		predata *PrePubData 
		txhash *big.Int
		finalize_end chan<- *big.Int 
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

func (round *base) GetIds() (smpc.SortableIDSSlice,error) {
    return round.idsign,nil
}

func (round *base) GetDNodeIDIndex(id string) (int,error) {
    if id == "" {
	return -1,nil
    }

    //idtmp,ok := new(big.Int).SetString(id,10)
    //if !ok {
//	return -1,errors.New("get id big number fail.")
    //}

    /*uidtmp, _ := hex.DecodeString(id)
    uid := new(big.Int).SetBytes(uidtmp[:])
    for k,v := range round.idsign {
	if v.Cmp(uid) == 0 {
	    return k,nil
	}
    }*/

    for k,v := range round.idsign {
	var id2 [32]byte
	copy(id2[:],v.Bytes())
	if strings.EqualFold(hex.EncodeToString(id2[:]),id) {
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

