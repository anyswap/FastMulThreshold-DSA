package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
)

func newRound8(temp *localTempData,save *dcrm.LocalDNodeSaveData,idsign dcrm.SortableIDSSlice,out chan<- dcrm.Message,end chan<-dcrm.PrePubData,kgid string,threshold int,paillierkeylength int,predata *dcrm.PrePubData,txhash *big.Int,finalize_end chan<- *big.Int) dcrm.Round {
    return &round8{
		&base{temp,save,idsign,out,end,make([]bool,threshold),false,0,kgid,threshold,paillierkeylength,predata,txhash,finalize_end}}
}

func (round *round8) Start() error {
	if round.started {
	    fmt.Printf("============= round8.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 8
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
	    return err
	}

	mk1 := new(big.Int).Mul(round.txhash, round.predata.K1)
	rSigma1 := new(big.Int).Mul(round.predata.R,round.predata.Sigma1)
	us1 := new(big.Int).Add(mk1, rSigma1)
	us1 = new(big.Int).Mod(us1, secp256k1.S256().N)

	srm := &dcrm.SignRound7Message{
	    SignRoundMessage: new(dcrm.SignRoundMessage),
	    Us1:us1,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound7Messages[cur_index] = srm
	round.out <- srm

	fmt.Printf("============= round8.start success, current node id = %v =======\n",round.kgid)
	return nil
}

func (round *round8) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*dcrm.SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round8) Update() (bool, error) {
	for j, msg := range round.temp.signRound7Messages {
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

func (round *round8) NextRound() dcrm.Round {
    fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round9{round}
}

