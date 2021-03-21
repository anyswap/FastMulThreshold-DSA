package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
)

func (round *round6) Start() error {
	if round.started {
	    fmt.Printf("============= round6.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 6
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
	    return err
	}

	msg5,_ := round.temp.signRound5Messages[0].(*SignRound5Message)
	deltaSum := msg5.Delta1

	for k,_ := range round.idsign {
	    if k == 0 {
		continue
	    }
		
	    msg5,_ := round.temp.signRound5Messages[k].(*SignRound5Message)
	    deltaSum = new(big.Int).Add(deltaSum,msg5.Delta1)
	}
	deltaSum = new(big.Int).Mod(deltaSum, secp256k1.S256().N)
	round.temp.deltaSum = deltaSum

	u1GammaZKProof := ec2.ZkUProve(round.temp.u1Gamma)
	
	srm := &SignRound6Message{
	    SignRoundMessage: new(SignRoundMessage),
	    CommU1D:round.temp.commitU1GammaG.D,
	    U1GammaZKProof:u1GammaZKProof,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound6Messages[cur_index] = srm
	round.out <-srm
    
	fmt.Printf("============= round6.start success, current node id = %v =============\n",round.kgid)

	return nil
}

func (round *round6) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*SignRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round6) Update() (bool, error) {
	for j, msg := range round.temp.signRound6Messages {
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

func (round *round6) NextRound() dcrm.Round {
    //fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round7{round}
}

