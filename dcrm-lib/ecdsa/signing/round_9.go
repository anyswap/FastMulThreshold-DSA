package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
)

func (round *round9) Start() error {
	if round.started {
	    fmt.Printf("============= round9.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 9
	round.started = true
	round.resetOK()

	msg7,_ := round.temp.signRound7Messages[0].(*dcrm.SignRound7Message)
	s := msg7.Us1

	for k,_ := range round.idsign {
	    if k == 0 {
		continue
	    }
	    
	    msg7,_ := round.temp.signRound7Messages[k].(*dcrm.SignRound7Message)
	    s = new(big.Int).Add(s,msg7.Us1)
	}
	s = new(big.Int).Mod(s, secp256k1.S256().N)

	round.finalize_end <- s
	fmt.Printf("============= round9.start success, current node id = %v =======\n",round.kgid)
	return nil
}

func (round *round9) CanAccept(msg dcrm.Message) bool {
	return false
}

func (round *round9) Update() (bool, error) {
	return false, nil
}

func (round *round9) NextRound() dcrm.Round {
    return nil
}

