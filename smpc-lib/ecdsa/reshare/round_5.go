package reshare 

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func (round *round5) Start() error {
	if round.started {
	    return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	round.end <- *round.Save

	fmt.Printf("========= round5 start success ==========\n")
	return nil
}

func (round *round5) CanAccept(msg smpc.Message) bool {
	return false
}

func (round *round5) Update() (bool, error) {
	return false, nil
}

func (round *round5) NextRound() smpc.Round {
	return nil 
}

