package signing

import (
	"errors"
	"fmt"
	//"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func (round *round3) Start() error {
	if round.started {
		fmt.Printf("============= round3.start fail =======\n")
		return errors.New("ed sign,round3 already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	srm := &SignRound3Message{
		SignRoundMessage: new(SignRoundMessage),
		DR:               round.temp.DR,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound3Messages[cur_index] = srm
	round.out <- srm

	fmt.Printf("============= ed sign,round3.start success, current node id = %v =======\n", round.kgid)
	return nil
}

func (round *round3) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, error) {
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) NextRound() smpc.Round {
	//fmt.Printf("========= round.next round ========\n")
	round.started = false
	return &round4{round}
}
