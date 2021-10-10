package signing

import (
	"errors"
	"fmt"
	//"math/big"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func (round *round2) Start() error {
	if round.started {
		fmt.Printf("============= round2.start fail =======\n")
		return errors.New("ed sign,round2 already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	srm := &SignRound2Message{
		SignRoundMessage: new(SignRoundMessage),
		ZkR:              round.temp.zkR,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound2Messages[cur_index] = srm
	round.out <- srm

	fmt.Printf("============= ed sign,round2.start success, current node id = %v =======\n", round.kgid)
	return nil
}

func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, error) {
	for j, msg := range round.temp.signRound2Messages {
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

func (round *round2) NextRound() smpc.Round {
	//fmt.Printf("========= round.next round ========\n")
	round.started = false
	return &round3{round}
}
