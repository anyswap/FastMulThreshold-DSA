package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
)

func (round *round3) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
	    return err
	}

	kg := &dcrm.KGRound3Message{
	    KGRoundMessage:new(dcrm.KGRoundMessage),
	    ComU1GD:round.temp.commitU1G.D,
	    ComC1GD:round.temp.commitC1G.D,
	    U1PolyGG:round.temp.u1PolyG.PolyG,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(cur_index)
	round.temp.kgRound3Messages[cur_index] = kg
	round.out <-kg

	fmt.Printf("========= round3 start success, u1polygg = %v, k = %v ==========\n",round.temp.u1PolyG.PolyG,cur_index)
	return nil
}

func (round *round3) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*dcrm.KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, error) {
	for j, msg := range round.temp.kgRound3Messages {
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

func (round *round3) NextRound() dcrm.Round {
	round.started = false
	return &round4{round}
}

