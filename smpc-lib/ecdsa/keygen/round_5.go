package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

func (round *round5) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	u1zkUProof := ec2.ZkUProve(round.temp.u1)
	if u1zkUProof == nil {
		return errors.New("zku prove fail.")
	}

	kg := &KGRound5Message{
		KGRoundMessage: new(KGRoundMessage),
		U1zkUProof:     u1zkUProof,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(cur_index)

	round.temp.kgRound5Messages[cur_index] = kg
	round.out <- kg

	fmt.Printf("========= round5 start success ==========\n")
	return nil
}

func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.kgRound5Messages {
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

func (round *round5) NextRound() smpc.Round {
	round.started = false
	return &round6{round}
}
