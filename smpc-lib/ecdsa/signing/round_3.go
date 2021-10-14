package signing

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
)

// Start broacast Kc
func (round *round3) Start() error {
	if round.started {
		fmt.Printf("============= round3.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	cur_index, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	fmt.Printf("============ round3.start, kc = %v, cur_index = %v ===========\n", round.temp.ukc)
	srm := &SignRound3Message{
		SignRoundMessage: new(SignRoundMessage),
		Kc:               round.temp.ukc,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound3Messages[cur_index] = srm
	round.out <- srm

	fmt.Printf("============= round3.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round3) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
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

// NextRound enter next round
func (round *round3) NextRound() smpc.Round {
	round.started = false
	return &round4{round}
}
