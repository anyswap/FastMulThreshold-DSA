package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

var (
	zero = big.NewInt(0)
)

func newRound0(save *LocalDNodeSaveData, temp *localTempData, out chan<- smpc.Message, end chan<- LocalDNodeSaveData, dnodeid string, dnodecount int, threshold int, paillierkeylength int) smpc.Round {
	return &round0{
		&base{save, temp, out, end, make([]bool, dnodecount), false, 0, dnodeid, dnodecount, threshold, paillierkeylength}}
}

// Start  Broadcast current dnode ID to other nodes 
func (round *round0) Start() error {
	if round.started {
		fmt.Printf("============= round0.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 0
	round.started = true
	round.resetOK()

	kg := &KGRound0Message{
		KGRoundMessage: new(KGRoundMessage),
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(-1)

	round.temp.kgRound0Messages = append(round.temp.kgRound0Messages, kg)
	round.out <- kg
	fmt.Printf("============= round0.start success, current node id = %v =======\n", round.dnodeid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round0) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound0Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round0) Update() (bool, error) {
	for j, msg := range round.temp.kgRound0Messages {
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
func (round *round0) NextRound() smpc.Round {
	round.started = false
	return &round1{round}
}
