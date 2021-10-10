package smpc

import (
	"errors"
	"fmt"
	"sync"
)

type DNode interface {
	Start() error
	Update(msg Message) (ok bool, err error)
	FirstRound() Round
	DNodeID() string
	StoreMessage(msg Message) (bool, error)
	SetDNodeID(id string)
	Finalize() bool
	FinalizeRound() Round

	// Private lifecycle methods
	setRound(Round) error
	Round() Round
	advance()
	lock()
	unlock()
}

type BaseDNode struct {
	mtx               sync.Mutex
	rnd               Round
	Id                string
	DNodeCountInGroup int
	ThresHold         int
	PaillierKeyLength int
}

// -----
// Private lifecycle methods

func (p *BaseDNode) setRound(round Round) error {
	if p.rnd != nil {
		return errors.New("a round is already set on this party")
	}
	p.rnd = round
	return nil
}

func (p *BaseDNode) Round() Round {
	return p.rnd
}

func (p *BaseDNode) advance() {
	p.rnd = p.rnd.NextRound()
}

func (p *BaseDNode) lock() {
	p.mtx.Lock()
}

func (p *BaseDNode) unlock() {
	p.mtx.Unlock()
}

// ----- //

func BaseStart(p DNode) error {
	p.lock()
	defer p.unlock()
	if p.DNodeID() == "" {
		return fmt.Errorf("could not start. this smpc node has an invalid DNodeID: %+v", p.DNodeID())
	}
	if p.Round() != nil {
		return errors.New("could not start. this smpc node is in an unexpected state. use the constructor and Start()")
	}

	if p.Finalize() {
		round := p.FinalizeRound()
		if err := p.setRound(round); err != nil {
			return err
		}
	} else {
		round := p.FirstRound()
		if err := p.setRound(round); err != nil {
			return err
		}
	}

	return p.Round().Start()
}

// an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p DNode, msg Message) (ok bool, err error) {
	p.lock() // data is written to P state below

	if p.Round() != nil {
		fmt.Printf("DNode %s round %d\n", p.DNodeID(), p.Round().RoundNumber())

		ok, err := p.StoreMessage(msg)
		if err != nil || !ok {
			p.unlock()
			return false, err
		}

		if _, err := p.Round().Update(); err != nil {
			fmt.Printf("=========== BaseUpdate,update err = %v ===========\n", err)
			p.unlock() // recursive so can't defer after return
			return false, err
		}

		if p.Round().CanProceed() {
			if p.advance(); p.Round() != nil {
				if err := p.Round().Start(); err != nil {
					p.unlock() // recursive so can't defer after return
					return false, err
				}
			} else {
				// finished! the round implementation will have sent the data through the `end` channel.
				fmt.Printf("DNode %s: finished!\n", p.DNodeID())
			}
			p.unlock()
			return BaseUpdate(p, msg) // re-run round update or finish)
			//return true,nil
		}
		p.unlock()
		return true, nil
	}
	p.unlock()
	return true, nil
}
