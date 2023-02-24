/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package smpc

import (
	"errors"
	"fmt"
	"sync"
)

// DNode base interface of local dnode
type DNode interface {
	Start() error
	Update(msg Message) (ok bool, err error)
	FirstRound() Round
	DNodeID() string
	StoreMessage(msg Message) (bool, error)
	DulMessage(msg Message) bool
	SetDNodeID(id string)
	Finalize() bool
	FinalizeRound() Round
	CheckforMsgToEnodeTee(msg Message) bool

	// Private lifecycle methods
	setRound(Round) error
	Round() Round
	advance()
	lock()
	unlock()
}

// BaseDNode the base type of LocalDNode 
type BaseDNode struct {
	mtx               sync.Mutex
	rnd               Round
	ID                string
	DNodeCountInGroup int
	ThresHold         int
	PaillierKeyLength int
	KeyType           string
	MsgPrex string
	TeeOut               chan string 
	Tee bool
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

// Round get the round of current dnode
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

// BaseStart begin to run first round
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

// BaseUpdate an implementation of Update that is shared across the different types of parties (keygen, signing, dynamic groups)
func BaseUpdate(p DNode, msg Message) (ok bool, err error) {
	p.lock() // data is written to P state below

	if p.Round() != nil {
		ok, err := p.StoreMessage(msg)
		if err != nil || !ok {
			//fmt.Printf("==========================BaseUpdate,store msg fail,msg = %v,err = %v=====================\n",msg,err)
			p.unlock()
			return false, err
		}

		if _, err := p.Round().Update(); err != nil {
			p.unlock() // recursive so can't defer after return
			return false, err
		}

		if p.Round().CanProceed() {
			if p.advance(); p.Round() != nil {
				if err := p.Round().Start(); err != nil {
					fmt.Printf("==========================BaseUpdate,round start fail,msg,err = %v=====================\n",msg,err)
					p.unlock() // recursive so can't defer after return
					return false, err
				}
				////fix bug: if the msg is the last one arrive,it must update
				_,err = p.Round().Update()
				if err == nil {
				    if p.Round().CanProceed() {
					if p.advance(); p.Round() != nil {
					    if err := p.Round().Start(); err != nil {
						    p.unlock() // recursive so can't defer after return
						    return false, err
					    }
					}
				    }
				}
				p.Round().ResetOK()  //reset the Update
				////
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

