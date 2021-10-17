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

// Package keygen ED MPC implementation of generating pubkey 
package keygen

import (
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"encoding/hex"
	cryptorand "crypto/rand"
	"io"
)

// LocalDNode current local node
type LocalDNode struct {
	*smpc.BaseDNode
	temp localTempData
	data LocalDNodeSaveData
	out  chan<- smpc.Message
	end  chan<- LocalDNodeSaveData
}

// localTempData  Store some data of MPC calculation process 
type localTempData struct {
	kgRound0Messages,
	kgRound1Messages,
	kgRound2Messages,
	kgRound3Messages,
	kgRound4Messages,
	kgRound5Messages []smpc.Message

	// temp data (thrown away after keygen)

	//round 1
	sk   [64]byte
	pk   [32]byte
	DPk  [64]byte
	zkPk [64]byte

	//round 2

	//round 3

	//round 4
	cfsBBytes [][32]byte
	uids      [][32]byte

	//round 5

	//round 6

	//round 7
}

// NewLocalDNode new a DNode data struct for current node
func NewLocalDNode(
	out chan<- smpc.Message,
	end chan<- LocalDNodeSaveData,
	DNodeCountInGroup int,
	threshold int,
) smpc.DNode {

	data := NewLocalDNodeSaveData(DNodeCountInGroup)
	p := &LocalDNode{
		BaseDNode: new(smpc.BaseDNode),
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	rand := cryptorand.Reader
	var id [32]byte
	if _, err := io.ReadFull(rand, id[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, id)")
		return nil
	}

	var zero [32]byte
	var one [32]byte
	one[0] = 1
	ed.ScMulAdd(&id, &id, &one, &zero)

	p.ID = hex.EncodeToString(id[:])
	//uid := smpc.GetRandomIntFromZn(secp256k1.S256().N)
	//p.ID = fmt.Sprintf("%v",uid)
	fmt.Printf("=========== ed,NewLocalDNode, id = %v, p.ID = %v =============\n", id, p.ID)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold

	p.temp.kgRound0Messages = make([]smpc.Message, 0)
	p.temp.kgRound1Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound3Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound4Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound5Messages = make([]smpc.Message, DNodeCountInGroup)
	return p
}

// FirstRound first round
func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound0(&p.data, &p.temp, p.out, p.end, p.ID, p.DNodeCountInGroup, p.ThresHold)
}

// FinalizeRound get finalize round
func (p *LocalDNode) FinalizeRound() smpc.Round {
	return nil
}

// Finalize weather gg20 round
func (p *LocalDNode) Finalize() bool {
	return false
}

// Start generating pubkey start 
func (p *LocalDNode) Start() error {
	return smpc.BaseStart(p)
}

// Update Collect data from other nodes and enter the next round 
func (p *LocalDNode) Update(msg smpc.Message) (ok bool, err error) {
	return smpc.BaseUpdate(p, msg)
}

// DNodeID get the ID of current DNode
func (p *LocalDNode) DNodeID() string { //lower
	return p.ID
}

// SetDNodeID set the ID of current DNode
func (p *LocalDNode) SetDNodeID(id string) {
	p.ID = id
}

// CheckFull  Check for empty messages 
func CheckFull(msg []smpc.Message) bool {
	if len(msg) == 0 {
		return false
	}

	for _, v := range msg {
		if v == nil {
			return false
		}
	}

	return true
}

// StoreMessage Collect data from other nodes
func (p *LocalDNode) StoreMessage(msg smpc.Message) (bool, error) {
	switch msg.(type) {
	case *KGRound0Message:
		if len(p.temp.kgRound0Messages) < p.DNodeCountInGroup {
			p.temp.kgRound0Messages = append(p.temp.kgRound0Messages, msg)
		}

		if len(p.temp.kgRound0Messages) == p.DNodeCountInGroup {
			//fmt.Printf("================ StoreMessage,get all 0 messages ==============\n")
			//time.Sleep(time.Duration(120) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound1Message:
		index := msg.GetFromIndex()
		p.temp.kgRound1Messages[index] = msg
		//m := msg.(*KGRound1Message)
		//p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.kgRound1Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound1Messages) {
			//fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound2Message:
		index := msg.GetFromIndex()
		p.temp.kgRound2Messages[index] = msg
		if len(p.temp.kgRound2Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound2Messages) {
			//fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
			return true, nil
		}
	case *KGRound3Message:
		index := msg.GetFromIndex()
		p.temp.kgRound3Messages[index] = msg
		if len(p.temp.kgRound3Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound3Messages) {
			//fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
			return true, nil
		}
	case *KGRound4Message:
		index := msg.GetFromIndex()
		//m := msg.(*KGRound4Message)
		//p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		p.temp.kgRound4Messages[index] = msg
		if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound4Messages) {
			//fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
			return true, nil
		}
	case *KGRound5Message:
		index := msg.GetFromIndex()
		p.temp.kgRound5Messages[index] = msg
		if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages) {
			//fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
			return true, nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}
