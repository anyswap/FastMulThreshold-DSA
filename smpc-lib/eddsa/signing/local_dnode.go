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

// Package signing ED MPC implementation of signing
package signing

import (
	"fmt"
	"time"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/keygen"
	"math/big"
)

// LocalDNode current local node
type LocalDNode struct {
	*smpc.BaseDNode
	temp         localTempData
	save         *keygen.LocalDNodeSaveData
	idsign       smpc.SortableIDSSlice
	out          chan<- smpc.Message
	end          chan<- EdSignData
	finalize     bool
	predata      *PrePubData //useness for ed
	txhash       *big.Int
	finalizeend chan<- *big.Int //useness for ed
}

// localTempData  Store some data of MPC calculation process 
type localTempData struct {
	signRound1Messages,
	signRound2Messages,
	signRound3Messages,
	signRound4Messages,
	signRound5Messages,
	signRound6Messages []smpc.Message

	// temp data (thrown away after sign)

	//round 1
	uids    [][32]byte
	sk      [64]byte
	tsk     [32]byte
	pkfinal [32]byte
	message []byte

	DR  [64]byte
	zkR [64]byte
	r   [32]byte

	//round 2

	//round 3

	//round 4
	s           [32]byte
	sBBytes     [32]byte
	DSB         [64]byte
	FinalRBytes [32]byte

	//round 5

	//round 6

	//round 7
}

// NewLocalDNode new a DNode data struct for current node
func NewLocalDNode(
	out chan<- smpc.Message,
	end chan<- EdSignData,
	save *keygen.LocalDNodeSaveData,
	idsign smpc.SortableIDSSlice,
	kgid *big.Int,
	threshold int,
	paillierkeylength int,
	finalize bool,
	predata *PrePubData, //nil for ed
	txhash *big.Int,
	finalizeend chan<- *big.Int, //useness for ed
) smpc.DNode {

	p := &LocalDNode{
		BaseDNode:    new(smpc.BaseDNode),
		save:         save,
		idsign:       idsign,
		temp:         localTempData{},
		out:          out,
		end:          end,
		predata:      predata,
		txhash:       txhash,
		finalizeend: finalizeend,
	}

	var id [32]byte
	copy(id[:], kgid.Bytes())
	p.ID = hex.EncodeToString(id[:])

	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.finalize = finalize

	p.temp.signRound1Messages = make([]smpc.Message, threshold)
	p.temp.signRound2Messages = make([]smpc.Message, threshold)
	p.temp.signRound3Messages = make([]smpc.Message, threshold)
	p.temp.signRound4Messages = make([]smpc.Message, threshold)
	p.temp.signRound5Messages = make([]smpc.Message, threshold)
	p.temp.signRound6Messages = make([]smpc.Message, threshold)
	return p
}

// FinalizeRound get finalize round
func (p *LocalDNode) FinalizeRound() smpc.Round {
	return nil // nil for ed
}

// FirstRound first round
func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound1(&p.temp, p.save, p.idsign, p.out, p.end, p.ID, p.ThresHold, p.PaillierKeyLength, p.txhash)
}

// Start ed signing start 
func (p *LocalDNode) Start() error {
	return smpc.BaseStart(p)
}

// Update Collect data from other nodes and enter the next round 
func (p *LocalDNode) Update(msg smpc.Message) (ok bool, err error) {
	return smpc.BaseUpdate(p, msg)
}

// DNodeID get the ID of current DNode
func (p *LocalDNode) DNodeID() string {
	return p.ID
}

// SetDNodeID set the ID of current DNode
// p.ID : enode --> DoubleHash --> index+1 --> Sprintf(index+1) --> []byte( Sprintf(index+1) ) --> EncodeToString
// *big.Int format: index+1
// string format: EncodeToString
func (p *LocalDNode) SetDNodeID(id string) {
	p.ID = hex.EncodeToString([]byte(id))
}

// Finalize weather gg20 round
func (p *LocalDNode) Finalize() bool {
	return p.finalize
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
	case *SignRound1Message:
		index := msg.GetFromIndex()
		p.temp.signRound1Messages[index] = msg
		if len(p.temp.signRound1Messages) == p.ThresHold && CheckFull(p.temp.signRound1Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 1 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *SignRound2Message:
		index := msg.GetFromIndex()
		//fmt.Printf("================ StoreMessage,get 2 messages,index = %v ============\n", index)
		p.temp.signRound2Messages[index] = msg
		if len(p.temp.signRound2Messages) == p.ThresHold && CheckFull(p.temp.signRound2Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 2 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *SignRound3Message:
		index := msg.GetFromIndex()
		//fmt.Printf("================ StoreMessage,get 3 messages,index = %v ============\n", index)
		p.temp.signRound3Messages[index] = msg
		if len(p.temp.signRound3Messages) == p.ThresHold && CheckFull(p.temp.signRound3Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 3 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *SignRound4Message:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages[index] = msg
		if len(p.temp.signRound4Messages) == p.ThresHold && CheckFull(p.temp.signRound4Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 4 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *SignRound5Message:
		index := msg.GetFromIndex()
		p.temp.signRound5Messages[index] = msg
		if len(p.temp.signRound5Messages) == p.ThresHold && CheckFull(p.temp.signRound5Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 5 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *SignRound6Message:
		index := msg.GetFromIndex()
		p.temp.signRound6Messages[index] = msg
		if len(p.temp.signRound6Messages) == p.ThresHold && CheckFull(p.temp.signRound6Messages) {
			fmt.Printf("================ StoreMessage,get all ed sign 6 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}

