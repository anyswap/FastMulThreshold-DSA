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

// Package signing MPC implementation of signing 
package signing

import (
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	"math/big"
)

type LocalDNode struct {
	*smpc.BaseDNode
	temp         localTempData
	save         *keygen.LocalDNodeSaveData
	idsign       smpc.SortableIDSSlice
	out          chan<- smpc.Message
	end          chan<- PrePubData
	finalize     bool
	predata      *PrePubData
	txhash       *big.Int
	finalize_end chan<- *big.Int
}

type localTempData struct {
	signRound1Messages,
	signRound2Messages,
	signRound3Messages,
	signRound4Messages,
	signRound4Messages1,
	signRound5Messages,
	signRound6Messages,
	signRound7Messages []smpc.Message

	// temp data (thrown away after sign)

	//round 1
	w1             *big.Int
	u1K            *big.Int
	u1Gamma        *big.Int
	commitU1GammaG *ec2.Commitment

	//round 2
	ukc  *big.Int
	ukc2 *big.Int

	//round 3

	//round 4
	betaU1Star []*big.Int
	betaU1     []*big.Int
	vU1Star    []*big.Int
	vU1        []*big.Int

	//round 5
	alpha1 []*big.Int
	uu1    []*big.Int
	delta1 *big.Int
	sigma1 *big.Int

	//round 6
	deltaSum *big.Int

	//round 7

	//round 8

	//round 9

	//round 10

}

// NewLocalDNode new a DNode data struct for current node
func NewLocalDNode(
	out chan<- smpc.Message,
	end chan<- PrePubData,
	save *keygen.LocalDNodeSaveData,
	idsign smpc.SortableIDSSlice,
	kgid *big.Int,
	threshold int,
	paillierkeylength int,
	finalize bool,
	predata *PrePubData,
	txhash *big.Int,
	finalize_end chan<- *big.Int,
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
		finalize_end: finalize_end,
	}

	p.Id = fmt.Sprintf("%v", kgid)
	fmt.Printf("=========== NewLocalDNode, kgid = %v, p.Id = %v =============\n", kgid, p.Id)

	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.finalize = finalize

	p.temp.signRound1Messages = make([]smpc.Message, threshold)
	p.temp.signRound2Messages = make([]smpc.Message, threshold)
	p.temp.signRound3Messages = make([]smpc.Message, threshold)
	p.temp.signRound4Messages = make([]smpc.Message, threshold)
	p.temp.signRound4Messages1 = make([]smpc.Message, threshold)
	p.temp.signRound5Messages = make([]smpc.Message, threshold)
	p.temp.signRound6Messages = make([]smpc.Message, threshold)
	p.temp.signRound7Messages = make([]smpc.Message, threshold)
	return p
}

// FinalizeRound for gg20
func (p *LocalDNode) FinalizeRound() smpc.Round {
	return newRound8(&p.temp, p.save, p.idsign, p.out, p.end, p.Id, p.ThresHold, p.PaillierKeyLength, p.predata, p.txhash, p.finalize_end)
}

func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound1(&p.temp, p.save, p.idsign, p.out, p.end, p.Id, p.ThresHold, p.PaillierKeyLength)
}

// Start signing start 
func (p *LocalDNode) Start() error {
	return smpc.BaseStart(p)
}

// Update Collect data from other nodes and enter the next round 
func (p *LocalDNode) Update(msg smpc.Message) (ok bool, err error) {
	return smpc.BaseUpdate(p, msg)
}

func (p *LocalDNode) DNodeID() string {
	return p.Id
}

func (p *LocalDNode) SetDNodeID(id string) {
	p.Id = id
}

func (p *LocalDNode) Finalize() bool {
	return p.finalize
}

// checkfull  Check for empty messages 
func checkfull(msg []smpc.Message) bool {
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
		if len(p.temp.signRound1Messages) == p.ThresHold && checkfull(p.temp.signRound1Messages) {
			fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound2Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 2 messages,index = %v ============\n", index)
		p.temp.signRound2Messages[index] = msg
		if len(p.temp.signRound2Messages) == p.ThresHold && checkfull(p.temp.signRound2Messages) {
			fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound3Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 3 messages,index = %v ============\n", index)
		p.temp.signRound3Messages[index] = msg
		if len(p.temp.signRound3Messages) == p.ThresHold && checkfull(p.temp.signRound3Messages) {
			fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound4Message:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages[index] = msg
		if len(p.temp.signRound4Messages) == p.ThresHold && checkfull(p.temp.signRound4Messages) {
			fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound4Message1:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages1[index] = msg
		if len(p.temp.signRound4Messages1) == p.ThresHold && checkfull(p.temp.signRound4Messages1) {
			fmt.Printf("================ StoreMessage,get all 4-1 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound5Message:
		index := msg.GetFromIndex()
		p.temp.signRound5Messages[index] = msg
		if len(p.temp.signRound5Messages) == p.ThresHold && checkfull(p.temp.signRound5Messages) {
			fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *SignRound6Message:
		index := msg.GetFromIndex()
		p.temp.signRound6Messages[index] = msg
		if len(p.temp.signRound6Messages) == p.ThresHold && checkfull(p.temp.signRound6Messages) {
			fmt.Printf("================ StoreMessage,get all 6 messages ==============\n")
			return true, nil
		}
	case *SignRound7Message:
		index := msg.GetFromIndex()
		p.temp.signRound7Messages[index] = msg
		if len(p.temp.signRound7Messages) == p.ThresHold && checkfull(p.temp.signRound7Messages) {
			fmt.Printf("================ StoreMessage,get all 7 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	/*case *smpc.SignRound8Message:
		index := msg.GetFromIndex()
		p.temp.signRound8Messages[index] = msg
		if len(p.temp.signRound8Messages) == p.ThresHold && checkfull(p.temp.signRound8Messages) {
		    fmt.Printf("================ StoreMessage,get all 8 messages ==============\n")
		    return true,nil
		}
	case *smpc.SignRound9Message:
		index := msg.GetFromIndex()
		p.temp.signRound9Messages[index] = msg
		if len(p.temp.signRound9Messages) == p.ThresHold && checkfull(p.temp.signRound9Messages) {
		    fmt.Printf("================ StoreMessage,get all 9 messages ==============\n")
		    return true,nil
		}
	case *smpc.SignRound10Message:
		index := msg.GetFromIndex()
		p.temp.signRound10Messages[index] = msg
		if len(p.temp.signRound10Messages) == p.ThresHold && checkfull(p.temp.signRound10Messages) {
		    fmt.Printf("================ StoreMessage,get all 10 messages ==============\n")
		    return true,nil
		}*/
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}
