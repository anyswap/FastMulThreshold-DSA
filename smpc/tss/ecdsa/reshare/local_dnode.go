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

// Package reshare  MPC implementation of reshare 
package reshare

import (
	"errors"
	"fmt"
	"time"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/hex"
)

// LocalDNode current local node
type LocalDNode struct {
	*smpc.BaseDNode
	temp    localTempData
	data    *keygen.LocalDNodeSaveData
	out     chan<- smpc.Message
	end     chan<- keygen.LocalDNodeSaveData
	oldnode bool //the node join the keygen and join the reshare
	oldindex int //the node join the keygen and join the reshare, return it's index in group
	//save for check msg0
	firstround smpc.Round
}

// localTempData  Store some data of MPC calculation process 
type localTempData struct {
	reshareRound0Messages,
	reshareRound1Messages,
	reshareRound2Messages,
	reshareRound2Messages1,
	reshareRound3Messages,
	reshareRound4Messages,
	reshareRound5Messages []smpc.Message

	// temp data (thrown away after keygen)

	//round 1
	w1        *big.Int
	comd      []*big.Int
	skP1Poly  *ec2.PolyStruct2
	skP1PolyG [][]*big.Int

	//round 2
	skP1Shares []*ec2.ShareStruct2

	//round 3
	pkx          *big.Int
	pky          *big.Int
	newskU1      *big.Int
	u1PaillierSk *ec2.PrivateKey
	u1PaillierPk *ec2.PublicKey

	//round 4
	u1NtildeH1H2 *ec2.NtildeH1H2
	u1NtildePrivData *ec2.NtildePrivData

	//round 5

	//round 6

	//round 7
}

// NewLocalDNode new a DNode data struct for current node
func NewLocalDNode(
	out chan<- smpc.Message,
	end chan<- keygen.LocalDNodeSaveData,
	DNodeCountInGroup int,
	threshold int,
	paillierkeylength int,
	sd *keygen.LocalDNodeSaveData,
	oldnode bool,
	oldindex int,
	keytype string,
) smpc.DNode {

	var id string
	if sd != nil {
		id = fmt.Sprintf("%v", sd.CurDNodeID)
	} else {
		uid := random.GetRandomIntFromZn(secp256k1.S256(keytype).N1())
		id = fmt.Sprintf("%v", uid)
	}

	if sd == nil {
		sdtmp := keygen.NewLocalDNodeSaveData(DNodeCountInGroup)
		sd = &sdtmp
	}

	p := &LocalDNode{
		BaseDNode: new(smpc.BaseDNode),
		temp:      localTempData{},
		data:      sd,
		out:       out,
		end:       end,
		oldnode:   oldnode,
		oldindex:   oldindex,
	}

	p.ID = id
	fmt.Printf("=========== reshare.NewLocalDNode,p.ID = %v,threshold = %v,DNodeCountInGroup = %v =============\n", p.ID, threshold, DNodeCountInGroup)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength
	p.KeyType = keytype

	p.temp.reshareRound0Messages = make([]smpc.Message, 0)
	p.temp.reshareRound1Messages = make([]smpc.Message, threshold)
	p.temp.reshareRound2Messages = make([]smpc.Message, threshold)
	p.temp.reshareRound2Messages1 = make([]smpc.Message, threshold)
	p.temp.reshareRound3Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.reshareRound4Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.reshareRound5Messages = make([]smpc.Message, DNodeCountInGroup)
	return p
}

// FirstRound first round
func (p *LocalDNode) FirstRound() smpc.Round {
	fr := newRound0(p.data, &p.temp, p.out, p.end, p.ID, p.DNodeCountInGroup, p.ThresHold, p.PaillierKeyLength, p.oldnode,p.oldindex,p.KeyType)
	p.firstround = fr
	return fr
}

// FinalizeRound get finalize round
func (p *LocalDNode) FinalizeRound() smpc.Round {
	return nil
}

// Finalize weather gg20 round
func (p *LocalDNode) Finalize() bool {
	return false
}

// Start reshare start 
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

func find(l []smpc.Message,msg smpc.Message) bool {
    if msg == nil || l == nil {
	return true
    }

    for _,v := range l {
	    if v == nil {
		    continue
	    }

	if v.GetMsgType() == msg.GetMsgType() && v.GetFromID() == msg.GetFromID() {
	    return true
	}
    }

    return false
}

// DulMessage check whether the msg already exists in the list.
func (p *LocalDNode) DulMessage(msg smpc.Message) bool {
	switch msg.(type) {
	case *ReRound0Message:
	    if find(p.temp.reshareRound0Messages,msg) {
		return true
	    }
	case *ReRound1Message:
	    if find(p.temp.reshareRound1Messages,msg) {
		return true
	    }
	case *ReRound2Message:
	    if find(p.temp.reshareRound2Messages,msg) {
		return true
	    }
	case *ReRound2Message1:
	    if find(p.temp.reshareRound2Messages1,msg) {
		return true
	    }
	case *ReRound3Message:
	    if find(p.temp.reshareRound3Messages,msg) {
		return true
	    }
	case *ReRound4Message:
	    if find(p.temp.reshareRound4Messages,msg) {
		return true
	    }
	case *ReRound5Message:
	    if find(p.temp.reshareRound5Messages,msg) {
		return true
	    }
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return true
	}

	return false
}

func (p *LocalDNode) CheckforMsgToEnodeTee(msg smpc.Message) bool {
    return false
}

// StoreMessage Collect data from other nodes
func (p *LocalDNode) StoreMessage(msg smpc.Message) (bool, error) {
	switch msg.(type) {
	case *ReRound0Message:
		if !find(p.temp.reshareRound0Messages,msg) {
		    if len(p.temp.reshareRound0Messages) < p.DNodeCountInGroup {
			    p.temp.reshareRound0Messages = append(p.temp.reshareRound0Messages, msg)
		    }

		    if len(p.temp.reshareRound0Messages) == p.DNodeCountInGroup {
			    fmt.Printf("================ StoreMessage,get all ec reshare 0 messages ==============\n")
			    time.Sleep(time.Duration(1000000)) //tmp code
			    return true, nil
		    }
		}
	case *ReRound1Message:
		if find(p.temp.reshareRound1Messages,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		p.temp.reshareRound1Messages[index] = msg
		if len(p.temp.reshareRound1Messages) == p.ThresHold && CheckFull(p.temp.reshareRound1Messages) {
			fmt.Printf("================ StoreMessage,get all ec reshare 1 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *ReRound2Message:
		if find(p.temp.reshareRound2Messages,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		p.temp.reshareRound2Messages[index] = msg
		if len(p.temp.reshareRound2Messages) == p.ThresHold && CheckFull(p.temp.reshareRound2Messages) {
			fmt.Printf("================ StoreMessage,get all ec reshare 2 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *ReRound2Message1:
		if find(p.temp.reshareRound2Messages1,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		p.temp.reshareRound2Messages1[index] = msg
		if len(p.temp.reshareRound2Messages1) == p.ThresHold && CheckFull(p.temp.reshareRound2Messages1) {
			fmt.Printf("================ StoreMessage,get all ec reshare 2-1 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *ReRound3Message:
		if find(p.temp.reshareRound3Messages,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		p.temp.reshareRound3Messages[index] = msg
		m := msg.(*ReRound3Message)
		p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.reshareRound3Messages) == p.DNodeCountInGroup && CheckFull(p.temp.reshareRound3Messages) {
			fmt.Printf("================ StoreMessage,get all ec reshare 3 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *ReRound4Message:
		if find(p.temp.reshareRound4Messages,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		m := msg.(*ReRound4Message)

		////////add for ntilde zk proof check
		H1 := m.U1NtildeH1H2.H1
		H2 := m.U1NtildeH1H2.H2
		Ntilde := m.U1NtildeH1H2.Ntilde
		pf1 := m.NtildeProof1
		pf2 := m.NtildeProof2
		if H1.Cmp(H2) == 0 {
			return false, errors.New("h1 and h2 were equal for this mpc node")
		}
		if !pf1.Verify(H1, H2, Ntilde) || !pf2.Verify(H2, H1, Ntilde) {
			return false, errors.New("ntilde zk proof check fail")
		}
		////////

		p.temp.reshareRound4Messages[index] = msg
		p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		if len(p.temp.reshareRound4Messages) == p.DNodeCountInGroup && CheckFull(p.temp.reshareRound4Messages) {
			fmt.Printf("================ StoreMessage,get all ec reshare 4 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *ReRound5Message:
		if find(p.temp.reshareRound5Messages,msg) {
		    return false,nil
		}
		
		index := msg.GetFromIndex()
		p.temp.reshareRound5Messages[index] = msg
		if len(p.temp.reshareRound5Messages) == p.DNodeCountInGroup && CheckFull(p.temp.reshareRound5Messages) {
			fmt.Printf("================ StoreMessage,get all ec reshare 5 messages ==============\n")
			time.Sleep(time.Duration(1000000)) //tmp code

			///check newskok
			for _, v := range p.temp.reshareRound5Messages {
				m := v.(*ReRound5Message)
				if m.NewSkOk != "TRUE" {
					return false, errors.New("check newsk ok fail")
				}
			}
			////

			return true, nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}

// CheckReshareMsg0 add for check msg0
func (p *LocalDNode) CheckReshareMsg0(msg smpc.Message) bool {
	switch msg.(type) {
	case *ReRound0Message:
		if len(p.temp.reshareRound0Messages) == (p.DNodeCountInGroup - 1) {
			p.temp.reshareRound0Messages = append(p.temp.reshareRound0Messages, msg)
		}

		return len(p.temp.reshareRound0Messages) == p.DNodeCountInGroup
	default:
		return false
	}

	return false
}

// SetIDReshare set all IDs of nodes in group to local dnode
func (p *LocalDNode) SetIDReshare(ids smpc.SortableIDSSlice) {
	fr, ok := p.firstround.(*round0)
	if ok {
		fr.idreshare = ids
	}
}
