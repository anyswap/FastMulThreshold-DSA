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

// Package keygen MPC implementation of generating pubkey 
package keygen

import (
	"errors"
	"fmt"
	"time"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/hex"
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
	kgRound2Messages1,
	kgRound2Messages2,
	kgRound3Messages,
	kgRound3Messages1,
	kgRound4Messages,
	kgRound5Messages,
	kgRound5Messages1,
	kgRound5Messages2,
	kgRound6Messages,
	kgRound7Messages []smpc.Message

	// temp data (thrown away after keygen)

	//round 1
	u1           *big.Int
	u1Poly       *ec2.PolyStruct2
	u1PolyG      *ec2.PolyGStruct2
	commitU1G    *ec2.Commitment
	c1           *big.Int
	commitC1G    *ec2.Commitment
	u1PaillierPk *ec2.PublicKey
	u1PaillierSk *ec2.PrivateKey
	// paillier.N = p*q
	p *big.Int 
	q *big.Int

	//round 2
	u1Shares []*ec2.ShareStruct2

	//round 3

	//round 4
	// Ntilde = p1*p2
	p1 *big.Int
	p2 *big.Int
	commitXiG  *ec2.Commitment

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
	paillierkeylength int,
	keytype string,
) smpc.DNode {

	data := NewLocalDNodeSaveData(DNodeCountInGroup)
	p := &LocalDNode{
		BaseDNode: new(smpc.BaseDNode),
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	uid := random.GetRandomIntFromZn(secp256k1.S256(keytype).N1())
	p.ID = fmt.Sprintf("%v", uid)
	//fmt.Printf("=========== NewLocalDNode, uid = %v, p.ID = %v =============\n", uid, p.ID)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength
	p.KeyType = keytype

	p.temp.kgRound0Messages = make([]smpc.Message, 0)
	p.temp.kgRound1Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages1 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages2 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound3Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound3Messages1 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound4Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound5Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound5Messages1 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound5Messages2 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound6Messages = make([]smpc.Message, DNodeCountInGroup)
	return p
}

// FirstRound first round
func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound0(&p.data, &p.temp, p.out, p.end, p.ID, p.DNodeCountInGroup, p.ThresHold, p.PaillierKeyLength,p.KeyType)
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
func (p *LocalDNode) DNodeID() string {
	return p.ID
}

// SetDNodeID set the ID of current DNode
// p.ID : enode --> DoubleHash --> index+1 --> Sprintf(index+1) --> []byte( Sprintf(index+1) ) --> EncodeToString
// big.Int format: index+1
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

// getFullCount  Check for empty messages 
func getFullCount(msg []smpc.Message) int {
	if len(msg) == 0 {
		return 0
	}

	count := 0 
	for _, v := range msg {
		if v == nil {
			continue
		}

		count++
	}

	return count
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
	case *KGRound0Message:
	    	if find(p.temp.kgRound0Messages,msg) {
		    return true
		}

	case *KGRound1Message:
	    	if find(p.temp.kgRound1Messages,msg) {
		    return true
		}
	case *KGRound2Message:
	    	if find(p.temp.kgRound2Messages,msg) {
		    return true
		}
	case *KGRound2Message1:
	    	if find(p.temp.kgRound2Messages1,msg) {
		    return true
		}
	case *KGRound2Message2:
	    	if find(p.temp.kgRound2Messages2,msg) {
		    return true
		}
	case *KGRound3Message:
	    	if find(p.temp.kgRound3Messages,msg) {
		    return true
		}
	case *KGRound3Message1:
	    	if find(p.temp.kgRound3Messages1,msg) {
		    return true
		}
	case *KGRound4Message:
	    	if find(p.temp.kgRound4Messages,msg) {
		    return true
		}
	case *KGRound5Message:
	    	if find(p.temp.kgRound5Messages,msg) {
		    return true
		}
	case *KGRound5Message1:
	    	if find(p.temp.kgRound5Messages1,msg) {
		    return true
		}
	case *KGRound5Message2:
	    	if find(p.temp.kgRound5Messages2,msg) {
		    return true
		}
	case *KGRound6Message:
	    	if find(p.temp.kgRound6Messages,msg) {
		    return true
		}
	default: // unrecognised message, just ignore!
		log.Info("storemessage,unrecognised message ignored","msg", msg)
		return true
	}

	return false
}

// StoreMessage Collect data from other nodes
func (p *LocalDNode) StoreMessage(msg smpc.Message) (bool, error) {
	switch msg.(type) {
	case *KGRound0Message:
		// fixed bug: node id error
	    	if !find(p.temp.kgRound0Messages,msg) {
		    if len(p.temp.kgRound0Messages) < p.DNodeCountInGroup {
			    p.temp.kgRound0Messages = append(p.temp.kgRound0Messages, msg)
		    }

		    if len(p.temp.kgRound0Messages) == p.DNodeCountInGroup {
			    log.Info("================ StoreMessage,get all ec keygen 0 messages ==============")
			    time.Sleep(time.Duration(1000000)) //tmp code
			    return true, nil
		    }
		}

	case *KGRound1Message:
	    	if find(p.temp.kgRound1Messages,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound1Messages[index] = msg
		m := msg.(*KGRound1Message)
		p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.kgRound1Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound1Messages) {
			log.Info("================ StoreMessage,get all ec keygen 1 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound2Message:
	    	if find(p.temp.kgRound2Messages,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound2Messages[index] = msg
		if len(p.temp.kgRound2Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound2Messages) {
			log.Info("================ StoreMessage,get all ec keygen 2 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound2Message1:
	    	if find(p.temp.kgRound2Messages1,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound2Messages1[index] = msg
		if len(p.temp.kgRound2Messages1) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound2Messages1) {
			log.Info("================ StoreMessage,get all ec keygen 2-1 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound2Message2:
	    	if find(p.temp.kgRound2Messages2,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound2Messages2[index] = msg
		if len(p.temp.kgRound2Messages2) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound2Messages2) {
			log.Info("================ StoreMessage,get all ec keygen 2-2 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound3Message:
	    	if find(p.temp.kgRound3Messages,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound3Messages[index] = msg
		if len(p.temp.kgRound3Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound3Messages) {
			log.Info("================ StoreMessage,get all ec keygen 3 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound3Message1:
	    	if find(p.temp.kgRound3Messages1,msg) {
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound3Messages1[index] = msg
		if len(p.temp.kgRound3Messages1) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound3Messages1) {
			log.Info("================ StoreMessage,get all ec keygen 3-1 messages ==============")
			time.Sleep(time.Duration(1000000)) //tmp code
			return true, nil
		}
	case *KGRound4Message:
	    	if find(p.temp.kgRound4Messages,msg) {
			//if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound4Messages) {
				//return true, nil
			//}
			//fmt.Printf("================ StoreMessage,the msg 4 have exsit already,msg = %v,len = %v ==============\n",msg,getFullCount(p.temp.kgRound4Messages))
			return false,nil
		}

		index := msg.GetFromIndex()
		m := msg.(*KGRound4Message)

		////////add for ntilde zk proof check
		H1 := m.U1NtildeH1H2.H1
		H2 := m.U1NtildeH1H2.H2
		Ntilde := m.U1NtildeH1H2.Ntilde
		pf1 := m.NtildeProof1
		pf2 := m.NtildeProof2
		zero,_ := new(big.Int).SetString("0",10)
		one,_ := new(big.Int).SetString("1",10)
		h1modn := new(big.Int).Mod(H1,Ntilde)
		h2modn := new(big.Int).Mod(H2,Ntilde)
		if h1modn.Cmp(zero) == 0 || h2modn.Cmp(zero) == 0 {
		    log.Error("=========================keygen StoreMessage, message 4, h1 or h2 is equal 0 mod ntilde.===========================")
		    return false,errors.New("h1 or h2 is equal 0 mod Ntilde")
		}
		if h1modn.Cmp(one) == 0 || h2modn.Cmp(one) == 0 {
		    log.Error("=========================keygen StoreMessage, message 4, h1 or h2 is equal 1 mod ntilde.===========================")
		    return false,errors.New("h1 or h2 is equal 1 mod Ntilde")
		}

		if h1modn.Cmp(h2modn) == 0 {
		    log.Error("=========================keygen StoreMessage, message 4, h1 and h2 were equal mod ntilde.===========================")
			return false, errors.New("h1 and h2 were equal mod Ntilde")
		}
		
		if !pf1.Verify(H1, H2, Ntilde) || !pf2.Verify(H2, H1, Ntilde) {
		    log.Error("=========================keygen StoreMessage, message 4, ntilde zk proof check fail. ===========================")
			return false, errors.New("ntilde zk proof check fail")
		}

		p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		p.temp.kgRound4Messages[index] = msg
		log.Info("=========================keygen StoreMessage, message 4 ====================","received msg counts", getFullCount(p.temp.kgRound4Messages))
		if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound4Messages) {
			log.Info("================ StoreMessage,get all ec keygen 4 messages ==============")
			time.Sleep(time.Duration(1000000))
			return true, nil
		}
	case *KGRound5Message:
	    	if find(p.temp.kgRound5Messages,msg) {
			//if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages) {
			//	return true, nil
			//}
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound5Messages[index] = msg
		log.Info("=========================keygen StoreMessage, message 5 =====================","received msg counts", getFullCount(p.temp.kgRound5Messages))
		if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages) {
			log.Info("================ StoreMessage,get all ec keygen 5 messages ==============")
			time.Sleep(time.Duration(1000000))
			return true, nil
		}
	case *KGRound5Message1:
	    	if find(p.temp.kgRound5Messages1,msg) {
			//if len(p.temp.kgRound5Messages1) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages1) {
			//	return true, nil
			//}
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound5Messages1[index] = msg
		log.Info("=========================keygen StoreMessage, message 5-1 ======================","received msg counts", getFullCount(p.temp.kgRound5Messages1))
		if len(p.temp.kgRound5Messages1) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages1) {
			log.Info("================ StoreMessage,get all ec keygen 5-1 messages ==============")
			time.Sleep(time.Duration(1000000))
			return true, nil
		}
	case *KGRound5Message2:
	    	if find(p.temp.kgRound5Messages2,msg) {
			//if len(p.temp.kgRound5Messages2) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages2) {
			//	return true, nil
			//}
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound5Messages2[index] = msg
		log.Info("=========================keygen StoreMessage, message 5-2========================","received msg counts", getFullCount(p.temp.kgRound5Messages2))
		if len(p.temp.kgRound5Messages2) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound5Messages2) {
			log.Info("================ StoreMessage,get all ec keygen 5-2 messages ==============")
			time.Sleep(time.Duration(1000000))
			return true, nil
		}
	case *KGRound6Message:
	    	if find(p.temp.kgRound6Messages,msg) {
			//if len(p.temp.kgRound6Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound6Messages) {
			//	return true, nil
			//}
			return false,nil
		}

		index := msg.GetFromIndex()
		p.temp.kgRound6Messages[index] = msg
		log.Info("=========================keygen StoreMessage, message 6=========================","received msg counts", getFullCount(p.temp.kgRound6Messages))
		if len(p.temp.kgRound6Messages) == p.DNodeCountInGroup && CheckFull(p.temp.kgRound6Messages) {
			log.Info("================ StoreMessage,get all ec keygen 6 messages ==============")
			time.Sleep(time.Duration(1000000))
			return true, nil
		}
	default: // unrecognised message, just ignore!
	log.Info("storemessage,unrecognised message ignored","msg", msg)	
	return false, nil
	}

	return false, nil
}


