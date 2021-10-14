
// Package keygen MPC implementation of generating pubkey 
package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/math/random"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

type LocalDNode struct {
	*smpc.BaseDNode
	temp localTempData
	data LocalDNodeSaveData
	out  chan<- smpc.Message
	end  chan<- LocalDNodeSaveData
}

type localMessageStore struct {
	kgRound0Messages,
	kgRound1Messages,
	kgRound2Messages,
	kgRound2Messages1,
	kgRound3Messages,
	kgRound4Messages,
	kgRound5Messages,
	kgRound6Messages,
	kgRound7Messages []smpc.Message
}

type localTempData struct {
	//localMessageStore
	kgRound0Messages,
	kgRound1Messages,
	kgRound2Messages,
	kgRound2Messages1,
	kgRound3Messages,
	kgRound4Messages,
	kgRound5Messages,
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

	//round 2
	u1Shares []*ec2.ShareStruct2

	//round 3

	//round 4

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
) smpc.DNode {

	data := NewLocalDNodeSaveData(DNodeCountInGroup)
	p := &LocalDNode{
		BaseDNode: new(smpc.BaseDNode),
		temp:      localTempData{},
		data:      data,
		out:       out,
		end:       end,
	}

	uid := random.GetRandomIntFromZn(secp256k1.S256().N)
	p.Id = fmt.Sprintf("%v", uid)
	fmt.Printf("=========== NewLocalDNode, uid = %v, p.Id = %v =============\n", uid, p.Id)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.temp.kgRound0Messages = make([]smpc.Message, 0)
	p.temp.kgRound1Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound2Messages1 = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound3Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound4Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound5Messages = make([]smpc.Message, DNodeCountInGroup)
	p.temp.kgRound6Messages = make([]smpc.Message, DNodeCountInGroup)
	return p
}

func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound0(&p.data, &p.temp, p.out, p.end, p.Id, p.DNodeCountInGroup, p.ThresHold, p.PaillierKeyLength)
}

func (p *LocalDNode) FinalizeRound() smpc.Round {
	return nil
}

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

func (p *LocalDNode) DNodeID() string {
	return p.Id
}

func (p *LocalDNode) SetDNodeID(id string) {
	p.Id = id
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
	case *KGRound0Message:
		if len(p.temp.kgRound0Messages) < p.DNodeCountInGroup {
			p.temp.kgRound0Messages = append(p.temp.kgRound0Messages, msg)
		}

		if len(p.temp.kgRound0Messages) == p.DNodeCountInGroup {
			fmt.Printf("================ StoreMessage,get all 0 messages ==============\n")
			//time.Sleep(time.Duration(120) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound1Message:
		index := msg.GetFromIndex()
		p.temp.kgRound1Messages[index] = msg
		m := msg.(*KGRound1Message)
		p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.kgRound1Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound1Messages) {
			fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound2Message:
		index := msg.GetFromIndex()
		p.temp.kgRound2Messages[index] = msg
		if len(p.temp.kgRound2Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound2Messages) {
			fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound2Message1:
		index := msg.GetFromIndex()
		p.temp.kgRound2Messages1[index] = msg
		if len(p.temp.kgRound2Messages1) == p.DNodeCountInGroup && checkfull(p.temp.kgRound2Messages1) {
			fmt.Printf("================ StoreMessage,get all 2-1 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound3Message:
		index := msg.GetFromIndex()
		p.temp.kgRound3Messages[index] = msg
		if len(p.temp.kgRound3Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound3Messages) {
			fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound4Message:
		index := msg.GetFromIndex()
		m := msg.(*KGRound4Message)

		////////add for ntilde zk proof check
		H1 := m.U1NtildeH1H2.H1
		H2 := m.U1NtildeH1H2.H2
		Ntilde := m.U1NtildeH1H2.Ntilde
		pf1 := m.NtildeProof1
		pf2 := m.NtildeProof2
		fmt.Printf("=========================keygen StoreMessage, message 4, curindex = %v, h1 = %v, h2 = %v, ntilde = %v, pf1 = %v, pf2 = %v ===========================\n", index, H1, H2, Ntilde, pf1, pf2)
		if H1.Cmp(H2) == 0 {
			return false, errors.New("h1 and h2 were equal for this mpc node")
		}
		if !pf1.Verify(H1, H2, Ntilde) || !pf2.Verify(H2, H1, Ntilde) {
			return false, errors.New("ntilde zk proof check fail.")
		}
		////////

		p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		p.temp.kgRound4Messages[index] = msg
		if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound4Messages) {
			fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound5Message:
		index := msg.GetFromIndex()
		p.temp.kgRound5Messages[index] = msg
		if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound5Messages) {
			fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	case *KGRound6Message:
		index := msg.GetFromIndex()
		p.temp.kgRound6Messages[index] = msg
		if len(p.temp.kgRound6Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound6Messages) {
			fmt.Printf("================ StoreMessage,get all 6 messages ==============\n")
			//time.Sleep(time.Duration(20) * time.Second) //tmp code
			return true, nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}
