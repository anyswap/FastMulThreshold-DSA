package keygen

import (
	"fmt"
	//"time"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"math/big"
)

type LocalDNode struct {
	*dcrm.BaseDNode
	temp localTempData
	data LocalDNodeSaveData 
	out chan<- dcrm.Message
	end chan<- LocalDNodeSaveData
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
	kgRound7Messages []dcrm.Message
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
	kgRound7Messages []dcrm.Message

	// temp data (thrown away after keygen)

	//round 1
	u1 *big.Int
	u1Poly *ec2.PolyStruct2
	u1PolyG *ec2.PolyGStruct2
	commitU1G *ec2.Commitment
	c1 *big.Int
	commitC1G *ec2.Commitment
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

func NewLocalDNode(
	out chan<- dcrm.Message,
	end chan<- LocalDNodeSaveData,
	DNodeCountInGroup int,
	threshold int,
	paillierkeylength int,
) dcrm.DNode {

    	data := NewLocalDNodeSaveData(DNodeCountInGroup)
	p := &LocalDNode{
		BaseDNode: new(dcrm.BaseDNode),
		temp:      localTempData{},
		data:	   data,
		out:       out,
		end:       end,
	}

	uid := dcrm.GetRandomIntFromZn(secp256k1.S256().N)
	p.Id = fmt.Sprintf("%v",uid)
	fmt.Printf("=========== NewLocalDNode, uid = %v, p.Id = %v =============\n",uid,p.Id)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.temp.kgRound0Messages = make([]dcrm.Message,0)
	p.temp.kgRound1Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound2Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound2Messages1 = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound3Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound4Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound5Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound6Messages = make([]dcrm.Message,DNodeCountInGroup)
	return p
}

func (p *LocalDNode) FirstRound() dcrm.Round {
	return newRound0(&p.data, &p.temp,p.out, p.end,p.Id,p.DNodeCountInGroup,p.ThresHold,p.PaillierKeyLength)
}

func (p *LocalDNode) FinalizeRound() dcrm.Round {
    return nil
}

func (p *LocalDNode) Finalize() bool {
    return false
}

func (p *LocalDNode) Start() error {
	return dcrm.BaseStart(p)
}

func (p *LocalDNode) Update(msg dcrm.Message) (ok bool, err error) {
	return dcrm.BaseUpdate(p, msg)
}

func (p *LocalDNode) DNodeID() string {
	return p.Id
}

func (p *LocalDNode) SetDNodeID(id string) {
	p.Id = id
}

func checkfull(msg []dcrm.Message) bool {
    if len(msg) == 0 {
	return false
    }

    for _,v := range msg {
	if v == nil {
	    return false
	}
    }

    return true
}

func (p *LocalDNode) StoreMessage(msg dcrm.Message) (bool, error) {
    switch msg.(type) {
	case *KGRound0Message:
		if len(p.temp.kgRound0Messages) < p.DNodeCountInGroup {
		    p.temp.kgRound0Messages = append(p.temp.kgRound0Messages,msg) 
		}

		if len(p.temp.kgRound0Messages) == p.DNodeCountInGroup {
		    fmt.Printf("================ StoreMessage,get all 0 messages ==============\n")
		    //time.Sleep(time.Duration(120) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound1Message:
		index := msg.GetFromIndex()
		p.temp.kgRound1Messages[index] = msg 
		m := msg.(*KGRound1Message)
		p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.kgRound1Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound1Messages) {
		    fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound2Message:
		index := msg.GetFromIndex()
		p.temp.kgRound2Messages[index] = msg 
		if len(p.temp.kgRound2Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound2Messages) {
		    fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound2Message1:
		index := msg.GetFromIndex()
		p.temp.kgRound2Messages1[index] = msg 
		if len(p.temp.kgRound2Messages1) == p.DNodeCountInGroup && checkfull(p.temp.kgRound2Messages1) {
		    fmt.Printf("================ StoreMessage,get all 2-1 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound3Message:
		index := msg.GetFromIndex()
		p.temp.kgRound3Messages[index] = msg 
		if len(p.temp.kgRound3Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound3Messages) {
		    fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound4Message:
		index := msg.GetFromIndex()
		m := msg.(*KGRound4Message)
		p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		p.temp.kgRound4Messages[index] = msg 
		if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound4Messages) {
		    fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound5Message:
		index := msg.GetFromIndex()
		p.temp.kgRound5Messages[index] = msg 
		if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound5Messages) {
		    fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *KGRound6Message:
		index := msg.GetFromIndex()
		p.temp.kgRound6Messages[index] = msg 
		if len(p.temp.kgRound6Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound6Messages) {
		    fmt.Printf("================ StoreMessage,get all 6 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false,nil
}

