package keygen

import (
	"fmt"
	//"time"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	//"math/big"
	"encoding/hex"
	//"strings"
	"io"
	cryptorand "crypto/rand"
)

type LocalDNode struct {
	*dcrm.BaseDNode
	temp localTempData
	data LocalDNodeSaveData 
	out chan<- dcrm.Message
	end chan<- LocalDNodeSaveData
}

type localTempData struct {
	kgRound0Messages,
	kgRound1Messages,
	kgRound2Messages,
	kgRound3Messages,
	kgRound4Messages,
	kgRound5Messages []dcrm.Message

	// temp data (thrown away after keygen)

	//round 1
	sk [64]byte
	pk [32]byte
	DPk [64]byte
	zkPk [64]byte

	//round 2

	//round 3

	//round 4
	cfsBBytes [][32]byte
	uids [][32]byte

	//round 5

	//round 6
	
	//round 7
}

func NewLocalDNode(
	out chan<- dcrm.Message,
	end chan<- LocalDNodeSaveData,
	DNodeCountInGroup int,
	threshold int,
) dcrm.DNode {

    	data := NewLocalDNodeSaveData(DNodeCountInGroup)
	p := &LocalDNode{
		BaseDNode: new(dcrm.BaseDNode),
		temp:      localTempData{},
		data:	   data,
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

	p.Id = hex.EncodeToString(id[:])
	//uid := dcrm.GetRandomIntFromZn(secp256k1.S256().N)
	//p.Id = fmt.Sprintf("%v",uid)
	fmt.Printf("=========== ed,NewLocalDNode, id = %v, p.Id = %v =============\n",id,p.Id)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold

	p.temp.kgRound0Messages = make([]dcrm.Message,0)
	p.temp.kgRound1Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound2Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound3Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound4Messages = make([]dcrm.Message,DNodeCountInGroup)
	p.temp.kgRound5Messages = make([]dcrm.Message,DNodeCountInGroup)
	return p
}

func (p *LocalDNode) FirstRound() dcrm.Round {
	return newRound0(&p.data, &p.temp,p.out, p.end,p.Id,p.DNodeCountInGroup,p.ThresHold)
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

func (p *LocalDNode) DNodeID() string { //lower
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
		//m := msg.(*KGRound1Message)
		//p.data.U1PaillierPk[index] = m.U1PaillierPk
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
		    return true,nil
		}
	case *KGRound3Message:
		index := msg.GetFromIndex()
		p.temp.kgRound3Messages[index] = msg 
		if len(p.temp.kgRound3Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound3Messages) {
		    fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
		    return true,nil
		}
	case *KGRound4Message:
		index := msg.GetFromIndex()
		//m := msg.(*KGRound4Message)
		//p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		p.temp.kgRound4Messages[index] = msg 
		if len(p.temp.kgRound4Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound4Messages) {
		    fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
		    return true,nil
		}
	case *KGRound5Message:
		index := msg.GetFromIndex()
		p.temp.kgRound5Messages[index] = msg 
		if len(p.temp.kgRound5Messages) == p.DNodeCountInGroup && checkfull(p.temp.kgRound5Messages) {
		    fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
		    return true,nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false,nil
}

