package reshare 

import (
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	"math/big"
	"errors"
)

type LocalDNode struct {
	*smpc.BaseDNode
	temp localTempData
	data *keygen.LocalDNodeSaveData 
	out chan<- smpc.Message
	end chan<- keygen.LocalDNodeSaveData
	oldnode bool //the node join the keygen and join the reshare
	//save for check msg0
	firstround smpc.Round
}

type localMessageStore struct {
	reshareRound0Messages,
	reshareRound1Messages,
	reshareRound2Messages,
	reshareRound2Messages1,
	reshareRound3Messages,
	reshareRound4Messages,
	reshareRound5Messages []smpc.Message
}

type localTempData struct {
	//localMessageStore
	reshareRound0Messages,
	reshareRound1Messages,
	reshareRound2Messages,
	reshareRound2Messages1,
	reshareRound3Messages,
	reshareRound4Messages,
	reshareRound5Messages []smpc.Message

	// temp data (thrown away after keygen)

	//round 1
	w1 *big.Int
	comd []*big.Int
	skP1Poly *ec2.PolyStruct2
	skP1PolyG [][]*big.Int

	//round 2
	skP1Shares []*ec2.ShareStruct2

	//round 3
	pkx *big.Int
	pky *big.Int
	newskU1 *big.Int
	u1PaillierSk *ec2.PrivateKey
	u1PaillierPk *ec2.PublicKey

	//round 4
	u1NtildeH1H2 *ec2.NtildeH1H2

	//round 5

	//round 6
	
	//round 7
}

func NewLocalDNode(
	out chan<- smpc.Message,
	end chan<- keygen.LocalDNodeSaveData,
	DNodeCountInGroup int,
	threshold int,
	paillierkeylength int,
	sd *keygen.LocalDNodeSaveData,
	oldnode bool,
) smpc.DNode {

    	var id string
	if sd != nil {
	    id = fmt.Sprintf("%v",sd.CurDNodeID)
	} else {
	    uid := smpc.GetRandomIntFromZn(secp256k1.S256().N)
	    id = fmt.Sprintf("%v",uid)
	}
    	
	if sd == nil {
	    sdtmp := keygen.NewLocalDNodeSaveData(DNodeCountInGroup)
	    sd = &sdtmp
	}

	p := &LocalDNode{
		BaseDNode: new(smpc.BaseDNode),
		temp:      localTempData{},
		data:	   sd,
		out:       out,
		end:       end,
		oldnode:   oldnode,
	}

	p.Id = id
	fmt.Printf("=========== reshare.NewLocalDNode,p.Id = %v,threshold = %v,DNodeCountInGroup = %v =============\n",p.Id,threshold,DNodeCountInGroup)

	p.DNodeCountInGroup = DNodeCountInGroup
	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.temp.reshareRound0Messages = make([]smpc.Message,0)
	p.temp.reshareRound1Messages = make([]smpc.Message,threshold)
	p.temp.reshareRound2Messages = make([]smpc.Message,threshold)
	p.temp.reshareRound2Messages1 = make([]smpc.Message,threshold)
	p.temp.reshareRound3Messages = make([]smpc.Message,DNodeCountInGroup)
	p.temp.reshareRound4Messages = make([]smpc.Message,DNodeCountInGroup)
	p.temp.reshareRound5Messages = make([]smpc.Message,DNodeCountInGroup)
	return p
}

func (p *LocalDNode) FirstRound() smpc.Round {
    fr := newRound0(p.data, &p.temp,p.out, p.end,p.Id,p.DNodeCountInGroup,p.ThresHold,p.PaillierKeyLength,p.oldnode)
    p.firstround = fr
    return fr
}

func (p *LocalDNode) FinalizeRound() smpc.Round {
    return nil
}

func (p *LocalDNode) Finalize() bool {
    return false
}

func (p *LocalDNode) Start() error {
	return smpc.BaseStart(p)
}

func (p *LocalDNode) Update(msg smpc.Message) (ok bool, err error) {
	return smpc.BaseUpdate(p, msg)
}

func (p *LocalDNode) DNodeID() string {
	return p.Id
}

func (p *LocalDNode) SetDNodeID(id string) {
	p.Id = id
}

func checkfull(msg []smpc.Message) bool {
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

func (p *LocalDNode) StoreMessage(msg smpc.Message) (bool, error) {
    switch msg.(type) {
	case *ReshareRound0Message:
		if len(p.temp.reshareRound0Messages) < p.DNodeCountInGroup {
		    p.temp.reshareRound0Messages = append(p.temp.reshareRound0Messages,msg)
		}

		if len(p.temp.reshareRound0Messages) == p.DNodeCountInGroup {
		    fmt.Printf("================ StoreMessage,get all 0 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound1Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ reshare.StoreMessage, index = %v, reshareRound1Messages len = %v ==============\n",index,len(p.temp.reshareRound1Messages))
		p.temp.reshareRound1Messages[index] = msg 
		if len(p.temp.reshareRound1Messages) == p.ThresHold && checkfull(p.temp.reshareRound1Messages) {
		    fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound2Message:
		index := msg.GetFromIndex()
		p.temp.reshareRound2Messages[index] = msg 
		if len(p.temp.reshareRound2Messages) == p.ThresHold && checkfull(p.temp.reshareRound2Messages) {
		    fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound2Message1:
		index := msg.GetFromIndex()
		p.temp.reshareRound2Messages1[index] = msg 
		if len(p.temp.reshareRound2Messages1) == p.ThresHold && checkfull(p.temp.reshareRound2Messages1) {
		    fmt.Printf("================ StoreMessage,get all 2-1 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound3Message:
		index := msg.GetFromIndex()
		p.temp.reshareRound3Messages[index] = msg 
		m := msg.(*ReshareRound3Message)
		p.data.U1PaillierPk[index] = m.U1PaillierPk
		if len(p.temp.reshareRound3Messages) == p.DNodeCountInGroup && checkfull(p.temp.reshareRound3Messages) {
		    fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound4Message:
		index := msg.GetFromIndex()
		p.temp.reshareRound4Messages[index] = msg 
		m := msg.(*ReshareRound4Message)
		p.data.U1NtildeH1H2[index] = m.U1NtildeH1H2
		if len(p.temp.reshareRound4Messages) == p.DNodeCountInGroup && checkfull(p.temp.reshareRound4Messages) {
		    fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
		    return true,nil
		}
	case *ReshareRound5Message:
		index := msg.GetFromIndex()
		p.temp.reshareRound5Messages[index] = msg 
		if len(p.temp.reshareRound5Messages) == p.DNodeCountInGroup && checkfull(p.temp.reshareRound5Messages) {
		    fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")

		    ///check newskok
		    for _,v := range p.temp.reshareRound5Messages {
		    m := v.(*ReshareRound5Message)
		    if m.NewSkOk != "TRUE" {
			return false,errors.New("check newsk ok fail.")
		    }
		}
		    ////

		    return true,nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false,nil
}

//add for check msg0
func (p *LocalDNode) CheckReshareMsg0(msg smpc.Message) bool {
    switch msg.(type) {
	case *ReshareRound0Message:
	    if len(p.temp.reshareRound0Messages) == (p.DNodeCountInGroup - 1) {
		p.temp.reshareRound0Messages = append(p.temp.reshareRound0Messages,msg)
	    }

	    return len(p.temp.reshareRound0Messages) == p.DNodeCountInGroup
	default:
	    return false
    }

    return false
}

func (p *LocalDNode) SetIdReshare(ids smpc.SortableIDSSlice) {
    fr,ok := p.firstround.(*round0)
    if ok {
	fr.idreshare = ids
    }
}

