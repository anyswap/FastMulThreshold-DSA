package signing 

import (
	"fmt"
	//"time"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"math/big"
)

type LocalDNode struct {
	*dcrm.BaseDNode
	temp localTempData
	save *dcrm.LocalDNodeSaveData
	idsign dcrm.SortableIDSSlice
	out chan<- dcrm.Message
	end chan<- dcrm.PrePubData
	finalize bool
	predata *dcrm.PrePubData
	txhash *big.Int
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
	signRound7Messages []dcrm.Message
//	signRound7Messages,
//	signRound8Messages,
//	signRound9Messages,
//	signRound10Messages []dcrm.Message

	// temp data (thrown away after sign)

	//round 1
	w1 *big.Int
	u1K *big.Int
	u1Gamma *big.Int
	commitU1GammaG *ec2.Commitment

	//round 2
	ukc *big.Int
	ukc2 *big.Int

	//round 3

	//round 4
	betaU1Star []*big.Int
	betaU1 []*big.Int
	vU1Star []*big.Int
	vU1 []*big.Int

	//round 5
	alpha1 []*big.Int
	uu1 []*big.Int
	delta1 *big.Int
	sigma1 *big.Int

	//round 6
	deltaSum *big.Int
	
	//round 7
	
	//round 8

	//round 9

	//round 10

}

func NewLocalDNode(
	out chan<- dcrm.Message,
	end chan<- dcrm.PrePubData,
	save *dcrm.LocalDNodeSaveData,
	idsign dcrm.SortableIDSSlice,
	kgid *big.Int,
	threshold int,
	paillierkeylength int,
	finalize bool,
	predata *dcrm.PrePubData,
	txhash *big.Int,
	finalize_end chan<- *big.Int,
) dcrm.DNode {

	p := &LocalDNode{
		BaseDNode: new(dcrm.BaseDNode),
		save:save,
		idsign:idsign,
		temp:      localTempData{},
		out:       out,
		end:	   end,
		predata: predata,
		txhash: txhash,
		finalize_end: finalize_end,
	}

	p.Id = fmt.Sprintf("%v",kgid)
	fmt.Printf("=========== NewLocalDNode, kgid = %v, p.Id = %v =============\n",kgid,p.Id)

	p.ThresHold = threshold
	p.PaillierKeyLength = paillierkeylength

	p.finalize = finalize

	p.temp.signRound1Messages = make([]dcrm.Message,threshold)
	p.temp.signRound2Messages = make([]dcrm.Message,threshold)
	p.temp.signRound3Messages = make([]dcrm.Message,threshold)
	p.temp.signRound4Messages = make([]dcrm.Message,threshold)
	p.temp.signRound4Messages1 = make([]dcrm.Message,threshold)
	p.temp.signRound5Messages = make([]dcrm.Message,threshold)
	p.temp.signRound6Messages = make([]dcrm.Message,threshold)
	p.temp.signRound7Messages = make([]dcrm.Message,threshold)
//	p.temp.signRound8Messages = make([]dcrm.Message,threshold)
//	p.temp.signRound9Messages = make([]dcrm.Message,threshold)
//	p.temp.signRound10Messages = make([]dcrm.Message,threshold)
	return p
}

func (p *LocalDNode) FinalizeRound() dcrm.Round {
	return newRound8(&p.temp,p.save,p.idsign,p.out,p.end,p.Id,p.ThresHold,p.PaillierKeyLength,p.predata,p.txhash,p.finalize_end)
}

func (p *LocalDNode) FirstRound() dcrm.Round {
	return newRound1(&p.temp,p.save,p.idsign,p.out,p.end,p.Id,p.ThresHold,p.PaillierKeyLength)
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

func (p *LocalDNode) Finalize() bool {
	return p.finalize
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
	case *dcrm.SignRound1Message:
		index := msg.GetFromIndex()
		p.temp.signRound1Messages[index] = msg 
		if len(p.temp.signRound1Messages) == p.ThresHold && checkfull(p.temp.signRound1Messages) {
		    fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound2Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 2 messages,index = %v ============\n",index)
		p.temp.signRound2Messages[index] = msg 
		if len(p.temp.signRound2Messages) == p.ThresHold && checkfull(p.temp.signRound2Messages) {
		    fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound3Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 3 messages,index = %v ============\n",index)
		p.temp.signRound3Messages[index] = msg 
		if len(p.temp.signRound3Messages) == p.ThresHold && checkfull(p.temp.signRound3Messages) {
		    fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound4Message:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages[index] = msg 
		if len(p.temp.signRound4Messages) == p.ThresHold && checkfull(p.temp.signRound4Messages) {
		    fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound4Message1:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages1[index] = msg 
		if len(p.temp.signRound4Messages1) == p.ThresHold && checkfull(p.temp.signRound4Messages1) {
		    fmt.Printf("================ StoreMessage,get all 4-1 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound5Message:
		index := msg.GetFromIndex()
		p.temp.signRound5Messages[index] = msg 
		if len(p.temp.signRound5Messages) == p.ThresHold && checkfull(p.temp.signRound5Messages) {
		    fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	case *dcrm.SignRound6Message:
		index := msg.GetFromIndex()
		p.temp.signRound6Messages[index] = msg 
		if len(p.temp.signRound6Messages) == p.ThresHold && checkfull(p.temp.signRound6Messages) {
		    fmt.Printf("================ StoreMessage,get all 6 messages ==============\n")
		    return true,nil
		}
	case *dcrm.SignRound7Message:
		index := msg.GetFromIndex()
		p.temp.signRound7Messages[index] = msg 
		if len(p.temp.signRound7Messages) == p.ThresHold && checkfull(p.temp.signRound7Messages) {
		    fmt.Printf("================ StoreMessage,get all 7 messages ==============\n")
		    //time.Sleep(time.Duration(20) * time.Second) //tmp code
		    return true,nil
		}
	/*case *dcrm.SignRound8Message:
		index := msg.GetFromIndex()
		p.temp.signRound8Messages[index] = msg 
		if len(p.temp.signRound8Messages) == p.ThresHold && checkfull(p.temp.signRound8Messages) {
		    fmt.Printf("================ StoreMessage,get all 8 messages ==============\n")
		    return true,nil
		}
	case *dcrm.SignRound9Message:
		index := msg.GetFromIndex()
		p.temp.signRound9Messages[index] = msg 
		if len(p.temp.signRound9Messages) == p.ThresHold && checkfull(p.temp.signRound9Messages) {
		    fmt.Printf("================ StoreMessage,get all 9 messages ==============\n")
		    return true,nil
		}
	case *dcrm.SignRound10Message:
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

	return false,nil
}

