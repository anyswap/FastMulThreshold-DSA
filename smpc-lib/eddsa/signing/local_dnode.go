package signing

import (
	"fmt"
	//"time"
	"encoding/hex"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	//"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	"math/big"
)

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
	finalize_end chan<- *big.Int //useness for ed
}

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
	finalize_end chan<- *big.Int, //useness for ed
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

	var id [32]byte
	copy(id[:], kgid.Bytes())
	p.Id = hex.EncodeToString(id[:])
	fmt.Printf("=========== NewLocalDNode, kgid = %v, p.Id = %v =============\n", kgid, p.Id)

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

func (p *LocalDNode) FinalizeRound() smpc.Round {
	return nil //nil for ed
	//return newRound8(&p.temp,p.save,p.idsign,p.out,p.end,p.Id,p.ThresHold,p.PaillierKeyLength,p.predata,p.txhash,p.finalize_end)
}

func (p *LocalDNode) FirstRound() smpc.Round {
	return newRound1(&p.temp, p.save, p.idsign, p.out, p.end, p.Id, p.ThresHold, p.PaillierKeyLength, p.txhash)
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

func (p *LocalDNode) Finalize() bool {
	return p.finalize
}

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

func (p *LocalDNode) StoreMessage(msg smpc.Message) (bool, error) {
	switch msg.(type) {
	case *SignRound1Message:
		index := msg.GetFromIndex()
		p.temp.signRound1Messages[index] = msg
		if len(p.temp.signRound1Messages) == p.ThresHold && checkfull(p.temp.signRound1Messages) {
			fmt.Printf("================ StoreMessage,get all 1 messages ==============\n")
			return true, nil
		}
	case *SignRound2Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 2 messages,index = %v ============\n", index)
		p.temp.signRound2Messages[index] = msg
		if len(p.temp.signRound2Messages) == p.ThresHold && checkfull(p.temp.signRound2Messages) {
			fmt.Printf("================ StoreMessage,get all 2 messages ==============\n")
			return true, nil
		}
	case *SignRound3Message:
		index := msg.GetFromIndex()
		fmt.Printf("================ StoreMessage,get 3 messages,index = %v ============\n", index)
		p.temp.signRound3Messages[index] = msg
		if len(p.temp.signRound3Messages) == p.ThresHold && checkfull(p.temp.signRound3Messages) {
			fmt.Printf("================ StoreMessage,get all 3 messages ==============\n")
			return true, nil
		}
	case *SignRound4Message:
		index := msg.GetFromIndex()
		p.temp.signRound4Messages[index] = msg
		if len(p.temp.signRound4Messages) == p.ThresHold && checkfull(p.temp.signRound4Messages) {
			fmt.Printf("================ StoreMessage,get all 4 messages ==============\n")
			return true, nil
		}
	case *SignRound5Message:
		index := msg.GetFromIndex()
		p.temp.signRound5Messages[index] = msg
		if len(p.temp.signRound5Messages) == p.ThresHold && checkfull(p.temp.signRound5Messages) {
			fmt.Printf("================ StoreMessage,get all 5 messages ==============\n")
			return true, nil
		}
	case *SignRound6Message:
		index := msg.GetFromIndex()
		p.temp.signRound6Messages[index] = msg
		if len(p.temp.signRound6Messages) == p.ThresHold && checkfull(p.temp.signRound6Messages) {
			fmt.Printf("================ StoreMessage,get all 6 messages ==============\n")
			return true, nil
		}
	default: // unrecognised message, just ignore!
		fmt.Printf("storemessage,unrecognised message ignored: %v\n", msg)
		return false, nil
	}

	return false, nil
}
