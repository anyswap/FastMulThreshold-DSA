package reshare 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
)

func (round *round1) Start() error {
	if round.started {
	    fmt.Printf("============ round1 start error,already started============\n")
	    return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.resetOK()

	if !round.oldnode {
	    return nil
	}

	index,err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
	    fmt.Printf("============round1 start,get dnode id index fail,err = %v ===========\n",err)
	    return err
	}

	var self *big.Int
	lambda1 := big.NewInt(1)
	for k,v := range round.idreshare {
	    if k == index {
		self = v
		break
	    }
	}
	
	if self == nil {
	    return errors.New("round start fail,self uid is nil")
	}
	
	for k,v := range round.idreshare {
	    if k == index {
		continue
	    }
	    
	    sub := new(big.Int).Sub(v, self)
	    subInverse := new(big.Int).ModInverse(sub, secp256k1.S256().N)
	    times := new(big.Int).Mul(subInverse,v)
	    lambda1 = new(big.Int).Mul(lambda1, times)
	    lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256().N)
	}
	w1 := new(big.Int).Mul(lambda1, round.Save.SkU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256().N)

	round.temp.w1 = w1
	
	skP1Poly, skP1PolyG, _ := ec2.Vss2Init(w1,round.threshold)
	skP1Gx, skP1Gy := secp256k1.S256().ScalarBaseMult(w1.Bytes())
	u1CommitValues := make([]*big.Int, 0)
	u1CommitValues = append(u1CommitValues, skP1Gx)
	u1CommitValues = append(u1CommitValues, skP1Gy)
	for i := 1; i < len(skP1PolyG.PolyG); i++ {
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][0])
		u1CommitValues = append(u1CommitValues, skP1PolyG.PolyG[i][1])
	}
	commitSkP1G := new(ec2.Commitment).Commit(u1CommitValues...)
	if commitSkP1G == nil {
	    return errors.New(" Error generating commitment data in reshare round 1")
	}

	round.temp.comd = commitSkP1G.D
	round.temp.skP1Poly = skP1Poly
	round.temp.skP1PolyG = skP1PolyG.PolyG

	re := &ReshareRound1Message{
	    ReshareRoundMessage:new(ReshareRoundMessage),
	    ComC:commitSkP1G.C,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(index)

	round.temp.reshareRound1Messages[index] = re
	round.out <- re

	fmt.Printf("============ round1 start success ============\n")
	return nil
}

func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReshareRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true

		//add for reshare only
		if j == ( len(round.temp.reshareRound1Messages) - 1 ) {
		    for jj,_ := range round.ok {
			round.ok[jj] = true
		    }
		}
		//
	}
	
	return true, nil
}

func (round *round1) NextRound() smpc.Round {
	round.started = false
	return &round2{round}
}
