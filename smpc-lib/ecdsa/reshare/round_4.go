package reshare 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
)

func (round *round4) Start() error {
	if round.started {
	    return errors.New("round already started")
	}
	round.number = 4
	round.started = true
	round.resetOK()

	idtmp,ok := new(big.Int).SetString(round.dnodeid,10)
	if !ok {
	    return errors.New("get id big number fail.")
	}

	cur_index := -1
	for k,v := range round.Save.Ids {
	    if v.Cmp(idtmp) == 0 {
		cur_index = k
		break
	    }
	}

	if cur_index < 0 {
	    return errors.New("get cur index fail")
	}

	// zk of paillier key
	NtildeLength := 2048
	u1NtildeH1H2,_,_,_,_ := ec2.GenerateNtildeH1H2(NtildeLength)
	if u1NtildeH1H2 == nil {
	    return errors.New("gen ntilde h1 h2 fail.")
	}
	
	re := &ReshareRound4Message{
	    ReshareRoundMessage:new(ReshareRoundMessage),
	    U1NtildeH1H2:u1NtildeH1H2,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(cur_index)

	//round.Save.U1NtildeH1H2[cur_index] = u1NtildeH1H2
	round.temp.u1NtildeH1H2 = u1NtildeH1H2
	round.temp.reshareRound4Messages[cur_index] = re
	round.out <-re
	
	fmt.Printf("========= round4 start success ==========\n")
	return nil
}

func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReshareRound4Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		
		round.ok[j] = true

		//add for reshare only
		if j == ( len(round.temp.reshareRound4Messages) - 1 ) {
		    for jj,_ := range round.ok {
			round.ok[jj] = true
		    }
		}
		//
	}
	
	return true, nil
}

func (round *round4) NextRound() smpc.Round {
	round.started = false
	return &round5{round}
}

