package signing 

import (
	"errors"
	"fmt"
	//"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
)

func (round *round2) Start() error {
	if round.started {
	    fmt.Printf("============= round2.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 2
	round.started = true
	round.resetOK()

	cur_index,err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
	    return err
	}

	oldindex := -1
	for k,v := range round.save.Ids {
	    if v.Cmp(round.save.CurDNodeID) == 0 {
		oldindex = k
		break
	    }
	}

	if oldindex == -1 {
	    return errors.New("error old index")
	}

	u1PaillierPk := round.save.U1PaillierPk[oldindex]
	if u1PaillierPk == nil {
	    return errors.New("error paillier pk for current node.")
	}

	u1KCipher,u1R,_ := u1PaillierPk.Encrypt(round.temp.u1K)
	round.temp.ukc = u1KCipher 
	round.temp.ukc2 = u1R

	for k,v := range round.idsign {
	    index := -1
	    for kk,vv := range round.save.Ids {
		if v.Cmp(vv) == 0 {
		    index = kk
		    break
		}
	    }

	    u1nt := round.save.U1NtildeH1H2[index]
	    u1u1MtAZK1Proof := ec2.MtAZK1Prove_nhh(round.temp.u1K,round.temp.ukc2,u1PaillierPk,u1nt)
	   
	    fmt.Printf("==============round2.start,cur_index = %v,oldindex = %v,index = %v, u1K = %v, ukc = %v, ukc2 = %v, pk = %v, ntilde = %v, u1u1MtAZK1Proof = %v ============\n",cur_index,oldindex,index,round.temp.u1K,round.temp.ukc,round.temp.ukc2,u1PaillierPk,u1nt,u1u1MtAZK1Proof)
	    srm := &SignRound2Message{
		SignRoundMessage: new(SignRoundMessage),
		U1u1MtAZK1Proof: u1u1MtAZK1Proof,
	    }
	    srm.SetFromID(round.kgid)
	    srm.SetFromIndex(cur_index)
	    
	    if cur_index == k {
		round.temp.signRound2Messages[cur_index] = srm
	    } else {
		srm.AppendToID(fmt.Sprintf("%v",v))
		round.out <-srm
	    }
	}
	
	fmt.Printf("============= round2.start success, current node id = %v =======\n",round.kgid)
	return nil
}

func (round *round2) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, error) {
	for j, msg := range round.temp.signRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	
	return true, nil
}

func (round *round2) NextRound() dcrm.Round {
    fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round3{round}
}

