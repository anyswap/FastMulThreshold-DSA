package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
)

func (round *round5) Start() error {
	if round.started {
	    fmt.Printf("============= round5.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 5
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
	
	alpha1 := make([]*big.Int, round.threshold)
	uu1 := make([]*big.Int, round.threshold)
	
	for k,v := range round.idsign {
	    index := -1
	    for kk,vv := range round.save.Ids {
		if v.Cmp(vv) == 0 {
		    index = kk
		    break
		}
	    }

	    u1PaillierPk := round.save.U1PaillierPk[oldindex]
	    u1nt := round.save.U1NtildeH1H2[index]
	    msg4,_ := round.temp.signRound4Messages[k].(*dcrm.SignRound4Message)
	    rlt111 := msg4.U1u1MtAZK2Proof.MtAZK2Verify_nhh(round.temp.ukc,msg4.U1KGamma1Cipher,u1PaillierPk,u1nt)
	    if !rlt111 {
		return errors.New("verify mkg fail.")
	    }
	    
	    msg41,_ := round.temp.signRound4Messages1[k].(*dcrm.SignRound4Message1)
	    rlt112 := msg41.U1u1MtAZK3Proof.MtAZK3Verify_nhh(round.temp.ukc,msg41.U1Kw1Cipher,u1PaillierPk,u1nt)
	    if !rlt112 {
		return errors.New("verify mkw fail.")
	    }
	
	    alpha1U1, _ := round.save.U1PaillierSk.Decrypt(msg4.U1KGamma1Cipher)
	    alpha1[k] = alpha1U1
	    u1U1, _ := round.save.U1PaillierSk.Decrypt(msg41.U1Kw1Cipher)
	    uu1[k] = u1U1
	}
	round.temp.alpha1 = alpha1
	round.temp.uu1 = uu1

	delta1 := alpha1[0]
	for i := 0; i < round.threshold; i++ {
		if i == 0 {
			continue
		}
		delta1 = new(big.Int).Add(delta1, alpha1[i])
	}
	for i := 0; i < round.threshold; i++ {
		delta1 = new(big.Int).Add(delta1, round.temp.betaU1[i])
	}
	round.temp.delta1 = delta1

	sigma1 := uu1[0]
	for i := 0; i < round.threshold; i++ {
		if i == 0 {
			continue
		}
		sigma1 = new(big.Int).Add(sigma1, uu1[i])
	}
	for i := 0; i < round.threshold; i++ {
		sigma1 = new(big.Int).Add(sigma1, round.temp.vU1[i])
	}
	round.temp.sigma1 = sigma1
	
	srm := &dcrm.SignRound5Message{
	    SignRoundMessage: new(dcrm.SignRoundMessage),
	    Delta1:delta1,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(cur_index)

	round.temp.signRound5Messages[cur_index] = srm
	round.out <-srm
    
	fmt.Printf("============= round5.start success, current node id = %v =============\n",round.kgid)

	return nil
}

func (round *round5) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*dcrm.SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.signRound5Messages {
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

func (round *round5) NextRound() dcrm.Round {
    fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round6{round}
}

