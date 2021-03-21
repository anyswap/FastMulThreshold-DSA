package signing 

import (
	"errors"
	"fmt"
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
)

func (round *round4) Start() error {
	if round.started {
	    fmt.Printf("============= round4.start fail =======\n")
	    return errors.New("round already started")
	}
	round.number = 4
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
	
	for k,v := range round.idsign {
	    index := -1
	    for kk,vv := range round.save.Ids {
		if v.Cmp(vv) == 0 {
		    index = kk
		    break
		}
	    }

	    msg2,_ := round.temp.signRound2Messages[k].(*SignRound2Message)
	    msg3,_ := round.temp.signRound3Messages[k].(*SignRound3Message)
	    
	    if k == cur_index {
		u1PaillierPk := round.save.U1PaillierPk[index]
		u1nt := round.save.U1NtildeH1H2[index]
		u1rlt1 := msg2.U1u1MtAZK1Proof.MtAZK1Verify_nhh(msg3.Kc,u1PaillierPk,u1nt)
		if !u1rlt1 {
		    fmt.Printf("============round4.start,verify mtazk1 proof fail.==============\n")
		    fmt.Printf("===========round4.start,cur_index = %v,index = %v,pk = %v,ntilde = %v,kc = %v,U1u1MtAZK1Proof = %v ==========\n",cur_index,index,u1PaillierPk,u1nt,msg3.Kc,msg2.U1u1MtAZK1Proof)
		    return errors.New("verify mtazk1 proof fail.")
		}
	    } else {
		u1PaillierPk := round.save.U1PaillierPk[index]
		u1nt := round.save.U1NtildeH1H2[oldindex]
		u1rlt1 := msg2.U1u1MtAZK1Proof.MtAZK1Verify_nhh(msg3.Kc,u1PaillierPk,u1nt)
		if !u1rlt1 {
		    fmt.Printf("============round4.start,verify mtazk1 proof fail.==============\n")
		    fmt.Printf("===========round4.start,cur_index = %v,index = %v,pk = %v,ntilde = %v,kc = %v,U1u1MtAZK1Proof = %v ==========\n",cur_index,index,u1PaillierPk,u1nt,msg3.Kc,msg2.U1u1MtAZK1Proof)
		    return errors.New("verify mtazk1 proof fail.")
		}

	    }
	}

	NSalt := new(big.Int).Lsh(big.NewInt(1), uint(round.paillierkeylength-round.paillierkeylength/10))
	NSubN2 := new(big.Int).Mul(secp256k1.S256().N, secp256k1.S256().N)
	NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
	// 2. MinusOne
	MinusOne := big.NewInt(-1)

	betaU1Star := make([]*big.Int, round.threshold)
	betaU1 := make([]*big.Int,round.threshold)
	for i := 0; i < round.threshold; i++ {
		beta1U1Star := dcrm.GetRandomIntFromZn(NSubN2)
		beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
		betaU1Star[i] = beta1U1Star
		betaU1[i] = beta1U1
	}

	vU1Star := make([]*big.Int,round.threshold)
	vU1 := make([]*big.Int, round.threshold)
	for i := 0; i < round.threshold; i++ {
		v1U1Star := dcrm.GetRandomIntFromZn(NSubN2)
		v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
		vU1Star[i] = v1U1Star
		vU1[i] = v1U1
	}

	round.temp.betaU1Star = betaU1Star
	round.temp.betaU1 = betaU1
	round.temp.vU1Star = vU1Star
	round.temp.vU1 = vU1

	for k,v := range round.idsign {
	    index := -1
	    for kk,vv := range round.save.Ids {
		if v.Cmp(vv) == 0 {
		    index = kk
		    break
		}
	    }

	    if k == cur_index {
		u1PaillierPk := round.save.U1PaillierPk[index]
		msg3,_ := round.temp.signRound3Messages[k].(*SignRound3Message)
		u1KGamma1Cipher := u1PaillierPk.HomoMul(msg3.Kc,round.temp.u1Gamma)
		beta1U1StarCipher, u1BetaR1, _ := u1PaillierPk.Encrypt(betaU1Star[k])
		u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher,beta1U1StarCipher)
		//u1nt := round.save.U1NtildeH1H2[index]
		u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(round.temp.u1Gamma, betaU1Star[k], u1BetaR1, round.temp.ukc,round.save.U1PaillierPk[oldindex],round.save.U1NtildeH1H2[oldindex])
	    
		srm := &SignRound4Message{
		    SignRoundMessage: new(SignRoundMessage),
		    U1KGamma1Cipher:u1KGamma1Cipher,
		    U1u1MtAZK2Proof:u1u1MtAZK2Proof,
		}
		srm.SetFromID(round.kgid)
		srm.SetFromIndex(cur_index)
		round.temp.signRound4Messages[cur_index] = srm

	    } else {
		u1PaillierPk := round.save.U1PaillierPk[index]
		msg3,_ := round.temp.signRound3Messages[k].(*SignRound3Message)
		u1KGamma1Cipher := u1PaillierPk.HomoMul(msg3.Kc,round.temp.u1Gamma)
		beta1U1StarCipher, u1BetaR1, _ := u1PaillierPk.Encrypt(betaU1Star[k])
		u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher,beta1U1StarCipher)
		//u1nt := round.save.U1NtildeH1H2[index]
		u1u1MtAZK2Proof := ec2.MtAZK2Prove_nhh(round.temp.u1Gamma, betaU1Star[k], u1BetaR1, msg3.Kc,u1PaillierPk,round.save.U1NtildeH1H2[oldindex])
		
		srm := &SignRound4Message{
		    SignRoundMessage: new(SignRoundMessage),
		    U1KGamma1Cipher:u1KGamma1Cipher,
		    U1u1MtAZK2Proof:u1u1MtAZK2Proof,
		}
		srm.SetFromID(round.kgid)
		srm.SetFromIndex(cur_index)
		srm.AppendToID(fmt.Sprintf("%v",v))
		round.out <-srm
	    }

	    fmt.Printf("============= round4.start success, current node id = %v =============\n",round.kgid)
	}

	for k,v := range round.idsign {
	    index := -1
	    for kk,vv := range round.save.Ids {
		if v.Cmp(vv) == 0 {
		    index = kk
		    break
		}
	    }

	    if k == cur_index {
		u1PaillierPk := round.save.U1PaillierPk[index]
		msg3,_ := round.temp.signRound3Messages[k].(*SignRound3Message)
		u1Kw1Cipher := u1PaillierPk.HomoMul(msg3.Kc,round.temp.w1)
		v1U1StarCipher,u1VR1, _ := u1PaillierPk.Encrypt(vU1Star[k])
		u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher)                                       // send to u1
		u1u1MtAZK3Proof := ec2.MtAZK3Prove_nhh(round.temp.w1, vU1Star[k], u1VR1, round.temp.ukc, round.save.U1PaillierPk[oldindex],round.save.U1NtildeH1H2[oldindex])
	    
		srm := &SignRound4Message1{
		    SignRoundMessage: new(SignRoundMessage),
		    U1Kw1Cipher:u1Kw1Cipher,
		    U1u1MtAZK3Proof:u1u1MtAZK3Proof,
		}
		srm.SetFromID(round.kgid)
		srm.SetFromIndex(cur_index)
		round.temp.signRound4Messages1[cur_index] = srm

	    } else {
		u1PaillierPk := round.save.U1PaillierPk[index]
		msg3,_ := round.temp.signRound3Messages[k].(*SignRound3Message)
		u1Kw1Cipher := u1PaillierPk.HomoMul(msg3.Kc,round.temp.w1)
		v1U1StarCipher,u1VR1, _ := u1PaillierPk.Encrypt(vU1Star[k])
		u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher)                                       // send to u1
		u1u1MtAZK3Proof := ec2.MtAZK3Prove_nhh(round.temp.w1, vU1Star[k], u1VR1, msg3.Kc, u1PaillierPk,round.save.U1NtildeH1H2[oldindex])
		
		srm := &SignRound4Message1{
		    SignRoundMessage: new(SignRoundMessage),
		    U1Kw1Cipher:u1Kw1Cipher,
		    U1u1MtAZK3Proof:u1u1MtAZK3Proof,
		}
		srm.SetFromID(round.kgid)
		srm.SetFromIndex(cur_index)
		srm.AppendToID(fmt.Sprintf("%v",v))
		round.out <-srm
	    }

	    fmt.Printf("============= round4.start success, current node id = %v =============\n",round.kgid)
	}

	return nil
}

func (round *round4) CanAccept(msg dcrm.Message) bool {
	if _, ok := msg.(*SignRound4Message); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.(*SignRound4Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, error) {
	for j, msg := range round.temp.signRound4Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg4 := round.temp.signRound4Messages1[j]
		if msg4 == nil || !round.CanAccept(msg4) {
			return false, nil
		}
		round.ok[j] = true
	}
	
	return true, nil
}

func (round *round4) NextRound() dcrm.Round {
    //fmt.Printf("========= round.next round ========\n")
    round.started = false
    return &round5{round}
}

