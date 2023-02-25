/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package signing

import (
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start verify MtAZK2Proof,paillier Decrypt,calc delta1
func (round *round5) Start() error {
	if round.started {
	    log.Error("============= round5.start fail =======")
	    return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	if round.tee {
	    return round.ExecTee(curIndex)
	}

	oldindex := -1
	for k, v := range round.save.IDs {
		if v.Cmp(round.save.CurDNodeID) == 0 {
			oldindex = k
			break
		}
	}

	alpha1 := make([]*big.Int, round.threshold)
	uu1 := make([]*big.Int, round.threshold)

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		u1PaillierPk := round.save.U1PaillierPk[oldindex]
		u1nt := round.save.U1NtildeH1H2[index]
		msg4, _ := round.temp.signRound4Messages[k].(*SignRound4Message)
		rlt111 := msg4.U1u1MtAZK2Proof.MtARespZKProofVerify(round.keytype,round.temp.ukc, msg4.U1KGamma1Cipher, u1PaillierPk, u1nt)
		if !rlt111 {
			log.Error("=====================round5.start,verify mkg fail================","msg4",*msg4,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
			return errors.New("verify mkg fail")
		}

		// add for GG18 A.2 Respondent ZK Proof for MtAwc
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
		deCommit := &ec2.Commitment{C: msg1.ComWiC, D: msg3.ComWiD}
		_,xG := deCommit.DeCommit(round.keytype)

		msg41, _ := round.temp.signRound4Messages1[k].(*SignRound4Message1)
		rlt112 := msg41.U1u1MtAZK3Proof.MtAwcRespZKProofVefify(round.keytype,xG,round.temp.ukc, msg41.U1Kw1Cipher, u1PaillierPk, u1nt)
		if !rlt112 {
			log.Error("=====================round5.start,verify mkw fail================","msg41",*msg41,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
			return errors.New("verify mkw fail")
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
	delta1 = new(big.Int).Mod(delta1, secp256k1.S256(round.keytype).N1())
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
	sigma1 = new(big.Int).Mod(sigma1, secp256k1.S256(round.keytype).N1())
	round.temp.sigma1 = sigma1

	// gg20: calculate T_i = g^sigma_i * h^l_i = sigma_i*G + l_i*h*G
	l1 := random.GetRandomIntFromZn(secp256k1.S256(round.keytype).N1())
	hx,hy,err := ec2.CalcHPoint(round.keytype)
	if err != nil {
	    fmt.Printf("calc h point fail, err = %v",err)
	    return err
	}

	l1Gx,l1Gy := secp256k1.S256(round.keytype).ScalarMult(hx,hy,l1.Bytes())
	sigmaGx,sigmaGy := secp256k1.S256(round.keytype).ScalarBaseMult(sigma1.Bytes())
	t1X,t1Y := secp256k1.S256(round.keytype).Add(sigmaGx,sigmaGy,l1Gx,l1Gy)
	// gg20: generate the ZK proof of T_i
	tProof := ec2.TProve(round.keytype,t1X,t1Y,hx,hy,sigma1,l1)
	if tProof == nil {
	    return errors.New("prove Ti proof fail")
	}
	//

	round.temp.t1X = t1X
	round.temp.t1Y = t1Y
	round.temp.l1 = l1

	srm := &SignRound5Message{
		SignRoundMessage: new(SignRoundMessage),
		Delta1:           delta1,
		T1X:		t1X,
		T1Y:		t1Y,
		Tpf:		tProof,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound5Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round5.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
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

// NextRound enter next round
func (round *round5) NextRound() smpc.Round {
	round.started = false
	return &round6{round}
}

func (round *round5) ExecTee(curIndex int) error {
    oldindex := -1
    for k, v := range round.save.IDs {
	    if v.Cmp(round.save.CurDNodeID) == 0 {
		    oldindex = k
		    break
	    }
    }

    alpha1 := make([]*big.Int, round.threshold)
    uu1 := make([]*big.Int, round.threshold)

    for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    u1PaillierPk := round.save.U1PaillierPk[oldindex]
	    u1nt := round.save.U1NtildeH1H2[index]
	    msg4, _ := round.temp.signRound4Messages[k].(*SignRound4Message)

	    s := &socket.SigningRound5MtARespZKProofCheck{UKC:round.temp.ukc,Clipher:msg4.U1KGamma1Cipher,PaiPk:u1PaillierPk,Nt:u1nt,MtAZK2Proof:msg4.U1u1MtAZK2Proof}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round4 start,check commitment error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
	    msgmap := make(map[string]string)
	    err = json.Unmarshal([]byte(kgs), &msgmap)
	    if err != nil {
		log.Error("round4 start,unmarshal return data error","err",err)
		return err
	    }

	    if msgmap["MtARespZKProofCheckRes"] == "FALSE" {
		    log.Error("=====================round5.start,verify mkg fail================","msg4",*msg4,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
		    return errors.New("verify mkg fail")
	    }

	    // add for GG18 A.2 Respondent ZK Proof for MtAwc
	    msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
	    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
	    msg41, _ := round.temp.signRound4Messages1[k].(*SignRound4Message1)
	    
	    s2 := &socket.SigningRound5ComCheck{C:msg1.ComWiC,D:msg3.ComWiD,MtAZK3Proof:msg41.U1u1MtAZK3Proof,UKC:round.temp.ukc,Cipher:msg41.U1Kw1Cipher,PaiPk:u1PaillierPk,Nt:u1nt,PaiSk:round.save.U1PaillierSkEnc,U1KGamma1Cipher:msg4.U1KGamma1Cipher}
	    s2.Base.SetBase(round.keytype,round.msgprex)
	    err = socket.SendMsgData(smpc.VSocketConnect,s2)
	    if err != nil {
		log.Error("round4 start,check commitment error","err",err)
		return err
	    }
	   
	    kgs = <-round.teeout
	    msgmap = make(map[string]string)
	    err = json.Unmarshal([]byte(kgs), &msgmap)
	    if err != nil {
		log.Error("round4 start,unmarshal return data error","err",err)
		return err
	    }

	    if msgmap["ComCheck"] == "FALSE" {
		    log.Error("=====================round5.start,verify mkw fail================","msg41",*msg41,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
		    return errors.New("verify mkw fail")
	    }

	    alpha1U1, _ := new(big.Int).SetString(msgmap["Alpha1U1"],10)
	    alpha1[k] = alpha1U1
	    u1U1, _ := new(big.Int).SetString(msgmap["U1U1"],10)
	    uu1[k] = u1U1
    }
    round.temp.alpha1 = alpha1
    round.temp.uu1 = uu1

    s := &socket.SigningRound5Msg{Alpha1:alpha1,UU1:uu1,ThresHold:round.threshold,BetaU1:round.temp.betaU1,VU1:round.temp.vU1}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round4 start,check commitment error","err",err)
	return err
    }
   
    kgs := <-round.teeout
    msgmap := make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	log.Error("round4 start,unmarshal return data error","err",err)
	return err
    }

    round.temp.delta1,_ = new(big.Int).SetString(msgmap["delta1"],10)
    round.temp.sigma1,_ = new(big.Int).SetString(msgmap["sigma1"],10)

    tProof := &ec2.TProof{}
    err = json.Unmarshal([]byte(msgmap["tProof"]),tProof)
    if err != nil {
	return err
    }

    if tProof == nil {
	return errors.New("prove Ti proof fail")
    }
    //
    t1X,_ := new(big.Int).SetString(msgmap["t1X"],10)
    t1Y,_ := new(big.Int).SetString(msgmap["t1Y"],10)
    //l1,_ := new(big.Int).SetString(msgmap["l1"],10)
    l1 := new(big.Int).SetBytes([]byte(msgmap["l1"]))

    round.temp.t1X = t1X
    round.temp.t1Y = t1Y
    round.temp.l1 = l1

    srm := &SignRound5Message{
	    SignRoundMessage: new(SignRoundMessage),
	    Delta1:           round.temp.delta1,
	    T1X:		t1X,
	    T1Y:		t1Y,
	    Tpf:		tProof,
    }
    srm.SetFromID(round.kgid)
    srm.SetFromIndex(curIndex)

    round.temp.signRound5Messages[curIndex] = srm
    round.out <- srm
    return nil
}

