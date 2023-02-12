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

package keygen

import (
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/json"
	"strings"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
)

// Start get commitment and vss data ....
func (round *round1) Start() error {
	if round.started {
	    log.Error("round1 start error,already started")
	    return errors.New("round1 already start")
	}

	round.number = 1
	round.started = true
	round.ResetOK()

	index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		fmt.Printf("============round1 start,get dnode id index fail,uid = %v,err = %v ===========\n", round.dnodeid,err)
		return err
	}

	if round.tee {
	    return round.ExecTee(index)
	}

	u1 := random.GetRandomIntFromZn(secp256k1.S256(round.keytype).N1())
	c1 := random.GetRandomIntFromZn(secp256k1.S256(round.keytype).N1())

	if u1 == nil || c1 == nil || round.threshold <= 1 || round.threshold > round.dnodecount {
	    return errors.New("round one fail")
	}

	u1Poly, u1PolyG, _ := ec2.Vss2Init(round.keytype,u1, round.threshold)
	_, c1PolyG, _ := ec2.Vss2Init(round.keytype,c1, round.threshold)

	u1Gx, u1Gy := secp256k1.S256(round.keytype).ScalarBaseMult(u1.Bytes())
	u1Secrets := make([]*big.Int, 0)
	u1Secrets = append(u1Secrets, u1Gx)
	u1Secrets = append(u1Secrets, u1Gy)
	for i := 1; i < len(u1PolyG.PolyG); i++ {
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][0])
		u1Secrets = append(u1Secrets, u1PolyG.PolyG[i][1])
	}
	commitU1G := new(ec2.Commitment).Commit(u1Secrets...)

	//bip32
	c1Gx, c1Gy := secp256k1.S256(round.keytype).ScalarBaseMult(c1.Bytes())
	c1Secrets := make([]*big.Int, 0)
	c1Secrets = append(c1Secrets, c1Gx)
	c1Secrets = append(c1Secrets, c1Gy)
	for i := 1; i < len(c1PolyG.PolyG); i++ {
		c1Secrets = append(c1Secrets, c1PolyG.PolyG[i][0])
		c1Secrets = append(c1Secrets, c1PolyG.PolyG[i][1])
	}
	commitC1G := new(ec2.Commitment).Commit(c1Secrets...)

	// 3. generate their own paillier public key and private key
	u1PaillierPk, u1PaillierSk,p,q := ec2.GenerateKeyPair(round.paillierkeylength)

	if u1PaillierPk == nil || u1PaillierSk == nil {
		return errors.New(" Error generating Paillier pubkey/private data ")
	}

	if commitU1G == nil || commitC1G == nil {
		return errors.New(" Error generating commitment/bip32-commitment data ")
	}

	round.temp.u1 = u1
	round.temp.u1Poly = u1Poly
	round.temp.u1PolyG = u1PolyG
	round.temp.commitU1G = commitU1G
	round.temp.c1 = c1
	round.temp.commitC1G = commitC1G
	round.temp.u1PaillierPk = u1PaillierPk
	round.temp.u1PaillierSk = u1PaillierSk
	round.temp.p = p
	round.temp.q = q

	kg := &KGRound1Message{
		KGRoundMessage: new(KGRoundMessage),
		ComC:           commitU1G.C,
		ComCBip32:     commitC1G.C,
		U1PaillierPk:   u1PaillierPk,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(index)

	round.Save.U1PaillierSk = u1PaillierSk
	round.Save.U1PaillierPk[index] = u1PaillierPk
	round.temp.kgRound1Messages[index] = kg
	round.out <- kg

	//fmt.Printf("============ round1 start success ============\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.kgRound1Messages {
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
func (round *round1) NextRound() smpc.Round {
	round.started = false
	return &round2{round}
}

//------------------------------------------------

//ExecTee  add for tee env.
func (round *round1) ExecTee(index int) error {
    s := &socket.KGRound1Msg{ThresHold: round.threshold, DNodeCount: round.dnodecount, PaillierKeyLen: round.paillierkeylength}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round1 start,marshal KGRound1 error","err",err)
	return err
    }
   
    kgs := <-round.teeout
    msgmap := make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	log.Error("round1 start,unmarshal KGRound1 return data error","err",err)
	return err
    }
   
    log.Info("round1 tee,get msg from channel","msgprex",round.msgprex)

    u1, _ := new(big.Int).SetString(msgmap["U1"], 10)
    c1, _ := new(big.Int).SetString(msgmap["C1"], 10)
    ugd := strings.Split(msgmap["U1Poly"], ":")
    u1gd := make([]*big.Int, len(ugd))
    for k, v := range ugd {
	    u1gd[k], _ = new(big.Int).SetString(v, 10)
	    if u1gd[k] == nil {
		log.Error("round1 start,get u1 poly data fail")
		return errors.New("get data error")
	    }
    }
    u1Poly := &ec2.PolyStruct2{Poly: u1gd}

    uggtmp := strings.Split(msgmap["U1PolyG"], "|")
    ugg := make([][]*big.Int, len(uggtmp))
    for k, v := range uggtmp {
	    uggtmp2 := strings.Split(v, ":")
	    tmp := make([]*big.Int, len(uggtmp2))
	    for kk, vv := range uggtmp2 {
		    tmp[kk], _ = new(big.Int).SetString(vv, 10)
		    if tmp[kk] == nil {
			log.Error("round1 start,get u1 polyG data fail")
			return nil
		    }
	    }
	    ugg[k] = tmp
    }
    u1PolyG := &ec2.PolyGStruct2{PolyG: ugg}
    round.temp.u1 = u1
    round.temp.u1Poly = u1Poly
    round.temp.u1PolyG = u1PolyG

    u1C, _ := new(big.Int).SetString(msgmap["CommitU1G.C"], 10)
    u1com := strings.Split(msgmap["CommitU1G.D"], ":")
    u1comgd := make([]*big.Int, len(u1com))
    for k, v := range u1com {
	    u1comgd[k], _ = new(big.Int).SetString(v, 10)
	    if u1comgd[k] == nil {
		log.Error("round1 start,get commitment u1 D fail")
		return errors.New("get data error")
	    }
    }
    commitU1G := &ec2.Commitment{C: u1C, D: u1comgd}
    
    c1C, _ := new(big.Int).SetString(msgmap["CommitC1G.C"], 10)
    c1com := strings.Split(msgmap["CommitC1G.D"], ":")
    c1comgd := make([]*big.Int, len(c1com))
    for k, v := range c1com {
	    c1comgd[k], _ = new(big.Int).SetString(v, 10)
	    if c1comgd[k] == nil {
		log.Error("round1 start,get commitment c1 D fail")
		return errors.New("get data error")
	    }
    }
    commitC1G := &ec2.Commitment{C: c1C, D: c1comgd}

    round.temp.commitU1G = commitU1G
    round.temp.c1 = c1
    round.temp.commitC1G = commitC1G

    paisk := &ec2.PrivateKey{} 
    err = paisk.UnmarshalJSON([]byte(msgmap["U1PaillierSk"]))
    if err != nil {
	log.Error("round1 start,unmarshal paillier sk error","err",err)
	return err
    }

    pub := &ec2.PublicKey{}
    err = pub.UnmarshalJSON([]byte(msgmap["U1PaillierPk"]))
    if err != nil {
	log.Error("round1 start,unmarshal paillier pubkey error","err",err)
	return err
    }

    p, _ := new(big.Int).SetString(msgmap["P"], 10)
    q, _ := new(big.Int).SetString(msgmap["Q"], 10)
    
    round.temp.u1PaillierPk = pub 
    round.temp.u1PaillierSk = paisk
    round.temp.p = p
    round.temp.q = q
    round.Save.U1PaillierSk = paisk 
    round.Save.U1PaillierPk[index] = pub
    
    kg := &KGRound1Message{
	    KGRoundMessage: new(KGRoundMessage),
	    ComC:           commitU1G.C,
	    ComCBip32:     commitC1G.C,
	    U1PaillierPk:   pub,
    }
    kg.SetFromID(round.dnodeid)
    kg.SetFromIndex(index)

    round.temp.kgRound1Messages[index] = kg
    round.out <- kg
    return nil
}

