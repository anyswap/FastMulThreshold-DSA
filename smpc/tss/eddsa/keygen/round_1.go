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
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"encoding/hex"

	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	r255 "github.com/gtank/ristretto255"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"encoding/json"
)

// Start get sk pk
func (round *round1) Start() error {
	if round.started {
	    log.Error("============ round1 start error,already started============")
	    return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.ResetOK()

	index, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
	    log.Error("============round1 start,get dnode id index fail ===========", "uid",round.dnodeid, "err",err)
	    return err
	}

	if round.tee {
	    return round.ExecTee(index)
	}

	//1.1-1.2 generate 32-bits privatekey', then bit calculation to privatekey
	rand := cryptorand.Reader

	var sk [32]byte
	var pk [32]byte
	var zkPk [64]byte

	if round.keytype == smpc.SR25519 {
		skScalar, err := ed_ristretto.NewRandomScalar()
		if err != nil {
			return err
		}
		PK := new(r255.Element).ScalarBaseMult(skScalar)

		skScalar.Encode(sk[:0])
		PK.Encode(pk[:0])

		zkPk, err = ed_ristretto.Prove2(sk, pk)
		if err != nil {
			return err
		}
	}else{
		var skTem [64]byte
		if _, err = io.ReadFull(rand, skTem[:]); err != nil {
			fmt.Println("Error: io.ReadFull(rand, sk)")
		}

		ed.ScReduce(&sk, &skTem)
		var A ed.ExtendedGroupElement
		ed.GeScalarMultBase(&A, &sk)
		A.ToBytes(&pk)

		zkPk, err = ed.Prove2(sk,pk)
		if err != nil {
			return err
		}
	}

	CPk, DPk, err := ed.Commit(pk)
	if err != nil {
	    return err
	}

	round.temp.sk = sk
	round.temp.pk = pk
	round.temp.DPk = DPk
	round.temp.zkPk = zkPk

	kg := &KGRound1Message{
		KGRoundMessage: new(KGRoundMessage),
		CPk:            CPk,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(index)

	round.Save.Sk = sk
	round.Save.Pk = pk
	round.temp.kgRound1Messages[index] = kg
	round.out <- kg

	//fmt.Printf("============ round1 start success,index = %v ============\n",index)
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

//----------------------------------------

func (round *round1) ExecTee(index int) error {
    s := &socket.EDKGRound1Msg{}
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
 
    /*var tmp []byte
    tmp,err = hex.DecodeString(msgmap["sk"])
    if err != nil {
	return err
    }
    var sk [32]byte
    copy(sk[:],tmp[:])*/

    tmp,err := hex.DecodeString(msgmap["pk"])
    if err != nil {
	return err
    }
    var pk [32]byte
    copy(pk[:],tmp[:])

    tmp,err = hex.DecodeString(msgmap["DPk"])
    if err != nil {
	return err
    }
    var DPk [64]byte
    copy(DPk[:],tmp[:])
    
    tmp,err = hex.DecodeString(msgmap["zkPk"])
    if err != nil {
	return err
    }
    var zkPk [64]byte
    copy(zkPk[:],tmp[:])
    
    tmp,err = hex.DecodeString(msgmap["CPk"])
    if err != nil {
	return err
    }
    var CPk [32]byte
    copy(CPk[:],tmp[:])
    
    //round.temp.sk = sk
    round.temp.skEnc = msgmap["sk"] 
    round.temp.pk = pk
    round.temp.DPk = DPk
    round.temp.zkPk = zkPk

    kg := &KGRound1Message{
	    KGRoundMessage: new(KGRoundMessage),
	    CPk:            CPk,
    }
    kg.SetFromID(round.dnodeid)
    kg.SetFromIndex(index)

    //round.Save.Sk = sk
    round.Save.SkEnc = msgmap["sk"]
    round.Save.Pk = pk
    round.temp.kgRound1Messages[index] = kg
    round.out <- kg
    return nil
}


