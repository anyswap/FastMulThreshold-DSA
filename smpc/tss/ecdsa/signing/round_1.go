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
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

var (
	zero = big.NewInt(0)
)

func newRound1(temp *localTempData, save *keygen.LocalDNodeSaveData, idsign smpc.SortableIDSSlice, out chan<- smpc.Message, end chan<- PrePubData, kgid string, threshold int, paillierkeylength int,keytype string,msgprex string,teeout chan string,tee bool) smpc.Round {
	finalizeendCh := make(chan *big.Int, threshold)
	return &round1{
		&base{temp, save, idsign, out, end, make([]bool, threshold), false, 0, kgid, threshold, paillierkeylength, nil, nil, finalizeendCh,keytype,msgprex,teeout,tee}}
}

// Start calc w1 and u1Gamma k1
func (round *round1) Start() error {
	if round.started {
		log.Error("============= round1.start fail =======")
		return errors.New("round already started")
	}
	round.number = 1
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	if round.tee {
	    return round.ExecTee(curIndex)
	}

	var self *big.Int
	lambda1 := big.NewInt(1)
	for k, v := range round.idsign {
		if k == curIndex {
			self = v
			break
		}
	}

	if self == nil {
		return errors.New("round start fail,self uid is nil")
	}

	for k, v := range round.idsign {
		if k == curIndex {
			continue
		}

		sub := new(big.Int).Sub(v, self)
		subInverse := new(big.Int).ModInverse(sub, secp256k1.S256(round.keytype).N1())
		if subInverse == nil {
		    return errors.New("calc times fail")
		}

		times := new(big.Int).Mul(subInverse, v)
		lambda1 = new(big.Int).Mul(lambda1, times)
		lambda1 = new(big.Int).Mod(lambda1, secp256k1.S256(round.keytype).N1())
	}
	w1 := new(big.Int).Mul(lambda1, round.save.SkU1)
	w1 = new(big.Int).Mod(w1, secp256k1.S256(round.keytype).N1())

	round.temp.w1 = w1

	u1K := random.GetRandomIntFromZn(secp256k1.S256(round.keytype).N1())
	u1Gamma := random.GetRandomIntFromZn(secp256k1.S256(round.keytype).N1())

	u1GammaGx, u1GammaGy := secp256k1.S256(round.keytype).ScalarBaseMult(u1Gamma.Bytes())
	commitU1GammaG := new(ec2.Commitment).Commit(u1GammaGx, u1GammaGy)
	if commitU1GammaG == nil {
		return errors.New(" Error generating commitment data in signing round 1")
	}

	// add for GG18 A.2 Respondent ZK Proof for MtAwc
	wiGx, wiGy := secp256k1.S256(round.keytype).ScalarBaseMult(round.temp.w1.Bytes())
	commitwiG := new(ec2.Commitment).Commit(wiGx, wiGy)
	if commitwiG == nil {
	    return errors.New(" Error generating commitment data for wi")
	}
	round.temp.commitwiG = commitwiG

	round.temp.u1K = u1K
	round.temp.u1Gamma = u1Gamma
	round.temp.commitU1GammaG = commitU1GammaG

	srm := &SignRound1Message{
		SignRoundMessage: new(SignRoundMessage),
		C11:              commitU1GammaG.C,
		ComWiC:		commitwiG.C, // add for GG18 A.2 Respondent ZK Proof for MtAwc
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound1Messages[curIndex] = srm
	round.out <- srm

	//fmt.Printf("============= round1.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round1) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}

	return false
}

// Update  is the message received and ready for the next round? 
func (round *round1) Update() (bool, error) {
	for j, msg := range round.temp.signRound1Messages {
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

//--------------------------------------

func (round *round1) ExecTee(curIndex int) error {

    s := &socket.SigningRound1Msg{Index:curIndex,IdSign:round.idsign,SkU1:round.save.SkU1}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round1 start,marshal KGRound1 error","err",err)
	return err
    }
   
    kgs := <-round.teeout
	bytesMap := make(map[string][]byte)
	err = json.Unmarshal([]byte(kgs), &bytesMap)
	msgmap := common.BytesMap2StringMap(bytesMap)
    if err != nil {
	log.Error("round1 start,unmarshal SigningRound1Msg return data error","err",err)
	return err
    }
  
    //w1,_ := new(big.Int).SetString(msgmap["W1"],10)
    //u1K,_ := new(big.Int).SetString(msgmap["U1K"],10)
    //u1Gamma,_ := new(big.Int).SetString(msgmap["U1Gamma"],10)

    commitwiG := &ec2.Commitment{}
    err = json.Unmarshal([]byte(msgmap["ComWiG"]),commitwiG)
    if err != nil {
	return err
    }

    commitU1GammaG := &ec2.Commitment{}
    err = json.Unmarshal([]byte(msgmap["ComU1GammaG"]),commitU1GammaG)
    if err != nil {
	return err
    }

    //round.temp.w1 = w1
    round.temp.w1Enc = msgmap["W1"]
    round.temp.commitwiG = commitwiG
    //round.temp.u1K = u1K
    round.temp.u1KEnc = msgmap["U1K"] 
    //round.temp.u1Gamma = u1Gamma
    round.temp.u1GammaEnc = msgmap["U1Gamma"]
    round.temp.commitU1GammaG = commitU1GammaG

    vdata := msgmap["TeeValidateData"]
    srm := &SignRound1Message{
	    SignRoundMessage: new(SignRoundMessage),
	    C11:              commitU1GammaG.C,
	    ComWiC:		commitwiG.C, // add for GG18 A.2 Respondent ZK Proof for MtAwc
    }
    srm.SetFromID(round.kgid)
    srm.SetFromIndex(curIndex)
    srm.SetTeeValidateData(vdata)

    round.temp.signRound1Messages[curIndex] = srm
    round.out <- srm

    return nil
}
