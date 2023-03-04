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
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common/math/random"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start verify MtAZK1Proof,paillier homo add ,paillier homo mul
func (round *round4) Start() error {
	if round.started {
	    log.Error("============= round4.start fail =======")
	    return errors.New("round already started")
	}
	round.number = 4
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

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		msg2, _ := round.temp.signRound2Messages[k].(*SignRound2Message)
		msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

		if k == curIndex {
			u1PaillierPk := round.save.U1PaillierPk[index]
			u1nt := round.save.U1NtildeH1H2[index]
			u1rlt1 := msg2.U1u1MtAZK1Proof.MtARangeProofVerify(round.keytype,msg3.Kc, u1PaillierPk, u1nt)
			if !u1rlt1 {
				log.Error("=====================round4.start,verify mtazk1 proof fail===================","msg2",*msg2,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex)
				return errors.New("verify mtazk1 proof fail")
			}
		} else {
			u1PaillierPk := round.save.U1PaillierPk[index]
			u1nt := round.save.U1NtildeH1H2[oldindex]
			u1rlt1 := msg2.U1u1MtAZK1Proof.MtARangeProofVerify(round.keytype,msg3.Kc, u1PaillierPk, u1nt)
			if !u1rlt1 {
				log.Error("=====================round4.start,verify mtazk1 proof fail===================","msg2",*msg2,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
				return errors.New("verify mtazk1 proof fail")
			}
		}

		// add for GG18 A.2 Respondent ZK Proof for MtAwc
		// check commitment
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		deCommit := &ec2.Commitment{C: msg1.ComWiC, D: msg3.ComWiD}
		if !deCommit.Verify(round.keytype) {
			log.Error("=====================round4.start,verify commit for wi fail================","msg1",*msg1,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
		    return errors.New("verify commit for wi fail")
		}
	}

	NSalt := new(big.Int).Lsh(big.NewInt(1), uint(round.paillierkeylength-round.paillierkeylength/10))
	NSubN2 := new(big.Int).Mul(secp256k1.S256(round.keytype).N1(), secp256k1.S256(round.keytype).N1())
	NSubN2 = new(big.Int).Sub(NSalt, NSubN2)
	// 2. MinusOne
	MinusOne := big.NewInt(-1)

	betaU1Star := make([]*big.Int, round.threshold)
	betaU1 := make([]*big.Int, round.threshold)
	for i := 0; i < round.threshold; i++ {
		beta1U1Star := random.GetRandomIntFromZn(NSubN2)
		beta1U1 := new(big.Int).Mul(MinusOne, beta1U1Star)
		betaU1Star[i] = beta1U1Star
		betaU1[i] = beta1U1
	}

	vU1Star := make([]*big.Int, round.threshold)
	vU1 := make([]*big.Int, round.threshold)
	for i := 0; i < round.threshold; i++ {
		v1U1Star := random.GetRandomIntFromZn(NSubN2)
		v1U1 := new(big.Int).Mul(MinusOne, v1U1Star)
		vU1Star[i] = v1U1Star
		vU1[i] = v1U1
	}

	round.temp.betaU1Star = betaU1Star
	round.temp.betaU1 = betaU1
	round.temp.vU1Star = vU1Star
	round.temp.vU1 = vU1

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		if k == curIndex {
			u1PaillierPk := round.save.U1PaillierPk[index]
			msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
			u1KGamma1Cipher := u1PaillierPk.HomoMul(msg3.Kc, round.temp.u1Gamma)
			beta1U1StarCipher, u1BetaR1, _ := u1PaillierPk.Encrypt(betaU1Star[k])
			u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher)
			u1u1MtAZK2Proof := ec2.MtARespZKProofProve(round.keytype,round.temp.u1Gamma, betaU1Star[k], u1BetaR1, round.temp.ukc, u1KGamma1Cipher,round.save.U1PaillierPk[oldindex], round.save.U1NtildeH1H2[oldindex])

			srm := &SignRound4Message{
				SignRoundMessage: new(SignRoundMessage),
				U1KGamma1Cipher:  u1KGamma1Cipher,
				U1u1MtAZK2Proof:  u1u1MtAZK2Proof,
			}
			srm.SetFromID(round.kgid)
			srm.SetFromIndex(curIndex)
			round.temp.signRound4Messages[curIndex] = srm

		} else {
			u1PaillierPk := round.save.U1PaillierPk[index]
			msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
			u1KGamma1Cipher := u1PaillierPk.HomoMul(msg3.Kc, round.temp.u1Gamma)
			beta1U1StarCipher, u1BetaR1, _ := u1PaillierPk.Encrypt(betaU1Star[k])
			u1KGamma1Cipher = u1PaillierPk.HomoAdd(u1KGamma1Cipher, beta1U1StarCipher)
			u1u1MtAZK2Proof := ec2.MtARespZKProofProve(round.keytype,round.temp.u1Gamma, betaU1Star[k], u1BetaR1, msg3.Kc, u1KGamma1Cipher,u1PaillierPk, round.save.U1NtildeH1H2[oldindex])

			srm := &SignRound4Message{
				SignRoundMessage: new(SignRoundMessage),
				U1KGamma1Cipher:  u1KGamma1Cipher,
				U1u1MtAZK2Proof:  u1u1MtAZK2Proof,
			}
			srm.SetFromID(round.kgid)
			srm.SetFromIndex(curIndex)
			tmp := fmt.Sprintf("%v",v)
			idtmp := hex.EncodeToString([]byte(tmp))
			srm.AppendToID(idtmp) //id-->dnodeid
			round.out <- srm
		}

		//fmt.Printf("============= round4.start success, current node id = %v =============\n", round.kgid)
	}

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		if k == curIndex {
			u1PaillierPk := round.save.U1PaillierPk[index]
			msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
			u1Kw1Cipher := u1PaillierPk.HomoMul(msg3.Kc, round.temp.w1)
			v1U1StarCipher, u1VR1, _ := u1PaillierPk.Encrypt(vU1Star[k])
			u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
			u1u1MtAZK3Proof := ec2.MtAwcRespZKProofProve(round.keytype,round.temp.w1, vU1Star[k], u1VR1, round.temp.ukc,u1Kw1Cipher,round.save.U1PaillierPk[oldindex], round.save.U1NtildeH1H2[oldindex])

			srm := &SignRound4Message1{
				SignRoundMessage: new(SignRoundMessage),
				U1Kw1Cipher:      u1Kw1Cipher,
				U1u1MtAZK3Proof:  u1u1MtAZK3Proof,
			}
			srm.SetFromID(round.kgid)
			srm.SetFromIndex(curIndex)
			round.temp.signRound4Messages1[curIndex] = srm

		} else {
			u1PaillierPk := round.save.U1PaillierPk[index]
			msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
			u1Kw1Cipher := u1PaillierPk.HomoMul(msg3.Kc, round.temp.w1)
			v1U1StarCipher, u1VR1, _ := u1PaillierPk.Encrypt(vU1Star[k])
			u1Kw1Cipher = u1PaillierPk.HomoAdd(u1Kw1Cipher, v1U1StarCipher) // send to u1
			u1u1MtAZK3Proof := ec2.MtAwcRespZKProofProve(round.keytype,round.temp.w1, vU1Star[k], u1VR1, msg3.Kc, u1Kw1Cipher,u1PaillierPk, round.save.U1NtildeH1H2[oldindex])

			srm := &SignRound4Message1{
				SignRoundMessage: new(SignRoundMessage),
				U1Kw1Cipher:      u1Kw1Cipher,
				U1u1MtAZK3Proof:  u1u1MtAZK3Proof,
			}
			srm.SetFromID(round.kgid)
			srm.SetFromIndex(curIndex)
			tmp := fmt.Sprintf("%v",v)
			idtmp := hex.EncodeToString([]byte(tmp))
			srm.AppendToID(idtmp) //id-->dnodeid
			round.out <- srm
		}

		//fmt.Printf("============= round4.start success, current node id = %v =============\n", round.kgid)
	}

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round4) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound4Message); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.(*SignRound4Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
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

// NextRound enter next round
func (round *round4) NextRound() smpc.Round {
	round.started = false
	return &round5{round}
}

//----------------------------------------------

type BetaStar struct {
    BetaU1Star []*big.Int
    BetaU1 []*big.Int 
    VU1Star []*big.Int 
    VU1 []*big.Int
}

func (round *round4) ExecTee(curIndex int) error {
    oldindex := -1
    for k, v := range round.save.IDs {
	    if v.Cmp(round.save.CurDNodeID) == 0 {
		    oldindex = k
		    break
	    }
    }

    for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    msg2, _ := round.temp.signRound2Messages[k].(*SignRound2Message)
	    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

	    if k == curIndex {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    u1nt := round.save.U1NtildeH1H2[index]
		    
		    s := &socket.SigningRound4MtARangeProofCheck{MtAZK1Proof:msg2.U1u1MtAZK1Proof,KC:msg3.Kc,PaiPk:u1PaillierPk,Nt:u1nt}
		    s.Base.SetBase(round.keytype,round.msgprex)
		    err := socket.SendMsgData(smpc.VSocketConnect,s)
		    if err != nil {
			log.Error("round4 start,send socket data error","err",err)
			return err
		    }
		   
		    kgs := <-round.teeout
		    msgmap := make(map[string]string)
		    err = json.Unmarshal([]byte(kgs), &msgmap)
		    if err != nil {
			log.Error("round4 start,unmarshal return data error","err",err)
			return err
		    }
		 
		    if msgmap["MtARangeProofCheckRes"] == "FALSE" {
			    log.Error("=====================round4.start,verify mtazk1 proof fail===================","msg2",*msg2,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex)
			    return errors.New("verify mtazk1 proof fail")
		    }
	    } else {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    u1nt := round.save.U1NtildeH1H2[oldindex]
		    s := &socket.SigningRound4MtARangeProofCheck{MtAZK1Proof:msg2.U1u1MtAZK1Proof,KC:msg3.Kc,PaiPk:u1PaillierPk,Nt:u1nt}
		    s.Base.SetBase(round.keytype,round.msgprex)
		    err := socket.SendMsgData(smpc.VSocketConnect,s)
		    if err != nil {
			log.Error("round4 start,send socket data error","err",err)
			return err
		    }
		   
		    kgs := <-round.teeout
		    msgmap := make(map[string]string)
		    err = json.Unmarshal([]byte(kgs), &msgmap)
		    if err != nil {
			log.Error("round4 start,unmarshal return data error","err",err)
			return err
		    }
		 
		    if msgmap["MtARangeProofCheckRes"] == "FALSE" {
			log.Error("=====================round4.start,verify mtazk1 proof fail===================","msg2",*msg2,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
			return errors.New("verify mtazk1 proof fail")
		    }
	    }

	    // add for GG18 A.2 Respondent ZK Proof for MtAwc
	    // check commitment
	    msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)

	    s := &socket.SigningRound4ComCheck{C:msg1.ComWiC,D:msg3.ComWiD}
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

	    if msgmap["ComCheck"] == "FALSE" {
		log.Error("=====================round4.start,verify commit for wi fail================","msg1",*msg1,"msg3",*msg3,"index",index,"oldindex",oldindex,"idsign",round.idsign,"save.IDs",round.save.IDs,"curIndex",curIndex,"k",k)
		return errors.New("verify commit for wi fail")
	    }
    }

    s := &socket.SigningRound4Beta{PaiKeyLen:round.paillierkeylength,ThresHold:round.threshold}
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

    beta := &BetaStar{}
    err = json.Unmarshal([]byte(msgmap["BetaStar"]),beta)
    if err != nil {
	return err
    }

    round.temp.betaU1Star = beta.BetaU1Star
    round.temp.betaU1 = beta.BetaU1
    round.temp.vU1Star = beta.VU1Star
    round.temp.vU1 = beta.VU1

    for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    if k == curIndex {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

		    s := &socket.SigningRound4Msg{KC:msg3.Kc,U1Gamma:round.temp.u1GammaEnc,CurPaiPk:u1PaillierPk,BetaStar:round.temp.betaU1Star[k],UKC:round.temp.ukc,OldPaiPk:round.save.U1PaillierPk[oldindex],OldNt:round.save.U1NtildeH1H2[oldindex]}
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

		    //u1KGamma1Cipher,_ := new(big.Int).SetString(msgmap["U1KGamma1Cipher"],10)
		    u1KGamma1Cipher := new(big.Int).SetBytes([]byte(msgmap["U1KGamma1Cipher"]))
		    u1u1MtAZK2Proof := &ec2.MtARespZKProof{}
		    err = json.Unmarshal([]byte(msgmap["MtAZK2Proof"]),u1u1MtAZK2Proof)
		    if err != nil {
			return err
		    }

		    srm := &SignRound4Message{
			    SignRoundMessage: new(SignRoundMessage),
			    U1KGamma1Cipher:  u1KGamma1Cipher,
			    U1u1MtAZK2Proof:  u1u1MtAZK2Proof,
		    }
		    srm.SetFromID(round.kgid)
		    srm.SetFromIndex(curIndex)
		    srm.SetTeeValidateData(msgmap["TeeValidateData"])
		    round.temp.signRound4Messages[curIndex] = srm

	    } else {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

		    s := &socket.SigningRound4Msg{KC:msg3.Kc,U1Gamma:round.temp.u1GammaEnc,CurPaiPk:u1PaillierPk,BetaStar:round.temp.betaU1Star[k],UKC:msg3.Kc,OldPaiPk:u1PaillierPk,OldNt:round.save.U1NtildeH1H2[oldindex]}
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

		    //u1KGamma1Cipher,_ := new(big.Int).SetString(msgmap["U1KGamma1Cipher"],10)
		    u1KGamma1Cipher := new(big.Int).SetBytes([]byte(msgmap["U1KGamma1Cipher"]))
		    u1u1MtAZK2Proof := &ec2.MtARespZKProof{}
		    err = json.Unmarshal([]byte(msgmap["MtAZK2Proof"]),u1u1MtAZK2Proof)
		    if err != nil {
			return err
		    }

		    srm := &SignRound4Message{
			    SignRoundMessage: new(SignRoundMessage),
			    U1KGamma1Cipher:  u1KGamma1Cipher,
			    U1u1MtAZK2Proof:  u1u1MtAZK2Proof,
		    }
		    srm.SetFromID(round.kgid)
		    srm.SetFromIndex(curIndex)
		    srm.SetTeeValidateData(msgmap["TeeValidateData"])
		    tmp := fmt.Sprintf("%v",v)
		    idtmp := hex.EncodeToString([]byte(tmp))
		    srm.AppendToID(idtmp) //id-->dnodeid
		    round.out <- srm
	    }

    }

    for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    if k == curIndex {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

		    s := &socket.SigningRound4Msg1{KC:msg3.Kc,W1:round.temp.w1Enc,CurPaiPk:u1PaillierPk,VU1Star:round.temp.vU1Star[k],UKC:round.temp.ukc,OldPaiPk:round.save.U1PaillierPk[oldindex],OldNt:round.save.U1NtildeH1H2[oldindex]}
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

		    //u1Kw1Cipher,_ := new(big.Int).SetString(msgmap["Kw1Cipher"],10)
		    u1Kw1Cipher := new(big.Int).SetBytes([]byte(msgmap["Kw1Cipher"]))
		    u1u1MtAZK3Proof := &ec2.MtAwcRespZKProof{}
		    err = json.Unmarshal([]byte(msgmap["MtAZK3Proof"]),u1u1MtAZK3Proof)
		    if err != nil {
			return err
		    }

		    srm := &SignRound4Message1{
			    SignRoundMessage: new(SignRoundMessage),
			    U1Kw1Cipher:      u1Kw1Cipher,
			    U1u1MtAZK3Proof:  u1u1MtAZK3Proof,
		    }
		    srm.SetFromID(round.kgid)
		    srm.SetFromIndex(curIndex)
		    srm.SetTeeValidateData(msgmap["TeeValidateData"])
		    round.temp.signRound4Messages1[curIndex] = srm

	    } else {
		    u1PaillierPk := round.save.U1PaillierPk[index]
		    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)

		    s := &socket.SigningRound4Msg1{KC:msg3.Kc,W1:round.temp.w1Enc,CurPaiPk:u1PaillierPk,VU1Star:round.temp.vU1Star[k],UKC:msg3.Kc,OldPaiPk:u1PaillierPk,OldNt:round.save.U1NtildeH1H2[oldindex]}
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

		    //u1Kw1Cipher,_ := new(big.Int).SetString(msgmap["Kw1Cipher"],10)
		    u1Kw1Cipher := new(big.Int).SetBytes([]byte(msgmap["Kw1Cipher"]))
		    u1u1MtAZK3Proof := &ec2.MtAwcRespZKProof{}
		    err = json.Unmarshal([]byte(msgmap["MtAZK3Proof"]),u1u1MtAZK3Proof)
		    if err != nil {
			return err
		    }

		    srm := &SignRound4Message1{
			    SignRoundMessage: new(SignRoundMessage),
			    U1Kw1Cipher:      u1Kw1Cipher,
			    U1u1MtAZK3Proof:  u1u1MtAZK3Proof,
		    }
		    srm.SetFromID(round.kgid)
		    srm.SetFromIndex(curIndex)
		    tmp := fmt.Sprintf("%v",v)
		    idtmp := hex.EncodeToString([]byte(tmp))
		    srm.AppendToID(idtmp) //id-->dnodeid
		    srm.SetTeeValidateData(msgmap["TeeValidateData"])
		    round.out <- srm
	    }

	    //fmt.Printf("============= round4.start success, current node id = %v =============\n", round.kgid)
    }

    return nil
}

