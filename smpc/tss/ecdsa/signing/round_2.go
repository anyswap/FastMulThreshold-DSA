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
	"math/big"
	"encoding/hex"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start paillier Encrypt and get MtAZK1Proof
func (round *round2) Start() error {
	if round.started {
	    log.Error("============= round2.start fail =======")
	    return errors.New("round already started")
	}
	round.number = 2
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

	if oldindex == -1 {
	    return errors.New("error old index")
	}

	u1PaillierPk := round.save.U1PaillierPk[oldindex]
	if u1PaillierPk == nil {
		return errors.New("error paillier pk for current node")
	}

	u1KCipher, u1R, _ := u1PaillierPk.Encrypt(round.temp.u1K)
	round.temp.ukc = u1KCipher
	round.temp.ukc2 = u1R

	for k, v := range round.idsign {
		index := -1
		for kk, vv := range round.save.IDs {
			if v.Cmp(vv) == 0 {
				index = kk
				break
			}
		}

		u1nt := round.save.U1NtildeH1H2[index]
		u1u1MtAZK1Proof := ec2.MtARangeProofProve(round.keytype,round.temp.ukc,round.temp.u1K, round.temp.ukc2, u1PaillierPk, u1nt)

		srm := &SignRound2Message{
			SignRoundMessage: new(SignRoundMessage),
			U1u1MtAZK1Proof:  u1u1MtAZK1Proof,
		}
		srm.SetFromID(round.kgid)
		srm.SetFromIndex(curIndex)

		if curIndex == k {
			round.temp.signRound2Messages[curIndex] = srm
		} else {
			tmp := fmt.Sprintf("%v",v)
			idtmp := hex.EncodeToString([]byte(tmp))
			srm.AppendToID(idtmp) //id-->dnodeid
			round.out <- srm
		}
	}

	//fmt.Printf("============= round2.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round2) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound2Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
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

// NextRound enter next round
func (round *round2) NextRound() smpc.Round {
	round.started = false
	return &round3{round}
}

//-----------------------------------------

func (round *round2) ExecTee(curIndex int) error {
    oldindex := -1
    for k, v := range round.save.IDs {
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
	    return errors.New("error paillier pk for current node")
    }

    s := &socket.SigningRound2PaiEnc{U1K:round.temp.u1K,U1PaillierPk:u1PaillierPk}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round2 start,send paillier enc data error","err",err)
	return err
    }
   
    kgs := <-round.teeout
    msgmap := make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	log.Error("round1 start,unmarshal SigningRound1Msg return data error","err",err)
	return err
    }
 
    u1KCipher,_ := new(big.Int).SetString(msgmap["U1KCipher"],10)
    u1R,_ := new(big.Int).SetString(msgmap["U1R"],10)

    round.temp.ukc = u1KCipher
    round.temp.ukc2 = u1R

    for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    u1nt := round.save.U1NtildeH1H2[index]
	    
	    s := &socket.SigningRound2Msg{UKC:round.temp.ukc,U1K:round.temp.u1K,UKC2:round.temp.ukc2,U1PaiPK:u1PaillierPk,U1Nt:u1nt}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round2 start,send signing round2 data error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
	    msgmap := make(map[string]string)
	    err = json.Unmarshal([]byte(kgs), &msgmap)
	    if err != nil {
		log.Error("round1 start,unmarshal SigningRound1Msg return data error","err",err)
		return err
	    }
	 
	    u1u1MtAZK1Proof := &ec2.MtARangeProof{}
	    err = json.Unmarshal([]byte(msgmap["U1MtAZK1Proof"]),u1u1MtAZK1Proof)
	    if err != nil {
		return err
	    }

	    srm := &SignRound2Message{
		    SignRoundMessage: new(SignRoundMessage),
		    U1u1MtAZK1Proof:  u1u1MtAZK1Proof,
	    }
	    srm.SetFromID(round.kgid)
	    srm.SetFromIndex(curIndex)

	    if curIndex == k {
		    round.temp.signRound2Messages[curIndex] = srm
	    } else {
		    tmp := fmt.Sprintf("%v",v)
		    idtmp := hex.EncodeToString([]byte(tmp))
		    srm.AppendToID(idtmp) //id-->dnodeid
		    round.out <- srm
	    }
    }

    return nil
}


