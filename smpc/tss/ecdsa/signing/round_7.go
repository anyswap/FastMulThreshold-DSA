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
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// Start verify commitment,zkuproof,calc R
func (round *round7) Start() error {
	if round.started {
	    log.Error("============= round7.start fail =======")
	    return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	if round.tee {
	    return round.ExecTee(curIndex)
	}

	var GammaGSumx *big.Int
	var GammaGSumy *big.Int
	for k := range round.idsign {
		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
		deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
		if !deCommit.Verify(round.keytype) {
			return errors.New("verify commit fail")
		}

		_, u1GammaG := deCommit.DeCommit(round.keytype)
		if !ec2.ZkUVerify(round.keytype,u1GammaG, msg6.U1GammaZKProof) {
			return errors.New("verify zkuproof fail")
		}

		if k == 0 {
			GammaGSumx = u1GammaG[0]
			GammaGSumy = u1GammaG[1]
		}
	}

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
		msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
		deCommit := &ec2.Commitment{C: msg1.C11, D: msg6.CommU1D}
		_, u1GammaG := deCommit.DeCommit(round.keytype)
		GammaGSumx, GammaGSumy = secp256k1.S256(round.keytype).Add(GammaGSumx, GammaGSumy, u1GammaG[0], u1GammaG[1])
	}
	
	deltaSumInverse := new(big.Int).ModInverse(round.temp.deltaSum, secp256k1.S256(round.keytype).N1())
	if deltaSumInverse == nil {
	    return errors.New("calc deltaSum Inverse fail")
	}

	deltaGammaGx, deltaGammaGy := secp256k1.S256(round.keytype).ScalarMult(GammaGSumx, GammaGSumy, deltaSumInverse.Bytes())

	// 4. get r = deltaGammaGx
	r := deltaGammaGx
	zero, _ := new(big.Int).SetString("0", 10)
	if r.Cmp(zero) == 0 {
		return errors.New("r == 0")
	}

	if r == nil || deltaGammaGy == nil {
		return errors.New("calc r fail")
	}

	round.temp.deltaGammaGx = deltaGammaGx
	round.temp.deltaGammaGy = deltaGammaGy

	// gg20: compute ZK proof of consistency between R_i and E_i(k_i) 
	bigRK1Gx,bigRK1Gy := secp256k1.S256(round.keytype).ScalarMult(deltaGammaGx,deltaGammaGy,round.temp.u1K.Bytes())

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
	
	u1NT := round.save.U1NtildeH1H2[oldindex]
	if u1NT == nil {
		return errors.New("error ntilde for current node")
	}

	pdlWSlackStatement := &ec2.PDLwSlackStatement{
		PK:         u1PaillierPk,
		CipherText: round.temp.ukc,
		K1RX:	bigRK1Gx,
		K1RY:   bigRK1Gy,
		Rx:     deltaGammaGx,
		Ry:     deltaGammaGy,
		H1:         u1NT.H1,
		H2:         u1NT.H2,
		NTilde:     u1NT.Ntilde,
	}
	pdlWSlackWitness := &ec2.PDLwSlackWitness{
		SK: round.save.U1PaillierSk,
		K1:  round.temp.u1K,
		K1Ra:  round.temp.ukc2,
	}
	pdlWSlackPf := ec2.NewPDLwSlackProof(round.keytype,pdlWSlackWitness, pdlWSlackStatement)
	if pdlWSlackPf == nil {
	    return errors.New("compute ZK proof of consistency between R_i and E_i(k_i) fail")
	}
	
	srm := &SignRound7Message{
		SignRoundMessage: new(SignRoundMessage),
		K1RX:              bigRK1Gx,
		K1RY:   bigRK1Gy,
		PdlwSlackPf: pdlWSlackPf,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound7Messages[curIndex] = srm
	round.out <- srm
	//

	//round.end <- PrePubData{K1: round.temp.u1K, R: r, Ry: deltaGammaGy, Sigma1: round.temp.sigma1}

	//fmt.Printf("============= round7.start success, current node id = %v =============\n", round.kgid)

	return nil
}

// CanAccept is it legal to receive this message 
func (round *round7) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound7Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round7) Update() (bool, error) {
	for j, msg := range round.temp.signRound7Messages {
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
func (round *round7) NextRound() smpc.Round {
	round.started = false
	return &round8{round}
}

//----------------------------------------

func (round *round7) ExecTee(curIndex int) error {
    var GammaGSumx *big.Int
    var GammaGSumy *big.Int
    for k := range round.idsign {
	    msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
	    msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
	    
	    s := &socket.SigningRound7ComCheck{C:msg1.C11,D:msg6.CommU1D,ZKProof:msg6.U1GammaZKProof}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round7 start,check commitment error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round7 start,unmarshal return data error","err",err)
		return err
	    }

	    if msgmap["ComCheck"] == "FALSE" {
		return errors.New("verify fail")
	    }

	    if k == 0 {
		g0,_ := new(big.Int).SetString(msgmap["u1GammaG0"],10)
		g1,_ := new(big.Int).SetString(msgmap["u1GammaG1"],10)
		    GammaGSumx = g0 
		    GammaGSumy = g1
	    }
    }

    for k := range round.idsign {
	    if k == 0 {
		    continue
	    }

	    msg1, _ := round.temp.signRound1Messages[k].(*SignRound1Message)
	    msg6, _ := round.temp.signRound6Messages[k].(*SignRound6Message)
	    
	    s := &socket.SigningRound7DeCom{C:msg1.C11,D:msg6.CommU1D}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round7 start,send de-commitment error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round7 start,unmarshal return data error","err",err)
		return err
	    }

	    g0,_ := new(big.Int).SetString(msgmap["u1GammaG0"],10)
	    g1,_ := new(big.Int).SetString(msgmap["u1GammaG1"],10)
	    GammaGSumx, GammaGSumy = secp256k1.S256(round.keytype).Add(GammaGSumx, GammaGSumy, g0,g1)
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
    
    u1NT := round.save.U1NtildeH1H2[oldindex]
    if u1NT == nil {
	    return errors.New("error ntilde for current node")
    }

    s := &socket.SigningRound7Msg{DeltaSum:round.temp.deltaSum,GammaX:GammaGSumx,GammaY:GammaGSumy,U1K:round.temp.u1KEnc,PaiPk:u1PaillierPk,Nt:u1NT,UKC:round.temp.ukc,PaiSk:round.save.U1PaillierSkEnc,U1Ra:round.temp.ukc2}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round7 start,send de-commitment error","err",err)
	return err
    }
   
    kgs := <-round.teeout
	bytesMap := make(map[string][]byte)
	err = json.Unmarshal([]byte(kgs), &bytesMap)
	msgmap := common.BytesMap2StringMap(bytesMap)
    if err != nil {
	log.Error("round7 start,unmarshal return data error","err",err)
	return err
    }

    round.temp.deltaGammaGx,_ = new(big.Int) .SetString(msgmap["deltaGammaGx"],10)
    round.temp.deltaGammaGy,_ = new(big.Int) .SetString(msgmap["deltaGammaGy"],10)

    pdlWSlackPf := &ec2.PDLwSlackProof{}
    err = json.Unmarshal([]byte(msgmap["WSlackPf"]),pdlWSlackPf)
    if err != nil {
	return err
    }

    bigRK1Gx,_ := new(big.Int) .SetString(msgmap["BigRK1Gx"],10)
    bigRK1Gy,_ := new(big.Int) .SetString(msgmap["BigRK1Gy"],10)

    srm := &SignRound7Message{
	    SignRoundMessage: new(SignRoundMessage),
	    K1RX:              bigRK1Gx,
	    K1RY:   bigRK1Gy,
	    PdlwSlackPf: pdlWSlackPf,
    }
    srm.SetFromID(round.kgid)
    srm.SetFromIndex(curIndex)
    srm.SetTeeValidateData(msgmap["TeeValidateData"])

    round.temp.signRound7Messages[curIndex] = srm
    round.out <- srm
    return nil
}

