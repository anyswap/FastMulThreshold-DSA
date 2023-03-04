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
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start verify commitment ...
func (round *round6) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 6
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIDs()
	if err != nil {
		return err
	}

	////////////////////////
	if round.tee {
	    return round.ExecTee(curIndex)
	}
	///////////////////////

	for k := range ids {
		msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
			return errors.New("round.Start get round5 msg fail")
		}

		msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
		if !ok {
			return errors.New("round.Start get round4 msg fail")
		}

		deCommit := &ec2.Commitment{C: msg4.ComXiC, D: msg5.ComXiGD}
		if !deCommit.Verify(round.keytype) {
			fmt.Printf("========= round6 verify commitment fail, k = %v ==========\n", k)
			return errors.New("verify commitment fail")
		}
	}

	// add for GG20: In keygen phase 3, each player Pi need to proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30].Similarly, it needs to prove it for ntilde.
	// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1
	for k := range ids {
	    msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		return errors.New("round.Start get round4 msg fail")
	    }

	    ntilde := msg4.U1NtildeH1H2.Ntilde
	    if ntilde == nil {
		    return errors.New("error kg round4 message")
	    }

	    msg52, ok := round.temp.kgRound5Messages2[k].(*KGRound5Message2)
	    if !ok {
		return errors.New("round.Start get round5 msg 2 fail")
	    }

	    if !ec2.SquareFreeVerify(ntilde,msg52.Num,msg52.SfPf) {
		log.Error("keygen round6,check that a zero-knowledge proof that ntilde is a square-free integer fail","k",k,"id",ids[k])
		return errors.New("check that a zero-knowledge proof that ntilde is a square-free integer fail")
	    }
	}

	// see Paper:   Attacking Threshold Wallets*   JP Aumasson and Omer Shlomovits   Taurus Group, Switzerland   ZenGo X, Israel   section 5  The Golden Shoe Attack
	// Mitigation: The fix is simple: Ntilde,h1,h2 must be validated on the receiving end.For Ntilde,the sender must attach a proof that Ntilde is a valid RSA modulus from two safe primes.For h1,h2, there is a nice trick in [FO97]: pick h1 at random and h2 = h1^alpha and prove to the receiver the knowledge of alpha with respect to h1, h2.
	// see Paper : Efficient Noninteractive Certification of RSA Moduli and Beyond   Sharon Goldberg*, Leonid Reyzin*, Omar Sagga*, and Foteini Baldimtsi      Boston University, Boston, MA, USA  George Mason University, Fairfax, VA, USA foteini@gmu.edu   October 3, 2019     section 3.4  HVZK Proof for a Product of Two Primes
	for k,_ := range ids {
	    msg4,ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		return errors.New("round.Start get round 4 msg fail")
	    }
	    ntilde := msg4.U1NtildeH1H2.Ntilde
	    if ntilde == nil {
		    return errors.New("error kg round4 message")
	    }

	    msg51, ok := round.temp.kgRound5Messages1[k].(*KGRound5Message1)
	    if !ok {
		return errors.New("round.Start get round 5-1 msg fail")
	    }
	    
	    if !ec2.HvVerify(ntilde,msg51.Num,msg51.HvPf) {
		log.Error("keygen round6,check that a zero-knowledge proof that ntilde is a valid RSA modulus from two safe primes fail","k",k,"id",ids[k])
		return errors.New("check that a zero-knowledge proof that ntilde is a valid RSA modulus from two safe primes fail")
	    }
	}
	///////////

	round.temp.p1 = nil
	round.temp.p2 = nil 

	// add prove for xi 
	u1zkXiProof := ec2.ZkXiProve(round.keytype,round.Save.SkU1)
	if u1zkXiProof == nil {
		return errors.New("zkx prove fail")
	}

	kg := &KGRound6Message{
		KGRoundMessage:      new(KGRoundMessage),
		U1zkXiProof:     u1zkXiProof,
		CheckPubkeyStatus: true,
	}
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)

	round.temp.kgRound6Messages[curIndex] = kg
	round.out <- kg

	//fmt.Printf("========= round6 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round6) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound6Message); ok {
		return msg.IsBroadcast()
	}
	
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round6) Update() (bool, error) {
	for j, msg := range round.temp.kgRound6Messages {
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
func (round *round6) NextRound() smpc.Round {
	round.started = false
	return &round7{round}
}

func (round *round6) ExecTee(curIndex int) error {
    ids, err := round.GetIDs()
    if err != nil {
	    return err
    }

    for k := range ids {
	    msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
	    if !ok {
		    return errors.New("round.Start get round5 msg fail")
	    }

	    msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		    return errors.New("round.Start get round4 msg fail")
	    }

	    s := &socket.KGRound6ComCheck{C:msg4.ComXiC,D:msg5.ComXiGD}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		return err
	    }
	   
	    kgs := <-round.teeout
	    msgmap := make(map[string]string)
	    err = json.Unmarshal([]byte(kgs), &msgmap)
	    if err != nil {
		return err
	    }

	    if msgmap["CommitCheckRes"] == "FALSE" {
		log.Error("========= round6 verify commitment fail ==========","k", k)
		return errors.New("verify commitment fail")
	    }
    }

    // add for GG20: In keygen phase 3, each player Pi need to proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30].Similarly, it needs to prove it for ntilde.
    // An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1
    for k := range ids {
	msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	if !ok {
	    return errors.New("round.Start get round4 msg fail")
	}

	ntilde := msg4.U1NtildeH1H2.Ntilde
	if ntilde == nil {
		return errors.New("error kg round4 message")
	}

	msg52, ok := round.temp.kgRound5Messages2[k].(*KGRound5Message2)
	if !ok {
	    return errors.New("round.Start get round5 msg 2 fail")
	}

	s := &socket.KGRound6SquareFeeCheck{Ntilde:ntilde,Num:msg52.Num,Sfp:msg52.SfPf}
	s.Base.SetBase(round.keytype,round.msgprex)
	err := socket.SendMsgData(smpc.VSocketConnect,s)
	if err != nil {
	    return err
	}
	
	kgs := <-round.teeout
	msgmap := make(map[string]string)
	err = json.Unmarshal([]byte(kgs), &msgmap)
	if err != nil {
	    return err
	}
	
	if msgmap["SquareFreeCheckRes"] == "FALSE" {
	    log.Error("keygen round6,check that a zero-knowledge proof that ntilde is a square-free integer fail","k",k,"id",ids[k])
	    return errors.New("check that a zero-knowledge proof that ntilde is a square-free integer fail")
	}
    }

    // see Paper:   Attacking Threshold Wallets*   JP Aumasson and Omer Shlomovits   Taurus Group, Switzerland   ZenGo X, Israel   section 5  The Golden Shoe Attack
    // Mitigation: The fix is simple: Ntilde,h1,h2 must be validated on the receiving end.For Ntilde,the sender must attach a proof that Ntilde is a valid RSA modulus from two safe primes.For h1,h2, there is a nice trick in [FO97]: pick h1 at random and h2 = h1^alpha and prove to the receiver the knowledge of alpha with respect to h1, h2.
    // see Paper : Efficient Noninteractive Certification of RSA Moduli and Beyond   Sharon Goldberg*, Leonid Reyzin*, Omar Sagga*, and Foteini Baldimtsi      Boston University, Boston, MA, USA  George Mason University, Fairfax, VA, USA foteini@gmu.edu   October 3, 2019     section 3.4  HVZK Proof for a Product of Two Primes
    for k,_ := range ids {
	msg4,ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	if !ok {
	    return errors.New("round.Start get round 4 msg fail")
	}
	ntilde := msg4.U1NtildeH1H2.Ntilde
	if ntilde == nil {
		return errors.New("error kg round4 message")
	}

	msg51, ok := round.temp.kgRound5Messages1[k].(*KGRound5Message1)
	if !ok {
	    return errors.New("round.Start get round 5-1 msg fail")
	}
	
	s := &socket.KGRound6HvCheck{Ntilde:ntilde,Num:msg51.Num,HvPf:msg51.HvPf}
	s.Base.SetBase(round.keytype,round.msgprex)
	err = socket.SendMsgData(smpc.VSocketConnect,s) 
	if err != nil {
	    return err
	}
       
	kgs := <-round.teeout
	msgmap := make(map[string]string)
	err = json.Unmarshal([]byte(kgs), &msgmap)
	if err != nil {
	    return err
	}
	
	if msgmap["HvCheckRes"] == "FALSE" {
	    log.Error("keygen round6,check that a zero-knowledge proof that ntilde is a valid RSA modulus from two safe primes fail","k",k,"id",ids[k])
	    return errors.New("check that a zero-knowledge proof that ntilde is a valid RSA modulus from two safe primes fail")
	}
    }
    ///////////

    round.temp.p1Enc = ""
    round.temp.p2Enc = "" 

    s := &socket.KGRound6Msg{Sk:round.Save.SkU1Enc}
    s.Base.SetBase(round.keytype,round.msgprex)
    err = socket.SendMsgData(smpc.VSocketConnect,s) 
    if err != nil {
	return err
    }
   
    kgs := <-round.teeout
    msgmap := make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	return err
    }

    u1zkXiProof := &ec2.ZkXiProof{}
    err = json.Unmarshal([]byte(msgmap["ZkXiProof"]),u1zkXiProof)
    if err != nil {
	return errors.New("zkx prove fail")
    }

    kg := &KGRound6Message{
	    KGRoundMessage:      new(KGRoundMessage),
	    U1zkXiProof:     u1zkXiProof,
	    CheckPubkeyStatus: true,
    }
    kg.SetFromID(round.dnodeid)
    kg.SetFromIndex(curIndex)
    kg.SetTeeValidateData(msgmap["TeeValidateData"])

    round.temp.kgRound6Messages[curIndex] = kg
    round.out <- kg

    return nil
}
