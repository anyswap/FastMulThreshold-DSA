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
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"fmt"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
)

const (
	ntildeBitsLen = 2048
)

// Start check ntilde bitlen/add HVZK Proof for a Product of Two Primes ...
func (round *round5) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 5
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	//check Ntilde bitlen
	for _,msg := range round.temp.kgRound4Messages {
		m,ok := msg.(*KGRound4Message)
		if !ok {
			return errors.New("error kg round4 message")
		}

		ntilde := m.U1NtildeH1H2
		if ntilde == nil || ntilde.Ntilde == nil {
			return errors.New("error kg round4 message")
		}

		if ntilde.Ntilde.BitLen() != ntildeBitsLen {
			return errors.New("got ntilde with not enough bits")
		}
	}
	//

	if round.tee {
	    return round.ExecTee(curIndex)
	}

	// add for GG20: In keygen phase 3, each player Pi need to proves in ZK that Ni is square-free using the proof of Gennaro, Micciancio, and Rabin [30].Similarly, it needs to prove it for ntilde.
	// An Efficient Non-Interactive Statistical Zero-Knowledge Proof System for Quasi-Safe Prime Products, section 3.1
	ntilde := round.temp.kgRound4Messages[curIndex].(*KGRound4Message).U1NtildeH1H2.Ntilde
	num := ec2.MustGetRandomInt(ntilde.BitLen())
	if num == nil {
	    return errors.New("get random int fail")
	}

	pMinus1 := new(big.Int).Sub(round.temp.p1, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(round.temp.p2, big.NewInt(1))
	l := new(big.Int).Mul(pMinus1, qMinus1)
	sfProof := ec2.SquareFreeProve(ntilde,num,l)
	if sfProof == nil {
	    return errors.New("get square free proof fail")
	}

	srm := &KGRound5Message2{    // same as KGRound2Message2
		KGRoundMessage: new(KGRoundMessage),
		Num:		num,
		SfPf:		sfProof,
	}
	srm.SetFromID(round.dnodeid)
	srm.SetFromIndex(curIndex)

	round.temp.kgRound5Messages2[curIndex] = srm
	round.out <- srm

	// see Paper:   Attacking Threshold Wallets*   JP Aumasson and Omer Shlomovits   Taurus Group, Switzerland   ZenGo X, Israel   section 5  The Golden Shoe Attack
	// Mitigation: The fix is simple: Ntilde,h1,h2 must be validated on the receiving end.For Ntilde,the sender must attach a proof that Ntilde is a valid RSA modulus from two safe primes.For h1,h2, there is a nice trick in [FO97]: pick h1 at random and h2 = h1^alpha and prove to the receiver the knowledge of alpha with respect to h1, h2.
	// see Paper : Efficient Noninteractive Certification of RSA Moduli and Beyond   Sharon Goldberg*, Leonid Reyzin*, Omar Sagga*, and Foteini Baldimtsi      Boston University, Boston, MA, USA  George Mason University, Fairfax, VA, USA foteini@gmu.edu   October 3, 2019     section 3.4  HVZK Proof for a Product of Two Primes
	num = ec2.MustGetRandomInt(ntilde.BitLen())
	if num == nil {
	    return errors.New("get random int fail")
	}

	//fmt.Printf("===========================keygen round 5, get num = %v for ntilde = %v==========================\n",num,ntilde)
	hvProof := ec2.HvProve(ntilde,num,round.temp.p1,round.temp.p2)
	if hvProof == nil {
		fmt.Printf("===========================keygen round 5, get hvzk proof fail==========================\n")
	    return errors.New("get hvzk proof fail")
	}

	srm2 := &KGRound5Message1{
		KGRoundMessage: new(KGRoundMessage),
		Num:		num,
		HvPf:		hvProof,
	}
	srm2.SetFromID(round.dnodeid)
	srm2.SetFromIndex(curIndex)

	round.temp.kgRound5Messages1[curIndex] = srm2
	round.out <- srm2

	kg := &KGRound5Message{
		KGRoundMessage: new(KGRoundMessage),
		ComXiGD:	round.temp.commitXiG.D,
	}
	
	kg.SetFromID(round.dnodeid)
	kg.SetFromIndex(curIndex)

	round.temp.kgRound5Messages[curIndex] = kg
	round.out <- kg

	//fmt.Printf("========= round5 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round5) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*KGRound5Message); ok {
		return msg.IsBroadcast()
	}
	
	if _, ok := msg.(*KGRound5Message1); ok {
		return msg.IsBroadcast()
	}
	
	if _, ok := msg.(*KGRound5Message2); ok {
		return msg.IsBroadcast()
	}
	
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round5) Update() (bool, error) {
	for j, msg := range round.temp.kgRound5Messages1 {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		
		msg5 := round.temp.kgRound5Messages[j]
		if msg5 == nil || !round.CanAccept(msg5) {
			return false, nil
		}
		
		msg52 := round.temp.kgRound5Messages2[j]
		if msg52 == nil || !round.CanAccept(msg52) {
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

//------------------------------------------

func (round *round5) ExecTee(curIndex int) error {
    ntilde := round.temp.kgRound4Messages[curIndex].(*KGRound4Message).U1NtildeH1H2.Ntilde
    s := &socket.KGRound5SquareFee{Ntilde:ntilde,P1:round.temp.p1Enc,P2:round.temp.p2Enc}
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

    num,_ := new(big.Int).SetString(msgmap["Num"],10)
    sfProof := &ec2.SquareFreeProof{}
    err = json.Unmarshal([]byte(msgmap["SfPf"]),sfProof)
    if err != nil {
	return err
    }

    srm := &KGRound5Message2{    // same as KGRound2Message2
	    KGRoundMessage: new(KGRoundMessage),
	    Num:		num,
	    SfPf:		sfProof,
    }
    srm.SetFromID(round.dnodeid)
    srm.SetFromIndex(curIndex)

    round.temp.kgRound5Messages2[curIndex] = srm
    round.out <- srm

    s2 := &socket.KGRound5Hv{Ntilde:ntilde,P1:round.temp.p1Enc,P2:round.temp.p2Enc}
    s2.Base.SetBase(round.keytype,round.msgprex)
    err = socket.SendMsgData(smpc.VSocketConnect,s2)
    if err != nil {
	return err
    }
   
    kgs = <-round.teeout
    msgmap = make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	return err
    }

    num,_ = new(big.Int).SetString(msgmap["Num"],10)

    hvProof := &ec2.HvProof{}
    err = json.Unmarshal([]byte(msgmap["HvPf"]),hvProof)
    if err != nil {
	return err
    }

    srm2 := &KGRound5Message1{
	    KGRoundMessage: new(KGRoundMessage),
	    Num:		num,
	    HvPf:		hvProof,
    }
    srm2.SetFromID(round.dnodeid)
    srm2.SetFromIndex(curIndex)

    round.temp.kgRound5Messages1[curIndex] = srm2
    round.out <- srm2
    
    kg := &KGRound5Message{
	    KGRoundMessage: new(KGRoundMessage),
	    ComXiGD:	round.temp.commitXiG.D,
    }
    
    kg.SetFromID(round.dnodeid)
    kg.SetFromIndex(curIndex)

    round.temp.kgRound5Messages[curIndex] = kg
    round.out <- kg

    return nil
}

