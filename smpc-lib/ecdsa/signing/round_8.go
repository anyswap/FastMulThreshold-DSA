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
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"math/big"
)

// Start broacast current node s to other nodes
func (round *round8) Start() error {
	if round.started {
		fmt.Printf("============= round8.start fail =======\n")
		return errors.New("round already started")
	}
	round.number = 8
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
		return err
	}

	var K1Rx *big.Int
	var K1Ry *big.Int

	for k, v := range round.idsign {
	    index := -1
	    for kk, vv := range round.save.IDs {
		    if v.Cmp(vv) == 0 {
			    index = kk
			    break
		    }
	    }

	    if index == -1 {
		return errors.New("get node uid error")
	    }
	    
	    paiPk := round.save.U1PaillierPk[index]
	    if paiPk == nil {
		return errors.New("get paillier public key fail")
	    }
	    nt := round.save.U1NtildeH1H2[index]
	    if nt == nil {
		return errors.New("get ntilde fail")
	    }
	    
	    msg7, _ := round.temp.signRound7Messages[k].(*SignRound7Message)
	    msg3, _ := round.temp.signRound3Messages[k].(*SignRound3Message)
	    pdlWSlackStatement := &ec2.PDLwSlackStatement{
		    PK:         paiPk,
		    CipherText: msg3.Kc,
		    K1RX:	msg7.K1RX,
		    K1RY:   msg7.K1RY,
		    Rx:     round.temp.deltaGammaGx,
		    Ry:     round.temp.deltaGammaGy,
		    H1:         nt.H1,
		    H2:         nt.H2,
		    NTilde:     nt.Ntilde,
	    }

	    if !ec2.PDLwSlackVerify(pdlWSlackStatement,msg7.PdlwSlackPf) {
		fmt.Printf("=======================signing round 8,failed to verify ZK proof of consistency between R_i and E_i(k_i) for Uid %v,k = %v=========================\n",v,k)
		return fmt.Errorf("failed to verify ZK proof of consistency between R_i and E_i(k_i) for Uid %v,k = %v", v,k)
	    }

	    if k == 0 {
		K1Rx = msg7.K1RX
		K1Ry = msg7.K1RY
		continue
	    }

	    K1Rx,K1Ry = secp256k1.S256().Add(K1Rx,K1Ry,msg7.K1RX,msg7.K1RY)
	}

	if K1Rx.Cmp(secp256k1.S256().Gx) != 0 || K1Ry.Cmp(secp256k1.S256().Gy) != 0 {
	    fmt.Printf("==============================signing round 8,consistency check failed: g != R products==================================\n")
	    return fmt.Errorf("consistency check failed: g != R products")
	}

	S1X,S1Y := secp256k1.S256().ScalarMult(round.temp.deltaGammaGx,round.temp.deltaGammaGy,round.temp.sigma1.Bytes())
	hx,hy,err := ec2.CalcHPoint()
	if err != nil {
	    fmt.Printf("calc h point fail, err = %v",err)
	    return err 
	}

	stProof := ec2.NewSTProof(round.temp.t1X,round.temp.t1Y,S1X,S1Y,round.temp.deltaGammaGx,round.temp.deltaGammaGy,hx,hy,round.temp.sigma1,round.temp.l1)
	if stProof == nil {
	    return fmt.Errorf("new stproof fail")
	}

	srm := &SignRound8Message{
		SignRoundMessage: new(SignRoundMessage),
		S1X:   S1X,
		S1Y:   S1Y,
		STpf: stProof,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound8Messages[curIndex] = srm
	round.out <- srm

	//round.end <- PrePubData{K1: round.temp.u1K, R: round.temp.deltaGammaGx, Ry: round.temp.deltaGammaGy, Sigma1: round.temp.sigma1}
	
	//fmt.Printf("============= round8.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round8) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound8Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round8) Update() (bool, error) {
	for j, msg := range round.temp.signRound8Messages {
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
func (round *round8) NextRound() smpc.Round {
	round.started = false
	return &round9{round}
}
