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
	"math/big"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
)

// Start return save data 
func (round *round7) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 7
	round.started = true
	round.resetOK()
	
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

		deCommit := &ec2.Commitment{C: msg4.ComXiC, D: msg5.ComXiGD}
		_, xiG := deCommit.DeCommit()

		msg6, ok := round.temp.kgRound6Messages[k].(*KGRound6Message)
		if !ok {
			return errors.New("round.Start get round6 msg fail")
		}

		if !ec2.ZkXiVerify(xiG, msg6.U1zkXiProof) {
			fmt.Printf("========= round7 verify zkx fail, k = %v ==========\n", k)
			return errors.New("verify zkx fail")
		}
	}

	// add HVZK Proof for a Product of Two Primes
	// for Ntilde = p*q
	// verifier check:
	// 1. Ntildei > 0
	// 2. Ntildei is not a prime
	// 3. the count of xij != 0 >= 3*m/8
	// 4. xij^2 = rohij (mod Ntildei) for every xij != 0  (j = 1,2,...m)
	for k := range round.Save.IDs {
	    msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	    if !ok {
		return errors.New("round.Start get round4 msg fail")
	    }

	    msg61, ok := round.temp.kgRound6Messages1[k].(*KGRound6Message1)
	    if !ok {
		return errors.New("round.Start get round 6-1 msg fail")
	    }

	    if !ec2.CheckPrime(msg4.U1NtildeH1H2.Ntilde) {
		fmt.Printf("=============keygen,round 7,check prime fail, N = %v=================================\n",msg4.U1NtildeH1H2.Ntilde)
		return errors.New("check ntilde fail")
	    }

	    zero,_ := new(big.Int).SetString("0",10)
	    one,_ := new(big.Int).SetString("1",10)
	    count := zero
	    for kk,vv := range msg61.Qua {
		if vv.Sign() == 0 {
		    //fmt.Printf("==================keygen,round 7,x = %v,kk = %v======================\n",vv,kk)
		    continue
		}

		count.Add(count,one)

		roh := round.temp.roh[k]
		t := new(big.Int).Mul(vv,vv)
		t = new(big.Int).Mod(t,msg4.U1NtildeH1H2.Ntilde)
		if t.Cmp(roh[kk]) != 0 {
		    fmt.Printf("=============keygen,round 7,check quadratic residue fail, kk = %v,x = %v,roh = %v,N = %v=================================\n",kk,vv,roh[kk],msg4.U1NtildeH1H2.Ntilde)
		    return errors.New("check quadratic residue fail")
		}
	    }
	    
	    three,_ := new(big.Int).SetString("3",10)
	    eight,_ := new(big.Int).SetString("8",10)
	    m := ec2.GetHoeffdingBound(ec2.HoeffdingBoundParam)
	    // t = 3*m/8
	    t := new(big.Int).Mul(three,m)
	    t = new(big.Int).Div(t,eight)
	    if count.Cmp(t) < 0 {
		fmt.Printf("=============keygen,round 7,check the number of nonzero responses fail,must at least 3m/8, count = %v, 3*m/8 = %v=================================\n",count,t)
		return errors.New("check the number of nonzero responses fail,must at least 3m/8")
	    }
	    
	}
	///

	round.end <- *round.Save

	//fmt.Printf("========= round7 start success ==========\n")
	return nil
}

// CanAccept end keygen
func (round *round7) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end keygen
func (round *round7) Update() (bool, error) {
	return false, nil
}

// NextRound end keygen
func (round *round7) NextRound() smpc.Round {
	return nil
}
