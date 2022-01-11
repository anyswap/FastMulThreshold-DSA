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

// Start start round 9 
func (round *round9) Start() error {
	if round.started {
	    fmt.Printf("============= round9.start fail =======\n")
	    return errors.New("round already started")
	}
	
	round.number = 9
	round.started = true
	round.resetOK()
	
	hx,hy,err := ec2.CalcHPoint()
	if err != nil {
	    fmt.Printf("calc h point fail, err = %v",err)
	    return err 
	}

	var s1x *big.Int
	var s1y *big.Int
	
	for k := range round.idsign {
	    msg8, _ := round.temp.signRound8Messages[k].(*SignRound8Message)
	    msg5, _ := round.temp.signRound5Messages[k].(*SignRound5Message)
	    if ok := ec2.STVerify(msg8.S1X,msg8.S1Y,msg5.T1X,msg5.T1Y,round.temp.deltaGammaGx,round.temp.deltaGammaGy,hx,hy,msg8.STpf); !ok {
		return fmt.Errorf("STProof verify fail")
	    }

	    if k == 0 {
		s1x = msg8.S1X
		s1y = msg8.S1Y
		continue
	    }

	    s1x,s1y = secp256k1.S256().Add(s1x,s1y,msg8.S1X,msg8.S1Y)
	}

	if s1x.Cmp(round.save.Pkx) != 0 || s1y.Cmp(round.save.Pky) != 0 {
	    fmt.Printf("==============================signing round 9,consistency check failed; pubkey != products==================================\n")
	    return fmt.Errorf("consistency check failed; pubkey != products")
	}

	round.end <- PrePubData{K1: round.temp.u1K, R: round.temp.deltaGammaGx, Ry: round.temp.deltaGammaGy, Sigma1: round.temp.sigma1}

	//fmt.Printf("============= round9.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept end signing
func (round *round9) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end signing
func (round *round9) Update() (bool, error) {
	return false, nil
}

// NextRound end signing
func (round *round9) NextRound() smpc.Round {
	return nil
}


