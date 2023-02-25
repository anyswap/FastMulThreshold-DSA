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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"encoding/json"
)

// Start start round 9 
func (round *round9) Start() error {
	if round.started {
	    fmt.Printf("============= round9.start fail =======\n")
	    return errors.New("round already started")
	}
	
	round.number = 9
	round.started = true
	round.ResetOK()

	if round.tee {
	    return round.ExecTee(-1)
	}

	hx,hy,err := ec2.CalcHPoint(round.keytype)
	if err != nil {
	    fmt.Printf("calc h point fail, err = %v",err)
	    return err 
	}

	var s1x *big.Int
	var s1y *big.Int
	
	for k := range round.idsign {
	    msg8, _ := round.temp.signRound8Messages[k].(*SignRound8Message)
	    msg5, _ := round.temp.signRound5Messages[k].(*SignRound5Message)
	    if ok := ec2.STVerify(round.keytype,msg8.S1X,msg8.S1Y,msg5.T1X,msg5.T1Y,round.temp.deltaGammaGx,round.temp.deltaGammaGy,hx,hy,msg8.STpf); !ok {
		return fmt.Errorf("STProof verify fail")
	    }

	    if k == 0 {
		s1x = msg8.S1X
		s1y = msg8.S1Y
		continue
	    }

	    s1x,s1y = secp256k1.S256(round.keytype).Add(s1x,s1y,msg8.S1X,msg8.S1Y)
	}

	if s1x.Cmp(round.save.Pkx) != 0 || s1y.Cmp(round.save.Pky) != 0 {
	    log.Error("==============================signing round 9,consistency check failed; pubkey != products==================================")
	    return fmt.Errorf("consistency check failed; pubkey != products")
	}

	round.end <- PrePubData{K1: round.temp.u1K, R: round.temp.deltaGammaGx, Ry: round.temp.deltaGammaGy, Sigma1: round.temp.sigma1}

	log.Debug("============= presign last round round9.start success ================")
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

//----------------------------------------

func (round *round9) ExecTee(curIndex int) error {
    s1x := make([]*big.Int,len(round.idsign))
    s1y := make([]*big.Int,len(round.idsign))
    t1x := make([]*big.Int,len(round.idsign))
    t1y := make([]*big.Int,len(round.idsign))
    stpf := make([]*ec2.STProof,len(round.idsign))

    for k := range round.idsign {
	msg8, _ := round.temp.signRound8Messages[k].(*SignRound8Message)
	msg5, _ := round.temp.signRound5Messages[k].(*SignRound5Message)

	s1x[k] = msg8.S1X
	s1y[k] = msg8.S1Y
	t1x[k] = msg5.T1X
	t1y[k] = msg5.T1Y
	stpf[k] = msg8.STpf
    }

    s := &socket.SigningRound9Msg{S1X:s1x,S1Y:s1y,T1X:t1x,T1Y:t1y,DeltaGammaGx:round.temp.deltaGammaGx,DeltaGammaGy:round.temp.deltaGammaGy,STProof:stpf,Pkx:round.save.Pkx,Pky:round.save.Pky}
    s.Base.SetBase(round.keytype,round.msgprex)
    err := socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round9 start,send msg data error","err",err)
	return err
    }
   
    kgs := <-round.teeout
    msgmap := make(map[string]string)
    err = json.Unmarshal([]byte(kgs), &msgmap)
    if err != nil {
	log.Error("round9 start,unmarshal return data error","err",err)
	return err
    }

    if msgmap["STCheckRes"] == "FALSE" {
	return fmt.Errorf("signing round9 check fail")
    }

    round.end <- PrePubData{K1Enc: round.temp.u1KEnc, R: round.temp.deltaGammaGx, Ry: round.temp.deltaGammaGy, Sigma1: round.temp.sigma1}

    log.Debug("============= presign last round round9.start success ================")
    return nil
}




