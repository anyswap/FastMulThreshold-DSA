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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/log"
)

// Start get S
func (round *round11) Start() error {
	if round.started {
	    log.Error("============= round11.start fail =======")
	    return errors.New("round already started")
	}
	
	round.number = 11
	round.started = true
	round.ResetOK()

	if round.tee {
	    return round.ExecTee(-1)
	}

	msg9, _ := round.temp.signRound9Messages[0].(*SignRound9Message)
	s := msg9.Us1

	for k := range round.idsign {
		if k == 0 {
			continue
		}

		msg9, _ := round.temp.signRound9Messages[k].(*SignRound9Message)
		s = new(big.Int).Add(s, msg9.Us1)
	}
	s = new(big.Int).Mod(s, secp256k1.S256(round.keytype).N1())

	round.finalizeend <- s
	//fmt.Printf("============= round9.start success, current node id = %v =======\n", round.kgid)
	return nil
}

// CanAccept end signing
func (round *round11) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end signing
func (round *round11) Update() (bool, error) {
	return false, nil
}

// NextRound end signing
func (round *round11) NextRound() smpc.Round {
	return nil
}

func (round *round11) ExecTee(curIndex int) error {

    us := make([]*big.Int,len(round.idsign))
    for k := range round.idsign {
	msg9, _ := round.temp.signRound9Messages[k].(*SignRound9Message)
	us[k] = msg9.Us1
    }

    s := &socket.SigningRound11Msg{S:us}
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

    S,_ := new(big.Int).SetString(msgmap["S"],10)

    round.finalizeend <- S
    return nil
}

