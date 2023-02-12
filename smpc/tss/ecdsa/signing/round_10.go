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
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"math/big"
	"github.com/anyswap/FastMulThreshold-DSA/log"
)

func newRound10(temp *localTempData, save *keygen.LocalDNodeSaveData, idsign smpc.SortableIDSSlice, out chan<- smpc.Message, end chan<- PrePubData, kgid string, threshold int, paillierkeylength int, predata *PrePubData, txhash *big.Int, finalizeend chan<- *big.Int,keytype string,msgprex string,teeout chan string,tee bool) smpc.Round {
	return &round10{
		&base{temp, save, idsign, out, end, make([]bool, threshold), false, 0, kgid, threshold, paillierkeylength, predata, txhash, finalizeend,keytype,msgprex,teeout,tee}}
}

// Start broacast current node s to other nodes
func (round *round10) Start() error {
	if round.started {
	    fmt.Printf("============= round10.start fail =======\n")
	    return errors.New("round already started")
	}

	round.number = 10
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.kgid)
	if err != nil {
	    return err
	}

	mk1 := new(big.Int).Mul(round.txhash, round.predata.K1)
	rSigma1 := new(big.Int).Mul(round.predata.R, round.predata.Sigma1)
	us1 := new(big.Int).Add(mk1, rSigma1)
	us1 = new(big.Int).Mod(us1, secp256k1.S256(round.keytype).N1())

	srm := &SignRound9Message{
		SignRoundMessage: new(SignRoundMessage),
		Us1:              us1,
	}
	srm.SetFromID(round.kgid)
	srm.SetFromIndex(curIndex)

	round.temp.signRound9Messages[curIndex] = srm
	round.out <- srm

	log.Debug("============= fillize start success, ==============","current node id",round.kgid)
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round10) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*SignRound9Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round10) Update() (bool, error) {
	for j, msg := range round.temp.signRound9Messages {
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
func (round *round10) NextRound() smpc.Round {
	round.started = false
	return &round11{round}
}
