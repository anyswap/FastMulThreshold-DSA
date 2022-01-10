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

package reshare

import (
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"math/big"
)

// Start verify vss and commitment data,calc pubkey and new SKi 
func (round *round3) Start() error {
	if round.started {
		return errors.New("round already started")
	}
	round.number = 3
	round.started = true
	round.resetOK()

	// use round.temp.reshareRound1Messages replace round.idreshare,because round.idreshare == nil when oldnode == false
	for k := range round.temp.reshareRound1Messages {
		msg2, ok := round.temp.reshareRound2Messages[k].(*ReRound2Message)
		if !ok {
			return errors.New("round.Start get round2 msg fail")
		}

		ushare := &ec2.ShareStruct2{ID: msg2.ID, Share: msg2.Share}
		msg21, ok := round.temp.reshareRound2Messages1[k].(*ReRound2Message1)
		if !ok {
			return errors.New("round.Start get round2-1 msg fail")
		}

		ps := &ec2.PolyGStruct2{PolyG: msg21.SkP1PolyG}
		if !ushare.Verify2(ps) {
			fmt.Printf("========= round3 verify share fail, k = %v ==========\n", k)
			return errors.New("verify share data fail")
		}

		//verify commitment
		msg1, ok := round.temp.reshareRound1Messages[k].(*ReRound1Message)
		if !ok {
			return errors.New("round.Start get round1 msg fail")
		}

		deCommit := &ec2.Commitment{C: msg1.ComC, D: msg21.ComD}
		if !deCommit.Verify() {
			fmt.Printf("========= round3 verify commitment fail, k = %v ==========\n", k)
			return errors.New("verify commitment fail")
		}
	}

	var pkx *big.Int
	var pky *big.Int
	var newskU1 *big.Int

	for k := range round.temp.reshareRound1Messages {
		msg21, _ := round.temp.reshareRound2Messages1[k].(*ReRound2Message1)
		msg1, _ := round.temp.reshareRound1Messages[k].(*ReRound1Message)
		msg2, _ := round.temp.reshareRound2Messages[k].(*ReRound2Message)
		ushare := &ec2.ShareStruct2{ID: msg2.ID, Share: msg2.Share}

		deCommit := &ec2.Commitment{C: msg1.ComC, D: msg21.ComD}
		_, u1G := deCommit.DeCommit()
		pkx = u1G[0]
		pky = u1G[1]

		newskU1 = ushare.Share
		break
	}

	for k := range round.temp.reshareRound1Messages {
		if k == 0 {
			continue
		}

		msg2, _ := round.temp.reshareRound2Messages[k].(*ReRound2Message)
		ushare := &ec2.ShareStruct2{ID: msg2.ID, Share: msg2.Share}
		msg21, _ := round.temp.reshareRound2Messages1[k].(*ReRound2Message1)
		msg1, _ := round.temp.reshareRound1Messages[k].(*ReRound1Message)

		deCommit := &ec2.Commitment{C: msg1.ComC, D: msg21.ComD}

		_, u1G := deCommit.DeCommit()
		pkx, pky = secp256k1.S256().Add(pkx, pky, u1G[0], u1G[1])

		newskU1 = new(big.Int).Add(newskU1, ushare.Share)
	}

	newskU1 = new(big.Int).Mod(newskU1, secp256k1.S256().N)

	round.Save.SkU1 = newskU1
	round.Save.Pkx = pkx
	round.Save.Pky = pky
	round.temp.pkx = pkx
	round.temp.pky = pky
	round.temp.newskU1 = newskU1

	idtmp, ok := new(big.Int).SetString(round.dnodeid, 10)
	if !ok {
		return errors.New("get id big number fail")
	}

	curIndex := -1
	for k, v := range round.Save.IDs {
		if v.Cmp(idtmp) == 0 {
			curIndex = k
			break
		}
	}

	if curIndex < 0 {
		return errors.New("get cur index fail")
	}

	var u1PaillierSk *ec2.PrivateKey
	var u1PaillierPk *ec2.PublicKey

	// old node use old paillier.PK/paillier.SK
	// new node generate new paillier.PK/paillier.SK
	if round.oldnode && round.oldindex != -1 {
	    u1PaillierSk = round.Save.U1PaillierSk
	    u1PaillierPk = round.Save.U1PaillierPk[round.oldindex]
	} else {
	    u1PaillierPk, u1PaillierSk,_,_ = ec2.GenerateKeyPair(round.paillierkeylength)
	}

	//round.Save.U1PaillierSk = u1PaillierSk
	//round.Save.U1PaillierPk[curIndex] = u1PaillierPk
	round.temp.u1PaillierSk = u1PaillierSk
	round.temp.u1PaillierPk = u1PaillierPk

	re := &ReRound3Message{
		ReRoundMessage: new(ReRoundMessage),
		U1PaillierPk:        u1PaillierPk,
	}
	re.SetFromID(round.dnodeid)
	re.SetFromIndex(curIndex)
	round.temp.reshareRound3Messages[curIndex] = re
	round.out <- re

	//fmt.Printf("========= round3 start success ==========\n")
	return nil
}

// CanAccept is it legal to receive this message 
func (round *round3) CanAccept(msg smpc.Message) bool {
	if _, ok := msg.(*ReRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

// Update  is the message received and ready for the next round? 
func (round *round3) Update() (bool, error) {
	for j, msg := range round.temp.reshareRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}

		round.ok[j] = true

		//add for reshare only
		if j == (len(round.temp.reshareRound3Messages) - 1) {
			for jj := range round.ok {
				round.ok[jj] = true
			}
		}
		//
	}

	return true, nil
}

// NextRound enter next round
func (round *round3) NextRound() smpc.Round {
	round.started = false
	return &round4{round}
}
