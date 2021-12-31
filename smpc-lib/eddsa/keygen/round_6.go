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
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	//"encoding/hex"
)

// Start verify vss,calc pk tSk
func (round *round6) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 6
	round.started = true
	round.resetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	ids, err := round.GetIDs()
	if err != nil {
		return err
	}

	var PkSet2 []byte
	for k, id := range ids {
		msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
		if !ok {
			return errors.New("ed,round.start get round4 msg fail")
		}

		msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
			return errors.New("ed,round.start get round5 msg fail")
		}

		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("ed,round.start get round3 msg fail")
		}

		shareUFlag := ed.VerifyVss(msg4.Share, round.temp.uids[curIndex], msg5.CfsBBytes)
		if !shareUFlag {
			fmt.Printf("error: vss share verification not pass at user: %v, k  = %v \n", id, k)
			return errors.New("smpc back-end internal error:vss share verification fail")
		}

		var temPk [32]byte
		t := msg3.DPk[:]
		copy(temPk[:], t[32:])
		PkSet2 = append(PkSet2[:], (temPk[:])...)
	}

	// 3.2 verify share2
	var a2 [32]byte
	var aDigest2 [64]byte

	// 3.3 calculate tSk
	var tSk [32]byte

	h := sha512.New()
	for k, id := range ids {
		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("ed,round.Start get round3 msg fail")
		}

		var temPk [32]byte
		t := msg3.DPk[:]
		copy(temPk[:], t[32:])

		h.Reset()
		_, err = h.Write(temPk[:])
		if err != nil {
			return err
		}
		_, err = h.Write(PkSet2)
		if err != nil {
			return err
		}
		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		var askBBytes [32]byte
		askB.ToBytes(&askBBytes)

		msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
		if !ok {
			return errors.New("ed,round.Start get round5 msg fail")
		}

		t2 := msg5.CfsBBytes
		tt := t2[0]
		if !bytes.Equal(askBBytes[:], tt[:]) {
			fmt.Printf("Error: VSS Coefficient Verification Not Pass at User: %v \n", id)
			return errors.New("smpc back-end internal error:VSS Coefficient verification fail")
		}

		msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
		if !ok {
			return errors.New("ed,round.Start get round4 msg fail")
		}

		t3 := msg4.Share
		ed.ScAdd(&tSk, &tSk, &t3)
	}

	// 3.4 calculate pk
	var finalPk ed.ExtendedGroupElement
	var finalPkBytes [32]byte

	i := 0
	for k := range ids {
		msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
		if !ok {
			return errors.New("ed,round.Start get round3 msg fail")
		}

		var temPk [32]byte
		t := msg3.DPk[:]
		copy(temPk[:], t[32:])

		h.Reset()
		_, err = h.Write(temPk[:])
		if err != nil {
			return err
		}

		_, err = h.Write(PkSet2)
		if err != nil {
			return err
		}

		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		if i == 0 {
			finalPk = askB
		} else {
			ed.GeAdd(&finalPk, &finalPk, &askB)
		}

		i++
	}

	finalPk.ToBytes(&finalPkBytes)

	round.Save.TSk = tSk
	round.Save.FinalPkBytes = finalPkBytes

	round.end <- *round.Save

	//pub := hex.EncodeToString(finalPkBytes[:])
	//fmt.Printf("========= round6 start success, pubkey = %v ==========\n", pub)
	return nil
}

// CanAccept end ed keygen
func (round *round6) CanAccept(msg smpc.Message) bool {
	return false
}

// Update end ed keygen
func (round *round6) Update() (bool, error) {
	return false, nil
}

// NextRound end ed keygen
func (round *round6) NextRound() smpc.Round {
	return nil
}
