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
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ed_ristretto"
	r255 "github.com/gtank/ristretto255"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	//"encoding/hex"
	"encoding/json"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/socket"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// Start verify vss,calc pk tSk
func (round *round6) Start() error {
	if round.started {
		return errors.New("ed,round already started")
	}
	round.number = 6
	round.started = true
	round.ResetOK()

	curIndex, err := round.GetDNodeIDIndex(round.dnodeid)
	if err != nil {
		return err
	}

	if round.tee {
	    return round.ExecTee(curIndex)
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

		var shareUFlag = false
		if round.keytype == smpc.SR25519 {
			shareUFlag = ed_ristretto.VerifyVss(msg4.Share, round.temp.uids[curIndex], msg5.CfsBBytes)
		}else {
			shareUFlag = ed.VerifyVss(msg4.Share, round.temp.uids[curIndex], msg5.CfsBBytes)
		}

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

		var askBBytes [32]byte
		if round.keytype == smpc.SR25519 {
			a2Scalar, err := ed_ristretto.BytesReduceToScalar(aDigest2[:])
			if err != nil {
				return err
			}
			var A = new(r255.Element)
			A.Decode(temPk[:])
			askB := new(r255.Element).ScalarMult(a2Scalar, A)
			askB.Encode(askBBytes[:0])
		}else {
			ed.ScReduce(&a2, &aDigest2)

			var askB, A ed.ExtendedGroupElement
			A.FromBytes(&temPk)
			ed.GeScalarMult(&askB, &a2, &A)
			askB.ToBytes(&askBBytes)
		}

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
		if round.keytype == smpc.SR25519 {
			ed_ristretto.ScAdd(&tSk, &tSk, &t3)
		}else {
			ed.ScAdd(&tSk, &tSk, &t3)
		}
	}

	// 3.4 calculate pk
	var finalPkBytes [32]byte

	if round.keytype == smpc.SR25519 {
		var finalPk = new(r255.Element)
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
			a2Scalar, _ := ed_ristretto.BytesReduceToScalar(aDigest2[:])

			var A = new(r255.Element)
			A.Decode(temPk[:])
			askB := new(r255.Element).ScalarMult(a2Scalar, A)

			if i == 0 {
				finalPk = askB
			} else {
				finalPk = new(r255.Element).Add(finalPk, askB)
			}

			i++
		}
		finalPk.Encode(finalPkBytes[:0])
	}else {
		var finalPk ed.ExtendedGroupElement
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
	}

	round.Save.TSk = tSk
	round.Save.FinalPkBytes = finalPkBytes

	round.end <- *round.Save

	pub := hex.EncodeToString(finalPkBytes[:])
	fmt.Printf("========= round6 start success, pubkey = %v ==========\n", pub)
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

//--------------------------------------

func (round *round6) ExecTee(curIndex int) error {
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

	    s := &socket.EDKGRound6VssCheck{Share:msg4.ShareEnc,ID:round.temp.uids[curIndex],CfsBBytes:msg5.CfsBBytes}
	    s.Base.SetBase(round.keytype,round.msgprex)
	    err := socket.SendMsgData(smpc.VSocketConnect,s)
	    if err != nil {
		log.Error("round6 start,marshal KGRound6 error","err",err)
		return err
	    }
	   
	    kgs := <-round.teeout
		bytesMap := make(map[string][]byte)
		err = json.Unmarshal([]byte(kgs), &bytesMap)
		msgmap := common.BytesMap2StringMap(bytesMap)
	    if err != nil {
		log.Error("round6 start,unmarshal KGRound6 return data error","err",err)
		return err
	    }
	    
	    if msgmap["VssCheckRes"] == "FALSE" {
		    fmt.Printf("error: vss share verification not pass at user: %v, k  = %v \n", id, k)
		    return errors.New("smpc back-end internal error:vss share verification fail")
	    }

	    var temPk [32]byte
	    t := msg3.DPk[:]
	    copy(temPk[:], t[32:])
	    PkSet2 = append(PkSet2[:], (temPk[:])...)
    }

    DPks := make([][64]byte,len(ids))
    Shares := make([]string,len(ids))
    CfsBBytes := make([][][32]byte,len(ids))
    for k, _ := range ids {
	msg3, ok := round.temp.kgRound3Messages[k].(*KGRound3Message)
	if !ok {
		return errors.New("ed,round.Start get round3 msg fail")
	}

	msg4, ok := round.temp.kgRound4Messages[k].(*KGRound4Message)
	if !ok {
		return errors.New("ed,round.Start get round4 msg fail")
	}

	msg5, ok := round.temp.kgRound5Messages[k].(*KGRound5Message)
	if !ok {
		return errors.New("ed,round.Start get round5 msg fail")
	}

	DPks[k] = msg3.DPk
	Shares[k] = msg4.ShareEnc
	CfsBBytes[k] = msg5.CfsBBytes
    }

    s := &socket.EDKGRound6Msg{PkSet2:PkSet2,Shares:Shares,DPks:DPks,CfsBBytes:CfsBBytes}
    s.Base.SetBase(round.keytype,round.msgprex)
    err = socket.SendMsgData(smpc.VSocketConnect,s)
    if err != nil {
	log.Error("round6 start,marshal KGRound6 error","err",err)
	return err
    }
   
    kgs := <-round.teeout
	bytesMap := make(map[string][]byte)
	err = json.Unmarshal([]byte(kgs), &bytesMap)
	msgmap := common.BytesMap2StringMap(bytesMap)
    if err != nil {
	log.Error("round6 start,unmarshal KGRound6 return data error","err",err)
	return err
    }
    
    /*tmp,err := hex.DecodeString(msgmap["tSk"])
    if err != nil {
	return err
    }
    var tSk [32]byte
    copy(tSk[:],tmp[:])*/

    tmp,err := hex.DecodeString(msgmap["finalPkBytes"])
    if err != nil {
	return err
    }
    var finalPkBytes [32]byte
    copy(finalPkBytes[:],tmp[:])
    
    round.Save.TSkEnc = []byte(msgmap["tSk"])
    round.Save.FinalPkBytes = finalPkBytes

    round.end <- *round.Save

    pub := hex.EncodeToString(finalPkBytes[:])
    fmt.Printf("========= round6 start success, pubkey = %v ==========\n", pub)
    return nil
}



