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

package smpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	edsigning "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/signing"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

//--------------------------------------------------------EDDSA start-------------------------------------------------------

// EdSignProcessInboundMessages Analyze the obtained P2P messages and enter next round
func EdSignProcessInboundMessages(msgprex string, finishChan chan struct{}, errChan chan struct{},wg *sync.WaitGroup, ch chan interface{}) {
	if msgprex == "" {
	    return
	}

	fmt.Printf("start ed sign processing inbound messages\n")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
	    if len(ch) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to ed sign process inbound messages")}
		ch <- res
	    }
	    
	    return
	}

	defer func() {
		wg.Done()
		fmt.Printf("stop ed sign processing inbound messages\n")
		close(errChan)
	}()

	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)

			//fmt.Printf("=================== EdSignProcessInboundMessages, msg = %v, err = %v, key = %v ====================\n", m, err, msgprex)
			if err != nil {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }

			    return
			}

			mm := EdSignGetRealMessage(msgmap)
			if mm == nil {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to ed sign process inbound messages")}
				ch <- res
			    }

			    return
			}

			//check sig
			if msgmap["Sig"] == "" {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
			    }

			    return
			}

			if msgmap["ENode"] == "" {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
			    }

			    return
			}

			sig, err := hex.DecodeString(msgmap["Sig"])
			if err != nil {
			    common.Error("[SIGN] decode msg sig data error","err",err,"key",msgprex)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err:err}
				ch <- res
			    }

			    return
			}
			
			common.Debug("===============sign ed,check p2p msg===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			if !checkP2pSig(sig,mm,msgmap["ENode"]) {
			    common.Error("===============sign ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
			    }

			    return
			}
			
			// check fromID
			// w.SmpcFrom is the MPC PubKey
			smpcpks, err := hex.DecodeString(w.SmpcFrom)
			if err != nil {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
			    }

			    return
			}

			exsit, da := GetPubKeyData(smpcpks[:])
			if !exsit || da == nil {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("ed sign get local save data fail")}
				ch <- res
			    }

			    return
			}
			
			pubs, ok := da.(*PubKeyData)
			if !ok || pubs.GroupID == "" {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("ed sign get local save data fail")}
				ch <- res
			    }

			    return
			}

			_,ID := GetNodeUID(msgmap["ENode"], "ED25519",pubs.GroupID)
			id := fmt.Sprintf("%v",ID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============sign ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"],"err","check from ID fail")
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check from ID fail")}
				ch <- res
			    }

			    return
			}
			
			// check whether 'from' is in the group
			succ := false
			_, nodes := GetGroup(w.groupid)
			others := strings.Split(nodes, common.Sep2)
			for _, v := range others {
			    node2 := ParseNode(v) //bug??
			    if strings.EqualFold(node2,msgmap["ENode"]) {
				succ = true
				break
			    }
			}

			if !succ {
				common.Error("===============sign ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
			    }

			    return
			}
			////

			_, err = w.DNode.Update(mm)
			if err != nil {
				fmt.Printf("========== EdSignProcessInboundMessages, dnode update fail, receiv smpc msg = %v, err = %v, key = %v ============\n", m, err, msgprex)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }

			    return
			}
		}
	}
}

// EdSignGetRealMessage get the message data struct by map. (p2p msg ---> map)
func EdSignGetRealMessage(msg map[string]string) smpclib.Message {
    	if msg == nil {
	    return nil
	}

	from := msg["FromID"]
	if from == "" {
	    return nil
	}

	var to []string
	v, ok := msg["ToID"]
	if ok && v != "" {
		to = strings.Split(v, ":")
	}

	index, indexerr := strconv.Atoi(msg["FromIndex"])
	if indexerr != nil {
		return nil
	}

	//1 message
	if msg["Type"] == "SignRound1Message" {
	    if msg["CR"] == "" {
		return nil
	    }

		cr, err := hex.DecodeString(msg["CR"])
		if cr == nil || err != nil {
		    return nil
		}

		var CR [32]byte
		copy(CR[:], cr[:])

		srm := &edsigning.SignRound1Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			CR:               CR,
		}

		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to
		return srm
	}

	//2 message
	if msg["Type"] == "SignRound2Message" {
	    if msg["ZkR"] == "" {
		return nil
	    }

		zkr, err := hex.DecodeString(msg["ZkR"])
		if zkr == nil || err != nil {
		    return nil
		}

		var ZkR [64]byte
		copy(ZkR[:], zkr[:])

		srm := &edsigning.SignRound2Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			ZkR:              ZkR,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//3 message
	if msg["Type"] == "SignRound3Message" {
	    if msg["DR"] == "" {
		return nil
	    }

		dr, err := hex.DecodeString(msg["DR"])
		if dr == nil || err != nil {
		    return nil
		}

		var DR [64]byte
		copy(DR[:], dr[:])

		srm := &edsigning.SignRound3Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			DR:               DR,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//4 message
	if msg["Type"] == "SignRound4Message" {
	    if msg["CSB"] == "" {
		return nil
	    }

		csb, err := hex.DecodeString(msg["CSB"])
		if csb == nil || err != nil {
		    return nil
		}

		var CSB [32]byte
		copy(CSB[:], csb[:])

		srm := &edsigning.SignRound4Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			CSB:              CSB,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//5 message
	if msg["Type"] == "SignRound5Message" {
	    if msg["DSB"] == "" {
		return nil
	    }

		dsb, err := hex.DecodeString(msg["DSB"])
		if dsb == nil || err != nil {
		    return nil
		}

		var DSB [64]byte
		copy(DSB[:], dsb[:])

		srm := &edsigning.SignRound5Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			DSB:              DSB,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	//6 message
	if msg["Type"] == "SignRound6Message" {
	    if msg["S"] == "" {
		return nil
	    }

		s, err := hex.DecodeString(msg["S"])
		if s == nil || err != nil {
		    return nil
		}

		var S [32]byte
		copy(S[:], s[:])

		srm := &edsigning.SignRound6Message{
			SignRoundMessage: new(edsigning.SignRoundMessage),
			S:                S,
		}
		srm.SetFromID(from)
		srm.SetFromIndex(index)
		srm.ToID = to

		return srm
	}

	return nil
}

// processSigned  Obtain the data to be sent in each round and send it to other nodes until the end of the sign command 
func processSigned(msgprex string, msgtoenode map[string]string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan edsigning.EdSignData) (*edsigning.EdSignData, error) {
	for {
		select {
		case <-errChan:
			fmt.Printf("=========================== processSigned,error channel closed fail to start local smpc node, key = %v =====================\n", msgprex)
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EdSignTimeout)):
			fmt.Printf("========================== processSigned,sign timeout, key = %v ==========================\n", msgprex)
			return nil, errors.New("signing timeout")
		case msg := <-outCh:
			err := SignProcessOutCh(msgprex, msgtoenode, msg, "")
			if err != nil {
				fmt.Printf("======================= processSigned, sign process outch err = %v, key = %v ====================\n", err, msgprex)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			//fmt.Printf("\n=======================ed sign finished successfully,sig data = %v, key = %v ======================\n", msg, msgprex)
			return &msg, nil
		}
	}
}

//-------------------------------------------------------EDDSA end---------------------------------------------------
