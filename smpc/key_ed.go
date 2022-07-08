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
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	edkeygen "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/keygen"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"strconv"
	"strings"
	"sync"
	"time"
)

//---------------------------------------EDDSA start-----------------------------------------------------------------------

// ProcessInboundMessagesEDDSA Analyze the obtained P2P messages and enter next round
func ProcessInboundMessagesEDDSA(msgprex string, finishChan chan struct{}, errChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
    	if msgprex == "" {
	    return
	}

	defer func() {
		wg.Done()
		fmt.Printf("stop processing inbound messages, key = %v \n", msgprex)
		close(errChan)
	}()

	fmt.Printf("start processing inbound messages, key = %v \n", msgprex)
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("ed,fail to process inbound messages")}
		ch <- res
		return
	}

	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			if msgmap["Type"] == "KGRound0Message" { //0 message
				from := msgmap["FromID"]
				w.MsgToEnode[from] = msgmap["ENode"]
			}

			mm := GetRealMessageEDDSA(msgmap)
			if mm == nil {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("ed,fail to process inbound messages")}
				ch <- res
				return
			}

			//check sig
			if msgmap["Sig"] == "" {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
				return
			}

			if msgmap["ENode"] == "" {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail")}
				ch <- res
				return
			}

			sig, err := hex.DecodeString(msgmap["Sig"])
			if err != nil {
			    common.Error("[KEYGEN] decode msg sig data error","err",err,"key",msgprex)
			    res := RPCSmpcRes{Ret: "", Err: err}
			    ch <- res
			    return
			}
			
			common.Debug("===============keygen ed,check p2p msg===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			if !checkP2pSig(sig,mm,msgmap["ENode"]) {
			    common.Error("===============keygen ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
			    ch <- res
			    return
			}
			
			// check fromID
			_,UID := GetNodeUID(msgmap["ENode"], "ED25519",w.groupid)
			id := fmt.Sprintf("%v", UID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============keygen ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"],"err","check from ID fail")
			    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check from ID fail")}
			    ch <- res
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
				common.Error("===============keygen ed,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
				return
			}
			////

			_, err = w.DNode.Update(mm)
			if err != nil {
				common.Error("====================ProcessInboundMessagesEDDSA,dnode update fail=======================", "receiv msg", m, "err", err)
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// GetRealMessageEDDSA get the message data struct by map. (p2p msg ---> map)
func GetRealMessageEDDSA(msg map[string]string) smpclib.Message {
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
	if msg["Type"] == "KGRound1Message" {
	    if msg["CPk"] == "" {
		return nil
	    }

		cpks, err := hex.DecodeString(msg["CPk"])
		if cpks == nil || err != nil {
		    return nil
		}

		var temCpk [32]byte
		copy(temCpk[:], cpks[:])
		kg := &edkeygen.KGRound1Message{
			KGRoundMessage: new(edkeygen.KGRoundMessage),
			CPk:            temCpk,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//2 message
	if msg["Type"] == "KGRound2Message" {
	    if msg["ZkPk"] == "" {
		return nil
	    }

		zkpks, err := hex.DecodeString(msg["ZkPk"])
		if zkpks == nil || err != nil {
		    return nil
		}

		var temzkpk [64]byte
		copy(temzkpk[:], zkpks[:])
		kg := &edkeygen.KGRound2Message{
			KGRoundMessage: new(edkeygen.KGRoundMessage),
			ZkPk:           temzkpk,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//3 message
	if msg["Type"] == "KGRound3Message" {
	    if msg["DPk"] == "" {
		return nil
	    }

		dpks, err := hex.DecodeString(msg["DPk"])
		if dpks == nil || err != nil {
		    return nil
		}

		var temdpk [64]byte
		copy(temdpk[:], dpks[:])
		kg := &edkeygen.KGRound3Message{
			KGRoundMessage: new(edkeygen.KGRoundMessage),
			DPk:            temdpk,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//4 message
	if msg["Type"] == "KGRound4Message" {
	    if msg["Share"] == "" {
		return nil
	    }

		shares, err := hex.DecodeString(msg["Share"])
		if shares == nil || err != nil {
		    return nil
		}

		var temsh [32]byte
		copy(temsh[:], shares[:])
		kg := &edkeygen.KGRound4Message{
			KGRoundMessage: new(edkeygen.KGRoundMessage),
			Share:          temsh,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//5 message
	if msg["Type"] == "KGRound5Message" {
	    if msg["CfsBBytes"] == "" {
		return nil
	    }

		tmp := strings.Split(msg["CfsBBytes"], ":")
		tmp2 := make([][32]byte, len(tmp))
		for k, v := range tmp {
			vv, err := hex.DecodeString(v)
			if vv == nil || err != nil {
			    return nil
			}

			var tem [32]byte
			copy(tem[:], vv[:])
			tmp2[k] = tem
		}

		kg := &edkeygen.KGRound5Message{
			KGRoundMessage: new(edkeygen.KGRoundMessage),
			CfsBBytes:      tmp2,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	kg := &edkeygen.KGRound0Message{
		KGRoundMessage: new(edkeygen.KGRoundMessage),
	}
	kg.SetFromID(from)
	kg.SetFromIndex(-1)
	kg.ToID = to

	return kg
}

// processKeyGenEDDSA  Obtain the data to be sent in each round and send it to other nodes until the end of the request command 
func processKeyGenEDDSA(msgprex string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan edkeygen.LocalDNodeSaveData) error {
    	if msgprex == "" {
	    return errors.New("param error")
	}

	for {
		select {
		case <-errChan: // when keyGenParty return
			fmt.Printf("=========== processKeyGenEDDSA,error channel closed fail to start local smpc node, key = %v ===========\n", msgprex)
			return errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EdKeygenTimeout)):
			fmt.Printf("====================== processKeyGenEDDSA,ed keygen timeout, key = %v ====================\n", msgprex)
			return errors.New("ed keygen timeout")
		case msg := <-outCh:
			err := ProcessOutCh(msgprex, msg)
			if err != nil {
				fmt.Printf("================= processKeyGenEDDSA,process outch err = %v,key = %v ==========\n", err, msgprex)
				return err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return fmt.Errorf("get worker fail")
			}

			w.edsku1.PushBack(string(msg.Sk[:]))
			w.edpk.PushBack(string(msg.FinalPkBytes[:]))

			s := "XXX" + common.Sep11 + string(msg.Pk[:]) + common.Sep11 + string(msg.TSk[:]) + common.Sep11 + string(msg.FinalPkBytes[:])
			w.edsave.PushBack(string(s))
			fmt.Printf("=======================processKeyGenEDDSA,success finish ed keygen, key = %v =======================\n", msgprex)
			return nil
		}
	}
}

// KGLocalDBSaveDataED ed keygen save data
type KGLocalDBSaveDataED struct {
	Save       *edkeygen.LocalDNodeSaveData
	MsgToEnode map[string]string
}

// OutMap  Convert KGLocalDBSaveDataED data struct to map 
func (kgsave *KGLocalDBSaveDataED) OutMap() map[string]string {
	out := kgsave.Save.OutMap()
	for key, value := range kgsave.MsgToEnode {
		out[key] = value
	}

	return out
}

// GetKGLocalDBSaveDataED get KGLocalDBSaveDataED data struct from map
func GetKGLocalDBSaveDataED(data map[string]string) *KGLocalDBSaveDataED {
	save := edkeygen.GetLocalDNodeSaveData(data)
	msgtoenode := make(map[string]string)
	for _, v := range save.IDs {
	    tmp := fmt.Sprintf("%v",v)
	    id := strings.ToLower(hex.EncodeToString([]byte(tmp)))
	    msgtoenode[id] = data[id]
	}

	kgsave := &KGLocalDBSaveDataED{Save: save, MsgToEnode: msgtoenode}
	return kgsave
}

//---------------------------------------EDDSA end-----------------------------------------------------------------------
