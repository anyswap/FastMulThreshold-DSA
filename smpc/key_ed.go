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
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	edkeygen "github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"strconv"
	"strings"
	"sync"
	"time"
)

//---------------------------------------EDDSA start-----------------------------------------------------------------------

// ProcessInboundMessages_EDDSA Analyze the obtained P2P messages and enter next round
func ProcessInboundMessages_EDDSA(msgprex string, finishChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
	defer wg.Done()
	fmt.Printf("start processing inbound messages, key = %v \n", msgprex)
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("ed,fail to process inbound messages")}
		ch <- res
		return
	}

	defer fmt.Printf("stop processing inbound messages, key = %v \n", msgprex)
	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			if msgmap["Type"] == "KGRound0Message" { //0 message
				from := msgmap["FromID"]
				w.MsgToEnode[from] = msgmap["ENode"]
			}

			mm := GetRealMessage_EDDSA(msgmap)
			if mm == nil {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("ed,fail to process inbound messages")}
				ch <- res
				return
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
				common.Error("====================ProcessInboundMessages_EDDSA,dnode update fail=======================", "receiv msg", m, "err", err)
				res := RpcSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// GetRealMessage_EDDSA get the message data struct by map. (p2p msg ---> map)
func GetRealMessage_EDDSA(msg map[string]string) smpclib.Message {
	from := msg["FromID"]
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
		cpks, _ := hex.DecodeString(msg["CPk"])
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
		zkpks, _ := hex.DecodeString(msg["ZkPk"])
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
		dpks, _ := hex.DecodeString(msg["DPk"])
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
		shares, _ := hex.DecodeString(msg["Share"])
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
		tmp := strings.Split(msg["CfsBBytes"], ":")
		tmp2 := make([][32]byte, len(tmp))
		for k, v := range tmp {
			vv, _ := hex.DecodeString(v)
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

// processKeyGen_EDDSA  Obtain the data to be sent in each round and send it to other nodes until the end of the request command 
func processKeyGen_EDDSA(msgprex string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan edkeygen.LocalDNodeSaveData) error {
	for {
		select {
		case <-errChan: // when keyGenParty return
			fmt.Printf("=========== processKeyGen_EDDSA,error channel closed fail to start local smpc node, key = %v ===========\n", msgprex)
			return errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * 300):
			fmt.Printf("====================== processKeyGen_EDDSA,ed keygen timeout, key = %v ====================\n", msgprex)
			return errors.New("ed keygen timeout")
		case msg := <-outCh:
			err := ProcessOutCh(msgprex, msg)
			if err != nil {
				fmt.Printf("================= processKeyGen_EDDSA,process outch err = %v,key = %v ==========\n", err, msgprex)
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
			fmt.Printf("=======================processKeyGen_EDDSA,success finish ed keygen, key = %v =======================\n", msgprex)
			return nil
		}
	}
}

type KGLocalDBSaveData_ed struct {
	Save       *edkeygen.LocalDNodeSaveData
	MsgToEnode map[string]string
}

// OutMap  Convert KGLocalDBSaveData_ed data struct to map 
func (kgsave *KGLocalDBSaveData_ed) OutMap() map[string]string {
	out := kgsave.Save.OutMap()
	for key, value := range kgsave.MsgToEnode {
		out[key] = value
	}

	return out
}

// GetKGLocalDBSaveData_ed get KGLocalDBSaveData_ed data struct from map
func GetKGLocalDBSaveData_ed(data map[string]string) *KGLocalDBSaveData_ed {
	save := edkeygen.GetLocalDNodeSaveData(data)
	msgtoenode := make(map[string]string)
	for _, v := range save.Ids {
		var tmp [32]byte
		copy(tmp[:], v.Bytes())
		id := strings.ToLower(hex.EncodeToString(tmp[:]))
		msgtoenode[id] = data[id]
	}

	kgsave := &KGLocalDBSaveData_ed{Save: save, MsgToEnode: msgtoenode}
	return kgsave
}

//---------------------------------------EDDSA end-----------------------------------------------------------------------
