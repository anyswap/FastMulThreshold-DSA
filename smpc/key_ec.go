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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"encoding/hex"
)

//---------------------------------------ECDSA start-----------------------------------------------------------------------

// ProcessInboundMessages Analyze the obtained P2P messages and enter next round
func ProcessInboundMessages(msgprex string, finishChan chan struct{}, wg *sync.WaitGroup, ch chan interface{}) {
    	if msgprex == "" {
	    return
	}

	defer wg.Done()
	fmt.Printf("start processing inbound messages\n")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to process inbound messages")}
		ch <- res
		return
	}

	defer fmt.Printf("stop processing inbound messages\n")
	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			if w.DNode == nil {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("node data error")}
				ch <- res
				return
			}
			
			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				fmt.Printf("======================ProcessInboundMessages,unmarshal msg error,key = %v,msg = %v,err = %v=============\n",msgprex,m,err)
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}

			if msgmap["Type"] == "KGRound0Message" { //0 message
				from := msgmap["FromID"]
				w.MsgToEnode[from] = msgmap["ENode"]
			}

			mm := GetRealMessage(msgmap)
			if mm == nil {
				fmt.Printf("======================ProcessInboundMessages,get msg error,key = %v,msg = %v,err = %v=============\n",msgprex,m,err)
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to process inbound messages")}
				ch <- res
				return
			}
			
			//check sig
			if msgmap["Sig"] == "" {
				fmt.Printf("======================ProcessInboundMessages,verify sig fail,sig data error,key = %v,msg = %v,err = %v=============\n",msgprex,m,err)
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail,sig data error")}
				ch <- res
				return
			}

			if msgmap["ENode"] == "" {
				fmt.Printf("======================ProcessInboundMessages,verify sig fail,enode info error,key = %v,msg = %v,err = %v=============\n",msgprex,m,err)
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail,enode info error")}
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
			
			if !checkP2pSig(sig,mm,msgmap["ENode"]) {
			    common.Error("===============keygen,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
			    ch <- res
			    return
			}

			// check fromID
			_,UID := GetNodeUID(msgmap["ENode"], "EC256K1",w.groupid)
			id := fmt.Sprintf("%v", UID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============keygen,check p2p msg fail===============","UID",UID,"uid",uid,"fromID",mm.GetFromID(),"gid",w.groupid,"sender",msgmap["ENode"],"msg type",msgmap["Type"],"err","check from ID fail")
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
				common.Error("===============keygen,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
				return
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
				common.Error("====================ProcessInboundMessages,dnode update fail=======================", "receiv msg", m, "err", err)
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
				return
			}
		}
	}
}

// GetRealMessage get the message data struct by map. (p2p msg ---> map)
func GetRealMessage(msg map[string]string) smpclib.Message {
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
		pub := &ec2.PublicKey{}
		if msg["U1PaillierPk"] == "" {
		    return nil
		}

		err := pub.UnmarshalJSON([]byte(msg["U1PaillierPk"]))
		if err == nil {
			comc, _ := new(big.Int).SetString(msg["ComC"], 10)
			ComCBip32, _ := new(big.Int).SetString(msg["ComC_bip32"], 10)
			if comc == nil || ComCBip32 == nil {
			    return nil
			}

			kg := &keygen.KGRound1Message{
				KGRoundMessage: new(keygen.KGRoundMessage),
				ComC:           comc,
				ComCBip32:     ComCBip32,
				U1PaillierPk:   pub,
			}
			kg.SetFromID(from)
			kg.SetFromIndex(index)
			kg.ToID = to
			return kg
		}
	}

	//2 message
	if msg["Type"] == "KGRound2Message" {
		id, _ := new(big.Int).SetString(msg["ID"], 10)
		sh, _ := new(big.Int).SetString(msg["Share"], 10)
		if id == nil || sh == nil {
		    return nil
		}

		kg := &keygen.KGRound2Message{
			KGRoundMessage: new(keygen.KGRoundMessage),
			ID:             id,
			Share:          sh,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//2-1 message
	if msg["Type"] == "KGRound2Message1" {
		c1, _ := new(big.Int).SetString(msg["C1"], 10)
		if c1 == nil {
		    return nil
		}

		kg := &keygen.KGRound2Message1{
			KGRoundMessage: new(keygen.KGRoundMessage),
			C1:             c1,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//2-2 message
	if msg["Type"] == "KGRound2Message2" {
	    if msg["SfPf"] == "" {
		return nil
	    }

	    if msg["Num"] == "" {
		return nil
	    }

	    pf := &ec2.SquareFreeProof{}
	    err := pf.UnmarshalJSON([]byte(msg["SfPf"]))
	    if err == nil {
		num, ok := new(big.Int).SetString(msg["Num"], 10)
		if !ok {
		    return nil
		}

		kg := &keygen.KGRound2Message2{
		    KGRoundMessage: new(keygen.KGRoundMessage),
		    Num:		num,
		    SfPf:             pf,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	    }
	}

	//3 message
	if msg["Type"] == "KGRound3Message" {
	    if msg["ComU1GD"] == "" || msg["ComC1GD"] == "" || msg["U1PolyGG"] == "" {
		return nil
	    }

		ugd := strings.Split(msg["ComU1GD"], ":")
		u1gd := make([]*big.Int, len(ugd))
		for k, v := range ugd {
			u1gd[k], _ = new(big.Int).SetString(v, 10)
			if u1gd[k] == nil {
			    return nil
			}
		}

		ucd := strings.Split(msg["ComC1GD"], ":")
		u1cd := make([]*big.Int, len(ucd))
		for k, v := range ucd {
			u1cd[k], _ = new(big.Int).SetString(v, 10)
			if u1cd[k] == nil {
			    return nil
			}
		}

		uggtmp := strings.Split(msg["U1PolyGG"], "|")
		ugg := make([][]*big.Int, len(uggtmp))
		for k, v := range uggtmp {
			uggtmp2 := strings.Split(v, ":")
			tmp := make([]*big.Int, len(uggtmp2))
			for kk, vv := range uggtmp2 {
				tmp[kk], _ = new(big.Int).SetString(vv, 10)
				if tmp[kk] == nil {
				    return nil
				}
			}
			ugg[k] = tmp
		}

		kg := &keygen.KGRound3Message{
			KGRoundMessage: new(keygen.KGRoundMessage),
			ComU1GD:        u1gd,
			ComC1GD:        u1cd,
			U1PolyGG:       ugg,
		}

		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//3-1 message
	if msg["Type"] == "KGRound3Message1" {
	    if msg["Y"] == "" {
		return nil
	    }

		y, _ := new(big.Int).SetString(msg["Y"], 10)
		if y == nil {
		    return nil
		}

		kg := &keygen.KGRound3Message1{
		    KGRoundMessage: new(keygen.KGRoundMessage),
		    Y:             y,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	}

	//4 message
	if msg["Type"] == "KGRound4Message" {
		nti := &ec2.NtildeH1H2{}
		if msg["U1NtildeH1H2"] == "" {
		    return nil
		}

		if err := nti.UnmarshalJSON([]byte(msg["U1NtildeH1H2"])); err == nil {
			pf1 := &ec2.NtildeProof{}
			if msg["NtildeProof1"] == "" {
			    return nil
			}

			if err := pf1.UnmarshalJSON([]byte(msg["NtildeProof1"])); err == nil {
				pf2 := &ec2.NtildeProof{}
				if msg["NtildeProof2"] == "" {
				    return nil
				}

				if err := pf2.UnmarshalJSON([]byte(msg["NtildeProof2"])); err == nil {
				    if msg["ComXiC"] == "" {
					return nil
				    }

				    comxic,_ := new(big.Int).SetString(msg["ComXiC"],10)
				    
					kg := &keygen.KGRound4Message{
						KGRoundMessage: new(keygen.KGRoundMessage),
						U1NtildeH1H2:   nti,
						NtildeProof1:   pf1,
						NtildeProof2:   pf2,
						ComXiC:		comxic,
					}
					kg.SetFromID(from)
					kg.SetFromIndex(index)
					kg.ToID = to
					return kg
				}
			}
		}
	}

	//5 message
	if msg["Type"] == "KGRound5Message" {
	    if msg["ComXiGD"] == "" {
		return nil
	    }

	    xgd := strings.Split(msg["ComXiGD"], ":")
	    xigd := make([]*big.Int, len(xgd))
	    for k, v := range xgd {
		xigd[k], _ = new(big.Int).SetString(v, 10)
		if xigd[k] == nil {
		    return nil
		}
	    }

	    kg := &keygen.KGRound5Message{
		    KGRoundMessage: new(keygen.KGRoundMessage),
		    ComXiGD:		xigd,
	    }
	    kg.SetFromID(from)
	    kg.SetFromIndex(index)
	    kg.ToID = to
	    return kg
	}

	//5-1 message
	if msg["Type"] == "KGRound5Message1" {
	    if msg["HvPf"] == "" || msg["Num"] == "" {
		return nil
	    }

	    pf := &ec2.HvProof{}
	    err := pf.UnmarshalJSON([]byte(msg["HvPf"]))
	    if err == nil {
		num, ok := new(big.Int).SetString(msg["Num"], 10)
		if !ok {
		    return nil
		}

		kg := &keygen.KGRound5Message1{
		    KGRoundMessage: new(keygen.KGRoundMessage),
		    Num:		num,
		    HvPf:             pf,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	    }
	}

	//5-2 message
	if msg["Type"] == "KGRound5Message2" {
	    if msg["SfPf"] == "" {
		return nil
	    }

	    if msg["Num"] == "" {
		return nil
	    }

	    pf := &ec2.SquareFreeProof{}
	    err := pf.UnmarshalJSON([]byte(msg["SfPf"]))
	    if err == nil {
		num, ok := new(big.Int).SetString(msg["Num"], 10)
		if !ok {
		    return nil
		}

		kg := &keygen.KGRound5Message2{
		    KGRoundMessage: new(keygen.KGRoundMessage),
		    Num:		num,
		    SfPf:             pf,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	    }
	}

	//6 message
	if msg["Type"] == "KGRound6Message" {
	    b := false
	    if msg["CheckPubkeyStatus"] == "true" {
		    b = true
	    }

	    if msg["U1zkXiProof"] == "" {
		return nil
	    }
	    
	    zk := &ec2.ZkXiProof{}
	    if err := zk.UnmarshalJSON([]byte(msg["U1zkXiProof"])); err == nil {
		kg := &keygen.KGRound6Message{
			KGRoundMessage:      new(keygen.KGRoundMessage),
			U1zkXiProof:     zk,
			CheckPubkeyStatus: b,
		}
		kg.SetFromID(from)
		kg.SetFromIndex(index)
		kg.ToID = to
		return kg
	    }
	}

	kg := &keygen.KGRound0Message{
		KGRoundMessage: new(keygen.KGRoundMessage),
	}
	kg.SetFromID(from)
	kg.SetFromIndex(-1)
	kg.ToID = to

	return kg
}

// processKeyGen  Obtain the data to be sent in each round and send it to other nodes until the end of the request command 
func processKeyGen(msgprex string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan keygen.LocalDNodeSaveData) error {
    	if msgprex == "" {
	    return errors.New("param error")
	}

	for {
		select {
		case <-errChan: // when keyGenParty return
			fmt.Printf("=========== processKeyGen,error channel closed fail to start local smpc node, key = %v ===========\n", msgprex)
			return errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EcKeygenTimeout)):
			fmt.Printf("=========== processKeyGen,keygen timeout, key = %v ===========\n", msgprex)
			return errors.New("keygen timeout")
		case msg := <-outCh:
			err := ProcessOutCh(msgprex, msg)
			if err != nil {
				fmt.Printf("================ processKeyGen,process outch err = %v, key = %v ================\n", err, msgprex)
				return err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return fmt.Errorf("get worker fail")
			}

			w.pkx.PushBack(fmt.Sprintf("%v", msg.Pkx))
			w.pky.PushBack(fmt.Sprintf("%v", msg.Pky))
			w.bip32c.PushBack(string(msg.C.Bytes()))
			w.sku1.PushBack(string(msg.SkU1.Bytes()))

			ss := "XXX"
			ss = ss + common.SepSave
			s1 := msg.U1PaillierSk.Length
			s2 := string(msg.U1PaillierSk.L.Bytes())
			s3 := string(msg.U1PaillierSk.U.Bytes())
			ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave

			for _, v := range msg.U1PaillierPk {
				s1 = v.Length
				s2 = string(v.N.Bytes())
				s3 = string(v.G.Bytes())
				s4 := string(v.N2.Bytes())
				ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave + s4 + common.SepSave
			}

			for _, v := range msg.U1NtildeH1H2 {
				s1 = string(v.Ntilde.Bytes())
				s2 = string(v.H1.Bytes())
				s3 = string(v.H2.Bytes())
				ss = ss + s1 + common.SepSave + s2 + common.SepSave + s3 + common.SepSave
			}
			
			ss += string(msg.U1NtildePrivData.Alpha.Bytes())
			ss += common.SepSave
			ss += string(msg.U1NtildePrivData.Beta.Bytes())
			ss += common.SepSave
			ss += string(msg.U1NtildePrivData.Q1.Bytes())
			ss += common.SepSave
			ss += string(msg.U1NtildePrivData.Q2.Bytes())
			ss += common.SepSave

			ss += "NULL"
			w.save.PushBack(string(ss))

			return nil
		}
	}
}

// KGLocalDBSaveData keygen save data
type KGLocalDBSaveData struct {
	Save       *keygen.LocalDNodeSaveData
	MsgToEnode map[string]string
}

// OutMap  Convert KGLocalDBSaveData data struct to map 
func (kgsave *KGLocalDBSaveData) OutMap() map[string]string {
	out := kgsave.Save.OutMap()
	for key, value := range kgsave.MsgToEnode {
		out[key] = value
	}

	return out
}

// GetKGLocalDBSaveData get KGLocalDBSaveData data struct from map
func GetKGLocalDBSaveData(data map[string]string) *KGLocalDBSaveData {
	save := keygen.GetLocalDNodeSaveData(data)
	msgtoenode := make(map[string]string)
	for _, v := range save.IDs {
	    tmp := fmt.Sprintf("%v",v)
	    id := strings.ToLower(hex.EncodeToString([]byte(tmp)))
	    msgtoenode[id] = data[id]
	}

	kgsave := &KGLocalDBSaveData{Save: save, MsgToEnode: msgtoenode}
	return kgsave
}

//---------------------------------------ECDSA end-----------------------------------------------------------------------

// ProcessOutCh send message to other node
func ProcessOutCh(msgprex string, msg smpclib.Message) error {
	if msg == nil {
		return fmt.Errorf("smpc info error")
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		return fmt.Errorf("get worker fail")
	}

	sig,err := sigP2pMsg(msg,curEnode)
	if err != nil {
	    return err
	}

	msgmap := msg.OutMap()
	msgmap["Key"] = msgprex
	msgmap["ENode"] = curEnode
	msgmap["Sig"] = hex.EncodeToString(sig)
	s, err := json.Marshal(msgmap)
	if err != nil {
		fmt.Printf("====================ProcessOutCh, marshal err = %v, key = %v ========================\n", err, msgprex)
		return err
	}

	if msg.IsBroadcast() {
		SendMsgToSmpcGroup(string(s), w.groupid)
	} else {
		for _, v := range msg.GetToID() {
			enode := w.MsgToEnode[v]
			_, enodes := GetGroup(w.groupid)
			nodes := strings.Split(enodes, common.Sep2)
			for _, node := range nodes {
				node2 := ParseNode(node)
				if strings.EqualFold(enode, node2) {
					SendMsgToPeer(node, string(s))
					break
				}
			}
		}
	}

	return nil
}

