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
	"github.com/anyswap/FastMulThreshold-DSA/tee"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"encoding/hex"
)

//---------------------------------------ECDSA start-----------------------------------------------------------------------

// ProcessInboundMessages Analyze the obtained P2P messages and enter next round
func ProcessInboundMessages(msgprex string, keytype string,finishChan chan struct{}, errChan chan struct{},wg *sync.WaitGroup, ch chan interface{}) {
    	if msgprex == "" {
	    return
	}

	defer func() {
		wg.Done()
		log.Info("stop processing inbound messages","key",msgprex)
		close(errChan)
	}()

	//log.Info("start processing inbound messages")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		log.Error("====================ProcessInboundMessages,not found worker by key===============","key",msgprex)
		if len(ch) == 0 {
		    res := RPCSmpcRes{Ret: "",Err:fmt.Errorf("fail to process inbound messages")}
		    ch <- res
		}
		
		return
	}

	for {
		select {
		case <-finishChan:
			return
		case m := <-w.SmpcMsg:

			if w.DNode == nil {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("node data error")}
				ch <- res
			    }
			    
			    return
			}
			
			///dul?
			hexs := Keccak256Hash([]byte(strings.ToLower(m))).Hex()
			//_, exist2 := w.Msg56[hexs]
			_, exist2 := w.Msg56.ReadMap(hexs)
			if exist2 {
			   break 
			}
			///

			log.Debug("========================ProcessInboundMessages,get msg====================","msg hash",hexs,"key",msgprex)
			msgmap := make(map[string]string)
			err := json.Unmarshal([]byte(m), &msgmap)
			if err != nil {
				log.Error("======================ProcessInboundMessages,unmarshal msg error===============","key",msgprex,"msg hash",hexs,"err",err)

				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: err}
				    ch <- res
				}
				
				return
			}

			if msgmap["Type"] == "KGRound0Message" { //0 message
				from := msgmap["FromID"]
				w.MsgToEnode[from] = msgmap["ENode"]
			}

			mm := GetRealMessage(msgmap)
			if mm == nil {
				log.Error("======================ProcessInboundMessages,get msg error=================","key",msgprex,"msg hash",hexs)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to process inbound messages")}
				    ch <- res
				}
				
				return
			}
			
			/////check whether the msg already exists in the msg list before update the msg list.
			//dul := w.DNode.DulMessage(mm)
			//if dul {
			//   break 
			//}
			/////
			
			//check sig
			if msgmap["Sig"] == "" {
				log.Error("======================ProcessInboundMessages,verify sig fail=====================","key",msgprex,"msg hash",hexs)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail,sig data error")}
				    ch <- res
				}
				
				return
			}

			if msgmap["Attestation"] == "" {
				log.Error("======================ProcessInboundMessages,verify sig fail, no TEE attestation=====================","key",msgprex,"msg hash",hexs)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail, TEE attestation error")}
				    ch <- res
				}
				
				return
			}

			if msgmap["ENode"] == "" {
				log.Error("======================ProcessInboundMessages,verify sig fail=====================","key",msgprex,"msg hash",hexs)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify sig fail,enode info error")}
				    ch <- res
				}
				
				return
			}

			sig, err := hex.DecodeString(msgmap["Sig"])
			if err != nil {
			    common.Error("[KEYGEN] decode msg sig data error","err",err,"key",msgprex,"msg hash",hexs)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }
			    
			    return
			}

			attestation, err := hex.DecodeString(msgmap["Attestation"])
			if err != nil {
			    common.Error("[KEYGEN] decode msg TEE attestation data error","err",err,"key",msgprex,"msg hash",hexs)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }
			    
			    return
			}
			
			if !checkP2pSig(keytype,sig,mm,msgmap["ENode"], attestation) {
			    common.Error("===============keygen,check p2p msg fail===============","msg hash",hexs,"sender",msgmap["ENode"])
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
			    }

			    return
			}

			rlt, err := tee.VerifyRemoteAttestationReport(attestation, []byte(msgmap["ENode"]), nil, 0, 0, true)
			if !rlt {
			    common.Error("===============keygen,check p2p msg fail, check TEE Attestation Report failed===============","msg hash",hexs,"sender",msgmap["ENode"])
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail, TEE attestation not valid")}
				ch <- res
			    }

			    return
			}

			// check fromID
			_,UID := GetNodeUID(msgmap["ENode"], keytype,w.groupid)
			id := fmt.Sprintf("%v", UID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============keygen,check p2p msg fail===============","UID",UID,"uid",uid,"fromID",mm.GetFromID(),"gid",w.groupid,"sender",msgmap["ENode"],"msg hash",hexs,"err","check from ID fail")
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
				common.Error("===============keygen,check p2p msg fail===============","sender",msgmap["ENode"],"msg hash",hexs)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				    ch <- res
				}
				
				return
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
				common.Error("====================ProcessInboundMessages,dnode update fail=======================", "msg hash",hexs, "err", err)
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: err}
				    ch <- res
				}

				return
			}

			//log.Debug("================ProcessInboundMessages,update msg success=====================","msg type    ",mm.GetMsgType(),"key",msgprex)

			w.Msg56.WriteMap(hexs,true)
			//w.Msg56[hexs] = true

		       //if !dul {
		       //////also broacast to group for msg
		       if RelayInPeers && mm.IsBroadcast() {
			   go func(msg string,gid string) {
			       for i:=0;i<1;i++ {
				   log.Debug("================ProcessInboundMessages,also broacast to group for msg===================","msg type",mm.GetMsgType(),"key",msgprex,"msg",msg,"gid",gid)
				   SendMsgToSmpcGroup(msg,gid)
				   //time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
			       }
			   }(m,w.groupid)
		       //}
		       //////
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
func processKeyGen(msgprex string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan keygen.LocalDNodeSaveData,keytype string) error {
    	if msgprex == "" {
	    return errors.New("param error")
	}

	for {
		select {
		case <-errChan: // when keyGenParty return
			log.Error("=========== processKeyGen,error channel closed fail to start local smpc node ===========","key", msgprex)
			return errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * time.Duration(EcKeygenTimeout)):
			log.Error("=========== processKeyGen,keygen timeout ============","key", msgprex)
			return errors.New("keygen timeout")
		case msg := <-outCh:
			err := ProcessOutCh(msgprex, msg,keytype)
			if err != nil {
				log.Error("================ processKeyGen,process outch fail ================","err",err,"key",msgprex)
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
func ProcessOutCh(msgprex string, msg smpclib.Message,keytype string) error {
	if msg == nil {
		return fmt.Errorf("smpc info error")
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		return fmt.Errorf("get worker fail")
	}

	fmt.Println("== curEnode ==", "curEnode", curEnode)

	attestation, err := tee.GetRemoteAttestationReport([]byte(curEnode))
	if err != nil {
		return fmt.Errorf("failed to get attestation report in TEE, key_ec.go")
	}

	sig,err := sigP2pMsg(msg,curEnode,keytype, attestation)
	if err != nil {
	    return err
	}

	msgmap := msg.OutMap()
	msgmap["Key"] = msgprex
	msgmap["ENode"] = curEnode
	msgmap["Sig"] = hex.EncodeToString(sig)
	msgmap["Attestation"] = hex.EncodeToString(attestation)
	s, err := json.Marshal(msgmap)
	if err != nil {
		log.Error("====================ProcessOutCh, marshal fail=================","err",err,"key",msgprex)
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
					//SendMsgToPeer(node, string(s))
					SendMsgToPeerWithBrodcast(msgprex,node,string(s),w.groupid)
					break
				}
			}
		}
	}

	return nil
}

