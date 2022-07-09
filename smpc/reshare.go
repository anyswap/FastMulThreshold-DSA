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
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/reshare"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/fsn-dev/cryptoCoins/coins"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

//----------------------------------------------------ECDSA start----------------------------------------------------------

// ReshareProcessInboundMessages Analyze the obtained P2P messages and enter next round
func ReshareProcessInboundMessages(msgprex string, finishChan chan struct{}, errChan chan struct{},wg *sync.WaitGroup, ch chan interface{}) {
	
	if msgprex == "" {
	    return
	}

	defer func() {
		wg.Done()
		fmt.Printf("stop processing inbound messages\n")
		close(errChan)
	}()

	fmt.Printf("start processing inbound messages\n")
	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
	    if len(ch) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to process inbound messages")}
		ch <- res
	    }

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
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: err}
				    ch <- res
				}

				return
			}

			if msgmap["Type"] == "ReRound0Message" { //0 message
				from := msgmap["FromID"]
				id, _ := new(big.Int).SetString(from, 10)
				w.MsgToEnode[fmt.Sprintf("%v", id)] = msgmap["ENode"]
			}

			mm := ReshareGetRealMessage(msgmap)
			if mm == nil {
				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("fail to process inbound messages")}
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
			    common.Error("[RESHARE] decode msg sig data error","err",err,"key",msgprex)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }

			    return
			}
			
			common.Debug("===============reshare,check p2p msg===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			if !checkP2pSig(sig,mm,msgmap["ENode"]) {
			    common.Error("===============reshare,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
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
				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("reshare get local save data fail")}
				ch <- res
			    }

			    return
			}
			
			pubs, ok := da.(*PubKeyData)
			if !ok || pubs.GroupID == "" {
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("reshare get local save data fail")}
				ch <- res
			    }

			    return
			}

			_,ID := GetNodeUID(msgmap["ENode"], "EC256K1",pubs.GroupID)
			id := fmt.Sprintf("%v", ID)
			uid := hex.EncodeToString([]byte(id))
			if !strings.EqualFold(uid,mm.GetFromID()) {
			    common.Error("===============reshare,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"],"err","check from ID fail")
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
			    common.Error("===============reshare,check p2p msg fail===============","sig",sig,"sender",msgmap["ENode"],"msg type",msgmap["Type"])
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("check msg sig fail")}
				ch <- res
			    }

			    return
			}
			////

			ld, ok := w.DNode.(*reshare.LocalDNode)
			if ok && ld.CheckReshareMsg0(mm) {
				idreshare := GetIDReshareByGroupID(w.MsgToEnode, w.groupid)
				ld.SetIDReshare(idreshare)
				fmt.Printf("====================== ReshareProcessInboundMessages, check msg0, idreshare = %v, msgprex = %v ======================\n", idreshare, msgprex)
			}

			_, err = w.DNode.Update(mm)
			if err != nil {
			    fmt.Printf("========== ReshareProcessInboundMessages, dnode update fail, receiv smpc msg = %v, err = %v ============\n", m, err)
			    if len(ch) == 0 {
				res := RPCSmpcRes{Ret: "", Err: err}
				ch <- res
			    }

			    return
			}
		}
	}
}

// ReshareGetRealMessage get the message data struct by map. (p2p msg ---> map)
func ReshareGetRealMessage(msg map[string]string) smpclib.Message {
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
	if msg["Type"] == "ReRound1Message" {
	    if msg["ComC"] == "" {
		return nil
	    }

		comc, _ := new(big.Int).SetString(msg["ComC"], 10)
		if comc == nil {
		    return nil
		}

		re := &reshare.ReRound1Message{
			ReRoundMessage: new(reshare.ReRoundMessage),
			ComC:                comc,
		}
		re.SetFromID(from)
		re.SetFromIndex(index)
		re.ToID = to
		return re
	}

	//2 message
	if msg["Type"] == "ReRound2Message" {
	    if msg["ID"] == "" || msg["Share"] == "" {
		return nil
	    }

		id, _ := new(big.Int).SetString(msg["ID"], 10)
		sh, _ := new(big.Int).SetString(msg["Share"], 10)
		re := &reshare.ReRound2Message{
			ReRoundMessage: new(reshare.ReRoundMessage),
			ID:                  id,
			Share:               sh,
		}
		re.SetFromID(from)
		re.SetFromIndex(index)
		re.ToID = to
		fmt.Printf("============ GetRealMessage, get real message 2 success, share struct id = %v, share = %v, msg map = %v ===========\n", re.ID, re.Share, msg)
		return re
	}

	//2-1 message
	if msg["Type"] == "ReRound2Message1" {
	    if msg["ComD"] == "" || msg["SkP1PolyG"] == "" {
		return nil
	    }

		ugd := strings.Split(msg["ComD"], ":")
		u1gd := make([]*big.Int, len(ugd))
		for k, v := range ugd {
			u1gd[k], _ = new(big.Int).SetString(v, 10)
			if u1gd[k] == nil {
			    return nil
			}
		}

		uggtmp := strings.Split(msg["SkP1PolyG"], "|")
		ugg := make([][]*big.Int, len(uggtmp))
		for k, v := range uggtmp {
		    if v == "" {
			return nil
		    }

			uggtmp2 := strings.Split(v, ":")
			tmp := make([]*big.Int, len(uggtmp2))
			for kk, vv := range uggtmp2 {
			    if vv == "" {
				return nil
			    }

				tmp[kk], _ = new(big.Int).SetString(vv, 10)
				if tmp[kk] == nil {
				    return nil
				}
			}
			ugg[k] = tmp
		}

		re := &reshare.ReRound2Message1{
			ReRoundMessage: new(reshare.ReRoundMessage),
			ComD:                u1gd,
			SkP1PolyG:           ugg,
		}
		re.SetFromID(from)
		re.SetFromIndex(index)
		re.ToID = to
		return re
	}

	//3 message
	if msg["Type"] == "ReRound3Message" {
	    if msg["U1PaillierPk"] == "" {
		return nil
	    }

		pub := &ec2.PublicKey{}
		err := pub.UnmarshalJSON([]byte(msg["U1PaillierPk"]))
		if err == nil {
			//fmt.Printf("============ ReshareGetRealMessage, get real message 3 success, msg map = %v ===========\n", msg)
			re := &reshare.ReRound3Message{
				ReRoundMessage: new(reshare.ReRoundMessage),
				U1PaillierPk:        pub,
			}
			re.SetFromID(from)
			re.SetFromIndex(index)
			re.ToID = to
			return re
		}
	}

	//4 message
	if msg["Type"] == "ReRound4Message" {
	    if msg["U1NtildeH1H2"] == "" || msg["NtildeProof1"] == "" || msg["NtildeProof2"] == "" {
		return nil
	    }

		nti := &ec2.NtildeH1H2{}
		if err := nti.UnmarshalJSON([]byte(msg["U1NtildeH1H2"])); err == nil {
			pf1 := &ec2.NtildeProof{}
			if err := pf1.UnmarshalJSON([]byte(msg["NtildeProof1"])); err == nil {
				pf2 := &ec2.NtildeProof{}
				if err := pf2.UnmarshalJSON([]byte(msg["NtildeProof2"])); err == nil {
					//fmt.Printf("============ ReshareGetRealMessage, get real message 4 success, msg map = %v ===========\n", msg)
					re := &reshare.ReRound4Message{
						ReRoundMessage: new(reshare.ReRoundMessage),
						U1NtildeH1H2:        nti,
						NtildeProof1:        pf1,
						NtildeProof2:        pf2,
					}
					re.SetFromID(from)
					re.SetFromIndex(index)
					re.ToID = to
					return re
				}
			}
		}
	}

	//5 message
	if msg["Type"] == "ReRound5Message" {
		//fmt.Printf("============ ReshareGetRealMessage, get real message 5 success, msg map = %v ===========\n", msg)
		if msg["NewSkOk"] == "" {
		    return nil
		}

		re := &reshare.ReRound5Message{
			ReRoundMessage: new(reshare.ReRoundMessage),
			NewSkOk:             msg["NewSkOk"],
		}
		re.SetFromID(from)
		re.SetFromIndex(index)
		re.ToID = to
		return re
	}

	//fmt.Printf("============ ReshareGetRealMessage, get real message 0 success, msg map = %v ===========\n", msg)
	re := &reshare.ReRound0Message{
		ReRoundMessage: new(reshare.ReRoundMessage),
	}
	re.SetFromID(from)
	re.SetFromIndex(-1)
	re.ToID = to

	return re
}

// processReshare  Obtain the data to be sent in each round and send it to other nodes until the end of the reshare command 
func processReshare(msgprex string, groupid string, pubkey string, account string, mode string, sigs string, errChan chan struct{}, outCh <-chan smpclib.Message, endCh <-chan keygen.LocalDNodeSaveData) (*big.Int, error) {
	for {
		select {
		case <-errChan:
			fmt.Printf("=========== processReshare,error channel closed fail to start local smpc node ===========\n")
			return nil, errors.New("error channel closed fail to start local smpc node")

		case <-time.After(time.Second * 300):
			fmt.Printf("=========== processReshare,reshare timeout ===========\n")
			// we bail out after KeyGenTimeoutSeconds
			return nil, errors.New("reshare timeout")
		case msg := <-outCh:
			err := ReshareProcessOutCh(msgprex, groupid, msg)
			if err != nil {
				fmt.Printf("======== processReshare,process outch err = %v ==========\n", err)
				return nil, err
			}
		case msg := <-endCh:
			w, err := FindWorker(msgprex)
			if w == nil || err != nil {
				return nil, fmt.Errorf("get worker fail")
			}

			w.pkx.PushBack(fmt.Sprintf("%v", msg.Pkx))
			w.pky.PushBack(fmt.Sprintf("%v", msg.Pky))
			w.sku1.PushBack(fmt.Sprintf("%v", msg.SkU1))
			fmt.Printf("\n===========reshare finished successfully, pkx = %v,pky = %v ===========\n", msg.Pkx, msg.Pky)

			kgsave := &KGLocalDBSaveData{Save: (&msg), MsgToEnode: w.MsgToEnode}
			sdout := kgsave.OutMap()
			s, err := json.Marshal(sdout)
			if err != nil {
				return nil, err
			}

			w.save.PushBack(string(s))

			smpcpks, err := hex.DecodeString(pubkey)
			if err != nil {
				return nil, err
			}

			ys := secp256k1.S256().Marshal(msg.Pkx, msg.Pky)
			pubkeyhex := hex.EncodeToString(ys)
			if !strings.EqualFold(pubkey, pubkeyhex) {
				common.Info("===================== reshare fail,new pubkey != old pubkey ====================", "old pubkey", pubkey, "new pubkey", pubkeyhex, "key", msgprex)
				return nil, errors.New("reshare fail,old pubkey != new pubkey")
			}

			//set new sk
			err = putSkU1ToLocalDb(smpcpks[:], msg.SkU1.Bytes())
			if err != nil {
				return nil, err
			}

			for _, ct := range coins.Cointypes {
				if strings.EqualFold(ct, "ALL") {
					continue
				}

				h := coins.NewCryptocoinHandler(ct)
				if h == nil {
					continue
				}
				ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
				if err != nil {
					continue
				}

				key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
				err = putSkU1ToLocalDb([]byte(key), msg.SkU1.Bytes())
				if err != nil {
					return nil, err
				}

			}
			//

			nonce, _, err := GetReqAddrNonce(account) //reqaddr nonce
			if err != nil {
				nonce = "0"
			}

			//**************TODO***************
			//default EC256K1 for reshare
			//ED25519 is not ready!!!

			rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + "EC256K1" + ":" + groupid + ":" + nonce + ":" + w.limitnum + ":" + mode))).Hex() //reqaddr key
			//**********************************

			tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
			pubs := &PubKeyData{Key: rk, Account: account, Pub: string(smpcpks[:]), Save: string(s), Nonce: nonce, GroupID: groupid, LimitNum: w.limitnum, Mode: mode, KeyGenTime: tt, RefReShareKeys: msgprex}
			epubs, err := Encode2(pubs)
			if err != nil {
				return nil, errors.New("encode PubKeyData fail in req ec2 pubkey")
			}

			ss1, err := Compress([]byte(epubs))
			if err != nil {
				return nil, errors.New("compress PubKeyData fail in req ec2 pubkey")
			}

			exsit, pda := GetPubKeyData(smpcpks[:])
			if exsit {
				daa, ok := pda.(*PubKeyData)
				if ok {
					//check mode
					if daa.Mode != mode {
						return nil, errors.New("check mode fail")
					}
					//

					//check account
					if !strings.EqualFold(account, daa.Account) {
						return nil, errors.New("check accout fail")
					}
					//

					err = DeletePubKeyData([]byte(daa.Key))
					if err != nil {
						return nil, err
					}
				}
			}

			err = PutPubKeyData(smpcpks[:], []byte(ss1))
			if err != nil {
				return nil, err
			}

			for _, ct := range coins.Cointypes {
				if strings.EqualFold(ct, "ALL") {
					continue
				}

				h := coins.NewCryptocoinHandler(ct)
				if h == nil {
					continue
				}
				ctaddr, err := h.PublicKeyToAddress(pubkey)
				if err != nil {
					continue
				}

				key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
				err = PutPubKeyData([]byte(key), []byte(ss1))
				if err != nil {
					return nil, err
				}
			}

			_, err = SetReqAddrNonce(account, nonce)
			if err != nil {
				return nil, errors.New("set reqaddr nonce fail")
			}

			wid := -1
			var allreply []NodeReply
			exsit, da2 := GetReShareInfoData([]byte(msgprex))
			if exsit {
				acr, ok := da2.(*AcceptReShareData)
				if ok {
					wid = acr.WorkID
					allreply = acr.AllReply
				}
			}

			ac := &AcceptReqAddrData{Initiator: curEnode, Account: account, Cointype: "EC256K1", GroupID: groupid, Nonce: nonce, LimitNum: w.limitnum, Mode: mode, TimeStamp: tt, Deal: "true", Accept: "true", Status: "Success", PubKey: pubkey, Tip: "", Error: "", AllReply: allreply, WorkID: wid, Sigs: sigs}
			err = SaveAcceptReqAddrData(ac)
			if err != nil {
				return nil, errors.New("save reqaddr accept data fail")
			}

			if mode == "0" {
				sigs2 := strings.Split(ac.Sigs, common.Sep)
				cnt, _ := strconv.Atoi(sigs2[0])
				for j := 0; j < cnt; j++ {
					fr := sigs2[2*j+2]
					exsit, da := GetPubKeyData([]byte(strings.ToLower(fr)))
					if !exsit {
						err = PutPubKeyData([]byte(strings.ToLower(fr)), []byte(rk))
						if err != nil {
							return nil, err
						}
					} else {
						//
						found := false
						keys := strings.Split(string(da.([]byte)), ":")
						for _, v := range keys {
							if strings.EqualFold(v, rk) {
								found = true
								break
							}
						}
						//

						if !found {
							da2 := string(da.([]byte)) + ":" + rk
							err = PutPubKeyData([]byte(strings.ToLower(fr)), []byte(da2))
							if err != nil {
								return nil, err
							}
						}
					}
				}
			} else {
				exsit, da := GetPubKeyData([]byte(strings.ToLower(account)))
				if !exsit {
					err = PutPubKeyData([]byte(strings.ToLower(account)), []byte(rk))
					if err != nil {
						return nil, err
					}
				} else {
					//
					found := false
					keys := strings.Split(string(da.([]byte)), ":")
					for _, v := range keys {
						if strings.EqualFold(v, rk) {
							found = true
							break
						}
					}
					//

					if !found {
						da2 := string(da.([]byte)) + ":" + rk
						err = PutPubKeyData([]byte(strings.ToLower(account)), []byte(da2))
						if err != nil {
							return nil, err
						}
					}

				}
			}

			_,err2 := AcceptReqAddr("", account, "ALL", groupid, nonce, w.limitnum, mode, "true", "true", "Success", pubkey, "", "", nil, w.id, "")
			if err2 != nil {
				return nil, err2
			}
			return msg.SkU1, nil
		}
	}
}

// ReshareProcessOutCh send message to other node
func ReshareProcessOutCh(msgprex string, groupid string, msg smpclib.Message) error {
	if msg == nil || msgprex == "" || groupid == "" {
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
		fmt.Printf("====================ReshareProcessOutCh, marshal err = %v ========================\n", err)
		return err
	}

	if msg.IsBroadcast() {
		fmt.Printf("=========== ReshareProcessOutCh,broacast msg = %v, group id = %v ===========\n", string(s), groupid)

		SendMsgToSmpcGroup(string(s), groupid)
	} else {
		for _, v := range msg.GetToID() {
			fmt.Printf("===============ReshareProcessOutCh, to id = %v,groupid = %v ==============\n", v, groupid)
			enode := w.MsgToEnode[v]
			_, enodes := GetGroup(groupid)
			nodes := strings.Split(enodes, common.Sep2)
			for _, node := range nodes {
				node2 := ParseNode(node)
				//fmt.Printf("===============ReshareProcessOutCh, enode = %v,node2 = %v ==============\n",enode,node2)

				if strings.EqualFold(enode, node2) {
					fmt.Printf("=========== ReshareProcessOutCh,send msg = %v, group id = %v,send to peer = %v ===========\n", string(s), groupid, node)
					SendMsgToPeer(node, string(s))
					break
				}
			}
		}
	}

	return nil
}

//-------------------------------------------------------ECDSA end-----------------------------------------------------------
