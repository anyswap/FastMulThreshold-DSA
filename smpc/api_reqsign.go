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
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"math/big"
	"strconv"
	"strings"

	"container/list"
	"crypto/sha512"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"time"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/layer2"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
)

// ReqSmpcSign sign cmd request
type ReqSmpcSign struct {
}

//--------------------------------------------------------------------------------------------------

// GetReplyFromGroup  Get the current reply status of the nodes in the group. About this command request 
func (req *ReqSmpcSign) GetReplyFromGroup(wid int, gid string, initiator string) []NodeReply {
	if wid < 0 || wid >= len(workers) {
		return nil
	}

	w := workers[wid]
	if w == nil {
		return nil
	}

	var ars []NodeReply
	_, enodes := GetGroup(gid)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator, node2) {
			in = "1"
			sta = "AGREE"
		}

		iter := w.msgacceptsignres.Front()
		if iter != nil {
			mdss := iter.Value.(string)
			key, _, _, _, _ := CheckRaw(mdss)
			key2 := GetReqAddrKeyByOtherKey(key, RPCSIGN)
			exsit, da := GetPubKeyData([]byte(key2))
			if exsit {
				ac, ok := da.(*AcceptReqAddrData)
				if ok && ac != nil {
					ret := GetRawReply(w.msgacceptsignres)
					//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
					mms := strings.Split(ac.Sigs, common.Sep)
					for k, mm := range mms {
						if strings.EqualFold(mm, node2) {
							reply, ok := ret.ReadMap(mms[k+1])
							if ok && reply != nil {
								if (reply.(*RawReply)).Accept == "true" {
									sta = "Agree"
								} else {
									sta = "DisAgree"
								}
								ts = (reply.(*RawReply)).TimeStamp
							}

							break
						}
					}

				}
			}
		}

		nr := NodeReply{Enode: node2, Approver:node2,Status: sta, TimeStamp: ts, Initiator: in}
		ars = append(ars, nr)
	}

	return ars
}

//-----------------------------------------------------------------------------------------------

// GetReqAddrKeyByKey sign key --->AccepSignData -----> pubkey ----->PubKeyData ---->reqaddr key
func (req *ReqSmpcSign) GetReqAddrKeyByKey(key string) string {
	exsit, da := GetSignInfoData([]byte(key))
	if !exsit {
		exsit, da = GetPubKeyData([]byte(key))
	}
	if exsit {
		ad, ok := da.(*AcceptSignData)
		if ok && ad != nil {
			smpcpks, err := hex.DecodeString(ad.PubKey)
			if err != nil {
			    return ""
			}

			exsit, da2 := GetPubKeyData(smpcpks[:])
			if exsit && da2 != nil {
				pd, ok := da2.(*PubKeyData)
				if ok && pd != nil {
					return pd.Key
				}
			}
		}
	}

	return ""
}

//-------------------------------------------------------------------------------------------------------

// GetRawReply put the reply to map, select the reply sent at the latest time 
// reply.From ---> reply
func (req *ReqSmpcSign) GetRawReply(ret *common.SafeMap, reply *RawReply) {
	if reply == nil || ret == nil {
		return
	}

	tmp, ok := ret.ReadMap(reply.From)
	if !ok {
		ret.WriteMap(reply.From, reply)
	} else {
		tmp2, ok := tmp.(*RawReply)
		if ok {
			t1, _ := new(big.Int).SetString(reply.TimeStamp, 10)
			t2, _ := new(big.Int).SetString(tmp2.TimeStamp, 10)
			if t1.Cmp(t2) > 0 {
				ret.WriteMap(reply.From, reply)
			}
		}

	}
}

//-------------------------------------------------------------------------------------------------------

// CheckReply  Detect whether all nodes in the group have sent accept data 
func (req *ReqSmpcSign) CheckReply(ac *AcceptReqAddrData, l *list.List, key string) bool {
	if l == nil || key == "" || ac == nil {
		return false
	}

	ret := GetRawReply(l)
	exsit, data := GetSignInfoData([]byte(key))
	if !exsit {
		common.Error("===================== CheckReply,get raw reply finish and get value by key fail================", "key", key)
		return false
	}

	sig, ok := data.(*AcceptSignData)
	if !ok || sig == nil {
		common.Error("===================== CheckReply,get raw reply finish and get accept sign data by key fail================", "key", key)
		return false
	}

	mms := strings.Split(ac.Sigs, common.Sep)
	_, enodes := GetGroup(sig.GroupID)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		foundeid := false
		for kk, v := range mms {
			if strings.EqualFold(v, node2) {
				foundeid = true
				found := false
				_, value := ret.ListMap()
				for _, vv := range value {
					if vv != nil && strings.EqualFold((vv.(*RawReply)).From, mms[kk+1]) { //allow user login diffrent node
						found = true
						break
					}
				}

				if !found {
					common.Debug("===================== CheckReply,mms[kk+1] no find in ret map and return fail==================", "key", key, "mms[kk+1]", mms[kk+1])
					return false
				}

				break
			}
		}

		if !foundeid {
			common.Debug("===================== CheckReply,get raw reply finish and find eid fail================", "key", key)
			return false
		}
	}

	return true
}

//--------------------------------------------------------------------------------------------------------------------

// SyncPreSign the status of pre-generating sign data
type SyncPreSign struct {
	MsgPrex string
	EnodeID string
	Msg     string // "success" or "fail"
}

// MarshalJSON marshal SyncPreSign data struct
func (sps *SyncPreSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MsgPrex string `json:"MsgPrex"`
		EnodeID string `json:"EnodeID"`
		Msg     string `json:"Msg"`
	}{
		MsgPrex: sps.MsgPrex,
		EnodeID: sps.EnodeID,
		Msg:     sps.Msg,
	})
}

// UnmarshalJSON unmarshal to SyncPreSign data struct
func (sps *SyncPreSign) UnmarshalJSON(raw []byte) error {
	var pre struct {
		MsgPrex string `json:"MsgPrex"`
		EnodeID string `json:"EnodeID"`
		Msg     string `json:"Msg"`
	}
	if err := json.Unmarshal(raw, &pre); err != nil {
		return err
	}

	sps.MsgPrex = pre.MsgPrex
	sps.EnodeID = pre.EnodeID
	sps.Msg = pre.Msg
	return nil
}

// SynchronizePreSignData  Every node broadcast own status tells other nodes whether their pre-sign data are pre generated and successfully written into the local database, and receives the corresponding status information of other nodes, so as to judge whether all nodes in the group are in the successful state. If so, keep the pre-sign data, otherwise the pre-sign data needs to be deleted. 
func SynchronizePreSignData(msgprex string, wid int, success bool) bool {
	w := workers[wid]
	if w == nil {
		log.Error("=============================SynchronizePreSignData,not found worker==========================","key",msgprex,"wid",wid,"success",success)
		return false
	}

	msg := "success"
	if !success {
		msg = "fail"
	}

	sps := &SyncPreSign{MsgPrex: msgprex, EnodeID: curEnode, Msg: msg}
	m := make(map[string]string)
	spsjson, err := sps.MarshalJSON()
	if err != nil {
		log.Error("=============================SynchronizePreSignData,marshal json fail==========================","key",msgprex,"wid",wid,"success",success,"err",err)
		return false
	}
	
	m["SyncPreSign"] = string(spsjson)
	m["Type"] = "SyncPreSign"
	val, err := json.Marshal(m)
	if err != nil {
		log.Error("=============================SynchronizePreSignData,marshal json fail==========================","key",msgprex,"wid",wid,"success",success,"err",err)
		return false
	}
	SendMsgToSmpcGroup(string(val), w.groupid)

	if w.msgsyncpresign.Len() < w.ThresHold {
		if !Find(w.msgsyncpresign, string(val)) {
			w.msgsyncpresign.PushBack(string(val))
			if w.msgsyncpresign.Len() == w.ThresHold {
				w.bsyncpresign <- true
			}
		}
	}

	reply := false
	timeout := make(chan bool, 1)
	go func() {
		syncWaitTime := 300 * time.Second
		syncWaitTimeOut := time.NewTicker(syncWaitTime)

		for {
			select {
			case <-w.bsyncpresign:
				iter := w.msgsyncpresign.Front()
				for iter != nil {
					val := iter.Value.(string)
					if val == "" {
						log.Error("=============================SynchronizePreSignData,msgsyncpresign value error==========================","key",msgprex,"wid",wid,"success",success)
						reply = false
						timeout <- false
						return
					}

					msgmap := make(map[string]string)
					err = json.Unmarshal([]byte(val), &msgmap)
					if err != nil {
						log.Error("=============================SynchronizePreSignData,unmarsh msgsyncpresign value error==========================","key",msgprex,"wid",wid,"success",success,"err",err)
						reply = false
						timeout <- false
						return
					}

					sps := &SyncPreSign{}
					if err = sps.UnmarshalJSON([]byte(msgmap["SyncPreSign"])); err != nil {
						log.Error("=============================SynchronizePreSignData,unmarsh msgsyncpresign value error==========================","key",msgprex,"wid",wid,"success",success,"err",err)
						reply = false
						timeout <- false
						return
					}

					if strings.EqualFold(sps.Msg, "fail") {
						log.Error("=============================SynchronizePreSignData,status is fail==========================","key",msgprex,"wid",wid,"success",success)
						reply = false
						timeout <- false
						return
					}

					iter = iter.Next()
				}

				reply = true
				timeout <- false
				return
			case <-syncWaitTimeOut.C:
				log.Error("=============================SynchronizePreSignData,wait time out==========================","key",msgprex,"wid",wid,"success",success)
				reply = false
				timeout <- true
				return
			}
		}
	}()

	<-timeout
	return reply
}

// GetReply 
// 0 accept
// 1 reject
// 2 uncertain
func GetReply(id int) int {
    if id < 0 {
	return 1
    }

    w := workers[id]
    if w == nil {
	return 1
    }

    yes := 0
    no := 0
    for _,rh := range w.ApprovReplys {
	if rh == nil {
	    continue
	}

	if strings.EqualFold(rh.Accept,"Agree") {
	    yes++
	} else {
	    no++
	}
    }

    if yes >= w.ThresHold {
	return 0
    }

    if no >= (w.NodeCnt-w.ThresHold+1) {
	return 1
    }

    return 2
}

func GetEnodesForSubGroup(id int,gid string) []string {
    if gid == "" || id < 0 {
	return nil
    }

    w := workers[id]
    if w == nil {
	return nil
    }

    var ret []string
   
    var count int
    for _,rh := range w.ApprovReplys {
	if count >= w.ThresHold {
	    break
	}

	if rh == nil {
	    continue
	}

	if !strings.EqualFold(rh.Accept,"Agree") {
	    continue
	}

	_, enodes := GetGroup(gid)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    if strings.EqualFold(rh.ENode,node2) {
		ret = append(ret,node)
		count++
		break
	    }
	}
    }

    return ret
}

// DoReq   1.Parse the sign or pre-sign command and implement the process 2.analyze the accept data   
func (req *ReqSmpcSign) DoReq(raw string, workid int, sender string, ch chan interface{}) bool {
	if raw == "" || workid < 0 || sender == "" {
		res := RPCSmpcRes{Ret: "", Tip: "do req fail.", Err: fmt.Errorf("do req fail")}
		ch <- res
		return false
	}

	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(raw), &msgmap)
	if err == nil {
		if msgmap["Type"] == "SignData" {

			sd := &SignData{}
			if err = sd.UnmarshalJSON([]byte(msgmap["SignData"])); err != nil {
			    common.Error("===============ReqSmpcSign.DoReq,unmarshal sign data error===================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			common.Debug("===============ReqSmpcSign.DoReq,raw is signdata type===================", "msgprex", sd.MsgPrex, "key", sd.Key, "pkx", sd.Pkx, "pky", sd.Pky)
			
			//check current node whther in group
			// cmd data default not to relay to other nodes
			if !IsInGroup(sd.GroupID) {
				common.Debug("===============ReqSmpcSign.DoReq,current node is not in group===================", "msgprex", sd.MsgPrex, "key", sd.Key)
				res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("current node is not in group")}
				ch <- res
				return false
			}
			//

			ys := secp256k1.S256().Marshal(sd.Pkx, sd.Pky)
			pubkeyhex := hex.EncodeToString(ys)

			w := workers[workid]
			w.sid = sd.Key
			w.groupid = sd.GroupID

			w.NodeCnt = sd.NodeCnt
			w.ThresHold = sd.ThresHold

			w.SmpcFrom = sd.SmpcFrom

			smpcpks, err := hex.DecodeString(pubkeyhex)
			if err != nil {
			    common.Error("===============ReqSmpcSign.DoReq,decode string fail===================", "msgprex", sd.MsgPrex, "key", sd.Key, "pkx", sd.Pkx, "pky", sd.Pky,"err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}

			exsit, da := GetPubKeyData(smpcpks[:])
			if exsit {
				pd, ok := da.(*PubKeyData)
				if ok {
					exsit, da2 := GetPubKeyData([]byte(pd.Key))
					if exsit {
						ac, ok := da2.(*AcceptReqAddrData)
						if ok {
							HandleC1Data(ac, sd.Key)
						}
					}

				}
			}

			childPKx := sd.Pkx
			childPKy := sd.Pky
			if sd.InputCodeT != "" {
				da3 := getBip32cFromLocalDb(smpcpks[:])
				if da3 == nil {
					res := RPCSmpcRes{Ret: "", Tip: "presign get bip32 fail", Err: fmt.Errorf("presign get bip32 fail")}
					ch <- res
					return false
				}
				bip32c := new(big.Int).SetBytes(da3)
				if bip32c == nil {
					res := RPCSmpcRes{Ret: "", Tip: "presign get bip32 error", Err: fmt.Errorf("presign get bip32 error")}
					ch <- res
					return false
				}

				indexs := strings.Split(sd.InputCodeT, "/")
				TRb := bip32c.Bytes()
				childSKU1 := sd.Sku1
				for idxi := 1; idxi < len(indexs); idxi++ {
					h := hmac.New(sha512.New, TRb)
					_,err := h.Write(childPKx.Bytes())
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					_,err = h.Write(childPKy.Bytes())
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					_,err = h.Write([]byte(indexs[idxi]))
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					T := h.Sum(nil)
					TRb = T[32:]
					TL := new(big.Int).SetBytes(T[:32])

					childSKU1 = new(big.Int).Add(TL, childSKU1)
					childSKU1 = new(big.Int).Mod(childSKU1, secp256k1.S256().N)

					TLGx, TLGy := secp256k1.S256().ScalarBaseMult(TL.Bytes())
					childPKx, childPKy = secp256k1.S256().Add(TLGx, TLGy, childPKx, childPKy)
				}
			}

			/*childpub := secp256k1.S256().Marshal(childPKx, childPKy)
			childpubkeyhex := hex.EncodeToString(childpub)
			_, _, err = GetSmpcAddr(childpubkeyhex)
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "get pubkey error", Err: fmt.Errorf("get pubkey error")}
				ch <- res
				return false
			}*///No need to check pubkey here.

			var ch1 = make(chan interface{}, 1)
			for i := 0; i < recalcTimes; i++ {
				common.Debug("===============ReqSmpcSign.DoReq,sign recalc===================", "i", i, "msgprex", sd.MsgPrex, "key", sd.Key)
				if len(ch1) != 0 {
					<-ch1
				}

				//w.Clear2()
				//Sign_ec2(sd.Key, sd.Save, sd.Sku1, sd.Txhash, sd.Keytype, sd.Pkx, sd.Pky, ch1, workid)
				SignEC3(sd.Key, sd.Txhash, sd.Keytype, sd.Save, childPKx, childPKy, ch1, workid, sd.Pre)
				ret, _, cherr := GetChannelValue(WaitMsgTimeGG20+10, ch1)
				if ret != "" && cherr == nil {

					ww, err2 := FindWorker(sd.MsgPrex)
					if err2 != nil || ww == nil {
						res2 := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("not find worker")}
						ch <- res2
						return false
					}

					ww.rsv.PushBack(ret)
					res2 := RPCSmpcRes{Ret: ret, Tip: "", Err: nil}
					ch <- res2
					return true
				}
				
				w.Clear2()
			}

			_, _, cherr := GetChannelValue(WaitMsgTimeGG20+10, ch1)
			errinfo := "sign fail"
			if cherr != nil {
			    errinfo = cherr.Error()
			}

			res2 := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf(errinfo)}
			ch <- res2
			return false
		}

		if msgmap["Type"] == "PreSign" {
			ps := &PreSign{}
			if err = ps.UnmarshalJSON([]byte(msgmap["PreSign"])); err != nil {
			    res2 := RPCSmpcRes{Ret: "", Tip: "unmarshal presign data fail", Err: fmt.Errorf("unmarshal presign data fail")}
			    ch <- res2
			    return false
			}
			
			//check current node whther in group
			// cmd data default not to relay to other nodes
			if !IsInGroup(ps.Gid) {
				common.Debug("===============ReqSmpcSign.DoReq,presign,current node is not in group===================", "presign data key", ps.Nonce)
				res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("current node is not in group")}
				ch <- res
				return false
			}
			//
			w := workers[workid]
			w.sid = ps.Nonce
			w.groupid = ps.Gid
			w.SmpcFrom = ps.Pub
			gcnt, _ := GetGroup(w.groupid)
			w.NodeCnt = gcnt
			w.ThresHold = gcnt

			smpcpks, err := hex.DecodeString(ps.Pub)
			if err != nil {
			    res2 := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res2
			    return false
			}

			exsit, da := GetPubKeyData(smpcpks[:])
			if !exsit {
				common.Debug("============================PreSign at ReqSmpcSign.DoReq,not exist presign data===========================", "pubkey", ps.Pub)
				res := RPCSmpcRes{Ret: "", Tip: "get pubkey data from db fail", Err: fmt.Errorf("get pubkey data from db fail")}
				ch <- res
				return false
			}

			pd, ok := da.(*PubKeyData)
			if !ok {
				common.Debug("============================PreSign at ReqSmpcSign.DoReq,presign data error==========================", "pubkey", ps.Pub)
				res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
				ch <- res
				return false
			}

			nodecount, _ := GetGroup(pd.GroupID)
			w.NodeCnt = nodecount

			save := pd.Save
			common.Debug("============================ReqSmpcSign.DoReq==========================", "w.SmpcFrom", w.SmpcFrom, "w.groupid", w.groupid, "w.NodeCnt", w.NodeCnt, "pd.GroupID", pd.GroupID)
			///sku1
			da2 := getSkU1FromLocalDb(smpcpks[:])
			if da2 == nil {
				res := RPCSmpcRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
				ch <- res
				return false
			}
			sku1 := new(big.Int).SetBytes(da2)
			if sku1 == nil {
				res := RPCSmpcRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
				ch <- res
				return false
			}

			childSKU1 := sku1
			smpcpub := (da.(*PubKeyData)).Pub
			smpcpkx, smpcpky := secp256k1.S256().Unmarshal(([]byte(smpcpub))[:])
			childPKx := smpcpkx
			childPKy := smpcpky
			if ps.InputCode != "" {
				da4 := getBip32cFromLocalDb(smpcpks[:])
				if da4 == nil {
					res := RPCSmpcRes{Ret: "", Tip: "presign get bip32 fail", Err: fmt.Errorf("presign get bip32 fail")}
					ch <- res
					return false
				}
				bip32c := new(big.Int).SetBytes(da4)
				if bip32c == nil {
					res := RPCSmpcRes{Ret: "", Tip: "presign get bip32 error", Err: fmt.Errorf("presign get bip32 error")}
					ch <- res
					return false
				}

				indexs := strings.Split(ps.InputCode, "/")
				TRb := bip32c.Bytes()
				for idxi := 1; idxi < len(indexs); idxi++ {
					h := hmac.New(sha512.New, TRb)
					_,err := h.Write(childPKx.Bytes())
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					_,err = h.Write(childPKy.Bytes())
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					_,err = h.Write([]byte(indexs[idxi]))
					if err != nil {
					    res := RPCSmpcRes{Ret: "", Tip: "", Err:err}
					    ch <- res
					    return false
					}
					T := h.Sum(nil)
					TRb = T[32:]
					TL := new(big.Int).SetBytes(T[:32])

					childSKU1 = new(big.Int).Add(TL, childSKU1)
					childSKU1 = new(big.Int).Mod(childSKU1, secp256k1.S256().N)

					TLGx, TLGy := secp256k1.S256().ScalarBaseMult(TL.Bytes())
					childPKx, childPKy = secp256k1.S256().Add(TLGx, TLGy, childPKx, childPKy)
				}
			}

			exsit, da3 := GetPubKeyData([]byte(pd.Key))
			ac, ok := da3.(*AcceptReqAddrData)
			if ok {
				HandleC1Data(ac, w.sid)
			}

			var ch1 = make(chan interface{}, 1)
			//pre := PreSignEC3(w.sid,save,sku1,"ECDSA",ch1,workid)
			pre := PreSignEC3(w.sid, save, childSKU1, childPKx,childPKy,"EC256K1", ch1, workid)
			if pre == nil {
				common.Info("============================PreSign at RecvMsg.Run, failed to generate the presign data this time ==========================", "pubkey", ps.Pub, "gid", ps.Gid, "presign data key", w.sid, "err", "return result is nil")
				if syncpresign && !SynchronizePreSignData(w.sid, w.id, false) {
					_, _, cherr := GetChannelValue(waitall, ch1)
					errinfo := "presign fail"
					if cherr != nil {
					    errinfo = cherr.Error()
					}

					res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf(errinfo)}
					ch <- res
					return false
				}

				_, _, cherr := GetChannelValue(waitall, ch1)
				errinfo := "presign fail"
				if cherr != nil {
				    errinfo = cherr.Error()
				}

				res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf(errinfo)}
				ch <- res
				return false
			}

			pre.Key = w.sid
			pre.Gid = w.groupid
			pre.Used = false
			pre.Index = ps.Index

			err = PutPreSignData(ps.Pub, ps.InputCode, ps.Gid, ps.Index, pre, true)
			if err != nil {
				common.Info("============================PreSign at RecvMsg.Run, failed to generate the presign data this time,put pre-sign data to local db fail. ==========================", "pubkey", ps.Pub, "gid", ps.Gid, "presign data key", w.sid, "err", err,"index",pre.Index)
				if syncpresign && !SynchronizePreSignData(w.sid, w.id, false) {
					common.Info("================================PreSign at RecvMsg.Run, put pre-sign data to local db fail=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index, "err", err)
					res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
					ch <- res
					return false
				}

				common.Info("================================PreSign at RecvMsg.Run, put pre-sign data to local db fail=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index, "err", err)
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
				return false
			}

			if syncpresign && !SynchronizePreSignData(w.sid, w.id, true) {
				err = DeletePreSignData(ps.Pub, ps.InputCode, ps.Gid, pre.Key)
				if err == nil {
					common.Debug("================================PreSign at RecvMsg.Run, delete pre-sign data from local db success=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index)
				} else {
					//.........
					common.Info("================================PreSign at RecvMsg.Run, delete pre-sign data from local db fail=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index, "err", err)
				}

				res := RPCSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
				ch <- res
				return false
			}

			common.Info("============================PreSign at RecvMsg.Run, pre-generated sign data succeeded.==========================", "pubkey", ps.Pub, "gid", ps.Gid, "presign data key", w.sid,"index",ps.Index)
			res := RPCSmpcRes{Ret: "success", Tip: "", Err: nil}
			ch <- res
			return true
		}

		if msgmap["Type"] == "ComSignSubGidBrocastData" {
			signbrocast, err := UnCompressSignSubGidBrocastData(msgmap["ComSignSubGidBrocastData"])
			if err != nil {
			    log.Error("=======================DoReq,uncompress sign brocast data fail========================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			key, _, _, txdata, err := CheckRaw(signbrocast.Raw)
			if err != nil {
			    log.Error("=======================sign.DoReq,check sign bracast raw data fail========================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			sig, ok := txdata.(*TxDataSign)
			if !ok {
			    log.Error("=======================sign.DoReq,check sign bracast raw data fail,sign data error========================")
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign data error")}
			    ch <- res
			    return false
			}
			
			//check current node whther in group
			// cmd data default not to relay to other nodes
			if !IsInGroup(signbrocast.SubGid) {
				log.Debug("=======================sign.DoReq,get ComSignBrocastData2 data,not in group========================","key",key,"groupid",signbrocast.SubGid)
				res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("current node is not in group")}
				ch <- res
				return false
			}
			//
			//////for mode == 2
			if sig.Mode == "2" {
			    w, err := FindWorker(key)
			    if err != nil {
				log.Error("=======================sign.DoReq,not found worker========================","key",key,"subgid",signbrocast.SubGid)
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
				return false
			    }

			    log.Debug("=======================sign.DoReq,get ComSignSubGidBrocastData data========================","key",key,"subgid",signbrocast.SubGid,"w.id",w.id,"threshold",w.ThresHold,"nodecnt",w.NodeCnt)
			    w.PickHash = signbrocast.PickHash
			    w.subgid = signbrocast.SubGid 
			    w.bgosign <-true
			    return true
			}
		}

		if msgmap["Type"] == "ComSignBrocastData" {
			signbrocast, err := UnCompressSignBrocastData(msgmap["ComSignBrocastData"])
			if err != nil {
			    log.Error("=======================DoReq,uncompress sign brocast data fail========================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			key, from, nonce, txdata, err := CheckRaw(signbrocast.Raw)
			if err != nil {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			sig, ok := txdata.(*TxDataSign)
			if !ok {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign data error")}
			    ch <- res
			    return false
			}
		
			//check current node whther in group
			// cmd data default not to relay to other nodes
			if !IsInGroup(sig.GroupID) {
				res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("current node is not in group")}
				ch <- res
				return false
			}
			//
			//////for mode == 2
			if sig.Mode == "2" {
			    ars := GetAllReplyFromGroup(workid,sig.GroupID,RPCSIGN,sender)
			    ac := &AcceptSignData{Raw:signbrocast.Raw,Initiator: sender, Account: from, GroupID: sig.GroupID, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkID: workid}
			    err = SaveAcceptSignData(ac)
			    if err != nil {
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("save sign accept data fail")}
				    ch <- res
				    return false 
			    }

			    common.Info("===============save sign accept data finish===================", "ars ", ars, "key ", key, "tx data", sig)
			    w := workers[workid]
			    w.sid = key
			    w.groupid = sig.GroupID
			    w.limitnum = sig.ThresHold
			    gcnt, _ := GetGroup(w.groupid)
			    w.NodeCnt = gcnt
			    w.ThresHold = w.NodeCnt

			    nums := strings.Split(w.limitnum, "/")
			    if len(nums) == 2 {
				    nodecnt, err := strconv.Atoi(nums[1])
				    if err == nil {
					    w.NodeCnt = nodecnt
				    }
				    nodecnt2, err := strconv.Atoi(nums[0])
				    if err == nil {
					    w.ThresHold = nodecnt2
				    }
			    }

			    w.SmpcFrom = sig.PubKey // pubkey replace smpcfrom in sign

			    //
			    index := -1
			    for j,rh := range w.ApprovReplys {
				if rh == nil {
				    continue
				}

				if strings.EqualFold(rh.From,from) {
				    index = j
				    break
				}
			    }

			    reqaddrkey := GetReqAddrKeyByOtherKey(key, RPCSIGN)
			    exsit, da := GetPubKeyData([]byte(reqaddrkey))
			    if !exsit {
				    log.Error("================get keygen data by key from db fail===============","sign key",key,"keygen key",reqaddrkey)
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("get keygen data by key from db fail")}
				    ch <- res
				    return false 
			    }

			    acceptreqdata, ok := da.(*AcceptReqAddrData)
			    if !ok || acceptreqdata == nil {
				    log.Error("================get keygen data fail===============","sign key",key,"keygen key",reqaddrkey)
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("get keygen data fail")}
				    ch <- res
				    return false
			    }

			    enode := curEnode
			    if acceptreqdata.Mode == "0" || acceptreqdata.Mode == "2" {
				    enode = GetENodeByFrom(from,acceptreqdata)
				    if enode == "" {
					    log.Error("================get enode fail===============","sign key",key,"keygen key",reqaddrkey)
					res := RPCSmpcRes{Ret: "", Tip: "", Err: errors.New("get enode fail")}
					ch <- res
					return false 
				    }
			    }

			    reply2 := &ApprovReply{ENode:enode,From: from, Accept: "AGREE", TimeStamp: acceptreqdata.TimeStamp}
			    if index != -1 {
				w.ApprovReplys[index] = reply2
			    } else {
				w.ApprovReplys = append(w.ApprovReplys,reply2)
			    }
			    
			    var reply bool
			    var tip string
			    var signtimeout bool

			    timeout := make(chan bool, 1)
			    go func(wid int) {
				    curEnode = discover.GetLocalID().String() //GetSelfEnode()
				    ato,err := strconv.Atoi(sig.AcceptTimeOut)
				    if err != nil || sig.AcceptTimeOut == "" {
					    ato = 600 
				    }

				    agreeWaitTime := time.Duration(ato) * time.Second
				    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

				    wtmp2 := workers[wid]

				    for {
					    select {
					    case account := <-wtmp2.acceptSignChan:
						    common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
						    ars := GetAllReplyFromGroup2(w.id,sender)
						    common.Info("==================get all signing approve results===============", "result ", ars, "key ", key)

						    res := GetReply(w.id)
						    if res == 1 {
							reply = false
						    } else {
							reply = true
						    }

						    if !reply {
							    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Someone refused to sign", "Someone refused to sign", ars, wid)
						    } else {
							    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, wid)
						    }

						    timeout <- true
						    return
					    case <-agreeWaitTimeOut.C:
						    ars := GetAllReplyFromGroup2(w.id,sender)
						    common.Info("================== DoSign, agree wait timeout=============", "ars", ars, "key ", key)
						    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "Approval timeout", "Approval timeout", ars, wid)
						    reply = false

						    signtimeout = true
						    timeout <- true
						    return
					    }
				    }
			    }(workid)

			    if len(workers[workid].acceptWaitSignChan) == 0 {
				    workers[workid].acceptWaitSignChan <- "go on"
			    }

			    DisAcceptMsg(signbrocast.Raw, workid)
			    exsit, da = GetPubKeyData([]byte(reqaddrkey))
			    if !exsit {
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return false
			    }

			    acceptreqdata, ok = da.(*AcceptReqAddrData)
			    if !ok || acceptreqdata == nil {
				    common.Debug("===============get req addr key by other key error ===================", "key ", key)
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return false
			    }

			    HandleC1Data(acceptreqdata, key)

			    <-timeout

			    if !reply {
				    arstmp := GetAllReplyFromGroup2(w.id,sender)
				if signtimeout {
				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "Approval timeout", "Approval timeout", arstmp, workid)
				} else {
				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Someone refused to sign", "Someone refused to sign", arstmp, workid)
				}

				res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("approval fail")}
				ch <- res
				return false
			    }

			    _,_, cherr := GetChannelValue(SubGidSignDataTimeOut, w.bgosign)
			    if cherr != nil {
				    log.Error("============================DoReq,get go on signing timeout============================","pubkey",sig.PubKey,"key",key,"sig.GroupID",sig.GroupID,"Mode",sig.Mode)
				    arstmp := GetAllReplyFromGroup2(w.id,sender)
				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "Not participating in MPC signing", "Not participating in MPC signing", arstmp, workid)
				res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("approval fail")}
				ch <- res
				return false
			    }

			    //must delete the pre-sign data before continuing with the next checking
			    mutex.Lock()
			    pickdata := make([]*PickHashData, 0)
			    for _, vv := range w.PickHash {
				    pre := GetPreSignData(sig.PubKey, sig.InputCode, w.subgid, vv.PickKey)
				    if pre == nil {
					log.Error("============================DoReq,get pre-sign data fail============================","pubkey",sig.PubKey,"gid",sig.GroupID,"subgid",w.subgid,"data key",vv.PickKey)
					arstmp := GetAllReplyFromGroup2(w.id,sender)
					AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "MPC calculation failed,please try again.", "MPC calculation failed,please try again.", arstmp, workid)
					res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get pre-sign data fail")}
					ch <- res
					mutex.Unlock()
					return false
				    }

				    pd := &PickHashData{Hash: vv.Hash, Pre: pre}
				    pickdata = append(pickdata, pd)
				    err = DeletePreSignData(sig.PubKey, sig.InputCode, w.subgid, vv.PickKey)
				    if err != nil {
					log.Error("============================DoReq,delete pre-sign data fail============================","err",err,"pubkey",sig.PubKey,"gid",sig.GroupID,"subgid",w.subgid,"data key",vv.PickKey)
					arstmp := GetAllReplyFromGroup2(w.id,sender)
					AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "MPC calculation failed,please try again.", "MPC calculation failed,please try again.", arstmp, workid)
					res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
					ch <- res
					mutex.Unlock()
					return false
				    }
			    }
			    mutex.Unlock()

			    w.groupid = w.subgid //must change the w.groupid
			    log.Debug("============================DoReq,continue the signing============================","w.id",w.id,"pubkey",sig.PubKey,"gid",sig.GroupID,"subgid",w.subgid,"key",w.sid,"threshold",w.ThresHold,"nodecnt",w.NodeCnt)

			    rch := make(chan interface{}, 1)
			    sign(w.sid, from, sig.PubKey, sig.InputCode, sig.MsgHash, sig.Keytype, nonce, sig.Mode, pickdata, rch)
			    chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
			    if chret != "" {
				    _, reply := AcceptSign("", from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, w.limitnum, sig.Mode, "true", "true", "Success", chret, "", "", nil, w.id)
				    if reply != nil {
					ars := GetAllReplyFromGroup2(w.id,sender)
					errinfo := "Abnormal value in MPC calculation,please try again."
					if cherr.Error() == "signing timeout" {
					    errinfo = "Data network transmission failure in MPC calculation,please try again."
					}

					AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
					res := RPCSmpcRes{Ret: "", Tip: tip, Err: errors.New(errinfo)}
					ch <- res
					return false 
				    }
				    
				    res := RPCSmpcRes{Ret: chret, Tip: "", Err: nil}
				    ch <- res
				    return true
			    }

			    if cherr != nil {
				    ars := GetAllReplyFromGroup2(w.id,sender)
				    errinfo := "Abnormal value in MPC calculation,please try again."
				    if cherr.Error() == "signing timeout" {
					errinfo = "Data network transmission failure in MPC calculation,please try again."
				    }

				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
				    res := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
				    ch <- res
				    return false 
			    }

			    ars = GetAllReplyFromGroup2(w.id,sender)
			    errinfo := "Abnormal value in MPC calculation,please try again."
			    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
			    res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf(errinfo)}
			    ch <- res
			    return false 
			}
			/////////

			//must delete the pre-sign data before continuing with the next checking
			mutex.Lock()
			pickdata := make([]*PickHashData, 0)
			for _, vv := range signbrocast.PickHash {
				pre := GetPreSignData(sig.PubKey, sig.InputCode, sig.GroupID, vv.PickKey)
				if pre == nil {
				    log.Error("============================DoReq,get pre-sign data fail============================","pubkey",sig.PubKey,"gid",sig.GroupID,"data key",vv.PickKey)
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get pre-sign data fail")}
				    ch <- res
				    mutex.Unlock()
				    return false
				}

				pd := &PickHashData{Hash: vv.Hash, Pre: pre}
				pickdata = append(pickdata, pd)
				err = DeletePreSignData(sig.PubKey, sig.InputCode, sig.GroupID, vv.PickKey)
				if err != nil {
				    log.Error("============================DoReq,delete pre-sign data fail============================","err",err,"pubkey",sig.PubKey,"gid",sig.GroupID,"data key",vv.PickKey)
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				    ch <- res
				    mutex.Unlock()
				    return false
				}
			}
			mutex.Unlock()

			signpick := &SignPickData{Raw: signbrocast.Raw, PickData: pickdata}
			errtmp := DoSign(signpick, workid, sender, ch)
			if errtmp == nil {
				return true
			}

			return false
		}

		if msgmap["Type"] == "ComSignData" {
			signpick, err := UnCompressSignData(msgmap["ComSignData"])
			if err != nil {
			    log.Error("=========================DoReq,uncompress sign data fail=========================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			//////for mode == 2
			key, from, nonce, txdata, err := CheckRaw(signpick.Raw)
			if err != nil {
			    log.Error("=========================DoReq,check sign raw data fail=========================","err",err)
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}

			sig, ok := txdata.(*TxDataSign)
			if !ok {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign data error")}
			    ch <- res
			    return false
			}
		
			//check current node whther in group
			// cmd data default not to relay to other nodes
			if !IsInGroup(sig.GroupID) {
				res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("current node is not in group")}
				ch <- res
				return false
			}
			//
			if sig.Mode == "2" {
			    ars := GetAllReplyFromGroup(workid,sig.GroupID,RPCSIGN,sender)
			    ac := &AcceptSignData{Raw:signpick.Raw,Initiator: sender, Account: from, GroupID: sig.GroupID, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkID: workid}
			    err = SaveAcceptSignData(ac)
			    if err != nil {
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("save sign accept data fail")}
				    ch <- res
				    return false 
			    }

			    common.Info("===============save sign accept data finish===================", "ars ", ars, "key ", key, "tx data", sig)
			    w := workers[workid]
			    w.sid = key
			    w.groupid = sig.GroupID
			    w.limitnum = sig.ThresHold
			    gcnt, _ := GetGroup(w.groupid)
			    w.NodeCnt = gcnt
			    w.ThresHold = w.NodeCnt

			    nums := strings.Split(w.limitnum, "/")
			    if len(nums) == 2 {
				    nodecnt, err := strconv.Atoi(nums[1])
				    if err == nil {
					    w.NodeCnt = nodecnt
				    }
				    nodecnt2, err := strconv.Atoi(nums[0])
				    if err == nil {
					    w.ThresHold = nodecnt2
				    }
			    }

			    w.SmpcFrom = sig.PubKey // pubkey replace smpcfrom in sign

			    //
			    index := -1
			    for j,rh := range w.ApprovReplys {
				if rh == nil {
				    continue
				}

				if strings.EqualFold(rh.From,from) {
				    index = j
				    break
				}
			    }

			    reqaddrkey := GetReqAddrKeyByOtherKey(key, RPCSIGN)
			    exsit, da := GetPubKeyData([]byte(reqaddrkey))
			    if !exsit {
				    log.Error("================get keygen data by key from db fail===============","sign key",key,"keygen key",reqaddrkey)
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("get keygen data by key from db fail")}
				    ch <- res
				    return false 
			    }

			    acceptreqdata, ok := da.(*AcceptReqAddrData)
			    if !ok || acceptreqdata == nil {
				    log.Error("================get keygen data fail===============","sign key",key,"keygen key",reqaddrkey)
				    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("get keygen data fail")}
				    ch <- res
				    return false
			    }

			    enode := curEnode
			    if acceptreqdata.Mode == "0" || acceptreqdata.Mode == "2" {
				    enode = GetENodeByFrom(from,acceptreqdata)
				    if enode == "" {
					    log.Error("================get enode fail===============","sign key",key,"keygen key",reqaddrkey)
					res := RPCSmpcRes{Ret: "", Tip: "", Err: errors.New("get enode fail")}
					ch <- res
					return false 
				    }
			    }

			    reply2 := &ApprovReply{ENode:enode,From: from, Accept: "AGREE", TimeStamp: acceptreqdata.TimeStamp}
			    if index != -1 {
				w.ApprovReplys[index] = reply2
			    } else {
				w.ApprovReplys = append(w.ApprovReplys,reply2)
			    }
			    
			    var reply bool
			    var tip string
			    var signtimeout bool

			    timeout := make(chan bool, 1)
			    go func(wid int) {
				    curEnode = discover.GetLocalID().String() //GetSelfEnode()
				    ato,err := strconv.Atoi(sig.AcceptTimeOut)
				    if err != nil || sig.AcceptTimeOut == "" {
					    ato = 600 
				    }

				    agreeWaitTime := time.Duration(ato) * time.Second
				    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

				    wtmp2 := workers[wid]

				    for {
					    select {
					    case account := <-wtmp2.acceptSignChan:
						    common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
						    ars := GetAllReplyFromGroup2(w.id,sender)
						    common.Info("==================get all signing approve results===============", "result ", ars, "key ", key)

						    res := GetReply(w.id) 
						    if res == 1 {
							reply = false
						    } else {
							reply = true
						    }

						    if !reply {
							    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Someone refused to sign", "Someone refused to sign", ars, wid)
						    } else {
							    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, wid)
						    }

						    timeout <- true
						    return
					    case <-agreeWaitTimeOut.C:
						    ars := GetAllReplyFromGroup2(w.id,sender)
						    common.Info("================== DoSign, agree wait timeout=============", "ars", ars, "key ", key)
						    _, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "Approval timeout", "Approval timeout", ars, wid)
						    reply = false

						    signtimeout = true
						    timeout <- true
						    return
					    }
				    }
			    }(workid)

			    if len(workers[workid].acceptWaitSignChan) == 0 {
				    workers[workid].acceptWaitSignChan <- "go on"
			    }

			    DisAcceptMsg(signpick.Raw, workid)
			    exsit, da = GetPubKeyData([]byte(reqaddrkey))
			    if !exsit {
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return false
			    }

			    acceptreqdata, ok = da.(*AcceptReqAddrData)
			    if !ok || acceptreqdata == nil {
				    common.Debug("===============get req addr key by other key error ===================", "key ", key)
				    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return false
			    }

			    HandleC1Data(acceptreqdata, key)

			    <-timeout

			    if !reply {
				    arstmp := GetAllReplyFromGroup2(w.id,sender)
				if signtimeout {
				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "Approval timeout", "Approval timeout", arstmp, workid)
				} else {
				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Someone refused to sign", "Someone refused to sign", arstmp, workid)
				}

				res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("approval fail")}
				ch <- res
				return false
			    }

			    enodes := GetEnodesForSubGroup(w.id,w.groupid)
			    _, err = layer2.CheckAddPeer(w.limitnum, enodes,false)
			    if err != nil {
				log.Error("=======================check add peer fail====================","err",err,"key",w.sid)
				arstmp := GetAllReplyFromGroup2(w.id,sender)
				AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Failed to select signing node,please try again.", "Failed to select signing node,please try again.", arstmp, workid)
				res := RPCSmpcRes{Ret: "", Tip:"", Err:err}
				ch <- res
				return false
			    }

			    gid, _, errtmp := layer2.CreateSDKGroup(w.limitnum, enodes, false)
			    if errtmp != "" {
				log.Error("=======================create group fail====================","err",err,"key",w.sid)
				arstmp := GetAllReplyFromGroup2(w.id,sender)
				AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "Failed to select signing node,please try again.", "Failed to select signing node,please try again.", arstmp, workid)
				res := RPCSmpcRes{Ret: "", Tip:"", Err:errors.New(errtmp)}
				ch <- res
				return false
			    }
			    time.Sleep(time.Duration(CreatingSignSubGidTimeOut) * time.Second)

			    //////choose pre-sign data
			    pickdata,err := HandleRPCSign3(gid,sig,w.sid,signpick.Raw)
			    if err != nil {
				log.Error("=======================pick pre-sign data fail====================","err",err,"key",w.sid)
				arstmp := GetAllReplyFromGroup2(w.id,sender)
				AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "MPC calculation failed,please try again.", "MPC calculation failed,please try again.", arstmp, workid)
				res := RPCSmpcRes{Ret: "", Tip:"", Err:err}
				ch <- res
				return false
			    }
			    //////

			    w.groupid = gid //must change the w.groupid
			    log.Debug("============================DoReq,continue the signing============================","w.id",w.id,"pubkey",sig.PubKey,"gid",sig.GroupID,"subgid",gid,"key",w.sid,"threshold",w.ThresHold,"nodecnt",w.NodeCnt,"choose nodes",enodes)

			    rch := make(chan interface{}, 1)
			    sign(w.sid, from, sig.PubKey, sig.InputCode, sig.MsgHash, sig.Keytype, nonce, sig.Mode, pickdata, rch)
			    chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
			    if chret != "" {
				    _, reply := AcceptSign("", from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, w.limitnum, sig.Mode, "true", "true", "Success", chret, "", "", nil, w.id)
				    if reply != nil {
					ars := GetAllReplyFromGroup2(w.id,sender)
					errinfo := "Abnormal value in MPC calculation,please try again."
					if cherr.Error() == "signing timeout" {
					    errinfo = "Data network transmission failure in MPC calculation,please try again."
					}

					AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
					res := RPCSmpcRes{Ret: "", Tip: tip, Err: errors.New(errinfo)}
					ch <- res
					return false 
				    }

				    res := RPCSmpcRes{Ret: chret, Tip: "", Err: nil}
				    ch <- res
				    return true
			    }

			    if cherr != nil {
				    ars := GetAllReplyFromGroup2(w.id,sender)
				    errinfo := "Abnormal value in MPC calculation,please try again."
				    if cherr.Error() == "signing timeout" {
					errinfo = "Data network transmission failure in MPC calculation,please try again."
				    }

				    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
				    res := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
				    ch <- res
				    return false 
			    }

			    ars = GetAllReplyFromGroup2(w.id,sender)
			    errinfo := "Abnormal value in MPC calculation,please try again."
			    AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "true", "Failure", "", "", errinfo, ars, workid)
			    res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf(errinfo)}
			    ch <- res
			    return false 
			}
			/////////

			errtmp := DoSign(signpick, workid, sender, ch)
			if errtmp == nil {
				return true
			}

			return false
		}
	}

	key, from, _, txdata, err := CheckRaw(raw)
	common.Debug("=====================DoReq,check raw data finish ================", "key", key, "from", from, "err", err, "raw", raw)
	if err != nil {
		common.Error("===============DoReq,check raw error===================", "err ", err)
		res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	acceptsig, ok := txdata.(*TxDataAcceptSign)
	if !ok {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign data error")}
		ch <- res
		return false
	}

	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
		common.Info("===============DoReq, worker was not found.=====================", "accept sign key ", acceptsig.Key, "from ", from)
		c1data := strings.ToLower(acceptsig.Key + "-" + from)
		C1Data.WriteMap(c1data, raw) // save the lastest accept msg??
		res := RPCSmpcRes{Ret: "Failure", Tip: "", Err: fmt.Errorf("not find worker")}
		ch <- res
		return false
	}

	/////fix bug: miss accept msg for 7-11 test
	if !strings.EqualFold(sender, curEnode) && Find(w.msgacceptsignres, raw) {
		res := RPCSmpcRes{Ret: "Success", Tip: "dul accept msg,but return success", Err: nil}
		ch <- res
		return true
	}
	////

	exsit, da := GetSignInfoData([]byte(acceptsig.Key))
	if !exsit {
		common.Error("===============DoReq, get sign accept data fail from db=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "Failure", Tip: "", Err: fmt.Errorf("get sign accept data fail from db")}
		ch <- res
		return false
	}

	ac, ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		common.Error("===============DoReq, it is acceptsign and decode accept data fail=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "Failure", Tip: "", Err: fmt.Errorf("decode accept data fail")}
		ch <- res
		return false
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign has handled before")}
		ch <- res
		return false
	}

	status := "Pending"
	accept := "false"
	if acceptsig.Accept == "AGREE" {
		accept = "true"
	} else {
		status = "Failure"
	}

	id, _ := GetWorkerID(w)
	DisAcceptMsg(raw, id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptsig.Key, RPCSIGN)
	exsit, da = GetPubKeyData([]byte(reqaddrkey))
	if !exsit {
		common.Error("===============DoReq, get reqaddr sigs data fail=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
		ch <- res
		return false
	}

	acceptreqdata, ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Error("===============DoReq, get reqaddr sigs data fail =====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get reqaddr sigs data fail")}
		ch <- res
		return false
	}

	HandleC1Data(acceptreqdata, acceptsig.Key)

	ars := GetAllReplyFromGroup2(id,ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("sign has handled before")}
		ch <- res
		return false
	}

	tip, err := AcceptSign(ac.Initiator, ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupID, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkID)
	if err != nil {
		res := RPCSmpcRes{Ret: "Failure", Tip: tip, Err: err}
		ch <- res
		return false
	}

	res := RPCSmpcRes{Ret: "Success", Tip: "", Err: nil}
	ch <- res
	return true
}

func HandleRPCSign3(gid string,sig *TxDataSign,key string,raw string) ([]*PickHashData,error) {
    if sig == nil || gid == "" || key == "" || raw == "" {
	return nil,errors.New("param error")
    }

    pickdata := make([]*PickHashData, 0)
    if sig.Keytype == "ED25519" {
	pickhash := make([]*PickHashKey, 0)
	m := make(map[string]string)
	send, err := CompressSignSubGidBrocastData(raw, pickhash,gid)
	if err == nil {
		m["ComSignSubGidBrocastData"] = send
	}
	m["Type"] = "ComSignSubGidBrocastData"
	val, err := json.Marshal(m)
	if err != nil {
		common.Error("=========================HandleRpcSign3======================", "sig.Pubkey", sig.PubKey, "key", key, "err", err,"subgid",gid,"gid",sig.GroupID)
		return nil,err
	}

	SendMsgToSmpcGroup(string(val), gid)
	time.Sleep(time.Duration(8) * time.Second)  //wait for sign(...)
	return pickdata,nil
    }

    return HandleRPCSign4(sig,gid,key,raw)
}

func HandleRPCSign4(sig *TxDataSign,gid string,key string,raw string) ([]*PickHashData,error) {
    if sig == nil || gid == "" || key== "" || raw == "" {
	return nil,errors.New("param error")
    }

    smpcpks, err := hex.DecodeString(sig.PubKey)
    if err != nil {
	return nil,err
    }

    exsit, da := GetPubKeyData(smpcpks[:])
    common.Debug("=========================HandleRpcSign4======================", "Pubkey", sig.PubKey, "key", key, "exsit", exsit,"subgid",gid,"gid",sig.GroupID)
    if !exsit {
	return nil,errors.New("get pubkey data fail")
    }

    _, ok := da.(*PubKeyData)
    common.Debug("=========================HandleRpcSign4======================", "Pubkey", sig.PubKey, "key", key, "exsit", exsit, "ok", ok,"subgid",gid,"gid",sig.GroupID)
    if !ok {
	return nil,errors.New("get pubkey data fail")
    }

    var datakey string
    var pick *PreSignData
    bret := false
    pickdata := make([]*PickHashData, 0)
    pickhash := make([]*PickHashKey, 0)
    for _, vv := range sig.MsgHash {
	go func(hashtmp string) {
	    for {
		if bret {
		    common.Debug("=========================HandleRpcSign4,pick pre-sign data fail======================", "Pubkey", sig.PubKey, "key", key, "subgid", gid)
		    return
		}

		datakey = DoPreSign(sig.PubKey,gid,hashtmp)
		if datakey == "" {
		    time.Sleep(time.Duration(1) * time.Second)
		    continue
		}

		common.Debug("=========================HandleRpcSign4,pick pre-sign data succes======================", "Pubkey", sig.PubKey, "key", key, "subgid", gid,"data key",datakey)
		return
	    }
	    
	}(vv)

	timeout := make(chan bool, 1)
	rch := make(chan bool, 1)
	go func() {
	    for {
		if bret {
		    common.Debug("=========================HandleRpcSign4,pick pre-sign data fail======================", "Pubkey", sig.PubKey, "key", key, "subgid", gid)
		    return
		}

		pick = GetPreSignData(sig.PubKey,sig.InputCode,gid,datakey)
		if pick != nil {
		    common.Debug("=========================HandleRpcSign4,pick pre-sign data successfully======================", "Pubkey", sig.PubKey, "key", key, "subgid", gid,"pick key",pick.Key,"data key",datakey)

		    rch <-true
		    bret = false
		    return
		}
		
		time.Sleep(time.Duration(3) * time.Second)
	    }
	}()

	go func() {
		syncWaitTime := 300 * time.Second
		syncWaitTimeOut := time.NewTicker(syncWaitTime)

		for {
			select {
			case <-rch:
				//common.Debug("=========================HandleRpcSign,pick pre-sign data finish======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID,"pick key",pick.Key)
				bret = false
				timeout <-false
				return
			case <-syncWaitTimeOut.C:
				common.Debug("=========================HandleRpcSign4,pick pre-sign data timeout======================", "Pubkey", sig.PubKey, "key", key, "subgid", gid)
				bret = true
				timeout <- true
				return
			}
		}
	}()
	<-timeout

	if bret {
	    return nil,errors.New("handle pre-sign data fail")
	}

	err = DeletePreSignData(sig.PubKey,sig.InputCode,gid,pick.Key)
	if err != nil {
	    log.Error("============================HandleRpcSign4,delete pre-sign data fail============================","err",err,"pubkey",sig.PubKey,"subgid",gid,"data key",pick.Key)
	    return nil,err 
	}
	
	common.Info("========================HandleRpcSign4,choose pickkey==================", "txhash", vv, "pickkey", pick.Key, "key", key,"subgid",gid)
	ph := &PickHashKey{Hash: vv, PickKey: pick.Key}
	pickhash = append(pickhash, ph)
	phd := &PickHashData{Hash: vv, Pre: pick}
	pickdata = append(pickdata, phd)

	datakey = ""
	pick = nil
    }

    if bret {
	return nil,errors.New("handle pre-sign data fail")
    }

    m := make(map[string]string)
    send, err := CompressSignSubGidBrocastData(raw, pickhash,gid)
    if err == nil {
	    m["ComSignSubGidBrocastData"] = send
    }
    m["Type"] = "ComSignSubGidBrocastData"
    val, err := json.Marshal(m)
    if err != nil {
	    common.Error("=========================HandleRpcSign4======================", "Pubkey", sig.PubKey, "key",key, "exsit", exsit, "ok", ok, "bret", bret, "err", err,"subgid",gid)
	    return nil,err 
    }

    SendMsgToSmpcGroup(string(val), gid)
    time.Sleep(time.Duration(8) * time.Second)  //wait for sign(...)

    return pickdata,nil
}

//-----------------------------------------------------------------------------------------------------

// GetGroupSigs No need for signing
func (req *ReqSmpcSign) GetGroupSigs(txdata []byte) (string, string, string, string) {
	return "", "", "", ""
}

//--------------------------------------------------------------------------------------------------------

// CheckTxData check sign/pre-sign command data and sign accept data
func (req *ReqSmpcSign) CheckTxData(txdata []byte, from string, nonce uint64) (string, string, string, interface{}, error) {
	if txdata == nil {
	    log.Error("======================ReqSmpcSign.CheckTxData=========================","err","tx data is nil")
		return "", "", "", nil, errors.New("tx data is nil")
	}

	sig := TxDataSign{}
	err := json.Unmarshal(txdata, &sig)
	log.Debug("======================ReqSmpcSign.CheckTxData=========================","err",err,"sig.TxType",sig.TxType)
	if err == nil && sig.TxType == "SIGN" {
		pubkey := sig.PubKey
		inputcode := sig.InputCode
		hash := sig.MsgHash
		keytype := sig.Keytype
		groupid := sig.GroupID
		threshold := sig.ThresHold
		mode := sig.Mode
		timestamp := sig.TimeStamp

		if from == "" || pubkey == "" || hash == nil || keytype == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
			log.Error("======================ReqSmpcSign.CheckTxData,param error from raw data=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp)
			return "", "", "", nil, fmt.Errorf("param error from raw data")
		}

		//check input code
		if inputcode != "" {
			indexs := strings.Split(inputcode, "/")
			if len(indexs) < 2 || indexs[0] != "m" {
			    log.Error("======================ReqSmpcSign.CheckTxData,bip32,param error from raw data=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp)
				return "", "", "", nil, fmt.Errorf("param error from raw data")
			}
		}
		//

		if keytype != "EC256K1" && keytype != "ED25519" {
		log.Error("======================ReqSmpcSign.CheckTxData,invalid keytype=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp)
		    return "","","",nil,fmt.Errorf("invalid keytype")
		}

		nums := strings.Split(threshold, "/")
		if len(nums) != 2 {
		    log.Error("======================ReqSmpcSign.CheckTxData,threshold is not right=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp)
			return "", "", "", nil, fmt.Errorf("threshold is not right")
		}
		nodecnt, err := strconv.Atoi(nums[1])
		if err != nil {
		    log.Error("======================ReqSmpcSign.CheckTxData=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"err",err)
			return "", "", "", nil, err
		}
		limit, err := strconv.Atoi(nums[0])
		if err != nil {
		    log.Error("======================ReqSmpcSign.CheckTxData=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"err",err)
			return "", "", "", nil, err
		}
		if nodecnt < limit || limit < 2 {
		    log.Error("======================ReqSmpcSign.CheckTxData,threshold format error=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt)
			return "", "", "", nil, fmt.Errorf("threshold format error")
		}

		nc, _ := GetGroup(groupid)
		if nc < limit || nc > nodecnt {
		    log.Error("======================ReqSmpcSign.CheckTxData,check group node count error=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc)
			return "", "", "", nil, fmt.Errorf("check group node count error")
		}

		if !CheckGroupEnode(groupid) {
		    log.Error("======================ReqSmpcSign.CheckTxData,there is same enodeID in group=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc)
			return "", "", "", nil, fmt.Errorf("there is same enodeID in group")
		}

		//check mode
		smpcpks, err := hex.DecodeString(pubkey)
		if err != nil {
		    log.Error("======================ReqSmpcSign.CheckTxData=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"err",err)
			return "", "", "", nil, err 
		}

		exsit, da := GetPubKeyData([]byte(smpcpks[:]))
		if !exsit {
		    log.Error("======================ReqSmpcSign.CheckTxData,get pubkey data fail=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc)
			return "", "", "", nil, fmt.Errorf("get data from db fail in func sign")
		}

		pubs, ok := da.(*PubKeyData)
		if pubs == nil || !ok {
		    log.Error("======================ReqSmpcSign.CheckTxData,get pubkey data fail in func sign=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc)
			return "", "", "", nil, fmt.Errorf("get data from db fail in func sign")
		}

		if pubs.Mode != mode {
		    log.Error("======================ReqSmpcSign.CheckTxData,can not sign with different mode in pubkey=========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode)
			return "", "", "", nil, fmt.Errorf("can not sign with different mode in pubkey")
		}

		if len(sig.MsgContext) > 16 {
		    log.Error("======================ReqSmpcSign.CheckTxData,=msgcontext counts must <= 16========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode)
			return "", "", "", nil, fmt.Errorf("msgcontext counts must <= 16")
		}
		for _, item := range sig.MsgContext {
			if len(item) > 1024*1024 {
			    log.Error("======================ReqSmpcSign.CheckTxData,msgcontext item size must <= 1M========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode)
				return "", "", "", nil, fmt.Errorf("msgcontext item size must <= 1M")
			}
		}

		ato,err := strconv.Atoi(sig.AcceptTimeOut)
		if err != nil || sig.AcceptTimeOut == "" {
			ato = 600
		}
		if ato <= 0 {
			log.Error("======================ReqSmpcSign.CheckTxData,illegal agreed timeout========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode,"sig.AcceptTimeOut",sig.AcceptTimeOut,"ato",ato)
			return "", "", "", nil, fmt.Errorf("illegal agreed timeout")
		}

		if ato > MaxAcceptTime {
			log.Error("======================ReqSmpcSign.CheckTxData,greater than the agreed maximum timeout========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode,"sig.AcceptTimeOut",sig.AcceptTimeOut,"ato",ato,"MaxAcceptTime",MaxAcceptTime)
			return "", "", "", nil, fmt.Errorf("greater than the agreed maximum timeout")
		}

		log.Info("======================ReqSmpcSign.CheckTxData,check txdata success========================","from",from,"sig.TxType",sig.TxType,"pubkey",pubkey,"hash",hash,"keytype",keytype,"groupid",groupid,"threshold",threshold,"mode",mode,"timestamp",timestamp,"limit",limit,"nodecnt",nodecnt,"nc",nc,"pubs.Mode",pubs.Mode,"sig.AcceptTimeOut",sig.AcceptTimeOut,"ato",ato,"MaxAcceptTime",MaxAcceptTime)
		key := Keccak256Hash([]byte(strings.ToLower(from + ":" + fmt.Sprintf("%v", nonce) + ":" + pubkey + ":" + getSignHash(hash, keytype) + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
		return key, from, fmt.Sprintf("%v", nonce), &sig, nil
	}

	pre := TxDataPreSignData{}
	err = json.Unmarshal(txdata, &pre)
	if err == nil && pre.TxType == "PRESIGNDATA" {
		pubkey := pre.PubKey
		subgids := pre.SubGid

		if from == "" || pubkey == "" || subgids == nil {
			return "", "", "", nil, fmt.Errorf("param error from raw data")
		}
		//

		smpcpks, err := hex.DecodeString(pubkey)
		if err != nil {
		    return "", "", "", nil,err 
		}

		exsit, _ := GetPubKeyData(smpcpks[:])
		if !exsit {
			return "", "", "", nil, fmt.Errorf("invalid pubkey")
		}

		return "", from, fmt.Sprintf("%v", nonce), &pre, nil
	}

	acceptsig := TxDataAcceptSign{}
	err = json.Unmarshal(txdata, &acceptsig)
	if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
		if acceptsig.MsgHash == nil {
			return "", "", "", nil, fmt.Errorf("accept data error")
		}

		if len(acceptsig.MsgContext) > 16 {
			return "", "", "", nil, fmt.Errorf("msgcontext counts must <= 16")
		}
		for _, item := range acceptsig.MsgContext {
			if len(item) > 1024*1024 {
				return "", "", "", nil, fmt.Errorf("msgcontext item size must <= 1M")
			}
		}

		if acceptsig.Accept != "AGREE" && acceptsig.Accept != "DISAGREE" {
			return "", "", "", nil, fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
		}

		exsit, da := GetSignInfoData([]byte(acceptsig.Key))
		if !exsit {
			return "", "", "", nil, fmt.Errorf("get accept result from db fail")
		}

		ac, ok := da.(*AcceptSignData)
		if !ok || ac == nil {
			return "", "", "", nil, fmt.Errorf("get accept result from db fail")
		}

		if ac.Mode == "1" {
			return "", "", "", nil, fmt.Errorf("mode = 1,do not need to accept")
		}

		if !CheckAccept(ac.PubKey, ac.Mode, from) {
			return "", "", "", nil, fmt.Errorf("invalid accepter")
		}

		return acceptsig.Key, from, "", &acceptsig, nil
	}

	return "", "", "", nil, errors.New("check tx data fail")
}

//----------------------------------------------------------------------------------------------------------

// GetSignRawValue get from/special tx data type/timestamp from sign command data 
func GetSignRawValue(raw string) (string, string, string) {
	if raw == "" {
		return "", "", ""
	}

	var from string
	var data []byte
	var msgsig bool 

	m := MsgSig{}
       err := json.Unmarshal([]byte(raw), &m)
       if err == nil {
	   msgsig = true
	   data = []byte(m.Msg)
       } else {
	    tx := new(types.Transaction)
	    raws := common.FromHex(raw)
	    if err := rlp.DecodeBytes(raws, tx); err != nil {
		    return "", "", ""
	    }

	    signer := types.NewEIP155Signer(big.NewInt(30400))
	    from2, err := types.Sender(signer, tx)
	    if err != nil {
		    return "", "", ""
	    }

	    data = tx.Data()
	    from = from2.Hex()
	    msgsig = false 
       }
 
	var txtype string
	var timestamp string

	sig := TxDataSign{}
	err = json.Unmarshal(data, &sig)
	if err == nil && sig.TxType == "SIGN" {
		txtype = "SIGN"
		timestamp = sig.TimeStamp
		if msgsig {
		    from = sig.Account
		}
	} else {
		pre := TxDataPreSignData{}
		err = json.Unmarshal(data, &pre)
		if err == nil && pre.TxType == "PRESIGNDATA" {
			txtype = "PRESIGNDATA"
			//timestamp = pre.TimeStamp
			if msgsig {
			    from = pre.Account
			}
		} else {
			acceptsig := TxDataAcceptSign{}
			err = json.Unmarshal(data, &acceptsig)
			if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
				txtype = "ACCEPTSIGN"
				timestamp = acceptsig.TimeStamp
				if msgsig {
				    from = acceptsig.Account
				}
			}
		}
	}

	return from, txtype, timestamp
}

// CheckSignDulpRawReply Filter duplicate accept data (command data is also a kind of accept data), 
// Take the latest accept data as the final data 
func CheckSignDulpRawReply(raw string, l *list.List) bool {
	if l == nil || raw == "" {
		return false
	}

	from, txtype, timestamp := GetSignRawValue(raw)

	if from == "" || txtype == "" || timestamp == "" {
		return false
	}

	var next *list.Element
	for e := l.Front(); e != nil; e = next {
		next = e.Next()

		if e.Value == nil {
			return false //error
		}

		s := e.Value.(string)

		if s == "" {
			return false //error
		}

		if strings.EqualFold(raw, s) {
			return false
		}

		from2, txtype2, timestamp2 := GetSignRawValue(s)
		if from2 == "" || txtype2 == "" || timestamp2 == "" {
			return false //error
		}

		if strings.EqualFold(from, from2) {
			t1, _ := new(big.Int).SetString(timestamp, 10)
			t2, _ := new(big.Int).SetString(timestamp2, 10)
			if t1.Cmp(t2) > 0 {
				l.Remove(e)
			} else {
				return false
			}
		}
	}

	return true
}

// DisAcceptMsg  Collect accept data of nodes in the group, after collection, continue the MPC process 
func (req *ReqSmpcSign) DisAcceptMsg(raw string, workid int, key string) {
	if raw == "" || workid < 0 || workid >= len(workers) || key == "" {
		return
	}

	w := workers[workid]
	if w == nil {
		return
	}

	if Find(w.msgacceptsignres, raw) {
		common.Debug("======================ReqSmpcSign.DisAcceptMsg,receive one msg and already in list.===========================", "raw", raw, "key", key)
		return
	}

	if !CheckSignDulpRawReply(raw, w.msgacceptsignres) {
		return
	}

	exsit, da := GetSignInfoData([]byte(key))
	if !exsit {
		return
	}

	ac, ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		return
	}

	w.msgacceptsignres.PushBack(raw)
	/////fix bug: miss accept msg for 7-11 test
	if RelayInPeers {
	    SendMsgToSmpcGroup(raw, ac.GroupID)
	}
	/////

	if w.msgacceptsignres.Len() >= w.ThresHold {
		if !CheckReply(w.msgacceptsignres, RPCSIGN, key) {
			common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg, but Not all accept data has been received ===================", "raw", raw, "key", key)
			return
		}

		//common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received===================", "raw", raw, "key", key)
		w.bacceptsignres <- true
		//common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received,set acceptSignChan ===================", "raw", raw, "key", key)
		workers[ac.WorkID].acceptSignChan <- "go on"
	}
}


