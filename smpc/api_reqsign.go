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
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"math/big"
	"strconv"
	"strings"

	"container/list"
	"crypto/sha512"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"time"
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

		nr := NodeReply{Enode: node2, Status: sta, TimeStamp: ts, Initiator: in}
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
		return false
	}
	
	m["SyncPreSign"] = string(spsjson)
	m["Type"] = "SyncPreSign"
	val, err := json.Marshal(m)
	if err != nil {
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
		syncWaitTime := 20 * time.Second
		syncWaitTimeOut := time.NewTicker(syncWaitTime)

		for {
			select {
			case <-w.bsyncpresign:
				iter := w.msgsyncpresign.Front()
				for iter != nil {
					val := iter.Value.(string)
					if val == "" {
						reply = false
						timeout <- false
						return
					}

					msgmap := make(map[string]string)
					err = json.Unmarshal([]byte(val), &msgmap)
					if err != nil {
						reply = false
						timeout <- false
						return
					}

					sps := &SyncPreSign{}
					if err = sps.UnmarshalJSON([]byte(msgmap["SyncPreSign"])); err != nil {
						reply = false
						timeout <- false
						return
					}

					if strings.EqualFold(sps.Msg, "fail") {
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
				reply = false
				timeout <- true
				return
			}
		}
	}()

	<-timeout
	return reply
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
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			common.Debug("===============ReqSmpcSign.DoReq,raw is signdata type===================", "msgprex", sd.MsgPrex, "key", sd.Key, "pkx", sd.Pkx, "pky", sd.Pky)

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
					h.Write(childPKx.Bytes())
					h.Write(childPKy.Bytes())
					h.Write([]byte(indexs[idxi]))
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
						res2 := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
						ch <- res2
						return false
					}

					ww.rsv.PushBack(ret)
					res2 := RPCSmpcRes{Ret: ret, Tip: "", Err: nil}
					ch <- res2
					return true
				}

			}

			res2 := RPCSmpcRes{Ret: "", Tip: "sign fail", Err: fmt.Errorf("sign fail")}
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
				res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
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
					h.Write(childPKx.Bytes())
					h.Write(childPKy.Bytes())
					h.Write([]byte(indexs[idxi]))
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
					res := RPCSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
					ch <- res
					return false
				}

				res := RPCSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
				ch <- res
				return false
			}

			pre.Key = w.sid
			pre.Gid = w.groupid
			pre.Used = false
			pre.Index = ps.Index

			err = PutPreSignData(ps.Pub, ps.InputCode, ps.Gid, ps.Index, pre, true)
			if err != nil {
				common.Info("============================PreSign at RecvMsg.Run, failed to generate the presign data this time,put pre-sign data to local db fail. ==========================", "pubkey", ps.Pub, "gid", ps.Gid, "presign data key", w.sid, "err", err)
				if syncpresign && !SynchronizePreSignData(w.sid, w.id, false) {
					common.Info("================================PreSign at RecvMsg.Run, put pre-sign data to local db fail=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index, "err", err)
					res := RPCSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
					ch <- res
					return false
				}

				common.Info("================================PreSign at RecvMsg.Run, put pre-sign data to local db fail=====================", "pick key", pre.Key, "pubkey", ps.Pub, "gid", ps.Gid, "index", ps.Index, "err", err)
				res := RPCSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
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

			common.Info("============================PreSign at RecvMsg.Run, pre-generated sign data succeeded.==========================", "pubkey", ps.Pub, "gid", ps.Gid, "presign data key", w.sid)
			res := RPCSmpcRes{Ret: "success", Tip: "", Err: nil}
			ch <- res
			return true
		}

		if msgmap["Type"] == "ComSignBrocastData" {
			signbrocast, err := UnCompressSignBrocastData(msgmap["ComSignBrocastData"])
			if err != nil {
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
			_, _, _, txdata, err := CheckRaw(signbrocast.Raw)
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
			
			pickdata := make([]*PickHashData, 0)
			for _, vv := range signbrocast.PickHash {
				pre := GetPreSignData(sig.PubKey, sig.InputCode, sig.GroupID, vv.PickKey)
				if pre == nil {
					res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get pre-sign data fail", Err: fmt.Errorf("get pre-sign data fail")}
					ch <- res
					return false
				}

				pd := &PickHashData{Hash: vv.Hash, Pre: pre}
				pickdata = append(pickdata, pd)
				DeletePreSignData(sig.PubKey, sig.InputCode, sig.GroupID, vv.PickKey)
			}

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
			    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			    ch <- res
			    return false
			}
			
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
		res := RPCSmpcRes{Ret: "", Tip: "sign data error", Err: fmt.Errorf("sign data error")}
		ch <- res
		return false
	}

	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
		common.Info("===============DoReq, worker was not found.=====================", "accept sign key ", acceptsig.Key, "from ", from)
		c1data := strings.ToLower(acceptsig.Key + "-" + from)
		C1Data.WriteMap(c1data, raw)
		res := RPCSmpcRes{Ret: "Failure", Tip: "get sign accept data fail from db when no find worker.", Err: fmt.Errorf("get sign accept data fail from db when no find worker")}
		ch <- res
		return false
	}

	exsit, da := GetSignInfoData([]byte(acceptsig.Key))
	if !exsit {
		common.Error("===============DoReq, get sign accept data fail from db=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:get sign accept data fail from db in init accept data", Err: fmt.Errorf("get sign accept data fail from db")}
		ch <- res
		return false
	}

	ac, ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		common.Error("===============DoReq, it is acceptsign and decode accept data fail=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
		ch <- res
		return false
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
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
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
		ch <- res
		return false
	}

	acceptreqdata, ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Error("===============DoReq, get reqaddr sigs data fail =====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
		ch <- res
		return false
	}

	HandleC1Data(acceptreqdata, acceptsig.Key)

	ars := GetAllReplyFromGroup(id, ac.GroupID, RPCSIGN, ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================", "key ", acceptsig.Key, "from ", from)
		res := RPCSmpcRes{Ret: "", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
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

//-----------------------------------------------------------------------------------------------------

// GetGroupSigs No need for signing
func (req *ReqSmpcSign) GetGroupSigs(txdata []byte) (string, string, string, string) {
	return "", "", "", ""
}

//--------------------------------------------------------------------------------------------------------

// CheckTxData check sign/pre-sign command data and sign accept data
func (req *ReqSmpcSign) CheckTxData(txdata []byte, from string, nonce uint64) (string, string, string, interface{}, error) {
	if txdata == nil {
		return "", "", "", nil, errors.New("tx data is nil")
	}

	sig := TxDataSign{}
	err := json.Unmarshal(txdata, &sig)
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
			return "", "", "", nil, fmt.Errorf("param error from raw data")
		}

		//check input code
		if inputcode != "" {
			indexs := strings.Split(inputcode, "/")
			if len(indexs) < 2 || indexs[0] != "m" {
				return "", "", "", nil, fmt.Errorf("param error from raw data")
			}
		}
		//

		nums := strings.Split(threshold, "/")
		if len(nums) != 2 {
			return "", "", "", nil, fmt.Errorf("threshold is not right")
		}
		nodecnt, err := strconv.Atoi(nums[1])
		if err != nil {
			return "", "", "", nil, err
		}
		limit, err := strconv.Atoi(nums[0])
		if err != nil {
			return "", "", "", nil, err
		}
		if nodecnt < limit || limit < 2 {
			return "", "", "", nil, fmt.Errorf("threshold format error")
		}

		nc, _ := GetGroup(groupid)
		if nc < limit || nc > nodecnt {
			common.Info("==============ReqSmpcSign.CheckTxData, sign,check group node count error============", "limit ", limit, "nodecnt ", nodecnt, "nc ", nc, "groupid ", groupid)
			return "", "", "", nil, fmt.Errorf("check group node count error")
		}

		if !CheckGroupEnode(groupid) {
			return "", "", "", nil, fmt.Errorf("there is same enodeID in group")
		}

		//check mode
		smpcpks, err := hex.DecodeString(pubkey)
		if err != nil {
			return "", "", "", nil, err 
		}

		exsit, da := GetPubKeyData([]byte(smpcpks[:]))
		if !exsit {
			return "", "", "", nil, fmt.Errorf("get data from db fail in func sign")
		}

		pubs, ok := da.(*PubKeyData)
		if pubs == nil || !ok {
			return "", "", "", nil, fmt.Errorf("get data from db fail in func sign")
		}

		if pubs.Mode != mode {
			return "", "", "", nil, fmt.Errorf("can not sign with different mode in pubkey")
		}

		if len(sig.MsgContext) > 16 {
			return "", "", "", nil, fmt.Errorf("msgcontext counts must <= 16")
		}
		for _, item := range sig.MsgContext {
			if len(item) > 1024*1024 {
				return "", "", "", nil, fmt.Errorf("msgcontext item size must <= 1M")
			}
		}

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

	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", "", ""
	}

	signer := types.NewEIP155Signer(big.NewInt(30400))
	from, err := types.Sender(signer, tx)
	if err != nil {
		return "", "", ""
	}

	var txtype string
	var timestamp string

	sig := TxDataSign{}
	err = json.Unmarshal(tx.Data(), &sig)
	if err == nil && sig.TxType == "SIGN" {
		txtype = "SIGN"
		timestamp = sig.TimeStamp
	} else {
		pre := TxDataPreSignData{}
		err = json.Unmarshal(tx.Data(), &pre)
		if err == nil && pre.TxType == "PRESIGNDATA" {
			txtype = "PRESIGNDATA"
			//timestamp = pre.TimeStamp
		} else {
			acceptsig := TxDataAcceptSign{}
			err = json.Unmarshal(tx.Data(), &acceptsig)
			if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
				txtype = "ACCEPTSIGN"
				timestamp = acceptsig.TimeStamp
			}
		}
	}

	return from.Hex(), txtype, timestamp
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
			continue
		}

		s := e.Value.(string)

		if s == "" {
			continue
		}

		if strings.EqualFold(raw, s) {
			return false
		}

		from2, txtype2, timestamp2 := GetSignRawValue(s)
		if strings.EqualFold(from, from2) && strings.EqualFold(txtype, txtype2) {
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

	w.msgacceptsignres.PushBack(raw)
	if w.msgacceptsignres.Len() >= w.ThresHold {
		if !CheckReply(w.msgacceptsignres, RPCSIGN, key) {
			common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg, but Not all accept data has been received ===================", "raw", raw, "key", key)
			return
		}

		common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received===================", "raw", raw, "key", key)
		w.bacceptsignres <- true
		exsit, da := GetSignInfoData([]byte(key))
		if !exsit {
			return
		}

		ac, ok := da.(*AcceptSignData)
		if !ok || ac == nil {
			return
		}

		common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received,set acceptSignChan ===================", "raw", raw, "key", key)
		workers[ac.WorkID].acceptSignChan <- "go on"
	}
}


