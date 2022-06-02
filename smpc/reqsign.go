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
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"

	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/crypto/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/signing"
	edkeygen "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/keygen"
	edsigning "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/signing"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/astaxie/beego/logs"
	"runtime/debug"
	"sync"
)

var (
        // SignChan the channel of RPCSignData
	SignChan = make(chan *RPCSignData, 10000)

	mutex    sync.Mutex
)

//--------------------------------------------------------------------------------------

// GetSignNonce get sign special tx nonce
func GetSignNonce(account string) (string, string, error) {
	mutex.Lock()
	defer mutex.Unlock()
	if account == "" {
		return "", "", fmt.Errorf("invalid account")
	}

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	exsit, da := GetPubKeyData([]byte(key))
	if !exsit {
		nonce := "0"
		err := PutPubKeyData([]byte(key), []byte(nonce))
		if err != nil {
		    return "", "", err 
		}

		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	err := PutPubKeyData([]byte(key), []byte(fmt.Sprintf("%v", nonce)))
	if err != nil {
	    return "", "", err 
	}
	return fmt.Sprintf("%v", nonce), "", nil
}

// SetSignNonce set sign special tx nonce
func SetSignNonce(account string, nonce string) (string, error) {
    	if account == "" || nonce == "" {
	    return "",errors.New("param error")
	}

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	err := PutPubKeyData([]byte(key), []byte(nonce))
	if err != nil {
		return err.Error(), err
	}

	return "", nil
}

//------------------------------------------------------------------------------------------

// DoSign execute sign
// sbd : sign command data + key of picked pre-sign data
// workid : current worker id
// sender : send node's enodeID
// ch : the channel to save the sign result or error info.
func DoSign(sbd *SignPickData, workid int, sender string, ch chan interface{}) error {
	if sbd == nil || workid < 0 || sender == "" || sbd.Raw == "" || sbd.PickData == nil {
		res := RPCSmpcRes{Ret: "", Tip: "do sign fail.", Err: fmt.Errorf("do sign fail")}
		ch <- res
		return fmt.Errorf("do sign fail")
	}

	key, from, nonce, txdata, err := CheckRaw(sbd.Raw)
	common.Info("=====================DoSign,check raw data finish ================", "key", key, "from", from, "err", err, "raw", sbd.Raw, "tx data", txdata)
	if err != nil {
		common.Error("===============DoSign,check raw data error===================", "err ", err, "key", key, "from", from, "raw", sbd.Raw)
		res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return err
	}

	sig, ok := txdata.(*TxDataSign)
	if !ok {
		res := RPCSmpcRes{Ret: "", Tip:"sign data error", Err: fmt.Errorf("sign data error")}
		ch <- res
		return fmt.Errorf("sign data error") 
	}

	exsit, _ := GetSignInfoData([]byte(key))
	if exsit {
		res := RPCSmpcRes{Ret: "", Tip:"the sign cmd has handled before", Err: fmt.Errorf("the sign cmd has handled before")}
		ch <- res
		return fmt.Errorf("the sign cmd has handled before")
	}

	ars := GetAllReplyFromGroup(workid, sig.GroupID, RPCSIGN, sender)
	ac := &AcceptSignData{Raw:sbd.Raw,Initiator: sender, Account: from, GroupID: sig.GroupID, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkID: workid}
	err = SaveAcceptSignData(ac)
	if err != nil {
		res := RPCSmpcRes{Ret: "", Tip:"save sign accept data fail", Err: fmt.Errorf("save sign accept data fail")}
		ch <- res
		return fmt.Errorf("save sign accept data fail")
	}

	common.Info("===============DoSign,save sign accept data finish===================", "ars ", ars, "key ", key, "tx data", sig)
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

		w.ThresHold = gcnt
	}

	w.SmpcFrom = sig.PubKey // pubkey replace smpcfrom in sign

	if sig.Mode == "0" { // self-group
		var reply bool
		var tip string
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

					reply = true
					for _, nr := range ars {
						if !strings.EqualFold(nr.Status, "Agree") {
							reply = false
							break
						}
					}

					if !reply {
						tip = "don't accept sign"
						_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars, wid)
					} else {
						tip = ""
						_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, wid)
					}

					if err != nil {
						tip = tip + " and accept sign data fail"
					}

					timeout <- true
					return
				case <-agreeWaitTimeOut.C:
					ars := GetAllReplyFromGroup(w.id, sig.GroupID, RPCSIGN, sender)
					common.Info("================== DoSign, agree wait timeout=============", "ars", ars, "key ", key)
					_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars, wid)
					reply = false
					tip = "get other node accept sign result timeout"
					if err != nil {
						tip = tip + " and accept sign data fail"
					}

					timeout <- true
					return
				}
			}
		}(workid)

		if len(workers[workid].acceptWaitSignChan) == 0 {
			workers[workid].acceptWaitSignChan <- "go on"
		}

		DisAcceptMsg(sbd.Raw, workid)
		reqaddrkey := GetReqAddrKeyByOtherKey(key, RPCSIGN)
		if reqaddrkey == "" {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
			ch <- res
			return fmt.Errorf("get reqaddr key fail")
		}

		exsit, da := GetPubKeyData([]byte(reqaddrkey))
		if !exsit {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
			ch <- res
			return fmt.Errorf("get reqaddr sigs data fail")
		}

		acceptreqdata, ok := da.(*AcceptReqAddrData)
		if !ok || acceptreqdata == nil {
			common.Debug("===============DoSign, get req addr key by other key error ===================", "key ", key)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
			ch <- res
			return fmt.Errorf("get reqaddr sigs data fail")
		}

		HandleC1Data(acceptreqdata, key)

		<-timeout

		if !reply {
			if tip == "get other node accept sign result timeout" {
				ars := GetAllReplyFromGroup(w.id, sig.GroupID, RPCSIGN, sender)
				_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars, workid)
			}

			res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept sign")}
			ch <- res
			return fmt.Errorf("don't accept sign")
		}
	} else {
		if len(workers[workid].acceptWaitSignChan) == 0 {
			workers[workid].acceptWaitSignChan <- "go on"
		}

		ars := GetAllReplyFromGroup(w.id, sig.GroupID, RPCSIGN, sender)
		_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, workid)
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return err
		}
	}

	rch := make(chan interface{}, 1)
	sign(w.sid, from, sig.PubKey, sig.InputCode, sig.MsgHash, sig.Keytype, nonce, sig.Mode, sbd.PickData, rch)
	chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
	if chret != "" {
		res := RPCSmpcRes{Ret: chret, Tip: "", Err: nil}
		ch <- res
		return nil
	}

	ars = GetAllReplyFromGroup(w.id, sig.GroupID, RPCSIGN, sender)
	if tip == "get other node accept sign result timeout" {
		_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupID, nonce, sig.ThresHold, sig.Mode, "true", "", "Timeout", "", tip, cherr.Error(), ars, workid)
	}

	if cherr != nil {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
		ch <- res
		return cherr
	}

	res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail")}
	ch <- res
	return fmt.Errorf("sign fail")
}

//------------------------------------------------------------------------------------------------------

// RPCAcceptSign Agree to the sign request 
// raw : accept data, including the key of the sign request
func RPCAcceptSign(raw string) (string, string, error) {
    	if raw == "" {
	    return "","",errors.New("param error")
	}

	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================RPCAcceptSign,check raw data error================", "raw", raw, "err", err)
		return "Failure", err.Error(), err
	}

	if key == "" || from == "" || txdata == nil {
		return "Failure", "check accept raw data fail", fmt.Errorf("check accept raw data fail")
	}

	acceptsig, ok := txdata.(*TxDataAcceptSign)
	if !ok {
		return "Failure", "check raw fail,it is not *TxDataAcceptSign", fmt.Errorf("check raw fail,it is not *TxDataAcceptSign")
	}

	if acceptsig.Key == "" || acceptsig.Accept == "" {
		return "Failure", "check accept raw data fail", fmt.Errorf("check accept raw data fail")
	}

	exsit, da := GetSignInfoData([]byte(acceptsig.Key))
	if exsit {
		ac, ok := da.(*AcceptSignData)
		if ok && ac != nil {
			SendMsgToSmpcGroup(raw, ac.GroupID)
			//SetUpMsgList(raw, curEnode)
			go ExecApproveSigning(raw,from,acceptsig,ac,true)
			return "Success", "", nil
		}
	}

	return "Failure", "accept fail", fmt.Errorf("accept fail")
}

func ExecApproveSigning(raw string,from string,sig *TxDataAcceptSign,ac *AcceptSignData,check bool) {
	w, err := FindWorker(sig.Key)
	if err != nil || w == nil {
		common.Info("===============ExecApproveSigning, worker was not found.=====================", "accept sign key ", sig.Key, "from ", from)
		c1data := strings.ToLower(sig.Key + "-" + from)
		C1Data.WriteMap(c1data, raw) // save the lastest accept msg??
		return
	}

	if w.approved {
	    return
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============ExecApproveSigning,sign has handled before=====================", "key ", sig.Key, "from ", from)
		return
	}

	reqaddrkey := GetReqAddrKeyByOtherKey(sig.Key, RPCSIGN)
	exsit, da := GetPubKeyData([]byte(reqaddrkey))
	if !exsit {
		common.Error("===============ExecApproveSigning, get reqaddr sigs data fail=====================", "key ",sig.Key, "from ", from)
		return
	}

	acceptreqdata, ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Error("===============ExecApproveSigning, get reqaddr sigs data fail =====================", "key ",sig.Key, "from ", from)
		return
	}

	/////fix bug: miss accept msg for 7-11 test
	if Find(w.msgacceptsignres, raw) {
		return
	}
	////

	if !IsValidAccept(ac.GroupID,from,acceptreqdata) {
	    return
	}

	if !CheckSignDulpRawReply(raw, w.msgacceptsignres) {
		return
	}

	if check {
	    HandleC1Data(acceptreqdata, sig.Key)
	}

	status := "Pending"
	accept := sig.Accept
	if accept == "" {
	    accept = "DISAGREE"
	}

	if sig.Accept != "AGREE" {
		status = "Failure"
	}

	AcceptSign(ac.Initiator, ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupID, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", nil, ac.WorkID)
	
	w.msgacceptsignres.PushBack(raw)
	/////fix bug: miss accept msg for 7-11 test
	//SendMsgToSmpcGroup(raw, ac.GroupID)
	/////

	index := -1
	for k,vv := range w.ApprovReplys {
	    if vv == nil {
		continue
	    }

	    if strings.EqualFold(vv.From,from) {
		index = k
		break
	    }
	}

	enode := GetENodeByFrom(from,acceptreqdata)
	if enode == "" {
	    return
	}

	reply := &ApprovReply{ENode:enode,From: from, Accept: accept, TimeStamp: sig.TimeStamp}
	if index != -1 {
	    w.ApprovReplys[index] = reply
	} else {
	    w.ApprovReplys = append(w.ApprovReplys,reply)
	}

	if w.msgacceptsignres.Len() >= w.ThresHold {
		//if !CheckReply(w.msgacceptsignres, RPCSIGN, sig.Key) {
		//	common.Debug("=====================ExecApproveSigning,receive one msg, but Not all accept data has been received ===================", "raw", raw, "key", sig.Key)
		//	return
		//}

		w.approved = true
		w.bacceptsignres <- true
		workers[ac.WorkID].acceptSignChan <- "go on"
	}
}

//------------------------------------------------------------------------------------------

// RPCSignData the sign data of put into the channel to handle 
type RPCSignData struct {
	Raw       string
	PubKey    string
	InputCode string
	GroupID   string
	MsgHash   []string
	Key       string
}

// TxDataSign the data of the special tx of sign 
type TxDataSign struct {
	TxType     string
	PubKey     string
	InputCode  string
	MsgHash    []string
	MsgContext []string
	Keytype    string
	GroupID    string
	ThresHold  string
	Mode       string
	AcceptTimeOut      string
	TimeStamp  string
}

// Sign execute the sign command
// raw : sign command data
func Sign(raw string) (string, string, error) {
    	if raw == "" {
	    return "","",errors.New("param error")
	}

	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================Sign,check raw data error================", "raw", raw, "err", err)
		return "", err.Error(), err
	}

	sig, ok := txdata.(*TxDataSign)
	if !ok {
		return "", "check raw fail,it is not *TxDataSign", fmt.Errorf("check raw fail,it is not *TxDataSign")
	}

	common.Debug("=====================Sign================", "key", key, "from", from, "raw", raw)

	if sig.Keytype == "ED25519" {
		pickdata := make([]*PickHashData, 0)
		pickhash := make([]*PickHashKey, 0)
		m := make(map[string]string)
		send, err := CompressSignBrocastData(raw, pickhash)
		if err != nil || send == "" {
		    return "","",err
		}

		m["ComSignBrocastData"] = send
		m["Type"] = "ComSignBrocastData"
		val, err := json.Marshal(m)
		if err != nil {
		    return "", "",err 
		}

		SendMsgToSmpcGroup(string(val), sig.GroupID)

		m2 := make(map[string]string)
		selfsend, err := CompressSignData(raw, pickdata)
		if err != nil || selfsend == "" {
		    return "","",err
		}

		m2["ComSignData"] = selfsend
		m2["Type"] = "ComSignData"
		val2, err := json.Marshal(m2)
		if err != nil {
		    return "", "",err 
		}
		SetUpMsgList(string(val2), curEnode)
	} else {
		rsd := &RPCSignData{Raw: raw, PubKey: sig.PubKey, InputCode: sig.InputCode, GroupID: sig.GroupID, MsgHash: sig.MsgHash, Key: key}
		SignChan <- rsd
	}
	return key, "", nil
}

// HandleRPCSign handle sign request,read sign command from the channel and do it!
func HandleRPCSign() {
	for {
		rsd := <-SignChan

		smpcpks, err := hex.DecodeString(rsd.PubKey)
		if err != nil {
		    common.Error("[SIGN] decode pubkey string error", "pubkey", rsd.PubKey, "key", rsd.Key,"err",err)
		    continue
		}

		exsit, da := GetPubKeyData(smpcpks[:])
		common.Debug("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit)
		if !exsit {
		    continue
		}
		
		_, ok := da.(*PubKeyData)
		common.Debug("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok)
		if !ok {
		    continue
		}
		
		var pub string
		if rsd.InputCode != "" {
			pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.InputCode + ":" + rsd.GroupID))).Hex()
		} else {
			pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.GroupID))).Hex()
		}

		bret := false
		pickdata := make([]*PickHashData, 0)
		pickhash := make([]*PickHashKey, 0)
		//var wg sync.WaitGroup
		for kk, vv := range rsd.MsgHash {
			//wg.Add(1)
			//go func(hash string) {
			    //wg.Done()
			    pick := PickPreSignData(rsd.PubKey, rsd.InputCode, rsd.GroupID)
			    if pick == nil && kk == 0 {
				//common.Debug("=========================HandleRpcSign,pick pre-sign data fail and excute pre-sign cmd======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID)
				subgid := make([]string,0)
				subgid = append(subgid,rsd.GroupID)
				pre := &TxDataPreSignData{TxType: "PRESIGNDATA", PubKey: rsd.PubKey, SubGid: subgid}
				ExcutePreSignData(pre)
			    }
				
			    timeout := make(chan bool, 1)
			    rch := make(chan bool, 1)
			    go func() {
				for {
				    if bret {
					common.Debug("=========================HandleRpcSign,pick pre-sign data fail======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID)
					return
				    }

				    pick = PickPreSignData(rsd.PubKey, rsd.InputCode, rsd.GroupID)
				    if pick != nil {
					common.Debug("=========================HandleRpcSign,pick pre-sign data successfully======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID,"pick key",pick.Key)
					rch <-true
					bret = false
					return
				    }
				    
				    time.Sleep(time.Duration(3) * time.Second)
				}
			    }()

			    go func() {
				    syncWaitTime := 180 * time.Second
				    syncWaitTimeOut := time.NewTicker(syncWaitTime)

				    for {
					    select {
					    case <-rch:
						    //common.Debug("=========================HandleRpcSign,pick pre-sign data finish======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID,"pick key",pick.Key)
						    bret = false
						    timeout <-false
						    return
					    case <-syncWaitTimeOut.C:
						    common.Debug("=========================HandleRpcSign,pick pre-sign data timeout======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "gid", rsd.GroupID)
						    bret = true
						    timeout <- true
						    return
					    }
				    }
			    }()
			    <-timeout

			    if bret {
				break
			    }

			    common.Info("========================HandleRpcSign,choose pickkey==================", "txhash", vv, "pickkey", pick.Key, "key", rsd.Key)

			    ph := &PickHashKey{Hash: vv, PickKey: pick.Key}
			    pickhash = append(pickhash, ph)
			    phd := &PickHashData{Hash: vv, Pre: pick}
			    pickdata = append(pickdata, phd)

			    //check pre sigal
			    if rsd.InputCode != "" {
				    if GetTotalCount(rsd.PubKey, rsd.InputCode, rsd.GroupID) >= (PreBip32DataCount/2) && GetTotalCount(rsd.PubKey, rsd.InputCode, rsd.GroupID) <= PreBip32DataCount {
					    PutPreSigal(pub, false)
				    } else {
					    PutPreSigal(pub, true)
				    }
			    } else {
				    if GetTotalCount(rsd.PubKey, "", rsd.GroupID) >= (PrePubDataCount*3/4) && GetTotalCount(rsd.PubKey, "", rsd.GroupID) <= PrePubDataCount {
					    PutPreSigal(pub, false)
				    } else {
					    PutPreSigal(pub, true)
				    }
			    }
			    //
			//}(vv)
		}
		//wg.Wait()

		if bret {
			continue
		}

		m := make(map[string]string)
		send, err := CompressSignBrocastData(rsd.Raw, pickhash)
		if err == nil {
			m["ComSignBrocastData"] = send
		}
		m["Type"] = "ComSignBrocastData"
		val, err := json.Marshal(m)
		if err != nil {
			common.Error("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok, "bret", bret, "err", err)
			continue
		}

		SendMsgToSmpcGroup(string(val), rsd.GroupID)

		m2 := make(map[string]string)
		selfsend, err := CompressSignData(rsd.Raw, pickdata)
		if err == nil {
			m2["ComSignData"] = selfsend
		}
		m2["Type"] = "ComSignData"
		val2, err := json.Marshal(m2)
		if err != nil {
			common.Error("=========================HandleRpcSign,compress hash data.======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok, "bret", bret, "err", err)
			continue
		}
		SetUpMsgList(string(val2), curEnode)
	}
}

//-----------------------------------------------------------------------------------------------

// getSignHash To get the key of sign command with the hash value,we must transfer hash array to a string
func getSignHash(hash []string, keytype string) string {
    	if hash == nil || keytype  == "" {
	    return ""
	}

	var ids smpclib.SortableIDSSlice
	for _, v := range hash {
		uid := DoubleHash(v, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)

	ret := ""
	for _, v := range ids {
		ret += fmt.Sprintf("%v", v)
		ret += ":"
	}

	ret += "NULL"
	return ret
}

//---------------------------------------------------------------------------------------------------

// SignStatus sign result
type SignStatus struct {
	Status    string
	Rsv       []string
	Tip       string
	Error     string
	AllReply  []NodeReply
	TimeStamp string
}

// GetSignStatus get the result of the sign request by key
func GetSignStatus(key string) (string, string, error) {
    	if key  == "" {
	    return "","",errors.New("param error")
	}

	exsit, da := GetPubKeyData([]byte(key))
	if !exsit || da == nil {
		common.Debug("=================GetSignStatus,get sign accept data fail from db================", "key", key)
		return "", "smpc back-end internal error:get sign accept data fail from db when GetSignStatus", fmt.Errorf("get sign accept data fail from db")
	}

	ac, ok := da.(*AcceptSignData)
	if !ok {
		common.Error("=================GetSignStatus,get sign accept data error from db================", "key", key)
		return "", "smpc back-end internal error:get sign accept data error from db when GetSignStatus", fmt.Errorf("get sign accept data error from db")
	}

	rsvs := strings.Split(ac.Rsv, ":")
	los := &SignStatus{Status: ac.Status, Rsv: rsvs[:len(rsvs)-1], Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

//--------------------------------------------------------------------------------------------------

// SignCurNodeInfo the info of the current node's approve list
type SignCurNodeInfo struct {
    	Raw	string
	Key        string
	Account    string
	PubKey     string
	MsgHash    []string
	MsgContext []string
	KeyType    string
	GroupID    string
	Nonce      string
	ThresHold  string
	Mode       string
	TimeStamp  string
}

// SignCurNodeInfoSort sort the info that get from current node's approve list
type SignCurNodeInfoSort struct {
	Info []*SignCurNodeInfo
}

// Len get the count of arrary elements
func (s *SignCurNodeInfoSort) Len() int {
	return len(s.Info)
}

// Less weather r.Info[i] < r.Info[j]
func (s *SignCurNodeInfoSort) Less(i, j int) bool {
	itime, _ := new(big.Int).SetString(s.Info[i].TimeStamp, 10)
	jtime, _ := new(big.Int).SetString(s.Info[j].TimeStamp, 10)
	return itime.Cmp(jtime) >= 0
}

// Swap swap value of r.Info[i] and r.Info[j]
func (s *SignCurNodeInfoSort) Swap(i, j int) {
	s.Info[i], s.Info[j] = s.Info[j], s.Info[i]
}

// GetCurNodeSignInfo  Get current node's sign command approval list 
func GetCurNodeSignInfo(geteracc string) ([]*SignCurNodeInfo, string, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("GetCurNodeSignInfo Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

    	if geteracc  == "" {
	    return nil,"",errors.New("param error")
	}

	var ret []*SignCurNodeInfo
	data := make(chan *SignCurNodeInfo, 1000)

	var wg sync.WaitGroup
	iter := signinfodb.NewIterator()
	for iter.Next() {
		key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		exsit, val := GetSignInfoData(key2)
		if !exsit || val == nil {
			continue
		}

		wg.Add(1)
		go func(key string, value interface{}, ch chan *SignCurNodeInfo) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Errorf("GetCurNodeSignInfo go Runtime error: %v\n%v", r, string(debug.Stack()))
				}
				wg.Done()
			}()

			if value == nil || key == "" {
				return
			}

			vv, ok := value.(*AcceptSignData)
			if vv == nil || !ok {
				return
			}

			if vv.Deal == "true" || vv.Status == "Success" {
				return
			}

			if vv.Status != "Pending" {
				return
			}

			if !CheckAccept(vv.PubKey, vv.Mode, geteracc) {
				return
			}

			//los := &SignCurNodeInfo{Key: key, Account: vv.Account, PubKey: vv.PubKey, MsgHash: vv.MsgHash, MsgContext: vv.MsgContext, KeyType: vv.Keytype, GroupID: vv.GroupID, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
			los := &SignCurNodeInfo{Raw:vv.Raw,Key: key, Account: vv.Account, PubKey: vv.PubKey, MsgHash: vv.MsgHash, MsgContext: vv.MsgContext, KeyType: vv.Keytype, GroupID: vv.GroupID, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
			if los == nil {
				common.Error("=========================GetCurNodeSignInfo,current info is nil========================", "key", key)
				return
			}

			ch <- los
		}(string(key2), val, data)
	}
	iter.Release()
	wg.Wait()

	l := len(data)
	for i := 0; i < l; i++ {
		info := <-data
		ret = append(ret, info)
	}

	signinfosort := SignCurNodeInfoSort{Info: ret}
	sort.Sort(&signinfosort)

	var tmp []*SignCurNodeInfo
	for i := 0; i < len(signinfosort.Info); i++ {
		if signinfosort.Info[i] == nil {
			continue
		}

		tmp = append(tmp, signinfosort.Info[i])
	}

	return tmp, "", nil
}

//----------------------------------------------------------------------------------------------------------

// sign execut the sign command,including ec and ed.
// keytype : EC256K1 || ED25519
func sign(wsid string, account string, pubkey string, inputcode string, unsignhash []string, keytype string, nonce string, mode string, pickdata []*PickHashData, ch chan interface{}) {
	smpcpks, err := hex.DecodeString(pubkey)
	if err != nil {
	    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
	    ch <- res
	    return
	}

	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit {
		common.Debug("============================sign,not exist sign data===========================", "pubkey", pubkey, "key", wsid)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	_, ok := da.(*PubKeyData)
	if !ok {
		common.Debug("============================sign,sign data error==========================", "pubkey", pubkey, "key", wsid)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	save := (da.(*PubKeyData)).Save
	smpcpub := (da.(*PubKeyData)).Pub

	var smpcpkx *big.Int
	var smpcpky *big.Int
	if keytype == "EC256K1" {
		smpcpks := []byte(smpcpub)
		smpcpkx, smpcpky = secp256k1.S256().Unmarshal(smpcpks[:])
	}

	///sku1
	da2 := getSkU1FromLocalDb(smpcpks[:])
	if da2 == nil {
		res := RPCSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RPCSmpcRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	//

	var result string
	var cherrtmp error
	rch := make(chan interface{}, 1)
	if keytype == "ED25519" {
		signED(wsid, unsignhash, save, sku1, smpcpub, keytype, rch)
		ret, tip, cherr := GetChannelValue(waitall, rch)
		if cherr != nil {
			res := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res
			return
		}

		result = ret
		cherrtmp = cherr
	} else {
		signEC(wsid, unsignhash, save, sku1, smpcpkx, smpcpky, inputcode, keytype, pickdata, rch)
		ret, tip, cherr := GetChannelValue(waitall, rch)
		common.Debug("=================sign,call signEC finish.==============", "return result", ret, "err", cherr, "key", wsid)
		if cherr != nil {
			res := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res
			return
		}

		result = ret
		cherrtmp = cherr
	}

	tmps := strings.Split(result, ":")
	for _, rsv := range tmps {

		if rsv == "NULL" {
			continue
		}

		//bug
		rets := []rune(rsv)
		if keytype != "ED25519" && len(rets) != 130 {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:wrong rsv size", Err: GetRetErr(ErrSmpcSigWrongSize)}
			ch <- res
			return
		}
	}

	if result != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			common.Debug("==========sign,no find worker============", "err", err, "key", wsid)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("get worker error")}
			ch <- res
			return
		}

		common.Debug("================sign,success sign and call AcceptSign==============", "key", wsid)
		tip, reply := AcceptSign("", account, pubkey, unsignhash, keytype, w.groupid, nonce, w.limitnum, mode, "true", "true", "Success", result, "", "", nil, w.id)
		if reply != nil {
			res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update sign status error")}
			ch <- res
			return
		}

		common.Info("================sign,the terminal sign res is success==============", "key", wsid)
		res := RPCSmpcRes{Ret: result, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherrtmp != nil {
		common.Info("================sign,the terminal sign res is failure================", "err", cherrtmp, "key", wsid)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:sign fail", Err: cherrtmp}
		ch <- res
		return
	}

	res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:sign fail", Err: fmt.Errorf("sign fail")}
	ch <- res
}

//----------------------------------------------------------------------------------------------

// SignData the data refer to sign
type SignData struct {
	MsgPrex    string
	Key        string
	InputCodeT string
	Save       string
	Sku1       *big.Int
	Txhash     string
	GroupID    string
	NodeCnt    int
	ThresHold  int
	SmpcFrom   string
	Keytype    string
	Cointype   string
	Pkx        *big.Int
	Pky        *big.Int
	Pre        *PreSignData
}

// MarshalJSON marshal *SignData to json byte
func (sd *SignData) MarshalJSON() ([]byte, error) {
	if sd.Pre == nil {
		return nil, errors.New("get pre-sign data fail")
	}

	s, err := sd.Pre.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct {
		MsgPrex    string `json:"MsgPrex"`
		Key        string `json:"Key"`
		InputCodeT string `json:"InputCodeT"`
		Save       string `json:"Save"`
		Sku1       string `json:"Sku1"`
		Txhash     string `json:"Txhash"`
		GroupID    string `json:"GroupID"`
		NodeCnt    string `json:"NodeCnt"`
		ThresHold  string `json:"ThresHold"`
		SmpcFrom   string `json:"SmpcFrom"`
		Keytype    string `json:"Keytype"`
		Cointype   string `json:"Cointype"`
		Pkx        string `json:"Pkx"`
		Pky        string `json:"Pky"`
		Pre        string `json:"Pre"`
	}{
		MsgPrex:    sd.MsgPrex,
		Key:        sd.Key,
		InputCodeT: sd.InputCodeT,
		Save:       sd.Save,
		Sku1:       fmt.Sprintf("%v", sd.Sku1),
		Txhash:     sd.Txhash,
		GroupID:    sd.GroupID,
		NodeCnt:    strconv.Itoa(sd.NodeCnt),
		ThresHold:  strconv.Itoa(sd.ThresHold),
		SmpcFrom:   sd.SmpcFrom,
		Keytype:    sd.Keytype,
		Cointype:   sd.Cointype,
		Pkx:        fmt.Sprintf("%v", sd.Pkx),
		Pky:        fmt.Sprintf("%v", sd.Pky),
		Pre:        string(s),
	})
}

// UnmarshalJSON unmarshal json string to *SignData
func (sd *SignData) UnmarshalJSON(raw []byte) error {
	var si struct {
		MsgPrex    string `json:"MsgPrex"`
		Key        string `json:"Key"`
		InputCodeT string `json:"InputCodeT"`
		Save       string `json:"Save"`
		Sku1       string `json:"Sku1"`
		Txhash     string `json:"Txhash"`
		GroupID    string `json:"GroupID"`
		NodeCnt    string `json:"NodeCnt"`
		ThresHold  string `json:"ThresHold"`
		SmpcFrom   string `json:"SmpcFrom"`
		Keytype    string `json:"Keytype"`
		Cointype   string `json:"Cointype"`
		Pkx        string `json:"Pkx"`
		Pky        string `json:"Pky"`
		Pre        string `json:"Pre"`
	}
	if err := json.Unmarshal(raw, &si); err != nil {
		return err
	}

	sd.MsgPrex = si.MsgPrex
	sd.Key = si.Key
	sd.InputCodeT = si.InputCodeT
	sd.Save = si.Save
	sd.Sku1, _ = new(big.Int).SetString(si.Sku1, 10)
	sd.Txhash = si.Txhash
	sd.GroupID = si.GroupID
	sd.NodeCnt, _ = strconv.Atoi(si.NodeCnt)
	sd.ThresHold, _ = strconv.Atoi(si.ThresHold)
	sd.SmpcFrom = si.SmpcFrom
	sd.Keytype = si.Keytype
	sd.Cointype = si.Cointype
	sd.Pkx, _ = new(big.Int).SetString(si.Pkx, 10)
	sd.Pky, _ = new(big.Int).SetString(si.Pky, 10)
	pre := &PreSignData{}
	err := pre.UnmarshalJSON([]byte(si.Pre))
	if err != nil {
		return err
	}

	sd.Pre = pre
	return nil
}

//----------------------------------------------------------------------------------------------------

// signEC execute the sign command with ec algorithm 
func signEC(msgprex string, txhash []string, save string, sku1 *big.Int, smpcpkx *big.Int, smpcpky *big.Int, inputcode string, keytype string, pickdata []*PickHashData, ch chan interface{}) string {

	tmp := make([]string, 0)
	for _, v := range txhash {
		txhashs := []rune(v)
		if string(txhashs[0:2]) == "0x" {
			tmp = append(tmp, string(txhashs[2:]))
		} else {
			tmp = append(tmp, string(txhashs))
		}
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		common.Debug("==========smpc_sign,no find worker===========", "key", msgprex, "err", err)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
		ch <- res
		return ""
	}

	curEnode = GetSelfEnode()

	var wg sync.WaitGroup
	for _, v := range tmp {
		wg.Add(1)
		go func(vv string) {
			defer wg.Done()

			//get pick
			var pick *PreSignData
			for _, val := range pickdata {
				if strings.EqualFold(val.Hash, ("0x"+vv)) || strings.EqualFold(val.Hash, vv) {
					pick = val.Pre
					break
				}
			}
			if pick == nil {
				return
			}
			//

			fmt.Printf("============================signEC,pkx = %v,pky = %v =============================\n", smpcpkx, smpcpky)
			key := Keccak256Hash([]byte(strings.ToLower(msgprex + "-" + vv))).Hex()
			sd := &SignData{MsgPrex: msgprex, Key: key, InputCodeT: inputcode, Save: save, Sku1: sku1, Txhash: vv, GroupID: w.groupid, NodeCnt: w.NodeCnt, ThresHold: w.ThresHold, SmpcFrom: w.SmpcFrom, Keytype: keytype, Cointype: "", Pkx: smpcpkx, Pky: smpcpky, Pre: pick}

			m := make(map[string]string)
			sdjson, err := sd.MarshalJSON()
			if err == nil {
				m["SignData"] = string(sdjson)
			}
			m["Type"] = "SignData"
			val, err := json.Marshal(m)
			if err != nil {
				common.Error("======================signEC, marshal SignData to json fail.==================", "unsign txhash", vv, "msgprex", msgprex, "key", key, "pick key", pick.Key, "err", err)
				return
			}

			rch := make(chan interface{}, 1)
			SetUpMsgList3(string(val), curEnode, rch)
			_, _, cherr := GetChannelValue(cht, rch)
			if cherr != nil {
				common.Error("======================signEC, sign error====================", "vv", vv, "msgprex", msgprex, "key", key, "cherr", cherr)
				return
			}
		}(v)
	}
	wg.Wait()

	common.Info("======================signEC, all sign finish===================", "msgprex", msgprex, "w.rsv", w.rsv)

	var ret string
	iter := w.rsv.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		ret += mdss
		ret += ":"
		iter = iter.Next()
	}

	ret += "NULL"
	tmps := strings.Split(ret, ":")
	common.Debug("======================signEC=====================", "return result", ret, "len(tmps)", len(tmps), "len(tmp)", len(tmp), "key", msgprex)
	if len(tmps) == (len(tmp) + 1) {
		res := RPCSmpcRes{Ret: ret, Tip: "", Err: nil}
		ch <- res
		return ""
	}

	res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: sign fail", Err: fmt.Errorf("sign fail")}
	ch <- res
	return ""
}

//-----------------------------------------------------------------------------------------------------

// GetPaillierPkByIndexFromSaveData get paillier pubkey by index from saved data that obtained when generating pubkey
func GetPaillierPkByIndexFromSaveData(save string, index int) *ec2.PublicKey {
	if save == "" || index < 0 {
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	s := 4 + 4*index
	if len(mm) < (s + 4) {
		return nil
	}

	l := mm[s]
	n := new(big.Int).SetBytes([]byte(mm[s+1]))
	g := new(big.Int).SetBytes([]byte(mm[s+2]))
	n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
	publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}

	return publicKey
}

//--------------------------------------------------------------------------------------------------

// GetCurNodeIndex get the serial number of uid of current node in group.
// gid is the `keygen gid`
func GetCurNodeIndex(gid string,subgid string,keytype string) int {
	if gid == "" || subgid == "" || keytype == "" {
		return -1
	}

	_,uid := GetNodeUID(curEnode, keytype,gid)
	ids := GetGroupNodeUIDs(keytype, gid,subgid)

	for k, v := range ids {
		if v.Cmp(uid) == 0 {
			return k
		}
	}

	return -1
}

//-----------------------------------------------------------------------------------------------------

// GetCurNodePaillierSkFromSaveData get current node's paillier private key from saved data that obtained when generating pubkey
// gid is not the sub-gid
func GetCurNodePaillierSkFromSaveData(save string, gid string, keytype string) *ec2.PrivateKey {
	if save == "" || gid == "" || keytype == "" {
		return nil
	}

	curIndex := GetCurNodeIndex(gid,gid,keytype)
	publicKey := GetPaillierPkByIndexFromSaveData(save, curIndex)
	if publicKey != nil {
		mm := strings.Split(save, common.SepSave)
		if len(mm) < 4 {
			return nil
		}

		l := mm[1]
		ll := new(big.Int).SetBytes([]byte(mm[2]))
		uu := new(big.Int).SetBytes([]byte(mm[3]))
		privateKey := &ec2.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
		return privateKey
	}

	return nil
}

//---------------------------------------------------------------------------------------------

// GetNtildeByIndexFromSaveData get ntilde data by index from saved data that obtained when generating pubkey
func GetNtildeByIndexFromSaveData(save string, index int, NodeCnt int) *ec2.NtildeH1H2 {
	if save == "" || index < 0 || NodeCnt < 0 {
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	s := 4 + 4*NodeCnt + 3*index
	if len(mm) < (s + 3) {
		return nil
	}

	ntilde := new(big.Int).SetBytes([]byte(mm[s]))
	h1 := new(big.Int).SetBytes([]byte(mm[s+1]))
	h2 := new(big.Int).SetBytes([]byte(mm[s+2]))
	ntildeh1h2 := &ec2.NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}

	return ntildeh1h2
}

//-------------------------------------------------------------------------------------------------------------

// GetNtildePrivDataByIndexFromSaveData get ntilde priv data by index from saved data that obtained when generating pubkey
func GetNtildePrivDataByIndexFromSaveData(save string,NodeCnt int) *ec2.NtildePrivData {
	if save == "" || NodeCnt < 0 {
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	s := 4 + 4*NodeCnt + 3*NodeCnt
	if len(mm) < (s + 3) {
		return nil
	}

	alpha := new(big.Int).SetBytes([]byte(mm[s]))
	beta := new(big.Int).SetBytes([]byte(mm[s+1]))
	q1 := new(big.Int).SetBytes([]byte(mm[s+2]))
	q2 := new(big.Int).SetBytes([]byte(mm[s+3]))
	priv := &ec2.NtildePrivData{Alpha: alpha, Beta: beta, Q1: q1,Q2:q2}

	return priv
}

//---------------------------------------------------------------------------------------------------

// GetMsgToEnode get uid of node in group by groupid,and put it to the map.
// map: uid ----> enodeID
// gid is the `keygen gid`
func GetMsgToEnode(keytype string, gid string,groupid string) map[string]string {
    if keytype == "" || gid == "" || groupid == "" {
	return nil
    }

    msgtoenode := make(map[string]string)
    _, nodes := GetGroup(groupid)
    others := strings.Split(nodes, common.Sep2)
    for _, v := range others {
	    node2 := ParseNode(v)
	    _,uid := GetNodeUID(node2, keytype,gid)
	    tmp := fmt.Sprintf("%v",uid)
	    msgtoenode[hex.EncodeToString([]byte(tmp))] = node2
    }

    return msgtoenode
}

//-----------------------------------------------------------------------------------------------------

// PreSignEC3 execute the action of generating the pre-sign data.
// msgprex = hash
//  the return value is the generated pre-sign data.
func PreSignEC3(msgprex string, save string, sku1 *big.Int, pkx *big.Int,pky *big.Int,cointype string, ch chan interface{}, id int) *PreSignData {
	if id < 0 || id >= len(workers) {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("no find worker")}
		ch <- res
		return nil
	}
	w := workers[id]
	if w.groupid == "" {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return nil
	}

	sd := &keygen.LocalDNodeSaveData{}
	sd.SkU1 = sku1
	sd.Pkx = pkx
	sd.Pky = pky

	smpcpks, err := hex.DecodeString(w.SmpcFrom)
	if err != nil {
	    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
	    ch <- res
	    return nil
	}

	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit || da == nil {
		res := RPCSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return nil
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return nil
	}

	sd.U1PaillierSk = GetCurNodePaillierSkFromSaveData(save, pubs.GroupID, cointype)

	U1PaillierPk := make([]*ec2.PublicKey, w.NodeCnt)
	U1NtildeH1H2 := make([]*ec2.NtildeH1H2, w.NodeCnt)
	for i := 0; i < w.NodeCnt; i++ {
		U1PaillierPk[i] = GetPaillierPkByIndexFromSaveData(save, i)
		U1NtildeH1H2[i] = GetNtildeByIndexFromSaveData(save, i, w.NodeCnt)
	}
	sd.U1PaillierPk = U1PaillierPk
	sd.U1NtildeH1H2 = U1NtildeH1H2

	sd.IDs = GetGroupNodeUIDs(cointype,pubs.GroupID,pubs.GroupID)
	_,sd.CurDNodeID = GetNodeUID(curEnode, cointype,pubs.GroupID)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupID,pubs.GroupID)
	kgsave := &KGLocalDBSaveData{Save: sd, MsgToEnode: msgtoenode}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	idsign := GetGroupNodeUIDs(cointype,pubs.GroupID,w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData, w.ThresHold)
	finalizeendCh := make(chan *big.Int, w.ThresHold)
	errChan := make(chan struct{})
	signDNode := signing.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, false, nil, nil, finalizeendCh)
	w.DNode = signDNode
	signDNode.SetDNodeID(fmt.Sprintf("%v", sd.CurDNodeID))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			common.Error("==========PreSignEC3, node start fail=======","key",msgprex,"err",err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		common.Debug("==========PreSignEC3, get reqaddr info from pubkeydata db==============","key",msgprex,"exsit",exsit)
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				common.Debug("==========PreSignEC3, get reqaddr info from pubkeydata db==============","key",msgprex,"acceptreqdata",acceptreqdata)
				HandleC1Data(acceptreqdata, w.sid)
			}
		}
	}()
	go SignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	pre, err := processSign(msgprex, kgsave.MsgToEnode, errChan, outCh, endCh)
	if err != nil || pre == nil {
	    	common.Debug("==========================PreSignEC3,process sign fail===========================","key",msgprex,"err",err)
		close(commStopChan)
		res := RPCSmpcRes{Ret: "", Err: err}
		ch <- res
		return nil
	}

	close(commStopChan)
	signWg.Wait()

	ret := &PreSignData{Key: msgprex, K1: pre.K1, R: pre.R, Ry: pre.Ry, Sigma1: pre.Sigma1, Gid: w.groupid, Used: false, Index: -1}
	return ret
}

// SignEC3 execute sign with gg20 MPC algorithm
// msgprex = hash
// return value is the backup for the smpc sign
func SignEC3(msgprex string, message string, cointype string, save string, pkx *big.Int, pky *big.Int, ch chan interface{}, id int, pre *PreSignData) string {
	if id < 0 || id >= len(workers) {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("no find worker")}
		ch <- res
		return ""
	}
	w := workers[id]
	gid := w.groupid

	if w.groupid == "" {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return ""
	}

	hashBytes, err2 := hex.DecodeString(message)
	if err2 != nil {
		res := RPCSmpcRes{Ret: "", Err: err2}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	mMtA, _ := new(big.Int).SetString(message, 16)
	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	}

	sd := &keygen.LocalDNodeSaveData{}
	sd.Pkx = pkx
	sd.Pky = pky

	ys := secp256k1.S256().Marshal(pkx, pky)
	exsit, da := GetPubKeyData(ys)
	if !exsit || da == nil {
		res := RPCSmpcRes{Ret: "", Tip: "sign get local pubkey data fail", Err: fmt.Errorf("sign get local pubkey data fail")}
		ch <- res
		return ""
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return ""
	}

	///sku1
	da2 := getSkU1FromLocalDb(ys)
	if da2 == nil {
		res := RPCSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return ""
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RPCSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return ""
	}
	//
	sd.SkU1 = sku1

	sd.U1PaillierSk = GetCurNodePaillierSkFromSaveData(save, pubs.GroupID, cointype)

	U1PaillierPk := make([]*ec2.PublicKey, w.NodeCnt)
	U1NtildeH1H2 := make([]*ec2.NtildeH1H2, w.NodeCnt)
	for i := 0; i < w.NodeCnt; i++ {
		U1PaillierPk[i] = GetPaillierPkByIndexFromSaveData(save, i)
		U1NtildeH1H2[i] = GetNtildeByIndexFromSaveData(save, i, w.NodeCnt)
	}
	sd.U1PaillierPk = U1PaillierPk
	sd.U1NtildeH1H2 = U1NtildeH1H2

	sd.IDs = GetGroupNodeUIDs(cointype, pubs.GroupID,pubs.GroupID)
	_,sd.CurDNodeID = GetNodeUID(curEnode, cointype,pubs.GroupID)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupID,pubs.GroupID)
	kgsave := &KGLocalDBSaveData{Save: sd, MsgToEnode: msgtoenode}

	idsign := GetGroupNodeUIDs(cointype,pubs.GroupID,w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData, w.ThresHold)
	finalizeendCh := make(chan *big.Int, w.ThresHold)
	errChan := make(chan struct{})
	predata := &signing.PrePubData{K1: pre.K1, R: pre.R, Ry: pre.Ry, Sigma1: pre.Sigma1}
	signDNode := signing.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, true, predata, mMtA, finalizeendCh)
	w.DNode = signDNode
	_,UID := GetNodeUID(curEnode, "EC256K1",pubs.GroupID)
	signDNode.SetDNodeID(fmt.Sprintf("%v", UID))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			fmt.Printf("==========SignEC3, node start, key = %v, err = %v ==========\n", msgprex,err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		common.Debug("======================SignEC3,get reqaddr info from pubkeydata db========================","key",msgprex,"exsit",exsit)
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				common.Debug("======================SignEC3,get reqaddr info from pubkeydata db========================","key",msgprex,"acceptreqdata",acceptreqdata)
				HandleC1Data(acceptreqdata, msgprex) // fixed: must use sub-key `msgprex`, don't use `w.sid`
			}
		}
	}()
	go SignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	s, err := processSignFinalize(msgprex, kgsave.MsgToEnode, errChan, outCh, finalizeendCh, gid)
	if err != nil || s == nil {
	    	common.Debug("=========================SignEC3,process sign fail==============================","key",msgprex,"err",err)
		close(commStopChan)
		res := RPCSmpcRes{Ret: "", Err: err}
		ch <- res
		return ""
	}

	close(commStopChan)
	signWg.Wait()

	// 5. calculate s
	//us1 := signing.CalcUs(mMtA, pre.K1, pre.R, pre.Sigma1)

	/*commitBigVAB1, commitbigvabs, rho1, l1 := DECDSASignRoundSeven(msgprex, pre.R, pre.Ry, us1, w, ch)
	if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
		return ""
	}
	common.Debug("=====================SignEC3, round seven finish=================","key",msgprex)

	u1zkABProof, zkabproofs := DECDSASignRoundEight(msgprex, pre.R, pre.Ry, us1, l1, rho1, w, ch, commitBigVAB1)
	if u1zkABProof == nil || zkabproofs == nil {
		return ""
	}
	common.Debug("=====================SignEC3, round eight finish=================","key",msgprex)

	commitbigcom, BigVx, BigVy := DECDSASignVerifyBigVAB(cointype, w, commitbigvabs, zkabproofs, commitBigVAB1, u1zkABProof, idSign, pre.R, pre.Ry, ch)
	if commitbigcom == nil || BigVx == nil || BigVy == nil {
		return ""
	}
	common.Debug("=====================SignEC3, verify BigVAB finish=================","key",msgprex)

	commitbiguts, commitBigUT1 := DECDSASignRoundNine(msgprex, cointype, w, idSign, mMtA, pre.R, pkx, pky, BigVx, BigVy, rho1, commitbigcom, l1, ch)
	if commitbiguts == nil || commitBigUT1 == nil {
		return ""
	}
	common.Debug("=====================SignEC3, round nine finish=================","key",msgprex)

	commitbigutd11s := DECDSASignRoundTen(msgprex, commitBigUT1, w, ch)
	if commitbigutd11s == nil {
		return ""
	}
	common.Debug("=====================SignEC3, round ten finish=================","key",msgprex)

	if !DECDSASignVerifyBigUTCommitment(msgprex,cointype, commitbiguts, commitbigutd11s, commitBigUT1, w, idSign, ch, commitbigcom) {
		return ""
	}
	common.Debug("=====================SignEC3, verify BigUT commitment finish=================","key",msgprex)
	*/ //------

	//ss1s := DECDSASignRoundEleven(msgprex, cointype, w, idSign, ch, us1)
	//if ss1s == nil {
	//	return ""
	//}
	//common.Debug("=====================SignEC3,round eleven finish=================","key",msgprex)

	//s := Calc_s(msgprex,cointype, w, idSign, ss1s, ch)
	//if s == nil {
	//	return ""
	//}
	//common.Debug("=====================SignEC3,calc s finish=================","key",msgprex)

	// 3. justify the s
	bb := false
	halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		bb = true
		s = new(big.Int).Sub(secp256k1.S256().N, s)
	}

	zero, _ := new(big.Int).SetString("0", 10)
	if s.Cmp(zero) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("s == 0")}
		ch <- res
		return ""
	}
	common.Debug("=====================SignEC3,justify s finish=================", "key", msgprex)

	// **[End-Test]  verify signature with MtA
	signature := new(ECDSASignature)
	signature.New()
	signature.SetR(pre.R)
	signature.SetS(s)

	invert := false
	if cointype == "ETH" && bb {
		invert = true
	}
	if cointype == "BTC" && bb {
		invert = true
	}

	recid := smpclib.DECDSASignCalcv(pre.R, pre.Ry, pkx, pky, signature.GetR(), signature.GetS(), hashBytes, invert)
	common.Debug("=====================SignEC3,first get recid =================", "recid", recid, "key", msgprex)

	////check v
	ys = secp256k1.S256().Marshal(pkx, pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
		pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
	for j := 0; j < 4; j++ {
		rsvBytes2 := append(rsvBytes1, byte(j))
		pkr, e := secp256k1.RecoverPubkey(hashBytes, rsvBytes2)
		pkr2 := hex.EncodeToString(pkr)
		pbhs2 := []rune(pkr2)
		if string(pbhs2[0:2]) == "0x" {
			pkr2 = string(pbhs2[2:])
		}
		if e == nil && strings.EqualFold(pkr2, pubkeyhex) {
			recid = j
			common.Debug("=====================SignEC3,second get recid =================", "recid", recid, "key", msgprex)
			break
		}
	}
	/////
	signature.SetRecoveryParam(int32(recid))
	common.Debug("=====================SignEC3,terminal get recid =================", "recid", signature.GetRecoveryParam(), "key", msgprex)

	if !DECDSASignVerifyRSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) {
		common.Error("=================SignEC3,verify fail==============", "key", msgprex)
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("sign verify fail")}
		ch <- res
		return ""
	}

	signature2 := GetSignString(signature.GetR(), signature.GetS(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	fmt.Printf("===============SignEC3,verify (r,s) pass,rsv str = %v, key = %v =============\n", signature2, msgprex)
	res := RPCSmpcRes{Ret: signature2, Err: nil}
	ch <- res

	return ""
}

//------------------------------------------------------------------------------------------

// ECDSASignature (r,s,v)
type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
}

// New new a *ECDSASignature
func (rsv *ECDSASignature) New() {
}

// GetR get r
func (rsv *ECDSASignature) GetR() *big.Int {
	return rsv.r
}

// SetR set r
func (rsv *ECDSASignature) SetR(r *big.Int) {
	rsv.r = r
}

// GetS get s
func (rsv *ECDSASignature) GetS() *big.Int {
	return rsv.s
}

// SetS set s
func (rsv *ECDSASignature) SetS(s *big.Int) {
	rsv.s = s
}

// GetRecoveryParam get v
func (rsv *ECDSASignature) GetRecoveryParam() int32 {
	return rsv.recoveryParam
}

// SetRecoveryParam set v
func (rsv *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	rsv.recoveryParam = recoveryParam
}

//------------------------------------------------------------------------------------------

// ToolDecimalByteSlice2HexString transfer Decimal byte to hex string
func ToolDecimalByteSlice2HexString(DecimalSlice []byte) string {
    	if DecimalSlice == nil {
	    return ""
	}

	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

// GetSignString get RSV string
func GetSignString(r *big.Int, s *big.Int, v int) string {
    	if r == nil || s == nil {
	    return "" 
	}

	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		smpclib.ReadBits(r, sigs[1:32])
		smpclib.ReadBits(s, sigs[32:64])
		sigs[64] = byte(v)
		ret := ToolDecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		smpclib.ReadBits(r, sigs[1:32])
		smpclib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(v)
		ret := ToolDecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		smpclib.ReadBits(r, sigs[0:32])
		smpclib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(v)
		ret := ToolDecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	smpclib.ReadBits(r, sigs[0:len(rr)])
	smpclib.ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(v)
	ret := ToolDecimalByteSlice2HexString(sigs)

	return ret
}

// DECDSASignVerifyRSV verify RSV
func DECDSASignVerifyRSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return smpclib.Verify2(r, s, v, message, pkx, pky)
}

//--------------------------------------------------------------------------------------------------

// signED execute the sign command with ed algorithm 
func signED(msgprex string, txhash []string, save string, sku1 *big.Int, pk string, keytype string, ch chan interface{}) string {

	tmp := make([]string, 0)
	for _, v := range txhash {
		txhashs := []rune(v)
		if string(txhashs[0:2]) == "0x" {
			tmp = append(tmp, string(txhashs[2:]))
		} else {
			tmp = append(tmp, string(txhashs))
		}

		//tmp = append(tmp, string(common.FromHex(v)))
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		logs.Debug("===========get worker fail.=============")
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	curEnode = GetSelfEnode()

	var result string
	var bakSig string
	for _, v := range tmp {
		var ch1 = make(chan interface{}, 1)
		for i := 0; i < recalcTimes; i++ {
			if len(ch1) != 0 {
				<-ch1
			}

			bakSig = SignED(msgprex, save, sku1, v, keytype, pk, ch1, id)
			ret, _, cherr := GetChannelValue(cht, ch1)
			if ret != "" && cherr == nil {
				result += ret
				result += ":"
				break
			}

			time.Sleep(time.Duration(3) * time.Second)
		}
	}

	result += "NULL"
	tmps := strings.Split(result, ":")
	if len(tmps) == (len(tmp) + 1) {
		res := RPCSmpcRes{Ret: result, Tip: "", Err: nil}
		ch <- res
	}

	return bakSig
}

//-----------------------------------------------------------------------------------------------------------------

// SignED execute the sign command with ed algorithm 
// msgprex = hash
// return value is the backup for the smpc sign
func SignED(msgprex string, save string, sku1 *big.Int, message string, cointype string, pk string, ch chan interface{}, id int) string {
	if id < 0 || id >= len(workers) || id >= RPCMaxWorker {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIDError)}
		ch <- res
		return ""
	}

	w := workers[id]
	GroupID := w.groupid
	if GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return ""
	}

	/*msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(save), &msgmap)
	if err != nil {
	    res := RPCSmpcRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return ""
	}
	kgsave := GetKGLocalDBSaveDataED(msgmap)
	if kgsave == nil {
	    res := RPCSmpcRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return ""
	}
	sd := kgsave.Save*/

	mm := strings.Split(save, common.Sep11)
	if len(mm) == 0 {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("ed get save data fail")}
		ch <- res
		return ""
	}

	smpcpks, err := hex.DecodeString(w.SmpcFrom)
	if err != nil {
	    res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
	    ch <- res
	    return ""
	}

	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit || da == nil {
		res := RPCSmpcRes{Ret: "", Tip: "ed sign get local save data fail", Err: fmt.Errorf("ed sign get local save data fail")}
		ch <- res
		return ""
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "ed sign get local save data fail", Err: fmt.Errorf("ed sign get local save data fail")}
		ch <- res
		return ""
	}

	sd := &edkeygen.LocalDNodeSaveData{}

	var sk [32]byte
	va := sku1.Bytes()
	if len(va) < 32 {
	    diff := 32 - len(va)
	    for i := 0;i<diff;i++ {
		sk[i] = byte(0x00)
	    }
	    copy(sk[diff:], va[:])
	} else {
	    copy(sk[:], va[:32])
	}

	var tsk [32]byte
	va = []byte(mm[2])
	copy(tsk[:], va[:32])
	var pkfinal [32]byte
	va = []byte(mm[3])
	copy(pkfinal[:], va[:32])

	sd.Sk = sk
	sd.TSk = tsk
	sd.FinalPkBytes = pkfinal
	sd.IDs = GetGroupNodeUIDs(cointype, pubs.GroupID,pubs.GroupID)
	_,sd.CurDNodeID = GetNodeUID(curEnode, cointype,pubs.GroupID)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupID,pubs.GroupID)
	kgsave := &KGLocalDBSaveDataED{Save: sd, MsgToEnode: msgtoenode}

	idsign := GetGroupNodeUIDs(cointype,pubs.GroupID,w.groupid)

	//mMtA, _ := new(big.Int).SetString(message, 16)
	mMtA := new(big.Int).SetBytes(common.FromHex(message))
	if mMtA == nil {
	    fmt.Errorf("==============SignED, w.groupid = %v, message = %v, message to []byte fail ==============\n", w.groupid, message)
	    res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("message to []byte fail")}
	    ch <- res
	    return ""
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan edsigning.EdSignData, w.ThresHold)
	finalizeendCh := make(chan *big.Int, w.ThresHold) //useness
	errChan := make(chan struct{})
	signDNode := edsigning.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, false, nil, mMtA, finalizeendCh)
	w.DNode = signDNode
	_,UID := GetNodeUID(curEnode, "ED25519",pubs.GroupID)
	signDNode.SetDNodeID(fmt.Sprintf("%v", UID))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			fmt.Printf("==========SignED, node start, key = %v, err = %v ==========\n", msgprex,err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		common.Debug("================SignED,get reqaddr info from pubkeydata db========================","key",msgprex,"exsit",exsit)
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				common.Debug("================SignED,get reqaddr info from pubkeydata db========================","key",msgprex,"acceptreqdata",acceptreqdata)
				HandleC1Data(acceptreqdata, msgprex) // fixed: must use sub-key `msgprex`, don't use `w.sid`
			}
		}
	}()
	go EdSignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	edrs, err := processSigned(msgprex, kgsave.MsgToEnode, errChan, outCh, endCh)
	if err != nil || edrs == nil {
		common.Debug("================SignED,process sign fail========================","key",msgprex,"err",err)
		close(commStopChan)
		res := RPCSmpcRes{Ret: "", Err: err}
		ch <- res
		return ""
	}

	close(commStopChan)
	signWg.Wait()

	signature := new([64]byte)
	copy(signature[:], edrs.Rx[:])
	copy(signature[32:], edrs.Sx[:])
	sig := hex.EncodeToString(signature[:])
	fmt.Printf("==================signED,get the sig = %v, signature = %v ===================\n", sig, signature)
	res := RPCSmpcRes{Ret: sig, Tip: "", Err: nil}
	ch <- res
	return ""
}

//--------------------------------------------------------------------------------------------------------------------------

/*func DECDSASignRoundSeven(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, w *RPCReqWorker, ch chan interface{}) (*ec2.Commitment, []string, *big.Int, *big.Int) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitBigVAB1, rho1, l1 := signing.DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1)

	mp := []string{msgprex, curEnode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigVAB"
	s1 := string(commitBigVAB1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigVAB finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(cht, w.bcommitbigvab)
	common.Debug("===================finish get CommitBigVAB, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigVAB",reqdataTrytimes,reqdataTimeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigVAB timeout.")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitbigvabs := make([]string, w.ThresHold)
	if w.msgcommitbigvab.Len() != w.ThresHold {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigVAB fail.")}
		ch <- res
		return nil, nil, nil, nil
	}

	itmp := 0
	iter := w.msgcommitbigvab.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigvabs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitBigVAB1, commitbigvabs, rho1, l1
}

func DECDSASignRoundEight(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, l1 *big.Int, rho1 *big.Int, w *RPCReqWorker, ch chan interface{}, commitBigVAB1 *ec2.Commitment) (*ec2.ZkABProof, []string) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil || l1 == nil || rho1 == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// *** Round 5B
	u1zkABProof := signing.DECDSA_Sign_ZkABProve(rho1, l1, us1, []*big.Int{r, deltaGammaGy})

	mp := []string{msgprex, curEnode}
	enode := strings.Join(mp, "-")
	s0 := "ZKABPROOF"
	dlen := len(commitBigVAB1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigVAB1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Alpha)
	s22 := strconv.Itoa(dlen)
	ss += (s22 + common.Sep)
	for _, alp := range u1zkABProof.Alpha {
		ss += string(alp.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Beta)
	s3 := strconv.Itoa(dlen)
	ss += (s3 + common.Sep)
	for _, bet := range u1zkABProof.Beta {
		ss += string(bet.Bytes())
		ss += common.Sep
	}

	//ss = prex-enode:ZKABPROOF:dlen:d1:d2:...:dl:alplen:a1:a2:....aalp:betlen:b1:b2:...bbet:t:u:NULL
	ss += (string(u1zkABProof.T.Bytes()) + common.Sep + string(u1zkABProof.U.Bytes()) + common.Sep)
	ss = ss + "NULL"
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send ZKABPROOF finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(cht, w.bzkabproof)
	common.Debug("===================finish get ZKABPROOF, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKABPROOF",reqdataTrytimes,reqdataTimeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all ZKABPROOF timeout.")}
		ch <- res
		return nil, nil
	}

	zkabproofs := make([]string, w.ThresHold)
	if w.msgzkabproof.Len() != w.ThresHold {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get all ZKABPROOF fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msgzkabproof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		zkabproofs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return u1zkABProof, zkabproofs
}

func DECDSASignVerifyBigVAB(cointype string, w *RPCReqWorker, commitbigvabs []string, zkabproofs []string, commitBigVAB1 *ec2.Commitment, u1zkABProof *ec2.ZkABProof, idSign sortableIDSSlice, r *big.Int, deltaGammaGy *big.Int, ch chan interface{}) (map[string]*ec2.Commitment, *big.Int, *big.Int) {
	if len(commitbigvabs) == 0 || len(zkabproofs) == 0 || commitBigVAB1 == nil || u1zkABProof == nil || cointype == "" || w == nil || len(idSign) == 0 || r == nil || deltaGammaGy == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil, nil, nil
	}

	var commitbigcom = make(map[string]*ec2.Commitment)
	for _, v := range commitbigvabs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgcommitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range zkabproofs {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgzkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgzkabproof fail.")}
						ch <- res
						return nil, nil, nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigcom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigcom[curEnode] = commitBigVAB1

	var zkabproofmap = make(map[string]*ec2.ZkABProof)
	zkabproofmap[curEnode] = u1zkABProof

	for _, vv := range zkabproofs {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")

		//alpha
		dlen, _ := strconv.Atoi(mmm[2])
		alplen, _ := strconv.Atoi(mmm[3+dlen])
		var alp = make([]*big.Int, 0)
		l := 0
		for j := 0; j < alplen; j++ {
			l++
			if len(mmm) < (4 + dlen + l) {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgzkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			alp = append(alp, new(big.Int).SetBytes([]byte(mmm[3+dlen+l])))
		}

		//beta
		betlen, _ := strconv.Atoi(mmm[3+dlen+1+alplen])
		var bet = make([]*big.Int, 0)
		l = 0
		for j := 0; j < betlen; j++ {
			l++
			if len(mmm) < (5 + dlen + alplen + l) {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgzkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			bet = append(bet, new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+l])))
		}

		t := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen]))
		u := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen+1]))

		zkABProof := &ec2.ZkABProof{Alpha: alp, Beta: bet, T: t, U: u}
		zkabproofmap[prexs2[len(prexs2)-1]] = zkABProof
	}

	var BigVx, BigVy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigcom[en[0]]) {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if !signing.DECDSA_Sign_ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify zkabproof fail.")}
			ch <- res
			return nil, nil, nil
		}

		if k == 0 {
			BigVx = BigVAB1[0]
			BigVy = BigVAB1[1]
			continue
		}

		BigVx, BigVy = secp256k1.S256().Add(BigVx, BigVy, BigVAB1[0], BigVAB1[1])
	}

	return commitbigcom, BigVx, BigVy
}

func DECDSASignRoundNine(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, mMtA *big.Int, r *big.Int, pkx *big.Int, pky *big.Int, BigVx *big.Int, BigVy *big.Int, rho1 *big.Int, commitbigcom map[string]*ec2.Commitment, l1 *big.Int, ch chan interface{}) ([]string, *ec2.Commitment) {
	//if len(idSign) == 0 || len(commitbigcom) == 0 || msgprex == "" || w == nil || cointype == "" || mMtA == nil || r == nil || pkx == nil || pky == nil || l1 == nil || rho1 == nil {
	//	res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
	//	ch <- res
	//	return nil, nil
	//}

	bigU1x, bigU1y := signing.DECDSA_Sign_Round_Nine(mMtA, r, pkx, pky, BigVx, BigVy, rho1)

	// bigA23 = bigA2 + bigA3
	var bigT1x, bigT1y *big.Int
	var ind int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, curEnode) {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x = BigVAB1[2]
		bigT1y = BigVAB1[3]
		ind = k
		break
	}

	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, curEnode) {
			continue
		}

		if k == ind {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x, bigT1y = secp256k1.S256().Add(bigT1x, bigT1y, BigVAB1[2], BigVAB1[3])
	}

	commitBigUT1 := signing.DECDSA_Sign_Round_Nine_Commitment(bigT1x, bigT1y, l1, bigU1x, bigU1y)

	// Broadcast commitBigUT1.C
	mp := []string{msgprex, curEnode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUT"
	s1 := string(commitBigUT1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUT finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(cht, w.bcommitbigut)
	common.Debug("===================finish get CommitBigUT, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUT",reqdataTrytimes,reqdataTimeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUT timeout.")}
		ch <- res
		return nil, nil
	}

	commitbiguts := make([]string, w.ThresHold)
	if w.msgcommitbigut.Len() != w.ThresHold {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigUT fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msgcommitbigut.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbiguts[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbiguts, commitBigUT1
}

func DECDSASignRoundTen(msgprex string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, ch chan interface{}) []string {
	if msgprex == "" || commitBigUT1 == nil || w == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// *** Round 5D
	// Broadcast
	// commitBigUT1.D,  commitBigUT2.D,  commitBigUT3.D
	mp := []string{msgprex, curEnode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUTD11"
	dlen := len(commitBigUT1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigUT1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss = ss + "NULL"
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUTD11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(cht, w.bcommitbigutd11)
	common.Debug("===================finish get CommitBigUTD11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUTD11",reqdataTrytimes,reqdataTimeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	commitbigutd11s := make([]string, w.ThresHold)
	if w.msgcommitbigutd11.Len() != w.ThresHold {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msgcommitbigutd11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigutd11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbigutd11s
}

func DECDSASignVerifyBigUTCommitment(msgprex string,cointype string, commitbiguts []string, commitbigutd11s []string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, commitbigcom map[string]*ec2.Commitment) bool {
	if msgprex == "" || cointype == "" || len(commitbiguts) == 0 || len(commitbigutd11s) == 0 || commitBigUT1 == nil || w == nil || len(idSign) == 0 || commitbigcom == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return false
	}

	var commitbigutmap = make(map[string]*ec2.Commitment)
	for _, v := range commitbiguts {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgcommitbigut fail.")}
			ch <- res
			return false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range commitbigutd11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgcommitbigutd11 fail.")}
				ch <- res
				return false
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get msgcommitbigutd11 fail.")}
						ch <- res
						return false
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigutmap[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigutmap[curEnode] = commitBigUT1

	var bigTBx, bigTBy *big.Int
	var bigUx, bigUy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigutmap[en[0]]) {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify commit big ut fail.")}
			ch <- res
			return false
		}

		_, BigUT1 := signing.DECDSA_Key_DeCommit(commitbigutmap[en[0]])
		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if k == 0 {
			bigTBx = BigUT1[2]
			bigTBy = BigUT1[3]
			bigUx = BigUT1[0]
			bigUy = BigUT1[1]
			bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
			continue
		}

		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigUT1[2], BigUT1[3])
		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
		bigUx, bigUy = secp256k1.S256().Add(bigUx, bigUy, BigUT1[0], BigUT1[1])
	}

	if bigTBx.Cmp(bigUx) != 0 || bigTBy.Cmp(bigUy) != 0 {
		common.Debug("==============verify bigTB = BigU fails.=================","key",msgprex)
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("verify bigTB = BigU fails.")}
		ch <- res
		return false
	}

	return true
}

func DECDSASignRoundEleven(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, us1 *big.Int) map[string]*big.Int {
	if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 4. Broadcast
	// s: s1, s2, s3
	mp := []string{msgprex, curEnode}
	enode := strings.Join(mp, "-")
	s0 := "SS1"
	s1 := string(us1.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// s: s1, s2, s3
	common.Info("===================send SS1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(WaitMsgTimeGG20, w.bss1)
	common.Info("===================finish get SS1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdataTrytimes,reqdataTimeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout.")}
		ch <- res
		return nil
	}

	var ss1s = make(map[string]*big.Int)
	ss1s[curEnode] = us1

	uss1s := make([]string, w.ThresHold)
	if w.msgss1.Len() != w.ThresHold {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msgss1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		uss1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, curEnode) {
			continue
		}

		for _, v := range uss1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmp := new(big.Int).SetBytes([]byte(mm[2]))
				ss1s[en[0]] = tmp
				break
			}
		}
	}

	return ss1s
}
*/
