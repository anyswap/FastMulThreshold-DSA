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
	"fmt"
	"math/big"
	"strings"
	"time"

	"container/list"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"strconv"
)

// ReqSmpcReshare reshare cmd request
type ReqSmpcReshare struct {
}

//---------------------------------------------------------------------------------------------------

// GetReplyFromGroup  Get the current reply status of the nodes in the group. About this command request 
func (req *ReqSmpcReshare) GetReplyFromGroup(wid int, gid string, initiator string) []NodeReply {
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

		iter := w.msgacceptreshareres.Front()
		for iter != nil {
			mdss := iter.Value.(string)
			_, from, _, txdata, err := CheckRaw(mdss)
			if err != nil {
				iter = iter.Next()
				continue
			}

			rh, ok := txdata.(*TxDataReShare)
			if ok {
				h := coins.NewCryptocoinHandler("FSN")
				if h == nil {
					iter = iter.Next()
					continue
				}

				pk := "04" + node2
				fr, err := h.PublicKeyToAddress(pk)
				if err != nil {
					iter = iter.Next()
					continue
				}

				if strings.EqualFold(from, fr) {
					sta = "Agree"
					ts = rh.TimeStamp
					break
				}
			}

			acceptrh, ok := txdata.(*TxDataAcceptReShare)
			if ok {
				h := coins.NewCryptocoinHandler("FSN")
				if h == nil {
					iter = iter.Next()
					continue
				}

				pk := "04" + node2
				fr, err := h.PublicKeyToAddress(pk)
				if err != nil {
					iter = iter.Next()
					continue
				}

				if strings.EqualFold(from, fr) {
					sta = "Agree"
					ts = acceptrh.TimeStamp
					break
				}
			}

			iter = iter.Next()
		}

		nr := NodeReply{Enode: node2, Approver:node2,Status: sta, TimeStamp: ts, Initiator: in}
		ars = append(ars, nr)
	}

	return ars
}

//---------------------------------------------------------------------------------------

// GetReqAddrKeyByKey No need for reshare
func (req *ReqSmpcReshare) GetReqAddrKeyByKey(key string) string {
	return ""
}

//-----------------------------------------------------------------------------------------

// GetRawReply put the reply to map, select the reply sent at the latest time 
// reply.From ---> reply
func (req *ReqSmpcReshare) GetRawReply(ret *common.SafeMap, reply *RawReply) {
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

//--------------------------------------------------------------------------------------------

// CheckReply  Detect whether all nodes in the group have sent accept data 
func (req *ReqSmpcReshare) CheckReply(ac *AcceptReqAddrData, l *list.List, key string) bool {
	if l == nil || key == "" {
		return false
	}

	exsit, da := GetReShareInfoData([]byte(key))
	if !exsit {
		return false
	}

	ac2, ok := da.(*AcceptReShareData)
	if !ok || ac2 == nil {
		return false
	}

	ret := GetRawReply(l)
	_, enodes := GetGroup(ac2.GroupID)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		pk := "04" + node2
		h := coins.NewCryptocoinHandler("FSN")
		if h == nil {
			continue
		}

		fr, err := h.PublicKeyToAddress(pk)
		if err != nil {
			return false
		}

		found := false
		_, value := ret.ListMap()
		for _, v := range value {
			if v != nil && strings.EqualFold((v.(*RawReply)).From, fr) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

//------------------------------------------------------------------------------------------------

// DoReq   1.Parse the reshare command and implement the process 2.analyze the accept data   
func (req *ReqSmpcReshare) DoReq(raw string, workid int, sender string, ch chan interface{}) bool {
	if raw == "" || workid < 0 || sender == "" {
		res := RPCSmpcRes{Ret: "", Tip: "do req fail.", Err: fmt.Errorf("do req fail")}
		ch <- res
		return false
	}

	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("===============DoReq,check raw data error===================", "raw", raw, "err ", err)
		res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	rh, ok := txdata.(*TxDataReShare)
	if ok {
		if RelayInPeers {
		    go func(msg2 string,gid string) {
			msghash := Keccak256Hash([]byte(strings.ToLower(msg2))).Hex()
			for i:=0;i<1;i++ {
			   common.Debug("================Call,also broacast to group for msg===================","key",key,"gid",gid,"msg hash",msghash)
			    SendMsgToSmpcGroup(msg2,gid)
			    //time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
			}
		    }(raw,rh.GroupID)
		}
		
		ars := GetAllReplyFromGroup(workid, rh.GroupID, RPCRESHARE, sender)
		sigs, err := GetGroupSigsDataByRaw(raw)
		common.Debug("=================DoReq,reshare=================", "get group sigs ", sigs, "err ", err, "key ", key)
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}

		ac := &AcceptReShareData{Initiator: sender, Account: from, GroupID: rh.GroupID, TSGroupID: rh.TSGroupID, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount: rh.Account, Mode: rh.Mode, Sigs: sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkID: workid}
		err = SaveAcceptReShareData(ac)
		common.Info("===================DoReq,finish call SaveAcceptReShareData======================", "err ", err, "workid ", workid, "account ", from, "group id ", rh.GroupID, "pubkey ", rh.PubKey, "threshold ", rh.ThresHold, "key ", key)
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}

		w := workers[workid]
		w.sid = key
		w.groupid = rh.TSGroupID
		w.limitnum = rh.ThresHold
		gcnt, _ := GetGroup(w.groupid)
		w.NodeCnt = gcnt
		w.ThresHold = w.NodeCnt

		nums := strings.Split(w.limitnum, "/")
		if len(nums) != 2 {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("threshold num error")}
			ch <- res
			return false
		}

		nodecnt, err := strconv.Atoi(nums[1])
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}
		w.NodeCnt = nodecnt

		w.ThresHold = gcnt
		if w.ThresHold == 0 {
			th, err := strconv.Atoi(nums[0])
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
				ch <- res
				return false
			}
			w.ThresHold = th
		}

		w.SmpcFrom = rh.PubKey // pubkey replace smpcfrom in reshare

		var reply bool
		var tip string
		var resharetimeout bool

		timeout := make(chan bool, 1)
		go func(wid int) {
			curEnode = discover.GetLocalID().String() //GetSelfEnode()
			ato,err := strconv.Atoi(rh.AcceptTimeOut)
			if err != nil || rh.AcceptTimeOut == "" {
				ato = 600 
			}

			agreeWaitTime := time.Duration(ato) * time.Second
			agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

			wtmp2 := workers[wid]

			for {
				select {
				case account := <-wtmp2.acceptReShareChan:
					common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
					//ars := GetAllReplyFromGroup2(w.id,sender)
					ars := GetAllReplyFromGroup(w.id, rh.GroupID, RPCRESHARE, sender)
					common.Info("================== DoReq, get all AcceptReShareRes================", "raw ", raw, "result ", ars, "key ", key)

					reply = true
					for _, nr := range ars {
						if !strings.EqualFold(nr.Status, "Agree") {
							reply = false
							break
						}
					}

					if !reply {
					    AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "false", "false", "Failure", "", "not all accept reshare", "not all accept reshare", ars, wid)
					} else {
					    AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "false", "false", "pending", "", "", "", ars, wid)
					}

					timeout <- true
					return
				case <-agreeWaitTimeOut.C:
					common.Info("================== DoReq, agree wait timeout===================", "raw ", raw, "key ", key)
					ars := GetAllReplyFromGroup(w.id, rh.GroupID, RPCRESHARE, sender)
					AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "false", "false", "Timeout", "", "approving  timeout", "approving timeout", ars, wid)
					reply = false

					resharetimeout = true
					timeout <- true
					return
				}
			}
		}(workid)

		if len(workers[workid].acceptWaitReShareChan) == 0 {
			workers[workid].acceptWaitReShareChan <- "go on"
		}

		DisAcceptMsg(raw, workid)
		HandleC1Data(nil, key)

		<-timeout

		if !reply {
		    arstmp := GetAllReplyFromGroup(w.id, rh.GroupID, RPCRESHARE, sender)
		    if resharetimeout {
			AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "true", "false", "Timeout", "", "approving  timeout", "approving timeout", arstmp, workid)
		    } else {
			AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "true", "false", "Failure", "", "not all accept reshare", "not all accept reshare", arstmp, workid)
		    }

		    res2 := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("approving fail")}
		    ch <- res2
		    return false
		}

		rch := make(chan interface{}, 1)
		_reshare(w.sid, from, rh.GroupID, rh.PubKey, rh.Account, rh.Mode, sigs, rch,rh.Keytype)
		chret, tip, cherr := GetChannelValue(cht, rch)
		if chret != "" {
			res2 := RPCSmpcRes{Ret: chret, Tip: "", Err: nil}
			ch <- res2
			return true
		}

		if cherr != nil {
			AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "true", "", "Failure", "", "", cherr.Error(), nil, workid)
			res2 := RPCSmpcRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res2
			return false
		}

		AcceptReShare(sender, from, rh.GroupID, rh.TSGroupID, rh.PubKey, rh.ThresHold, rh.Mode, "true", "", "Failure", "", "", cherr.Error(), nil, workid)
		res2 := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("reshare fail")}
		ch <- res2
		return false
	}

	acceptrh, ok := txdata.(*TxDataAcceptReShare)
	if ok {
		w, err := FindWorker(acceptrh.Key)
		if err != nil || w == nil {
			c1data := strings.ToLower(acceptrh.Key + "-" + from)
			C1Data.WriteMap(c1data, raw)
			res := RPCSmpcRes{Ret: "Failure", Tip: "get reshare accept data fail from db when no find worker", Err: fmt.Errorf("get reshare accept data fail from db when no find worker")}
			ch <- res
			return false
		}

		exsit, da := GetReShareInfoData([]byte(acceptrh.Key))
		if !exsit {
			res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:get reshare accept data fail from db in init accept data", Err: fmt.Errorf("get reshare accept data fail from db in init accept data")}
			ch <- res
			return false
		}

		ac, ok := da.(*AcceptReShareData)
		if !ok || ac == nil {
			res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
			ch <- res
			return false
		}

		status := "Pending"
		accept := "false"
		if acceptrh.Accept == "AGREE" {
			accept = "true"
		} else {
			status = "Failure"
		}

		id, _ := GetWorkerID(w)
		DisAcceptMsg(raw, id)
		HandleC1Data(nil, acceptrh.Key)

		ars := GetAllReplyFromGroup(id, ac.GroupID, RPCRESHARE, ac.Initiator)
		tip, err := AcceptReShare(ac.Initiator, ac.Account, ac.GroupID, ac.TSGroupID, ac.PubKey, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkID)
		if err != nil {
			res := RPCSmpcRes{Ret: "Failure", Tip: tip, Err: err}
			ch <- res
			return false
		}

		res := RPCSmpcRes{Ret: "Success", Tip: "", Err: nil}
		ch <- res
		return true
	}

	return false
}

//---------------------------------------------------------------------------------------------

// GetGroupSigs get account sigs data from all node in group
// account sigs data:  Signatures generated by respective accounts,the signature object is the pubkey of eNode,that is,enodeID.
// account sigs data: sig1 | sig2 | ... | sigN   (N is the count of nodes in group.)
func (req *ReqSmpcReshare) GetGroupSigs(txdata []byte) (string, string, string, string) {
	if txdata == nil {
		return "", "", "", ""
	}

	rh := TxDataReShare{}
	err := json.Unmarshal(txdata, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		return rh.ThresHold, rh.Mode, rh.Sigs, rh.GroupID
	}

	return "", "", "", ""
}

//-------------------------------------------------------------------------------------------------------

// CheckTxData check reshare command data and accept data
func (req *ReqSmpcReshare) CheckTxData(txdata []byte, from string, nonce uint64) (string, string, string, interface{}, error) {
	if txdata == nil {
		return "", "", "", nil, fmt.Errorf("tx data is nil")
	}

	rh := TxDataReShare{}
	err := json.Unmarshal(txdata, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		if !IsValidReShareAccept(from, rh.GroupID) {
			return "", "", "", nil, fmt.Errorf("check current enode account fail from raw data")
		}

		if from == "" || rh.PubKey == "" || rh.TSGroupID == "" || rh.ThresHold == "" || rh.Account == "" || rh.Mode == "" || rh.TimeStamp == "" {
			return "", "", "", nil, fmt.Errorf("param error")
		}

		nums := strings.Split(rh.ThresHold, "/")
		if len(nums) != 2 {
			return "", "", "", nil, fmt.Errorf("transacion data format error,threshold is not right")
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

		nc, _ := GetGroup(rh.GroupID)
		if nc < limit || nc > nodecnt {
			return "", "", "", nil, fmt.Errorf("check group node count error")
		}

		ato,err := strconv.Atoi(rh.AcceptTimeOut)
		if err != nil || rh.AcceptTimeOut == "" {
			ato = 600
		}
		if ato <= 0 {
			return "", "", "", nil, fmt.Errorf("illegal agreed timeout")
		}

		if ato > MaxAcceptTime {
			return "", "", "", nil, fmt.Errorf("greater than the agreed maximum timeout")
		}

		key := Keccak256Hash([]byte(strings.ToLower(from + ":" + rh.GroupID + ":" + rh.TSGroupID + ":" + rh.PubKey + ":" + rh.ThresHold + ":" + rh.Mode))).Hex()

		return key, from, fmt.Sprintf("%v", nonce), &rh, nil
	}

	acceptrh := TxDataAcceptReShare{}
	err = json.Unmarshal(txdata, &acceptrh)
	if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
		if acceptrh.Accept != "AGREE" && acceptrh.Accept != "DISAGREE" {
			return "", "", "", nil, fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
		}

		exsit, da := GetReShareInfoData([]byte(acceptrh.Key))
		if !exsit {
			return "", "", "", nil, fmt.Errorf("get accept result from db fail")
		}

		ac, ok := da.(*AcceptReShareData)
		if !ok || ac == nil {
			return "", "", "", nil, fmt.Errorf("get accept result from db fail")
		}

		if ac.Mode == "1" {
			return "", "", "", nil, fmt.Errorf("mode = 1,do not need to accept")
		}

		return acceptrh.Key, from, "", &acceptrh, nil
	}

	return "", "", "", nil, fmt.Errorf("check tx data fail")
}

//---------------------------------------------------------------------------------------------

// GetReshareRawValue get from/special tx data type/timestamp from reshare command data 
func GetReshareRawValue(raw string) (string, string, string) {
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

	rh := TxDataReShare{}
	err = json.Unmarshal(data, &rh)
	if err == nil && rh.TxType == "RESHARE" {
		txtype = "RESHARE"
		timestamp = rh.TimeStamp
		if msgsig {
		    from = rh.Account
		}
	} else {
		acceptrh := TxDataAcceptReShare{}
		err = json.Unmarshal(data, &acceptrh)
		if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
			txtype = "ACCEPTRESHARE"
			timestamp = acceptrh.TimeStamp
			if msgsig {
			    from = acceptrh.Account
			}
		}
	}

	return from, txtype, timestamp
}

// CheckReshareDulpRawReply Filter duplicate accept data (command data is also a kind of accept data), 
// Take the latest accept data as the final data 
func CheckReshareDulpRawReply(raw string, l *list.List) bool {
	if l == nil || raw == "" {
		return false
	}

	from, txtype, timestamp := GetReshareRawValue(raw)

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

		from2, txtype2, timestamp2 := GetReshareRawValue(s)
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
func (req *ReqSmpcReshare) DisAcceptMsg(raw string, workid int, key string) {
	if raw == "" || workid < 0 || workid >= len(workers) || key == "" {
		return
	}

	w := workers[workid]
	if w == nil {
		return
	}

	if Find(w.msgacceptreshareres, raw) {
		common.Debug("======================ReqSmpcReshare.DisAcceptMsg,receive one msg and already in list.===========================", "raw", raw, "key", key)
		return
	}

	if !CheckReshareDulpRawReply(raw, w.msgacceptreshareres) {
		return
	}

	w.msgacceptreshareres.PushBack(raw)
	if w.msgacceptreshareres.Len() >= w.NodeCnt {
		if !CheckReply(w.msgacceptreshareres, RPCRESHARE, key) {
			common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg, but Not all accept data has been received ===================", "raw", raw, "key", key)
			return
		}

		common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg,all accept data has been received===================", "raw", raw, "key", key)
		w.bacceptreshareres <- true
		exsit, da := GetReShareInfoData([]byte(key))
		if !exsit {
			return
		}

		ac, ok := da.(*AcceptReShareData)
		if !ok || ac == nil {
			return
		}

		common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg,all accept data has been received,set acceptReShareChan ===================", "raw", raw, "key", key)
		workers[ac.WorkID].acceptReShareChan <- "go on"
	}
}
