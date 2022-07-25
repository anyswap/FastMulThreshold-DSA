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
	"container/list"
	"encoding/json"
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// ReqSmpcAddr keygen cmd request
type ReqSmpcAddr struct {
}

//-------------------------------------------------------------------------------------------------

// GetReplyFromGroup  Get the current reply status of the nodes in the group. About this command request 
func (req *ReqSmpcAddr) GetReplyFromGroup(wid int, gid string, initiator string) []NodeReply {
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

		iter := w.msgacceptreqaddrres.Front()
		if iter != nil {
			mdss := iter.Value.(string)
			key, _, _, _, _ := CheckRaw(mdss)
			exsit, da := GetReqAddrInfoData([]byte(key))
			if !exsit || da == nil {
				exsit, da = GetPubKeyData([]byte(key))
			}

			if exsit {
				ac, ok := da.(*AcceptReqAddrData)
				if ok && ac != nil {
					ret := GetRawReply(w.msgacceptreqaddrres)
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

//-----------------------------------------------------------------------------------------

// GetReqAddrKeyByKey No need for reqaddr
func (req *ReqSmpcAddr) GetReqAddrKeyByKey(key string) string {
	return ""
}

//-----------------------------------------------------------------------------------------

// GetRawReply put the reply to map, select the reply sent at the latest time 
// reply.From ---> reply
func (req *ReqSmpcAddr) GetRawReply(ret *common.SafeMap, reply *RawReply) {
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

//------------------------------------------------------------------------------------------------------

// CheckReply  Detect whether all nodes in the group have sent accept data 
func (req *ReqSmpcAddr) CheckReply(ac *AcceptReqAddrData, l *list.List, key string) bool {
	if l == nil || key == "" || ac == nil {
		return false
	}

	ret := GetRawReply(l)
	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(ac.Sigs, common.Sep)
	count := (len(mms) - 1) / 2
	if count <= 0 {
		common.Debug("===================== CheckReply,reqaddr================", "ac.Sigs", ac.Sigs, "count", count, "key", key, "ret", ret)
		return false
	}

	for j := 0; j < count; j++ {
		found := false
		_, value := ret.ListMap()
		for _, v := range value {
			if v != nil && strings.EqualFold((v.(*RawReply)).From, mms[2*j+2]) { //allow user login diffrent node
				found = true
				break
			}
		}

		if !found {
			common.Debug("===================== CheckReply,reqaddr, return false.====================", "ac.Sigs", ac.Sigs, "count", count, "key", key)
			return false
		}
	}

	return true
}

//-----------------------------------------------------------------------------------------------

// DoReq   1.Parse the generated pubkey command and implement the process 2.analyze the accept data   
func (req *ReqSmpcAddr) DoReq(raw string, workid int, sender string, ch chan interface{}) bool {
	if raw == "" || workid < 0 || sender == "" {
		res := RPCSmpcRes{Ret: "", Tip: "do req fail.", Err: fmt.Errorf("do req fail")}
		ch <- res
		return false
	}

	key, from, nonce, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("===============DoReq,check raw error===================", "err ", err)
		res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return false
	}

	req2, ok := txdata.(*TxDataReqAddr)
	if ok {
		exsit, _ := GetReqAddrInfoData([]byte(key))
		if exsit {
		    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("the pubkey requestion has already exsit")}
		    ch <- res
		    return false
		}
		
		/*curnonce, _, _ := GetReqAddrNonce(from)
		curnoncenum, _ := new(big.Int).SetString(curnonce, 10)
		newnoncenum, _ := new(big.Int).SetString(nonce, 10)
		if newnoncenum.Cmp(curnoncenum) < 0 {
		    res := RPCSmpcRes{Ret: "", Tip:"", Err: fmt.Errorf("nonce error")}
		    ch <- res
		    return false
		}*/

		_, err := SetReqAddrNonce(from, nonce)
		if err != nil {
		    res := RPCSmpcRes{Ret: "", Tip:"", Err: err}
		    ch <- res
		    return false
		}

		ars := GetAllReplyFromGroup(workid, req2.GroupID, RPCREQADDR, sender)
		sigs, err := GetGroupSigsDataByRaw(raw)
		if err != nil {
			common.Debug("=================DoReq================", "get group sigs ", sigs, "err ", err, "key ", key)
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}

		ac := &AcceptReqAddrData{Initiator: sender, Account: from, Cointype: req2.Keytype, GroupID: req2.GroupID, Nonce: nonce, LimitNum: req2.ThresHold, Mode: req2.Mode, TimeStamp: req2.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", PubKey: "", Tip: "", Error: "", AllReply: ars, WorkID: workid, Sigs: sigs}
		err = SaveAcceptReqAddrData(ac)
		common.Info("===================DoReq,call SaveAcceptReqAddrData finish====================", "account ", from, "err ", err, "key ", key)
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}

		rch := make(chan interface{}, 1)
		w := workers[workid]
		w.sid = key
		w.groupid = req2.GroupID
		w.limitnum = req2.ThresHold
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

		th, err := strconv.Atoi(nums[0])
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
			ch <- res
			return false
		}
		w.ThresHold = th

		if req2.Mode == "0" { // self-group
			////
			var reply bool
			var tip string
			timeout := make(chan bool, 1)
			go func(wid int) {
				curEnode = discover.GetLocalID().String() //GetSelfEnode()
				ato,err := strconv.Atoi(req2.AcceptTimeOut)
				if err != nil || req2.AcceptTimeOut == "" {
					ato = 600 
				}

				agreeWaitTime := time.Duration(ato) * time.Second
				agreeWaitTimeOut := time.NewTicker(agreeWaitTime)
				if wid < 0 || wid >= len(workers) || workers[wid] == nil {
					ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
					_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "false", "Failure", "", "workid error", "workid error", ars, wid, "")
					if err != nil {
						tip = "accept reqaddr error"
						reply = false
						timeout <- true
						return
					}

					tip = "worker id error"
					reply = false
					timeout <- true
					return
				}

				wtmp2 := workers[wid]
				for {
					select {
					case account := <-wtmp2.acceptReqAddrChan:
						common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
						//ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
						ars := GetAllReplyFromGroup2(w.id,sender)
						common.Info("==================get all keygen approve results====================", "raw ", raw, "result ", ars, "key ", key)

						//bug
						reply = true
						for _, nr := range ars {
							if !strings.EqualFold(nr.Status, "Agree") {
								reply = false
								break
							}
						}
						//

						if !reply {
							tip = "don't accept req addr"
							_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "false", "Failure", "", "don't accept req addr", "don't accept req addr", ars, wid, "")
							if err != nil {
								tip = "don't accept req addr and accept reqaddr error"
								timeout <- true
								return
							}
						} else {
							tip = ""
							_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "true", "Pending", "", "", "", ars, wid, "")
							if err != nil {
								tip = "accept reqaddr error"
								timeout <- true
								return
							}
						}

						///////
						timeout <- true
						return
					case <-agreeWaitTimeOut.C:
						common.Info("================== DoReq, agree wait timeout==================", "raw ", raw, "key ", key)
						ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
						//bug: if self not accept and timeout
						_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "false", "Timeout", "", "get other node accept req addr result timeout", "get other node accept req addr result timeout", ars, wid, "")
						if err != nil {
							tip = "get other node accept req addr result timeout and accept reqaddr fail"
							reply = false
							timeout <- true
							return
						}

						tip = "get other node accept req addr result timeout"
						reply = false
						//

						timeout <- true
						return
					}
				}
			}(workid)

			if len(workers[workid].acceptWaitReqAddrChan) == 0 {
				workers[workid].acceptWaitReqAddrChan <- "go on"
			}

			DisAcceptMsg(raw, workid)
			HandleC1Data(ac, key)

			<-timeout

			common.Debug("================== DoReq ======================", "raw ", raw, "the terminal accept req addr result ", reply, "key ", key)

			ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
			if !reply {
				if tip == "get other node accept req addr result timeout" {
					_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "", "Timeout", "", tip, "don't accept req addr", ars, workid, "")
				} else {
					_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "", "Failure", "", tip, "don't accept req addr", ars, workid, "")
				}

				if err != nil {
					res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept req addr")}
					ch <- res
					return false
				}

				res := RPCSmpcRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_smpcaddr", Tip: tip, Err: fmt.Errorf("don't accept req addr")}
				ch <- res
				return false
			}
		} else {
			if len(workers[workid].acceptWaitReqAddrChan) == 0 {
				workers[workid].acceptWaitReqAddrChan <- "go on"
			}

			ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
			_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "true", "Pending", "", "", "", ars, workid, "")
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
				ch <- res
				return false
			}
		}

		smpcGenPubKey(w.sid, from, req2.Keytype, rch, req2.Mode, nonce)
		chret, tip, cherr := GetChannelValue(waitall, rch)
		if cherr != nil {
			ars := GetAllReplyFromGroup(w.id, req2.GroupID, RPCREQADDR, sender)
			_, err = AcceptReqAddr(sender, from, req2.Keytype, req2.GroupID, nonce, req2.ThresHold, req2.Mode, "false", "", "Failure", "", tip, cherr.Error(), ars, workid, "")
			status,_,err3 := GetReqAddrStatus(w.sid)
			common.Error("=====================DoReq,AcceptReqAddr finish======================","key",w.sid,"status",status,"accepte reqaddr err",err,"status err",err3)
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: err.Error(), Err: err}
				ch <- res
				return false
			}

			res := RPCSmpcRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_smpcaddr", Tip: tip, Err: cherr}
			ch <- res
			return false
		}

		res := RPCSmpcRes{Ret: strconv.Itoa(workid) + common.Sep + "rpc_req_smpcaddr" + common.Sep + chret, Tip: "", Err: nil}
		ch <- res
		return true
	}

	acceptreq, ok := txdata.(*TxDataAcceptReqAddr)
	if ok {
		common.Debug("===============DoReq, check accept reqaddr raw success======================", "raw ", raw, "key ", acceptreq.Key, "from ", from, "txdata ", acceptreq)

		w, err := FindWorker(acceptreq.Key)
		if err != nil || w == nil {
			c1data := strings.ToLower(acceptreq.Key + "-" + from)
			C1Data.WriteMap(c1data, raw) // save the lastest accept msg??
			res := RPCSmpcRes{Ret: "Failure", Tip: "get reqaddr accept data fail from db", Err: fmt.Errorf("get reqaddr accept data fail from db when no find worker")}
			ch <- res
			return false
		}

		/////fix bug: miss accept msg for 7-11 test
		if !strings.EqualFold(sender, curEnode) && Find(w.msgacceptreqaddrres, raw) {
			res := RPCSmpcRes{Ret: "Success", Tip: "dul accept msg,but return success", Err: nil}
			ch <- res
			return true
		}
		////

		exsit, da := GetReqAddrInfoData([]byte(acceptreq.Key))
		if !exsit {
			res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:get reqaddr accept data fail from db", Err: fmt.Errorf("get reqaddr accept data fail from db in init accept data")}
			ch <- res
			return false
		}

		ac, ok := da.(*AcceptReqAddrData)
		if !ok || ac == nil {
			res := RPCSmpcRes{Ret: "Failure", Tip: "smpc back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
			ch <- res
			return false
		}

		status := "Pending"
		accept := "false"
		if acceptreq.Accept == "AGREE" {
			accept = "true"
		} else {
			status = "Failure"
		}

		id, _ := GetWorkerID(w)
		DisAcceptMsg(raw, id)
		HandleC1Data(ac, acceptreq.Key)

		ars := GetAllReplyFromGroup(id, ac.GroupID, RPCREQADDR, ac.Initiator)
		tip, err := AcceptReqAddr(ac.Initiator, ac.Account, ac.Cointype, ac.GroupID, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", ars, ac.WorkID, "")
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

//-------------------------------------------------------------------------------------------

// GetGroupSigs get account sigs data from all node in group
// account sigs data:  Signatures generated by respective accounts,the signature object is the pubkey of eNode,that is,enodeID.
// account sigs data: sig1 | sig2 | ... | sigN   (N is the count of nodes in group.)
func (req *ReqSmpcAddr) GetGroupSigs(txdata []byte) (string, string, string, string) {
	if txdata == nil {
		return "", "", "", ""
	}

	req2 := TxDataReqAddr{}
	err := json.Unmarshal(txdata, &req2)
	if err == nil && req2.TxType == "REQSMPCADDR" {
		return req2.ThresHold, req2.Mode, req2.Sigs, req2.GroupID
	}

	return "", "", "", ""
}

//--------------------------------------------------------------------------------------------

// CheckTxData check generating pubkey command data and accept data
func (req *ReqSmpcAddr) CheckTxData(txdata []byte, from string, nonce uint64) (string, string, string, interface{}, error) {
	if txdata == nil {
		return "", "", "", nil, fmt.Errorf("tx data is nil")
	}

	req2 := TxDataReqAddr{}
	err := json.Unmarshal(txdata, &req2)
	if err == nil && req2.TxType == "REQSMPCADDR" {
		keytype := req2.Keytype 
		if keytype != "EC256K1" && keytype != "ED25519" {
			return "","","",nil,fmt.Errorf("invalid keytype")
		}
		
		groupid := req2.GroupID
		if groupid == "" {
			return "", "", "", nil, fmt.Errorf("get group id fail")
		}

		threshold := req2.ThresHold
		if threshold == "" {
			return "", "", "", nil, fmt.Errorf("get threshold fail")
		}

		mode := req2.Mode
		if mode == "" {
			return "", "", "", nil, fmt.Errorf("get mode fail")
		}

		ato,err := strconv.Atoi(req2.AcceptTimeOut)
		if err != nil || req2.AcceptTimeOut == "" {
			ato = 600
		}
		if ato <= 0 {
			return "", "", "", nil, fmt.Errorf("illegal agreed timeout")
		}

		if ato > MaxAcceptTime {
			return "", "", "", nil, fmt.Errorf("greater than the agreed maximum timeout")
		}

		timestamp := req2.TimeStamp
		if timestamp == "" {
			return "", "", "", nil, fmt.Errorf("get timestamp fail")
		}

		nums := strings.Split(threshold, "/")
		if len(nums) != 2 {
			return "", "", "", nil, fmt.Errorf("tx.data error")
		}

		nodecnt, err := strconv.Atoi(nums[1])
		if err != nil {
			return "", "", "", nil, err
		}

		ts, err := strconv.Atoi(nums[0])
		if err != nil {
			return "", "", "", nil, err
		}

		if nodecnt < ts || ts < 2 {
			return "", "", "", nil, fmt.Errorf("threshold format error")
		}

		nc, _ := GetGroup(groupid)
		if nc != nodecnt {
			return "", "", "", nil, fmt.Errorf("check group node count error")
		}

		if !CheckGroupEnode(groupid) {
			return "", "", "", nil, fmt.Errorf("there is same enodeID in group")
		}

		key := Keccak256Hash([]byte(strings.ToLower(from + ":" + req2.Keytype + ":" + groupid + ":" + fmt.Sprintf("%v", nonce) + ":" + threshold + ":" + mode))).Hex()

		return key, from, fmt.Sprintf("%v", nonce), &req2, nil
	}

	acceptreq := TxDataAcceptReqAddr{}
	err = json.Unmarshal(txdata, &acceptreq)
	if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
		if acceptreq.Accept != "AGREE" && acceptreq.Accept != "DISAGREE" {
			return "", "", "", nil, fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
		}

		exsit, da := GetReqAddrInfoData([]byte(acceptreq.Key))
		if !exsit {
			return "", "", "", nil, fmt.Errorf("get accept data fail from db in checking raw reqaddr accept data")
		}

		ac, ok := da.(*AcceptReqAddrData)
		if !ok || ac == nil {
			return "", "", "", nil, fmt.Errorf("decode accept data fail")
		}

		///////
		if ac.Mode == "1" {
			return "", "", "", nil, fmt.Errorf("mode = 1,do not need to accept")
		}

		if !CheckAcc(curEnode, from, ac.Sigs) {
			return "", "", "", nil, fmt.Errorf("invalid accept account")
		}

		return acceptreq.Key, from, "", &acceptreq, nil
	}

	return "", "", "", nil, fmt.Errorf("check tx data fail")
}

//-------------------------------------------------------------------------------

// GetReqAddrRawValue get from/special tx data type/timestamp from generating pubkey command data 
func GetReqAddrRawValue(raw string) (string, string, string) {
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

	req := TxDataReqAddr{}
	err = json.Unmarshal(tx.Data(), &req)
	if err == nil && req.TxType == "REQSMPCADDR" {
		txtype = "REQSMPCADDR"
		timestamp = req.TimeStamp
	} else {
		acceptreq := TxDataAcceptReqAddr{}
		err = json.Unmarshal(tx.Data(), &acceptreq)
		if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
			txtype = "ACCEPTREQADDR"
			timestamp = acceptreq.TimeStamp
		}
	}

	return from.Hex(), txtype, timestamp
}

// CheckReqAddrDulpRawReply Filter duplicate accept data (command data is also a kind of accept data), 
// Take the latest accept data as the final data 
func CheckReqAddrDulpRawReply(raw string, l *list.List) bool {
	if l == nil || raw == "" {
		return false
	}

	from, txtype, timestamp := GetReqAddrRawValue(raw)

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

		from2, txtype2, timestamp2 := GetReqAddrRawValue(s)
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
func (req *ReqSmpcAddr) DisAcceptMsg(raw string, workid int, key string) {
	if raw == "" || workid < 0 || workid >= len(workers) || key == "" {
		return
	}

	w := workers[workid]
	if w == nil {
		return
	}

	if Find(w.msgacceptreqaddrres, raw) {
		return
	}

	if !CheckReqAddrDulpRawReply(raw, w.msgacceptreqaddrres) {
		return
	}

	exsit, da := GetReqAddrInfoData([]byte(key))
	if !exsit {
	    return
	}

	ac, ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    return
	}

	w.msgacceptreqaddrres.PushBack(raw)
	
	/////fix bug: miss accept msg for 7-11 test
	//SendMsgToSmpcGroup(raw, ac.GroupID)
	/////

	if w.msgacceptreqaddrres.Len() >= w.NodeCnt {
	    if !CheckReply(w.msgacceptreqaddrres, RPCREQADDR, key) {
		    return
	    }

	    //common.Debug("=====================ReqSmpcAddr.DisAcceptMsg,receive one msg,all accept data has been received===================", "raw", raw, "key", key)
	    w.bacceptreqaddrres <- true
	    workers[ac.WorkID].acceptReqAddrChan <- "go on"
	}
}


