/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  haijun.cai@anyswap.exchange
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
	"fmt"
	"math/big"
	"strings"
	"time"
	"encoding/json"

	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"strconv"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/fsn-dev/cryptoCoins/coins"
	"container/list"
)

type ReqSmpcReshare struct {
}

//---------------------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) GetReplyFromGroup(wid int,gid string,initiator string) []NodeReply {
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
	    if strings.EqualFold(initiator,node2) {
		in = "1"
	    }

	    iter := w.msg_acceptreshareres.Front()
	    for iter != nil {
		mdss := iter.Value.(string)
		_,from,_,txdata,err := CheckRaw(mdss)
		if err != nil {
		    iter = iter.Next()
		    continue
		}

		rh,ok := txdata.(*TxDataReShare)
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

		acceptrh,ok := txdata.(*TxDataAcceptReShare)
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
	    
	    nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
	    ars = append(ars,nr)
    }

    return ars
}

//---------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) GetReqAddrKeyByKey(key string) string {
    return ""
}

//-----------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) GetRawReply(ret *common.SafeMap,reply *RawReply) {
    if reply == nil {
	return
    }

    tmp,ok := ret.ReadMap(reply.From)
    if !ok {
	ret.WriteMap(reply.From,reply)
    } else {
	tmp2,ok := tmp.(*RawReply)
	if ok {
	    t1,_ := new(big.Int).SetString(reply.TimeStamp,10)
	    t2,_ := new(big.Int).SetString(tmp2.TimeStamp,10)
	    if t1.Cmp(t2) > 0 {
		ret.WriteMap(reply.From,reply)
	    }
	}

    }
}

//--------------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) CheckReply(ac *AcceptReqAddrData,l *list.List,key string) bool {
    if l == nil || key == "" {
	return false
    }

    exsit,da := GetReShareInfoData([]byte(key))
    if !exsit {
	return false
    }

    ac2,ok := da.(*AcceptReShareData)
    if !ok || ac2 == nil {
	return false
    }

    ret := GetRawReply(l)
    _, enodes := GetGroup(ac2.GroupId)
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
	_,value := ret.ListMap()
	for _,v := range value {
	    if v != nil && strings.EqualFold((v.(*RawReply)).From,fr) {
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

func (req *ReqSmpcReshare) DoReq(raw string,workid int,sender string,ch chan interface{}) bool {
    if raw == "" || workid < 0 || sender == "" {
	res := RpcSmpcRes{Ret: "", Tip: "do req fail.", Err: fmt.Errorf("do req fail")}
	ch <- res
	return false 
    }

    key,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Error("===============DoReq,check raw data error===================","raw",raw,"err ",err)
	res := RpcSmpcRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return false
    }
    
    rh,ok := txdata.(*TxDataReShare)
    if ok {
	ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
	sigs,err := GetGroupSigsDataByRaw(raw) 
	common.Debug("=================DoReq,reshare=================","get group sigs ",sigs,"err ",err,"key ",key)
	if err != nil {
	    res := RpcSmpcRes{Ret: "", Tip: err.Error(), Err: err}
	    ch <- res
	    return false
	}

	ac := &AcceptReShareData{Initiator:sender,Account: from, GroupId: rh.GroupId, TSGroupId:rh.TSGroupId, PubKey: rh.PubKey, LimitNum: rh.ThresHold, PubAccount:rh.Account, Mode:rh.Mode, Sigs:sigs, TimeStamp: rh.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", NewSk: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
	err = SaveAcceptReShareData(ac)
	common.Info("===================DoReq,finish call SaveAcceptReShareData======================","err ",err,"workid ",workid,"account ",from,"group id ",rh.GroupId,"pubkey ",rh.PubKey,"threshold ",rh.ThresHold,"key ",key)
	if err == nil {
	    w := workers[workid]
	    w.sid = key 
	    w.groupid = rh.TSGroupId 
	    w.limitnum = rh.ThresHold
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
		if w.ThresHold == 0 {
		    th,_ := strconv.Atoi(nums[0])
		    w.ThresHold = th
		}
	    }

	    w.SmpcFrom = rh.PubKey  // pubkey replace smpcfrom in reshare 

	    var reply bool
	    var tip string
	    timeout := make(chan bool, 1)
	    go func(wid int) {
		    cur_enode = discover.GetLocalID().String() //GetSelfEnode()
		    agreeWaitTime := 10 * time.Minute
		    agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

		    wtmp2 := workers[wid]

		    for {
			    select {
			    case account := <-wtmp2.acceptReShareChan:
				    common.Debug("(self *RecvMsg) Run(),", "account= ", account, "key = ", key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    common.Info("================== DoReq, get all AcceptReShareRes================","raw ",raw,"result ",ars,"key ",key)
				    
				    reply = true
				    for _,nr := range ars {
					if !strings.EqualFold(nr.Status,"Agree") {
					    reply = false
					    break
					}
				    }

				    if !reply {
					    tip = "don't accept reshare"
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Failure", "", "don't accept reshare", "don't accept reshare", nil, wid)
				    } else {
					    tip = ""
					    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "pending", "", "", "", ars, wid)
				    }

				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

				    timeout <- true
				    return
			    case <-agreeWaitTimeOut.C:
				    common.Info("================== DoReq, agree wait timeout===================","raw ",raw,"key ",key)
				    ars := GetAllReplyFromGroup(w.id,rh.GroupId,Rpc_RESHARE,sender)
				    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "false", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars, wid)
				    reply = false
				    tip = "get other node accept reshare result timeout"
				    if err != nil {
					tip = tip + " and accept reshare data fail"
				    }

				    timeout <- true
				    return
			    }
		    }
	    }(workid)

	    if len(workers[workid].acceptWaitReShareChan) == 0 {
		    workers[workid].acceptWaitReShareChan <- "go on"
	    }

	    DisAcceptMsg(raw,workid)
	    HandleC1Data(nil,key)
	    
	    <-timeout

	    if !reply {
		    if tip == "get other node accept reshare result timeout" {
			    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
			    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold, rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
		    } 

		    res2 := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept reshare.")}
		    ch <- res2
		    return false
	    }

	    rch := make(chan interface{}, 1)
	    _reshare(w.sid,from,rh.GroupId,rh.PubKey,rh.Account,rh.Mode,sigs,rch)
	    chret, tip, cherr := GetChannelValue(ch_t, rch)
	    if chret != "" {
		    res2 := RpcSmpcRes{Ret: chret, Tip: "", Err: nil}
		    ch <- res2
		    return true
	    }

	    if tip == "get other node accept reshare result timeout" {
		    ars := GetAllReplyFromGroup(workid,rh.GroupId,Rpc_RESHARE,sender)
		    _,err = AcceptReShare(sender,from, rh.GroupId, rh.TSGroupId,rh.PubKey, rh.ThresHold,rh.Mode,"false", "", "Timeout", "", "get other node accept reshare result timeout", "get other node accept reshare result timeout", ars,workid)
	    } 

	    if cherr != nil {
		    res2 := RpcSmpcRes{Ret:"", Tip: tip, Err: cherr}
		    ch <- res2
		    return false
	    }

	    res2 := RpcSmpcRes{Ret:"", Tip: tip, Err: fmt.Errorf("reshare fail.")}
	    ch <- res2
	    return false
	}
    }
   
    acceptrh,ok := txdata.(*TxDataAcceptReShare)
    if ok {
	w, err := FindWorker(acceptrh.Key)
	if err != nil || w == nil {
	    c1data := strings.ToLower(acceptrh.Key + "-" + from)
	    C1Data.WriteMap(c1data,raw)
	    res := RpcSmpcRes{Ret:"Failure", Tip: "get reshare accept data fail from db when no find worker.", Err: fmt.Errorf("get reshare accept data fail from db when no find worker")}
	    ch <- res
	    return false
	}

	exsit,da := GetReShareInfoData([]byte(acceptrh.Key))
	if !exsit {
	    res := RpcSmpcRes{Ret:"Failure", Tip: "smpc back-end internal error:get reshare accept data fail from db in init accept data", Err: fmt.Errorf("get reshare accept data fail from db in init accept data")}
	    ch <- res
	    return false
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    res := RpcSmpcRes{Ret:"Failure", Tip: "smpc back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
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

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	HandleC1Data(nil,acceptrh.Key)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_RESHARE,ac.Initiator)
	tip,err := AcceptReShare(ac.Initiator,ac.Account, ac.GroupId, ac.TSGroupId,ac.PubKey, ac.LimitNum, ac.Mode,"false", accept, status, "", "", "", ars,ac.WorkId)
	if err != nil {
	    res := RpcSmpcRes{Ret:"Failure", Tip: tip, Err: err}
	    ch <- res
	    return false
	}

	res := RpcSmpcRes{Ret:"Success", Tip: "", Err: nil}
	ch <- res
	return true
    }
	    
    return false
}

//---------------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) GetGroupSigs(txdata []byte) (string,string,string,string) {
    if txdata == nil {
	return "","","",""
    }
    
    rh := TxDataReShare{}
    err := json.Unmarshal(txdata, &rh)
    if err == nil && rh.TxType == "RESHARE" {
	return rh.ThresHold,rh.Mode,rh.Sigs,rh.GroupId
    }
    
    return "","","",""
}

//-------------------------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) CheckTxData(txdata []byte,from string,nonce uint64) (string,string,string,interface{},error) {
    if txdata == nil {
	return "","","",nil,fmt.Errorf("tx data is nil")
    }
    
    rh := TxDataReShare{}
    err := json.Unmarshal(txdata, &rh)
    if err == nil && rh.TxType == "RESHARE" {
	if !IsValidReShareAccept(from,rh.GroupId) {
	    return "","","",nil,fmt.Errorf("check current enode account fail from raw data")
	}

	if from == "" || rh.PubKey == "" || rh.TSGroupId == "" || rh.ThresHold == "" || rh.Account == "" || rh.Mode == "" || rh.TimeStamp == "" {
	    return "","","",nil,fmt.Errorf("param error.")
	}

	////
	nums := strings.Split(rh.ThresHold, "/")
	if len(nums) != 2 {
	    return "","","",nil,fmt.Errorf("transacion data format error,threshold is not right")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
	    return "","","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
	    return "","","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(rh.GroupId)
	if nc < limit || nc > nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}
	
	key := Keccak256Hash([]byte(strings.ToLower(from + ":" + rh.GroupId + ":" + rh.TSGroupId + ":" + rh.PubKey + ":" + rh.ThresHold + ":" + rh.Mode))).Hex()
	
	return key,from,fmt.Sprintf("%v", nonce),&rh,nil
    }
    
    acceptrh := TxDataAcceptReShare{}
    err = json.Unmarshal(txdata, &acceptrh)
    if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	if acceptrh.Accept != "AGREE" && acceptrh.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetReShareInfoData([]byte(acceptrh.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	return acceptrh.Key,from,"",&acceptrh,nil
    }
    
    return "","","",nil,fmt.Errorf("check tx data fail")
}
   
//---------------------------------------------------------------------------------------------

func (req *ReqSmpcReshare) DisAcceptMsg(raw string,workid int,key string) {
    if raw == "" || workid < 0 || workid >= len(workers) || key == "" {
	return
    }

    w := workers[workid]
    if w == nil {
	return
    }
    
    if Find(w.msg_acceptreshareres, raw) {
	common.Debug("======================ReqSmpcReshare.DisAcceptMsg,receive one msg and already in list.===========================","raw",raw,"key",key)
	return
    }

    w.msg_acceptreshareres.PushBack(raw)
    if w.msg_acceptreshareres.Len() >= w.NodeCnt {
	if !CheckReply(w.msg_acceptreshareres,Rpc_RESHARE,key) {
	    common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg, but Not all accept data has been received ===================","raw",raw,"key",key)
	    return
	}

	common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg,all accept data has been received===================","raw",raw,"key",key)
	w.bacceptreshareres <- true
	exsit,da := GetReShareInfoData([]byte(key))
	if !exsit {
	    return
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return
	}

	common.Debug("=====================ReqSmpcReshare.DisAcceptMsg,receive one msg,all accept data has been received,set acceptReShareChan ===================","raw",raw,"key",key)
	workers[ac.WorkId].acceptReShareChan <- "go on"
    }
}



