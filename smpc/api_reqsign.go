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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"errors"
	"crypto/hmac"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"

	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"container/list"
	"crypto/sha512"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
)

type ReqSmpcSign struct {
}

//--------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) GetReplyFromGroup(wid int,gid string,initiator string) []NodeReply {
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

	    iter := w.msg_acceptsignres.Front()
	    if iter != nil {
		mdss := iter.Value.(string)
		key,_,_,_,_ := CheckRaw(mdss)
		key2 := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
		exsit,da := GetPubKeyData([]byte(key2))
		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok && ac != nil {
			ret := GetRawReply(w.msg_acceptsignres)
			//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			mms := strings.Split(ac.Sigs, common.Sep)
			for k,mm := range mms {
			    if strings.EqualFold(mm,node2) {
				reply,ok := ret.ReadMap(mms[k+1])
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
	    
	    nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
	    ars = append(ars,nr)
    }

    return ars
}

//-----------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) GetReqAddrKeyByKey(key string) string {
    exsit,da := GetSignInfoData([]byte(key))
    if !exsit {
	exsit,da = GetPubKeyData([]byte(key))
    }
    if exsit {
	ad,ok := da.(*AcceptSignData)
	if ok && ad != nil {
	    smpcpks, _ := hex.DecodeString(ad.PubKey)
	    exsit,da2 := GetPubKeyData(smpcpks[:])
	    if exsit && da2 != nil {
		pd,ok := da2.(*PubKeyData)
		if ok && pd != nil {
		    return pd.Key
		}
	    }
	}
    }

    return ""
}

//-------------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) GetRawReply(ret *common.SafeMap,reply *RawReply) {
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

//-------------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) CheckReply(ac *AcceptReqAddrData,l *list.List,key string) bool {
    if l == nil || key == "" || ac == nil {
	return false
    }

    ret := GetRawReply(l)
    exsit,data := GetSignInfoData([]byte(key))
    if !exsit {
	common.Error("===================== CheckReply,get raw reply finish and get value by key fail================","key",key)
	return false
    }

    sig,ok := data.(*AcceptSignData)
    if !ok || sig == nil {
	common.Error("===================== CheckReply,get raw reply finish and get accept sign data by key fail================","key",key)
	return false
    }

    mms := strings.Split(ac.Sigs, common.Sep)
    _, enodes := GetGroup(sig.GroupId)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	foundeid := false
	for kk,v := range mms {
	    if strings.EqualFold(v,node2) {
		foundeid = true
		found := false
		_,value := ret.ListMap()
		for _,vv := range value {
		    if vv != nil && strings.EqualFold((vv.(*RawReply)).From,mms[kk+1]) { //allow user login diffrent node
			found = true
			break
		    }
		}

		if !found {
		    common.Error("===================== CheckReply,mms[kk+1] no find in ret map and return fail==================","key",key,"mms[kk+1]",mms[kk+1])
		    return false
		}

		break
	    }
	}

	if !foundeid {
	    common.Error("===================== CheckReply,get raw reply finish and find eid fail================","key",key)
	    return false
	}
    }

    return true
}

//--------------------------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) DoReq(raw string,workid int,sender string,ch chan interface{}) bool {
    if raw == "" || workid < 0 || sender == "" {
	res := RpcSmpcRes{Ret: "", Tip: "do req fail.", Err: fmt.Errorf("do req fail")}
	ch <- res
	return false 
    }

    msgmap := make(map[string]string)
    err := json.Unmarshal([]byte(raw), &msgmap)
    if err == nil {
	if msgmap["Type"] == "SignData" {
	    sd := &SignData{}
	    if err = sd.UnmarshalJSON([]byte(msgmap["SignData"]));err == nil {
		common.Debug("===============ReqSmpcSign.DoReq,raw is signdata type===================","msgprex",sd.MsgPrex,"key",sd.Key,"pkx",sd.Pkx,"pky",sd.Pky)

		ys := secp256k1.S256().Marshal(sd.Pkx, sd.Pky)
		pubkeyhex := hex.EncodeToString(ys)

		w := workers[workid]
		w.sid = sd.Key
		w.groupid = sd.GroupId
		
		w.NodeCnt = sd.NodeCnt
		w.ThresHold = sd.ThresHold
		
		w.SmpcFrom = sd.SmpcFrom

		smpcpks, _ := hex.DecodeString(pubkeyhex)
		exsit,da := GetPubKeyData(smpcpks[:])
		if exsit {
			pd,ok := da.(*PubKeyData)
			if ok {
			    exsit,da2 := GetPubKeyData([]byte(pd.Key))
			    if exsit {
				    ac,ok := da2.(*AcceptReqAddrData)
				    if ok {
					HandleC1Data(ac,sd.Key)
				    }
			    }

			}
		}

		childPKx := sd.Pkx
		childPKy := sd.Pky 
		if sd.InputCodeT != "" {
		    da3 := getBip32cFromLocalDb(smpcpks[:])
		    if da3 == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get bip32 fail", Err: fmt.Errorf("presign get bip32 fail")}
			ch <- res
			return false
		    }
		    bip32c := new(big.Int).SetBytes(da3)
		    if bip32c == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get bip32 error", Err: fmt.Errorf("presign get bip32 error")}
			ch <- res
			return false
		    }
		    
		    indexs := strings.Split(sd.InputCodeT, "/")
		    TRb := bip32c.Bytes()
		    childSKU1 := sd.Sku1
		    for idxi := 1; idxi <len(indexs); idxi++ {
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
		
		childpub := secp256k1.S256().Marshal(childPKx,childPKy)
		childpubkeyhex := hex.EncodeToString(childpub)
		addr,_,err := GetSmpcAddr(childpubkeyhex)
		if err != nil {
		    res := RpcSmpcRes{Ret: "", Tip: "get pubkey error", Err: fmt.Errorf("get pubkey error")}
		    ch <- res
		    return false
		}
		fmt.Printf("===================ReqSmpcSign.DoReq, sign, pubkey = %v, inputcode = %v, addr = %v ===================\n",childpubkeyhex,sd.InputCodeT,addr)
 
		var ch1 = make(chan interface{}, 1)
		for i:=0;i < recalc_times;i++ {
		    common.Debug("===============ReqSmpcSign.DoReq,sign recalc===================","i",i,"msgprex",sd.MsgPrex,"key",sd.Key)
		    if len(ch1) != 0 {
			<-ch1
		    }

		    //w.Clear2()
		    //Sign_ec2(sd.Key, sd.Save, sd.Sku1, sd.Txhash, sd.Keytype, sd.Pkx, sd.Pky, ch1, workid)
		    Sign_ec3(sd.Key,sd.Txhash,sd.Keytype,sd.Save,childPKx,childPKy,ch1,workid,sd.Pre)
		    common.Info("===============ReqSmpcSign.DoReq, ec3 sign finish ===================","WaitMsgTimeGG20",WaitMsgTimeGG20)
		    ret, _, cherr := GetChannelValue(WaitMsgTimeGG20 + 10, ch1)
		    if ret != "" && cherr == nil {

			ww, err2 := FindWorker(sd.MsgPrex)
			if err2 != nil || ww == nil {
			    res2 := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
			    ch <- res2
			    return false
			}

			common.Info("===============ReqSmpcSign.DoReq, ec3 sign success ===================","i",i,"get ret",ret,"cherr",cherr,"msgprex",sd.MsgPrex,"key",sd.Key)

			ww.rsv.PushBack(ret)
			res2 := RpcSmpcRes{Ret: ret, Tip: "", Err: nil}
			ch <- res2
			return true 
		    }
		    
		    common.Info("===============ReqSmpcSign.DoReq,ec3 sign fail===================","ret",ret,"cherr",cherr,"msgprex",sd.MsgPrex,"key",sd.Key)
		}	
		
		res2 := RpcSmpcRes{Ret: "", Tip: "sign fail", Err: fmt.Errorf("sign fail")}
		ch <- res2
		return false 
	    }
	}
	
	if msgmap["Type"] == "PreSign" {
	    ps := &PreSign{}
	    if err = ps.UnmarshalJSON([]byte(msgmap["PreSign"]));err == nil {
		w := workers[workid]
		w.sid = ps.Nonce 
		w.groupid = ps.Gid
		w.SmpcFrom = ps.Pub
		gcnt, _ := GetGroup(w.groupid)
		w.NodeCnt = gcnt
		w.ThresHold = gcnt

		smpcpks, _ := hex.DecodeString(ps.Pub)
		exsit,da := GetPubKeyData(smpcpks[:])
		if !exsit {
		    common.Debug("============================PreSign at ReqSmpcSign.DoReq,not exist presign data===========================","pubkey",ps.Pub)
		    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
		    ch <- res
		    return false
		}

		pd,ok := da.(*PubKeyData)
		if !ok {
		    common.Debug("============================PreSign at ReqSmpcSign.DoReq,presign data error==========================","pubkey",ps.Pub)
		    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get presign data from db fail", Err: fmt.Errorf("get presign data from db fail")}
		    ch <- res
		    return false
		}

		nodecount, _ := GetGroup(pd.GroupId)
		w.NodeCnt = nodecount

		save := pd.Save
		common.Debug("============================ReqSmpcSign.DoReq==========================","w.SmpcFrom",w.SmpcFrom,"w.groupid",w.groupid,"w.NodeCnt",w.NodeCnt,"pd.GroupId",pd.GroupId)
		///sku1
		da2 := getSkU1FromLocalDb(smpcpks[:])
		if da2 == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
			ch <- res
			return false
		}
		sku1 := new(big.Int).SetBytes(da2)
		if sku1 == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get sku1 fail", Err: fmt.Errorf("presign get sku1 fail")}
			ch <- res
			return false
		}

		childSKU1 := sku1
		if ps.InputCode != "" {
		    da4 := getBip32cFromLocalDb(smpcpks[:])
		    if da4 == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get bip32 fail", Err: fmt.Errorf("presign get bip32 fail")}
			ch <- res
			return false
		    }
		    bip32c := new(big.Int).SetBytes(da4)
		    if bip32c == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign get bip32 error", Err: fmt.Errorf("presign get bip32 error")}
		    ch <- res
		    return false
		    }
		    
		    smpcpub := (da.(*PubKeyData)).Pub
		    smpcpkx, smpcpky := secp256k1.S256().Unmarshal(([]byte(smpcpub))[:])
		    indexs := strings.Split(ps.InputCode, "/")
		    TRb := bip32c.Bytes()
		    childPKx := smpcpkx
		    childPKy := smpcpky 
		    for idxi := 1; idxi <len(indexs); idxi++ {
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

		exsit,da3 := GetPubKeyData([]byte(pd.Key))
		ac,ok := da3.(*AcceptReqAddrData)
		if ok {
		    HandleC1Data(ac,w.sid)
		}

		var ch1 = make(chan interface{}, 1)
		//pre := PreSign_ec3(w.sid,save,sku1,"ECDSA",ch1,workid)
		pre := PreSign_ec3(w.sid,save,childSKU1,"EC256K1",ch1,workid)
		if pre == nil {
			res := RpcSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
			ch <- res
			return false
		}

		pre.Key = w.sid
		pre.Gid = w.groupid
		pre.Used = false
		pre.Index = ps.Index

		err = PutPreSignData(ps.Pub,ps.InputCode,ps.Gid,ps.Index,pre)
		if err != nil {
		    res := RpcSmpcRes{Ret: "", Tip: "presign fail", Err: fmt.Errorf("presign fail")}
		    ch <- res
		    return false
		}

		res := RpcSmpcRes{Ret: "success", Tip: "", Err: nil}
		ch <- res
		return true
	    }
	}
	
	if msgmap["Type"] == "ComSignBrocastData" {
	    signbrocast,err := UnCompressSignBrocastData(msgmap["ComSignBrocastData"])
	    if err == nil {
		_,_,_,txdata,err := CheckRaw(signbrocast.Raw)
		if err == nil {
		    sig,ok := txdata.(*TxDataSign)
		    if ok {
			pickdata := make([]*PickHashData,0)
			for _,vv := range signbrocast.PickHash {
			    pre := GetPreSignData(sig.PubKey,sig.InputCode,sig.GroupId,vv.PickKey)
			    if pre == nil {
				res := RpcSmpcRes{Ret: "", Tip: "dcrm back-end internal error:get pre-sign data fail", Err: fmt.Errorf("get pre-sign data fail.")}
				ch <- res
				return false
			    }

			    pd := &PickHashData{Hash:vv.Hash,Pre:pre}
			    pickdata = append(pickdata,pd)
			    DeletePreSignData(sig.PubKey,sig.InputCode,sig.GroupId,vv.PickKey)
			}

			signpick := &SignPickData{Raw:signbrocast.Raw,PickData:pickdata}
			errtmp := DoSign(signpick,workid,sender,ch)
			if errtmp == nil {
			    return true
			}

			return false
		    }
		}
	    }
	}

	if msgmap["Type"] == "ComSignData" {
	    signpick,err := UnCompressSignData(msgmap["ComSignData"])
	    if err == nil {
		errtmp := DoSign(signpick,workid,sender,ch)
		if errtmp == nil {
		    return true
		}

		return false
	    }
	}
    }

    key,from,_,txdata,err := CheckRaw(raw)
    common.Debug("=====================DoReq,check raw data finish ================","key",key,"from",from,"err",err,"raw",raw)
    if err != nil {
	common.Error("===============DoReq,check raw error===================","err ",err)
	res := RpcSmpcRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return false 
    }
   
    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if ok {
	w, err := FindWorker(acceptsig.Key)
	if err != nil || w == nil {
		common.Info("===============DoReq, worker was not found.=====================","accept sign key ",acceptsig.Key,"from ",from)
	    c1data := strings.ToLower(acceptsig.Key + "-" + from)
	    C1Data.WriteMap(c1data,raw)
	    res := RpcSmpcRes{Ret:"Failure", Tip: "get sign accept data fail from db when no find worker.", Err: fmt.Errorf("get sign accept data fail from db when no find worker")}
	    ch <- res
	    return false
	}

	exsit,da := GetSignInfoData([]byte(acceptsig.Key))
	if !exsit {
		common.Error("===============DoReq, get sign accept data fail from db=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret:"Failure", Tip: "smpc back-end internal error:get sign accept data fail from db in init accept data", Err: fmt.Errorf("get sign accept data fail from db")}
	    ch <- res
	    return false
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
		common.Error("===============DoReq, it is acceptsign and decode accept data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret:"Failure", Tip: "smpc back-end internal error:decode accept data fail", Err: fmt.Errorf("decode accept data fail")}
	    ch <- res
	    return false
	}

	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
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

	id,_ := GetWorkerId(w)
	DisAcceptMsg(raw,id)
	reqaddrkey := GetReqAddrKeyByOtherKey(acceptsig.Key,Rpc_SIGN)
	exsit,da = GetPubKeyData([]byte(reqaddrkey))
	if !exsit {
		common.Error("===============DoReq, get reqaddr sigs data fail=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return false
	}

	acceptreqdata,ok := da.(*AcceptReqAddrData)
	if !ok || acceptreqdata == nil {
		common.Error("===============DoReq, get reqaddr sigs data fail =====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
	    ch <- res
	    return false
	}

	HandleC1Data(acceptreqdata,acceptsig.Key)

	ars := GetAllReplyFromGroup(id,ac.GroupId,Rpc_SIGN,ac.Initiator)
	if ac.Deal == "true" || ac.Status == "Success" || ac.Status == "Failure" || ac.Status == "Timeout" {
		common.Info("===============DoReq,sign has handled before=====================","key ",acceptsig.Key,"from ",from)
	    res := RpcSmpcRes{Ret:"", Tip: "sign has handled before", Err: fmt.Errorf("sign has handled before")}
	    ch <- res
	    return false
	}

	tip, err := AcceptSign(ac.Initiator,ac.Account, ac.PubKey, ac.MsgHash, ac.Keytype, ac.GroupId, ac.Nonce,ac.LimitNum,ac.Mode,"false", accept, status, "", "", "", ars, ac.WorkId)
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

//-----------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) GetGroupSigs(txdata []byte) (string,string,string,string) {
    return "","","",""
}

//--------------------------------------------------------------------------------------------------------

func (req *ReqSmpcSign) CheckTxData(txdata []byte,from string,nonce uint64) (string,string,string,interface{},error) {
    if txdata == nil {
	return "","","",nil,errors.New("tx data is nil")
    }
    
    sig := TxDataSign{}
    err := json.Unmarshal(txdata, &sig)
    if err == nil && sig.TxType == "SIGN" {
	pubkey := sig.PubKey
	inputcode := sig.InputCode
	hash := sig.MsgHash
	keytype := sig.Keytype
	groupid := sig.GroupId
	threshold := sig.ThresHold
	mode := sig.Mode
	timestamp := sig.TimeStamp

	if from == "" || pubkey == "" || hash == nil || keytype == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	}

	//check input code
	if inputcode != "" {
	    indexs := strings.Split(inputcode, "/")
	    if len(indexs) < 2 || indexs[0] != "m" {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	    }
	}
	//

	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "","","",nil,fmt.Errorf("threshold is not right.")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "", "","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
		return "", "","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error.")
	}

	nc,_ := GetGroup(groupid)
	if nc < limit || nc > nodecnt {
	    common.Info("==============ReqSmpcSign.CheckTxData, sign,check group node count error============","limit ",limit,"nodecnt ",nodecnt,"nc ",nc,"groupid ",groupid)
	    return "","","",nil,fmt.Errorf("check group node count error")
	}

	if !CheckGroupEnode(groupid) {
	    return "","","",nil,fmt.Errorf("there is same enodeID in group")
	}
	
	//check mode
	smpcpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetPubKeyData([]byte(smpcpks[:]))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get data from db fail in func sign")
	}

	pubs,ok := da.(*PubKeyData)
	if pubs == nil || !ok {
	    return "","","",nil,fmt.Errorf("get data from db fail in func sign")
	}

	if pubs.Mode != mode {
	    return "","","",nil,fmt.Errorf("can not sign with different mode in pubkey.")
	}

	if len(sig.MsgContext) > 16 {
	    return "","","",nil,fmt.Errorf("msgcontext counts must <= 16")
	}
	for _,item := range sig.MsgContext {
	    if len(item) > 1024*1024 {
		return "","","",nil,fmt.Errorf("msgcontext item size must <= 1M")
	    }
	}

	key := Keccak256Hash([]byte(strings.ToLower(from + ":" + fmt.Sprintf("%v", nonce) + ":" + pubkey + ":" + get_sign_hash(hash,keytype) + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	return key,from,fmt.Sprintf("%v", nonce),&sig,nil
    }
    
    pre := TxDataPreSignData{}
    err = json.Unmarshal(txdata, &pre)
    if err == nil && pre.TxType == "PRESIGNDATA" {
	pubkey := pre.PubKey
	subgids := pre.SubGid

	if from == "" || pubkey == "" || subgids == nil {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	}
	//

	smpcpks, _ := hex.DecodeString(pubkey)
	exsit,_ := GetPubKeyData(smpcpks[:])
	if !exsit {
		return "","","",nil,fmt.Errorf("invalid pubkey")
	}

	return "",from,fmt.Sprintf("%v", nonce),&pre,nil
    }
    
    acceptsig := TxDataAcceptSign{}
    err = json.Unmarshal(txdata, &acceptsig)
    if err == nil && acceptsig.TxType == "ACCEPTSIGN" {
	if acceptsig.MsgHash == nil {
	    return "","","",nil,fmt.Errorf("accept data error.")
	}

	if len(acceptsig.MsgContext) > 16 {
	    return "","","",nil,fmt.Errorf("msgcontext counts must <= 16")
	}
	for _,item := range acceptsig.MsgContext {
	    if len(item) > 1024*1024 {
		return "","","",nil,fmt.Errorf("msgcontext item size must <= 1M")
	    }
	}

	if acceptsig.Accept != "AGREE" && acceptsig.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetSignInfoData([]byte(acceptsig.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAccept(ac.PubKey,ac.Mode,from) {
	    return "","","",nil,fmt.Errorf("invalid accepter")
	}
	
	return acceptsig.Key,from,"",&acceptsig,nil
    }
	
    return "","","",nil,errors.New("check tx data fail")
}

//----------------------------------------------------------------------------------------------------------

func GetSignRawValue(raw string) (string,string,string) {
    if raw == "" {
	return "","",""
    }

    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	return "","",""
    }

    signer := types.NewEIP155Signer(big.NewInt(30400))
    from, err := types.Sender(signer,tx)
    if err != nil {
	return "","",""
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

    return from.Hex(),txtype,timestamp
}

func CheckSignDulpRawReply(raw string,l *list.List) bool {
    if l == nil || raw == "" {
	return false
    }
   
    from,txtype,timestamp := GetSignRawValue(raw)

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

	if strings.EqualFold(raw,s) {
	   return false 
	}
	
	from2,txtype2,timestamp2 := GetSignRawValue(s)
	if strings.EqualFold(from,from2) && strings.EqualFold(txtype,txtype2) {
	    t1,_ := new(big.Int).SetString(timestamp,10)
	    t2,_ := new(big.Int).SetString(timestamp2,10)
	    if t1.Cmp(t2) > 0 {
		l.Remove(e)
	    } else {
		return false
	    }
	}
    }

    return true
}

func (req *ReqSmpcSign) DisAcceptMsg(raw string,workid int,key string) {
    if raw == "" || workid < 0 || workid >= len(workers) || key == "" {
	return
    }

    w := workers[workid]
    if w == nil {
	return
    }
    
    if Find(w.msg_acceptsignres,raw) {
	common.Debug("======================ReqSmpcSign.DisAcceptMsg,receive one msg and already in list.===========================","raw",raw,"key",key)
	return
    }

    if !CheckSignDulpRawReply(raw,w.msg_acceptsignres) {
	return
    }

    w.msg_acceptsignres.PushBack(raw)
    if w.msg_acceptsignres.Len() >= w.ThresHold {
	if !CheckReply(w.msg_acceptsignres,Rpc_SIGN,key) {
	    common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg, but Not all accept data has been received ===================","raw",raw,"key",key)
	    return
	}

	common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received===================","raw",raw,"key",key)
	w.bacceptsignres <- true
	exsit,da := GetSignInfoData([]byte(key))
	if !exsit {
	    return
	}

	ac,ok := da.(*AcceptSignData)
	if !ok || ac == nil {
	    return
	}

	common.Debug("=====================ReqSmpcSign.DisAcceptMsg,receive one msg,all accept data has been received,set acceptSignChan ===================","raw",raw,"key",key)
	workers[ac.WorkId].acceptSignChan <- "go on"
    }
}
    


