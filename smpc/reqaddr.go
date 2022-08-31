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
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	keygen "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/ecdsa/keygen"
	edkeygen "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/eddsa/keygen"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc-lib/smpc"
	"github.com/fsn-dev/cryptoCoins/coins"
	"math/big"
	"sort"
	"strings"
	"strconv"
	"sync"
	"time"
	"errors"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	ethcrypto "github.com/fsn-dev/cryptoCoins/tools/crypto"
	"crypto/ecdsa"
)

var (
	// PaillierKeyLength paillier key len
	PaillierKeyLength = 2048

	// reqdataTrytimes try times of requesting data by p2p 
	reqdataTrytimes  = 5

	// reqdataTimeout request data timeout
	reqdataTimeout   = 60
)

//------------------------------------------------------------------------

// GetReqAddrNonce get keygen special tx nonce
func GetReqAddrNonce(account string) (string, string, error) {
    	if account == "" {
	    return "","",errors.New("param error")
	}

	key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	var da []byte
	exsit, datmp := GetPubKeyData([]byte(key2))
	if !exsit {
		return "0", "", nil
	}

	da = datmp.([]byte)
	nonce, _ := new(big.Int).SetString(string(da), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)

	return fmt.Sprintf("%v", nonce), "", nil
}

//-----------------------------------------------------------------------------

// SetReqAddrNonce set keygen special tx nonce
func SetReqAddrNonce(account string, nonce string) (string, error) {
    	if account == "" || nonce == "" {
	    return "",errors.New("param error")
	}

	key := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	err := PutPubKeyData([]byte(key), []byte(nonce))
	if err != nil {
		return err.Error(), err
	}

	return "", nil
}

//----------------------------------------------------------------------------

// TxDataReqAddr the data of the special tx of keygen
type TxDataReqAddr struct {
	TxType    string
	Account    string
	Nonce    string
	Keytype   string
	GroupID   string
	ThresHold string
	Mode      string
	FixedApprover []string
	AcceptTimeOut      string
	TimeStamp string
	Sigs      string
	Comment string
}

// GetSmpcAddr Obtain SMPC addresses in different currencies in pubkey
func GetSmpcAddr(pubkey string) (string, string, error) {
    	if pubkey == "" {
	    return "","",errors.New("pubkey is nil")
	}

	var m interface{}
	addrmp := make(map[string]string)
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

		addrmp[ct] = ctaddr
	}

	m = &PubkeyRes{Account: "", PubKey: pubkey, SmpcAddress: addrmp}
	b, _ := json.Marshal(m)
	return string(b), "", nil
}

//-----------------------------------------------------------------------------

// ReqKeyGen Request to generate pubkey 
// raw : keygen command data
func ReqKeyGen(raw string) (string, string, error) {
	if raw == "" {
	    return "","",errors.New("param error")
	}

	key, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("============ReqKeyGen,check raw data error==============", "err ", err)
		return "", err.Error(), err
	}

	req, ok := txdata.(*TxDataReqAddr)
	if !ok {
		return "", "check raw fail,it is not *TxDataReqAddr", fmt.Errorf("check raw fail,it is not *TxDataReqAddr")
	}

	common.Debug("============ReqKeyGen,SendMsgToSmpcGroup===============", "raw ", raw, "gid ", req.GroupID, "key ", key)
	SendMsgToSmpcGroup(raw, req.GroupID)
	SetUpMsgList(raw, curEnode)
	return key, "", nil
}

//----------------------------------------------------------------------------------

// RPCAcceptReqAddr Agree to the keygen request 
// raw : accept data, including the key of the keygen request
func RPCAcceptReqAddr(raw string) (string, string, error) {
	if raw == "" {
	    return "","",errors.New("param error")
	}

	_, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================RPCAcceptReqAddr,check raw data error ================", "raw", raw, "err", err)
		return "Failure", err.Error(), err
	}

	acceptreq, ok := txdata.(*TxDataAcceptReqAddr)
	if !ok {
		return "Failure", "check raw fail,it is not *TxDataAcceptReqAddr", fmt.Errorf("check raw fail,it is not *TxDataAcceptReqAddr")
	}

	exsit, da := GetReqAddrInfoData([]byte(acceptreq.Key))
	if exsit {
		ac, ok := da.(*AcceptReqAddrData)
		if ok && ac != nil {
			common.Debug("=====================RPCAcceptReqAddr, SendMsgToSmpcGroup ================", "raw", raw, "gid", ac.GroupID, "key", acceptreq.Key)
			SendMsgToSmpcGroup(raw, ac.GroupID)
			//SetUpMsgList(raw, curEnode)
			go ExecApproveKeyGen(raw,from,acceptreq,ac,true)
			return "Success", "", nil
		}
	}

	return "Failure", "accept fail", fmt.Errorf("accept fail")
}

func IsValidAccept(gid string,from string,ac *AcceptReqAddrData) bool {
    if gid == "" || from == "" || ac == nil || ac.Sigs == "" {
	return false
    }
    
    mms := strings.Split(ac.Sigs, common.Sep)
    if len(mms) < 3 {
	return false
    }

    nums := strings.Split(ac.LimitNum, "/")
    if len(nums) != 2 {
	    return false
    }

    nodecnt, err := strconv.Atoi(nums[1])
    if err != nil {
	    return false
    }

    if len(mms) != (2*nodecnt + 1) {
	return false
    }

    _, nodes := GetGroup(gid)
    others := strings.Split(nodes, common.Sep2)
    for _, v := range others {
	node2 := ParseNode(v)
	for k,vv := range mms {
	    if strings.EqualFold(vv,node2) {
		if (k+1) < len(mms) && strings.EqualFold(mms[k+1],from) {
		    return true
		}
	    }
	}
    }

    return false
}

func GetENodeByFrom(from string,ac *AcceptReqAddrData) string {
    if from == "" || ac == nil {
	return ""
    }
   
	log.Debug("================GetENodeByFrom=================","sigs",ac.Sigs) 
    mms := strings.Split(ac.Sigs, common.Sep)
    if len(mms) < 3 {
	log.Error("================GetENodeByFrom,sigs data error=================","sigs",ac.Sigs) 
	return ""
    }

    nums := strings.Split(ac.LimitNum, "/")
    if len(nums) != 2 {
	log.Error("================GetENodeByFrom,threshold error=================","threshold",ac.LimitNum) 
	    return ""
    }

    nodecnt, err := strconv.Atoi(nums[1])
    if err != nil {
	log.Error("================GetENodeByFrom,get node count by threshold fail=================","threshold",ac.LimitNum,"err",err) 
	    return ""
    }

    if len(mms) != (2*nodecnt + 1) {
	log.Error("================GetENodeByFrom,check node count fail=================","threshold",ac.LimitNum,"nodecnt",nodecnt,"mms",mms,"mms len",len(mms)) 
	return ""
    }

    for k,_ := range mms {
	log.Debug("================GetENodeByFrom,get approver=================","k",k,"value",mms[k],"from",from,"mms len",len(mms)) 
	if k < len(mms) && strings.EqualFold(mms[k],from) {
	    return mms[k-1]
	}
    }

    return ""
}

func ExecApproveKeyGen(raw string,from string,req *TxDataAcceptReqAddr,ac *AcceptReqAddrData,check bool) {
    common.Debug("===============ExecApproveKeyGen, check accept reqaddr raw success======================", "raw ", raw, "key ", req.Key, "from ", from, "txdata ",req)

    w, err := FindWorker(req.Key)
    if err != nil || w == nil {
	    c1data := strings.ToLower(req.Key + "-" + from)
	    C1Data.WriteMap(c1data, raw) // save the lastest accept msg??
	    return
    }

    if w.approved {
	return
    }

    /////fix bug: miss accept msg for 7-11 test
    if Find(w.msgacceptreqaddrres, raw) {
	    return
    }
    ////

    if !IsValidAccept(ac.GroupID,from,ac) {
	return
    }

    if !CheckReqAddrDulpRawReply(raw, w.msgacceptreqaddrres) {
	    return
    }

    w.msgacceptreqaddrres.PushBack(raw)
    
    if check {
	HandleC1Data(ac, req.Key)
    }
    
    //status := "Pending"
    accept := req.Accept
    if accept == "" {
	accept = "DISAGREE"
    }

    //if req.Accept != "AGREE" {
	//    status = "Failure"
    //}

    //AcceptReqAddr(ac.Initiator, ac.Account, ac.Cointype, ac.GroupID, ac.Nonce, ac.LimitNum, ac.Mode, "false", accept, status, "", "", "", nil, ac.WorkID, "")
     
    /////fix bug: miss accept msg for 7-11 test
    if RelayInPeers {
	SendMsgToSmpcGroup(raw, ac.GroupID)
    }
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

    enode := curEnode
    if ac.Mode == "0" || ac.Mode == "2" { 
	    enode = GetENodeByFrom(from,ac)
	    if enode == "" {
		return
	    }
    }

    reply := &ApprovReply{ENode:enode,From: from, Accept: accept, TimeStamp: req.TimeStamp}
    if index != -1 {
	w.ApprovReplys[index] = reply
    } else {
	w.ApprovReplys = append(w.ApprovReplys,reply)
    }

    if w.msgacceptreqaddrres.Len() >= w.NodeCnt && len(w.ApprovReplys) >= w.NodeCnt {
	//if !CheckReply(w.msgacceptreqaddrres, RPCREQADDR, req.Key) {
	//	return
	//}

	w.approved = true
	w.bacceptreqaddrres <- true
	workers[ac.WorkID].acceptReqAddrChan <- "go on"
    }
}

//--------------------------------------------------------------------------------

// ReqAddrStatus keygen result
type ReqAddrStatus struct {
	KeyID    string
	From string
	GroupID string
	Status    string
	PubKey    string
	ThresHold    string
	Tip       string
	Error     string
	AllReply  []NodeReply
	TimeStamp string
}

func GetApproverByReqAddrKey(key string,enodeID string) string {
    if key == "" || enodeID == "" {
	return ""
    }

    var ac *AcceptReqAddrData
    exsit, da := GetReqAddrInfoData([]byte(key))
    if exsit {
	ac, _ = da.(*AcceptReqAddrData)
    }

    if ac == nil {
	exsit, da = GetPubKeyData([]byte(key))
	if !exsit || da == nil {
		return ""
	}

	ac, _ = da.(*AcceptReqAddrData)
	if ac == nil {
	    return ""
	}
    }

    mms := strings.Split(ac.Sigs, common.Sep)
    if len(mms) < 3 {
	return "" 
    }

    nums := strings.Split(ac.LimitNum, "/")
    if len(nums) != 2 {
	    return ""
    }

    nodecnt, err := strconv.Atoi(nums[1])
    if err != nil {
	    return ""
    }

    if len(mms) != (2*nodecnt + 1) {
	return ""
    }

    for k,v := range mms {
	if strings.EqualFold(v,enodeID) {
	    if (k+1) < len(mms) {
		return mms[k+1]
	    }
	}
    }

    return ""
}

// GetReqAddrStatus get the result of the keygen request by key
func GetReqAddrStatus(key string) (string, string, error) {
	if key == "" {
	    return "","",errors.New("Input data error")
	}

	exsit, da := GetReqAddrInfoData([]byte(key))
	if exsit {
	    ac, ok := da.(*AcceptReqAddrData)
	    if !ok {
		    return "", "", fmt.Errorf("Create public key fail,data error,please try again")
	    }

	    var rep []NodeReply
	    for _,v := range ac.AllReply {
		acc := GetApproverByReqAddrKey(key,v.Enode)
		nr := NodeReply{Enode: v.Enode, Approver:acc,Status: v.Status, TimeStamp: v.TimeStamp, Initiator: v.Initiator}
		rep = append(rep,nr)
	    }

	    los := &ReqAddrStatus{KeyID:key,From:ac.Account,GroupID:ac.GroupID,Status: ac.Status, PubKey: ac.PubKey, ThresHold:ac.LimitNum,Tip: ac.Tip, Error: ac.Error, AllReply: rep, TimeStamp: ac.TimeStamp}
	    ret, _ := json.Marshal(los)
	    return string(ret), "", nil
	}

	exsit, da = GetPubKeyData([]byte(key))
	if !exsit || da == nil {
		return "", "", fmt.Errorf("The MPC calculation record cannot be found")
	}

	ac, ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "", fmt.Errorf("Create public key fail,data error,please try again")
	}

	var rep []NodeReply
	for _,v := range ac.AllReply {
	    acc := GetApproverByReqAddrKey(key,v.Enode)
	    nr := NodeReply{Enode: v.Enode, Approver:acc,Status: v.Status, TimeStamp: v.TimeStamp, Initiator: v.Initiator}
	    rep = append(rep,nr)
	}

	los := &ReqAddrStatus{KeyID:key,From:ac.Account,GroupID:ac.GroupID,Status: ac.Status, PubKey: ac.PubKey, ThresHold:ac.LimitNum,Tip: ac.Tip, Error: ac.Error, AllReply: rep, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

//------------------------------------------------------------------------------

// CheckAcc Check whether the account has permission to agree the request(keygen/sign/reshare)
func CheckAcc(eid string, geteracc string, sigs string) bool {

	if eid == "" || geteracc == "" || sigs == "" {
		return false
	}

	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(sigs, common.Sep)
	for _, mm := range mms {
		//		if strings.EqualFold(mm, eid) {
		//			if len(mms) >= (k+1) && strings.EqualFold(mms[k+1], geteracc) {
		//			    return true
		//			}
		//		}

		if strings.EqualFold(geteracc, mm) { //allow user login diffrent node
			return true
		}
	}

	return false
}

//----------------------------------------------------------------------------------

// ReqAddrReply the accept data of keygen  
type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupID   string
	Nonce     string
	ThresHold string
	Mode      string
	TimeStamp string
}

// ReqAddrCurNodeInfoSort sort the info of current node's approve list
type ReqAddrCurNodeInfoSort struct {
	Info []*ReqAddrReply
}

// Len get the count of arrary elements
func (r *ReqAddrCurNodeInfoSort) Len() int {
	return len(r.Info)
}

// Less weather r.Info[i] < r.Info[j]
func (r *ReqAddrCurNodeInfoSort) Less(i, j int) bool {
	itime, _ := new(big.Int).SetString(r.Info[i].TimeStamp, 10)
	jtime, _ := new(big.Int).SetString(r.Info[j].TimeStamp, 10)
	return itime.Cmp(jtime) >= 0
}

// Swap swap value of r.Info[i] and r.Info[j]
func (r *ReqAddrCurNodeInfoSort) Swap(i, j int) {
	r.Info[i], r.Info[j] = r.Info[j], r.Info[i]
}

// GetCurNodeReqAddrInfo  Get current node's keygen command approval list 
func GetCurNodeReqAddrInfo(geteracc string) ([]*ReqAddrReply, string, error) {
	if geteracc == "" {
	    return nil,"",errors.New("param error")
	}

	var ret []*ReqAddrReply
	data := make(chan *ReqAddrReply, 1000)

	var wg sync.WaitGroup
	iter := reqaddrinfodb.NewIterator()
	for iter.Next() {
		key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		if len(key2) == 0 {
			continue
		}

		exsit, da := GetReqAddrInfoData(key2)
		if !exsit || da == nil {
			continue
		}

		wg.Add(1)
		go func(key string, value interface{}, ch chan *ReqAddrReply) {
			defer wg.Done()

			vv, ok := value.(*AcceptReqAddrData)
			if vv == nil || !ok {
				return
			}

			if vv.Deal == "true" || vv.Status == "Success" {
				return
			}

			if vv.Status != "Pending" {
				return
			}

			if vv.Mode == "1" {
				return
			}

			if (vv.Mode == "0" || vv.Mode == "2") && !CheckAcc(curEnode, geteracc, vv.Sigs) {
				return
			}

			los := &ReqAddrReply{Key: key, Account: vv.Account, Cointype: vv.Cointype, GroupID: vv.GroupID, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
			ch <- los
		}(string(key2), da, data)
	}
	iter.Release()
	wg.Wait()

	l := len(data)
	for i := 0; i < l; i++ {
		info := <-data
		ret = append(ret, info)
	}

	reqaddrinfosort := ReqAddrCurNodeInfoSort{Info: ret}
	sort.Sort(&reqaddrinfosort)

	return reqaddrinfosort.Info, "", nil
}

//--------------------------------------------------------------------------------------

// PubKeyData the data of after keygen,include: pubkey,all nodes's paillier pubkey,paillier privatekey,mpc sk,ntilde data .... etc.
type PubKeyData struct {
	Key            string
	Account        string
	Pub            string
	Save           string
	Nonce          string
	GroupID        string
	LimitNum       string
	Mode           string
	KeyGenTime     string
	RefReShareKeys string //key1:key2...
	Comment string
}

// smpcGenPubKey generate the pubkey 
// ec2
// msgprex = hash
// cointype = keytype    // EC256K1||ed25519
func smpcGenPubKey(msgprex string, account string, cointype string, ch chan interface{}, mode string, nonce string) {
	if msgprex == "" || account == "" || cointype == "" || mode == "" || nonce == "" {
	    res := RPCSmpcRes{Ret: "", Tip: "", Err: errors.New("param error")}
	    ch <- res
	    return
	}

	wk, err := FindWorker(msgprex)
	if err != nil || wk == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}
	id := wk.id

	curEnode = GetSelfEnode()

	if cointype == "ED25519" {
		ok2 := false
		for j := 0; j < recalcTimes; j++ {
			if len(ch) != 0 {
				<-ch
			}

			ok2 = KeyGenerateDEDDSA(msgprex, ch, id, cointype)
			if ok2 {
				break
			}

			wk.Clear2()
			time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
		}

		if !ok2 {
			return
		}

		itertmp := workers[id].edpk.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenPubkeyFail)}
			ch <- res
			return
		}
		sedpk := []byte(itertmp.Value.(string))

		itertmp = workers[id].edsave.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsave := itertmp.Value.(string)
		itertmp = workers[id].edsku1.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsku1 := itertmp.Value.(string)
		tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
		pubkeyhex := hex.EncodeToString(sedpk)

		pubs := &PubKeyData{Key: msgprex, Account: account, Pub: string(sedpk), Save: sedsave, Nonce: nonce, GroupID: wk.groupid, LimitNum: wk.limitnum, Mode: mode, KeyGenTime: tt}
		epubs, err := Encode2(pubs)
		if err != nil {
			common.Error("===============smpcGenPubKey,encode fail=================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		ss, err := Compress([]byte(epubs))
		if err != nil {
			common.Error("===============smpcGenPubKey,commpress fail=================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		tip, reply := AcceptReqAddr("", account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id, "")
		if reply != nil {
			common.Error("===============smpcGenPubKey,update reqaddr status error=================", "err", reply, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error")}
			ch <- res
			return
		}

		err = PutPubKeyData(sedpk[:], []byte(ss))
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		err = PutAccountDataToDb(sedpk[:], []byte(pubkeyhex))
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		err = putSkU1ToLocalDb(sedpk[:], []byte(sedsku1))
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
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

			err = PutPubKeyData([]byte(key), []byte(ss))
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
				return
			}

			err = PutAccountDataToDb([]byte(key), []byte(pubkeyhex))
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
				return
			}

			err = putSkU1ToLocalDb([]byte(key), []byte(sedsku1))
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
				ch <- res
				return
			}
		}

		res := RPCSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
		ch <- res
		return
	}

	ok := false
	for j := 0; j < recalcTimes; j++ {
	    log.Debug("==========================smpcGenPubKey,recalc=============================","j",j,"recalc times",recalcTimes,"msgprex",msgprex,"cointype",cointype)
		if len(ch) != 0 {
			<-ch
		}

		ok = KeyGenerateDECDSA(msgprex, ch, id, cointype)
		if ok {
			break
		}

		wk.Clear2()
	}

	if !ok {
		return
	}

	iter := workers[id].pkx.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spkx := iter.Value.(string)
	pkx, _ := new(big.Int).SetString(spkx, 10)
	iter = workers[id].pky.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spky := iter.Value.(string)
	pky, _ := new(big.Int).SetString(spky, 10)
	ys := secp256k1.S256(cointype).Marshal(pkx, pky)

	iter = workers[id].save.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	save := iter.Value.(string)
	iter = workers[id].sku1.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	sku1 := iter.Value.(string)

	err = putSkU1ToLocalDb(ys, []byte(sku1))
	if err != nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}

	//bip32
	iter = workers[id].bip32c.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get c for bip32 fail in req ec2 pubkey")}
		ch <- res
		return
	}
	bip32c := iter.Value.(string)
	err = putBip32cToLocalDb(ys, []byte(bip32c))
	if err != nil {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}

	tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()

	pubkeyhex := hex.EncodeToString(ys)
	common.Info("================ smpc_genpubkey,pubkey generated successfully ===================","pkx",pkx,"pky",pky,"pubkey hex",pubkeyhex,"key",msgprex)

	pubs := &PubKeyData{Key: msgprex, Account: account, Pub: string(ys), Save: save, Nonce: nonce, GroupID: wk.groupid, LimitNum: wk.limitnum, Mode: mode, KeyGenTime: tt}
	epubs, err := Encode2(pubs)
	if err != nil {
		common.Error("===============smpcGenPubKey,encode fail===================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", rk)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	ss, err := Compress([]byte(epubs))
	if err != nil {
		common.Error("===============smpcGenPubKey,compress fail===================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", rk)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	tip, reply := AcceptReqAddr("", account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id, "")
	if reply != nil {
		common.Error("===============smpcGenPubKey,update reqaddr status===================", "err", reply, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", rk)
		res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error")}
		ch <- res
		return
	}

	err = PutPubKeyData(ys, []byte(ss))
	if err != nil {
		common.Error("================================smpcGenPubKey,put pubkey data to local db fail=========================", "err", err, "key", msgprex)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	err = PutAccountDataToDb(ys, []byte(pubkeyhex))
	if err != nil {
		common.Error("================================smpcGenPubKey,put account data to local db fail=========================", "err", err, "key", msgprex)
		res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
		ch <- res
		return
	}

	for _, ct := range coins.Cointypes {
		if strings.EqualFold(ct, "ALL") {
			continue
		}

		h := coins.NewCryptocoinHandler(ct)
		if h == nil {
			continue
		}

		common.Debug("================================smpc_genPubKey,pubkey to address=========================","pubkeyhex",pubkeyhex,"coin type",ct,"key", msgprex)

		/////
		var ctaddr string
		if ct == "ERC20GUSD" || ct == "ERC20MKR" || ct == "ERC20HT" || ct == "ERC20BNB" || ct == "ERC20BNT" || ct == "ERC20RMBT" || ct == "ERC20USDT" {
		    pubKeyHex := strings.TrimPrefix(pubkeyhex, "0x")
		    erc20data := hexEncPubkey(pubKeyHex[2:])
		    pub, err := decodePubkey(erc20data,cointype)
		    if err != nil {
			continue
		    }
		    ctaddr = ethcrypto.PubkeyToAddress(*pub).Hex()
		    if ctaddr == "" {
			continue
		    }
		} else {
		    ctaddr, err = h.PublicKeyToAddress(pubkeyhex)
		    if err != nil {
			    continue
		    }
		}
		/////

		key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()

		err = PutPubKeyData([]byte(key), []byte(ss))
		if err != nil {
			common.Error("================================smpc_genPubKey,put pubkey data to localdb fail=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		err = PutAccountDataToDb([]byte(key), []byte(pubkeyhex))
		if err != nil {
			common.Error("================================smpcGenPubKey,put account data to localdb fail=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		err = putSkU1ToLocalDb([]byte(key), []byte(sku1))
		if err != nil {
			common.Error("================================smpcGenPubKey,put sku1 data to local db fail,=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}

		err = putBip32cToLocalDb([]byte(key), []byte(bip32c))
		if err != nil {
			common.Error("================================smpcGenPubKey,put bip32c to local db fail,=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "", Err: err}
			ch <- res
			return
		}
	}

	res := RPCSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
	ch <- res
}

func hexEncPubkey(h string) (ret [64]byte) {
         b, err := hex.DecodeString(h)
         if err != nil {
                 panic(err)
         }
         if len(b) != len(ret) {
                 panic("invalid length")
         }
         copy(ret[:], b)
         return ret
 }

 func decodePubkey(e [64]byte,keytype string) (*ecdsa.PublicKey, error) {
         p := &ecdsa.PublicKey{Curve: secp256k1.S256(keytype), X: new(big.Int), Y: new(big.Int)}
         half := len(e) / 2
         p.X.SetBytes(e[:half])
         p.Y.SetBytes(e[half:])
         if !p.Curve.IsOnCurve(p.X, p.Y) {
                 return nil, errors.New("invalid secp256k1 curve point")
         }
         return p, nil
}

//-----------------------------------------------------------------------------------------------------------------------

// KeyGenerateDECDSA generate the pubkey
//ec2
//msgprex = hash
func KeyGenerateDECDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RPCSmpcRes{Ret: "", Err: GetRetErr(ErrGetWorkerIDError)}
		ch <- res
		return false
	}

	w := workers[id]
	if w.groupid == "" {
		w, err := FindWorker(msgprex)
		if err != nil || w.groupid == "" {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail")}
			ch <- res
			return false
		}
	}

	ns, _ := GetGroup(w.groupid)
	if ns != w.NodeCnt {
		res := RPCSmpcRes{Ret: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan keygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := keygen.NewLocalDNode(outCh, endCh, ns, w.ThresHold, 2048,cointype)
	w.DNode = keyGenDNode
	_,UID := GetNodeUID(curEnode, cointype,w.groupid)
	if UID == nil {
		res := RPCSmpcRes{Ret: "", Err: errors.New("get node uid fail")}
		ch <- res
		return false
	}
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v", UID))
	//fmt.Printf("=========== KeyGenerateDECDSA, current node uid = %v ===========\n", keyGenDNode.DNodeID())

	if w.DNode.DNodeID() == "" {
		res := RPCSmpcRes{Ret: "", Err: errors.New("get node uid fail")}
		ch <- res
		return false
	}
	w.MsgToEnode[w.DNode.DNodeID()] = curEnode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
			log.Error("==========KeyGenerateDECDSA, node start error============","key",msgprex,"err",err)
			close(errChan)
		}

		exsit, da := GetReqAddrInfoData([]byte(msgprex))
		if exsit {
			ac, ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
				common.Debug("==========KeyGenerateDECDSA, get reqaddr info from db==================","key",msgprex,"ac",ac)
				HandleC1Data(ac, w.sid)
			}
		}
	}()
	go ProcessInboundMessages(msgprex, cointype,commStopChan, errChan,&keyGenWg, ch)
	err := processKeyGen(msgprex, errChan, outCh, endCh,cointype)
	if err != nil {
		if len(ch) == 0 {
		    res := RPCSmpcRes{Ret: "", Err: err}
		    ch <- res
		}
		close(commStopChan)
		log.Error("==========KeyGenerateDECDSA,process keygen error,close commStopChan============","key",msgprex,"err",err)
		return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	return true
}

//------------------------------------------------------------------------------------

// KeyGenerateDEDDSA generate the pubkey
// ed
// msgprex = hash
// cointype = keytype    // ec || ed25519
func KeyGenerateDEDDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGetWorkerIDError)}
		ch <- res
		return false
	}

	w := workers[id]
	GroupID := w.groupid
	if GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return false
	}

	ns, _ := GetGroup(GroupID)
	if ns != w.NodeCnt {
		res := RPCSmpcRes{Ret: "", Tip: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan edkeygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := edkeygen.NewLocalDNode(outCh, endCh, ns, w.ThresHold)
	w.DNode = keyGenDNode
	_,UID := GetNodeUID(curEnode, cointype,w.groupid)
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v", UID))
	w.MsgToEnode[w.DNode.DNodeID()] = curEnode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
			log.Error("==========KeyGenerateDEDDSA,node start error==========","key",msgprex,"err",err)
			close(errChan)
		}

		exsit, da := GetReqAddrInfoData([]byte(msgprex))
		if exsit {
			ac, ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
				common.Debug("=========================KeyGenerateDEDDSA,get reqaddr info from db===========================","key",msgprex,"ac",ac)
				HandleC1Data(ac, w.sid)
			}
		}
	}()
	go ProcessInboundMessagesEDDSA(msgprex, cointype,commStopChan, errChan,&keyGenWg, ch)
	err := processKeyGenEDDSA(msgprex, errChan, outCh, endCh,cointype)
	if err != nil {
		log.Error("==========KeyGenerateDEDDSA,process ed keygen error==========","key",msgprex,"err",err)
		close(commStopChan)

		if len(ch) == 0 {
		    res := RPCSmpcRes{Ret: "", Err: err}
		    ch <- res
		}
		
		return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	return true
}


