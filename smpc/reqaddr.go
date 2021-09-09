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
	"fmt"
	"math/big"
	"strings"
	"time"
	"encoding/json"
	"sync"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	keygen "github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	edkeygen "github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
)

var (
	PaillierKeyLength        = 2048
	reqdata_trytimes = 5
	reqdata_timeout = 60
)

//------------------------------------------------------------------------

func GetReqAddrNonce(account string) (string, string, error) {
	key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	var da []byte
	exsit,datmp := GetPubKeyData([]byte(key2))
	if !exsit {
	    return "0", "", nil
	} else {
		da = datmp.([]byte)
	}

	nonce, _ := new(big.Int).SetString(string(da), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)

	return fmt.Sprintf("%v", nonce), "", nil
}

//-----------------------------------------------------------------------------

func SetReqAddrNonce(account string, nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	err := PutPubKeyData([]byte(key),[]byte(nonce))
	if err != nil {
	    return err.Error(),err
	}
	
	return "", nil
}

//----------------------------------------------------------------------------

type TxDataReqAddr struct {
    TxType string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Sigs string
}

func GetSmpcAddr(pubkey string) (string, string, error) {
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

	m = &SmpcPubkeyRes{Account: "", PubKey: pubkey, SmpcAddress: addrmp}
	b,_ := json.Marshal(m)
	return string(b), "", nil
}

//-----------------------------------------------------------------------------

func Req_SmpcAddr(raw string) (string, string, error) {

    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Error("============Req_SmpcAddr,check raw data error==============","err ",err)
	return "",err.Error(),err
    }

    req,ok := txdata.(*TxDataReqAddr)
    if !ok {
	return "","check raw fail,it is not *TxDataReqAddr",fmt.Errorf("check raw fail,it is not *TxDataReqAddr")
    }

    common.Debug("============Req_SmpcAddr,SendMsgToSmpcGroup===============","raw ",raw,"gid ",req.GroupId,"key ",key)
    SendMsgToSmpcGroup(raw, req.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

//----------------------------------------------------------------------------------

func RpcAcceptReqAddr(raw string) (string, string, error) {
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Error("=====================RpcAcceptReqAddr,check raw data error ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptReqAddr",fmt.Errorf("check raw fail,it is not *TxDataAcceptReqAddr")
    }

    exsit,da := GetReqAddrInfoData([]byte(acceptreq.Key))
    if exsit {
	ac,ok := da.(*AcceptReqAddrData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptReqAddr, SendMsgToSmpcGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptreq.Key)
	    SendMsgToSmpcGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

//--------------------------------------------------------------------------------

type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReqAddrStatus(key string) (string, string, error) {
	exsit,da := GetPubKeyData([]byte(key))
	///////
	if !exsit || da == nil {
		common.Debug("=====================GetReqAddrStatus,key does not exsit======================","key",key)
		return "", "smpc back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus", fmt.Errorf("get reqaddr accept data fail from db")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "smpc back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus", fmt.Errorf("get reqaddr accept data error from db")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

//------------------------------------------------------------------------------

func CheckAcc(eid string, geter_acc string, sigs string) bool {

	if eid == "" || geter_acc == "" || sigs == "" {
	    return false
	}

	//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
	mms := strings.Split(sigs, common.Sep)
	for _, mm := range mms {
//		if strings.EqualFold(mm, eid) {
//			if len(mms) >= (k+1) && strings.EqualFold(mms[k+1], geter_acc) {
//			    return true
//			}
//		}
		
		if strings.EqualFold(geter_acc,mm) { //allow user login diffrent node
		    return true
		}
	}
	
	return false
}

//----------------------------------------------------------------------------------

type ReqAddrReply struct {
	Key       string
	Account   string
	Cointype  string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeReqAddrInfo(geter_acc string) ([]*ReqAddrReply, string, error) {
	var ret []*ReqAddrReply
	data := make(chan *ReqAddrReply,1000)

	var wg sync.WaitGroup
	iter := reqaddrinfodb.NewIterator()
	for iter.Next() {
	    key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
	    if len(key2) == 0 {
		continue
	    }

	    exsit,da := GetReqAddrInfoData(key2) 
	    if !exsit || da == nil {
		continue
	    }
	    
	    wg.Add(1)
	    go func(key string,value interface{},ch chan *ReqAddrReply) {
		defer wg.Done()

		vv,ok := value.(*AcceptReqAddrData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeReqAddrInfo, it is *AcceptReqAddrData===================","vv",vv,"vv.Deal",vv.Deal,"vv.Mode",vv.Mode,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if vv.Mode == "1" {
		    return
		}
		
		if vv.Mode == "0" && !CheckAcc(cur_enode,geter_acc,vv.Sigs) {
		    return
		}

		los := &ReqAddrReply{Key: key, Account: vv.Account, Cointype: vv.Cointype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ch <- los
		common.Debug("================GetCurNodeReqAddrInfo success return================","key",key)
	    }(string(key2),da,data)
	}
	iter.Release()
	wg.Wait()

	l := len(data)
	for i:=0;i<l;i++ {
	    info := <-data
	    ret = append(ret,info)
	}

	return ret, "", nil
}

//--------------------------------------------------------------------------------------

type PubKeyData struct {
        Key string
	Account  string
	Pub      string
	Save     string
	Nonce    string
	GroupId  string
	LimitNum string
	Mode     string
	KeyGenTime string
	RefReShareKeys string //key1:key2...
}

//ec2
//msgprex = hash
//cointype == keytype    //EC256K1||ed25519
func smpc_genPubKey(msgprex string, account string, cointype string, ch chan interface{}, mode string, nonce string) {

	wk, err := FindWorker(msgprex)
	if err != nil || wk == nil {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: err}
		ch <- res
		return
	}
	id := wk.id

	cur_enode = GetSelfEnode()

	if cointype == "ED25519" {
		ok2 := false
		for j := 0;j < recalc_times;j++ {
		    if len(ch) != 0 {
			<-ch
		    }

		    ok2 = KeyGenerate_DEDDSA(msgprex, ch, id, cointype)
		    if ok2 {
			break
		    }
		    
		    wk.Clear2()
		    time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}

		if !ok2 {
			return
		}

		itertmp := workers[id].edpk.Front()
		if itertmp == nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edpk fail", Err: GetRetErr(ErrGetGenPubkeyFail)}
			ch <- res
			return
		}
		sedpk := []byte(itertmp.Value.(string))

		itertmp = workers[id].edsave.Front()
		if itertmp == nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edsave fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsave := itertmp.Value.(string)
		itertmp = workers[id].edsku1.Front()
		if itertmp == nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edsku1 fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsku1 := itertmp.Value.(string)
		tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
		pubkeyhex := hex.EncodeToString(sedpk)
		
		pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(sedpk), Save: sedsave, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
		epubs, err := Encode2(pubs)
		if err != nil {
			common.Error("===============smpc_genPubKey,encode fail=================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:encode PubKeyData fail in req ed pubkey", Err: err}
			ch <- res
			return
		}

		ss, err := Compress([]byte(epubs))
		if err != nil {
			common.Error("===============smpc_genPubKey,commpress fail=================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:compress PubKeyData fail in req ed pubkey", Err: err}
			ch <- res
			return
		}

		tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
		if reply != nil {
			common.Error("===============smpc_genPubKey,update reqaddr status error=================","err",reply,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error.")}
			ch <- res
			return
		}

		err = PutPubKeyData(sedpk[:],[]byte(ss))
		if err != nil {
		    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
		    ch <- res
		    return
		}

		err = PutAccountDataToDb(sedpk[:],[]byte(pubkeyhex))
		if err != nil {
		    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to db fail", Err: err}
		    ch <- res
		    return
		}

		err = putSkU1ToLocalDb(sedpk[:],[]byte(sedsku1))
		if err != nil {
		    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
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

		    err = PutPubKeyData([]byte(key),[]byte(ss))
		    if err != nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
			ch <- res
			return
		    }

		    err = PutAccountDataToDb([]byte(key),[]byte(pubkeyhex))
		    if err != nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to db fail", Err: err}
			ch <- res
			return
		    }


		    err = putSkU1ToLocalDb([]byte(key),[]byte(sedsku1))
		    if err != nil {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
			ch <- res
			return
		    }
		}

		res := RpcSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
		ch <- res
		return
	}

	ok := false
	for j := 0;j < recalc_times;j++ { //try 20 times
	    if len(ch) != 0 {
		<-ch
	    }

	    ok = KeyGenerate_DECDSA(msgprex, ch, id, cointype)
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
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get pkx fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spkx := iter.Value.(string)
	pkx,_ := new(big.Int).SetString(spkx,10)
	iter = workers[id].pky.Front()
	if iter == nil {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get pky fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spky := iter.Value.(string)
	pky,_ := new(big.Int).SetString(spky,10)
	ys := secp256k1.S256().Marshal(pkx, pky)

	iter = workers[id].save.Front()
	if iter == nil {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get save data fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	save := iter.Value.(string)
	iter = workers[id].sku1.Front()
	if iter == nil {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sku1 fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	sku1 := iter.Value.(string)

	err = putSkU1ToLocalDb(ys,[]byte(sku1)) 
	if err != nil {
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:put sku1 to local db fail.", Err: GetRetErr(ErrGetGenSaveDataFail)}
	    ch <- res
	    return
	}

	//bip32
	iter = workers[id].bip32c.Front()
	if iter == nil {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get c for bip32 fail in req ec2 pubkey", Err: fmt.Errorf("get c for bip32 fail in req ec2 pubkey")}
		ch <- res
		return
	}
	bip32c := iter.Value.(string)
	err = putBip32cToLocalDb(ys,[]byte(bip32c)) 
	if err != nil {
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:put bip32c to local db fail.", Err: GetRetErr(ErrGetGenSaveDataFail)}
	    ch <- res
	    return
	}

	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()

	pubkeyhex := hex.EncodeToString(ys)
	fmt.Printf("================ smpc_genpubkey,pubkey generated successfully ,pkx = %v,pky = %v,pubkeyhex = %v ==================\n",pkx,pky,pubkeyhex)
	
	pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(ys), Save: save, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
	epubs, err := Encode2(pubs)
	if err != nil {
		common.Error("===============smpc_genPubKey,encode fail===================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:encode PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	ss, err := Compress([]byte(epubs))
	if err != nil {
		common.Error("===============smpc_genPubKey,compress fail===================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:compress PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
	if reply != nil {
		common.Error("===============smpc_genPubKey,update reqaddr status===================","err",reply,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error.")}
		ch <- res
		return
	}

	err = PutPubKeyData(ys,[]byte(ss))
	if err != nil {
	    common.Error("================================smpc_genPubKey,put pubkey data to local db fail=========================","err",err,"key",msgprex)
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
	    ch <- res
	    return
	}

	err = PutAccountDataToDb(ys,[]byte(pubkeyhex))
	if err != nil {
	    common.Error("================================smpc_genPubKey,put account data to local db fail=========================","err",err,"key",msgprex)
	    res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to local db fail", Err: err}
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

	    err = PutPubKeyData([]byte(key),[]byte(ss))
	    if err != nil {
		common.Error("================================dcrm_genPubKey,put pubkey data to localdb fail=========================","err",err,"key",msgprex)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
		ch <- res
		return
	    }

	    err = PutAccountDataToDb([]byte(key),[]byte(pubkeyhex))
	    if err != nil {
		common.Error("================================smpc_genPubKey,put account data to localdb fail=========================","err",err,"key",msgprex)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to local db fail", Err: err}
		ch <- res
		return
	    }

	    err = putSkU1ToLocalDb([]byte(key),[]byte(sku1))
	    if err != nil {
		common.Error("================================smpc_genPubKey,put sku1 data to local db fail,=========================","err",err,"key",msgprex)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
		ch <- res
		return
	    }
	    
	    err = putBip32cToLocalDb([]byte(key),[]byte(bip32c))
	    if err != nil {
		common.Error("================================smpc_genPubKey,put bip32c to local db fail,=========================","err",err,"key",msgprex)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: put bip32c fail", Err: err}
		ch <- res
		return
	    }
	}

	res := RpcSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
	ch <- res
}

//-----------------------------------------------------------------------------------------------------------------------

//ec2
//msgprex = hash
func KeyGenerate_DECDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcSmpcRes{Ret: "", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	w := workers[id]
	if w.groupid == "" {
		///bug groupid == nil ???
		w, err := FindWorker(msgprex)
		if err != nil || w.groupid == "" {
		    res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		    ch <- res
		    return false
		}
		//////
	}

	ns, _ := GetGroup(w.groupid)
	if ns != w.NodeCnt {
		res := RpcSmpcRes{Ret: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan keygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := keygen.NewLocalDNode(outCh,endCh,ns,w.ThresHold,2048)
	w.DNode = keyGenDNode
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v",DoubleHash(cur_enode,"EC256K1")))
	fmt.Printf("=========== keygen, node uid = %v ===========\n",keyGenDNode.DNodeID())
	
	uid,_ := new(big.Int).SetString(w.DNode.DNodeID(),10)
	w.MsgToEnode[fmt.Sprintf("%v",uid)] = cur_enode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
		    fmt.Printf("==========keygen node start err = %v ==========\n",err)
			close(errChan)
		}
		
		exsit,da := GetReqAddrInfoData([]byte(msgprex))
		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok && ac != nil {
			HandleC1Data(ac,w.sid)
		    }
		}
	}()
	go ProcessInboundMessages(msgprex,commStopChan,&keyGenWg,ch)
	err := processKeyGen(msgprex,errChan, outCh, endCh)
	if err != nil {
	    fmt.Printf("==========process keygen err = %v ==========\n",err)
	    close(commStopChan)
	    res := RpcSmpcRes{Ret: "", Err: err}
	    ch <- res
	    return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	return true
}

//------------------------------------------------------------------------------------

//ed
//msgprex = hash
//cointype == keytype    //ec || ed25519
func KeyGenerate_DEDDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker id", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	w := workers[id]
	GroupId := w.groupid
	if GroupId == "" {
		res := RpcSmpcRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return false
	}

	ns, _ := GetGroup(GroupId)
	if ns != w.NodeCnt {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:the group is not ready", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan edkeygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := edkeygen.NewLocalDNode(outCh,endCh,ns,w.ThresHold)
	w.DNode = keyGenDNode
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v",DoubleHash(cur_enode,"ED25519")))

	w.MsgToEnode[w.DNode.DNodeID()] = cur_enode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
		    fmt.Printf("==========ed,keygen node start err = %v, key = %v ==========\n",err,msgprex)
			close(errChan)
		}
	
		exsit,da := GetReqAddrInfoData([]byte(msgprex))
		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok && ac != nil {
			HandleC1Data(ac,w.sid)
		    }
		}
	}()
	go ProcessInboundMessages_EDDSA(msgprex,commStopChan,&keyGenWg,ch)
	err := processKeyGen_EDDSA(msgprex,errChan, outCh, endCh)
	if err != nil {
	    fmt.Printf("==========process ed keygen err = %v, key = %v ==========\n",err,msgprex)
	    close(commStopChan)
	    res := RpcSmpcRes{Ret: "", Err: err}
	    ch <- res
	    return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	return true
}

