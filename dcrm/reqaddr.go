/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  caihaijun@fusion.org
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

package dcrm 

import (
	//"bytes"
	//cryptorand "crypto/rand"
	//"crypto/sha512"
	"encoding/hex"
	"fmt"
	//"io"
	"math/big"
	//"strconv"
	"sort"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"strings"
	"time"
	"encoding/json"
	"sync"
	"github.com/fsn-dev/cryptoCoins/coins"
	//"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	dcrmlib "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	keygen "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/ecdsa/keygen"
	edkeygen "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/eddsa/keygen"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
)

var (
	PaillierKeyLength        = 2048
	reqdata_trytimes = 5
	reqdata_timeout = 60
)

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

func GetReqAddrNonce(account string) (string, string, error) {
	key2 := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	var da []byte
	datmp, exsit := LdbPubKeyData.ReadMap(key2)
	if !exsit {
		da2 := GetPubKeyDataValueFromDb(key2)
		if da2 == nil {
			exsit = false
		} else {
			exsit = true
			da = da2
		}
	} else {
		da = datmp.([]byte)
	}
	///////
	if !exsit {
		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)

	return fmt.Sprintf("%v", nonce), "", nil
}

func SetReqAddrNonce(account string, nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account))).Hex()
	kd := KeyData{Key: []byte(key), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key, []byte(nonce))
	return "", nil
}

type TxDataReqAddr struct {
    TxType string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
    Sigs string
}

func GetDcrmAddr(pubkey string) (string, string, error) {
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

	m = &DcrmPubkeyRes{Account: "", PubKey: pubkey, DcrmAddress: addrmp}
	b,_ := json.Marshal(m)
	return string(b), "", nil
}

func ReqDcrmAddr(raw string) (string, string, error) {

    common.Debug("=====================ReqDcrmAddr call CheckRaw ================","raw ",raw)
    key,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Debug("============ReqDcrmAddr==============","err ",err)
	return "",err.Error(),err
    }

    req,ok := txdata.(*TxDataReqAddr)
    if !ok {
	return "","check raw fail,it is not *TxDataReqAddr",fmt.Errorf("check raw fail,it is not *TxDataReqAddr")
    }

    common.Info("============ReqDcrmAddr,SendMsgToDcrmGroup===============","raw ",raw,"gid ",req.GroupId,"key ",key)
    SendMsgToDcrmGroup(raw, req.GroupId)
    SetUpMsgList(raw,cur_enode)
    return key, "", nil
}

func RpcAcceptReqAddr(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptReqAddr call CheckRaw ================","raw",raw)
    _,_,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================RpcAcceptReqAddr,CheckRaw ================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptreq,ok := txdata.(*TxDataAcceptReqAddr)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptReqAddr",fmt.Errorf("check raw fail,it is not *TxDataAcceptReqAddr")
    }

    exsit,da := GetValueFromPubKeyData(acceptreq.Key)
    if exsit {
	ac,ok := da.(*AcceptReqAddrData)
	if ok && ac != nil {
	    common.Debug("=====================RpcAcceptReqAddr, SendMsgToDcrmGroup ================","raw",raw,"gid",ac.GroupId,"key",acceptreq.Key)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetReqAddrStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		common.Debug("=====================GetReqAddrStatus,no exist key======================","key",key)
		return "", "dcrm back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus", fmt.Errorf("dcrm back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "dcrm back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus", fmt.Errorf("dcrm back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

type EnAcc struct {
	Enode    string
	Accounts []string
}

type EnAccs struct {
	EnodeAccounts []EnAcc
}

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
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
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
		ret = append(ret, los)
		common.Debug("================GetCurNodeReqAddrInfo success return================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

//ec2
//msgprex = hash
//cointype == keytype    //ec||ed25519
func dcrm_genPubKey(msgprex string, account string, cointype string, ch chan interface{}, mode string, nonce string) {

	wk, err := FindWorker(msgprex)
	if err != nil || wk == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: err}
		ch <- res
		return
	}
	id := wk.id

	cur_enode = GetSelfEnode()

	//fmt.Printf("====================dcrm_genPubKey,cointype = %v ================\n",cointype)
	if cointype == "ED25519" {
	//if types.IsDefaultED25519(cointype) {
		ok2 := false
		for j := 0;j < recalc_times;j++ { //try 20 times
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
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get workers[id].edpk fail", Err: GetRetErr(ErrGetGenPubkeyFail)}
			ch <- res
			return
		}
		sedpk := []byte(itertmp.Value.(string))

		itertmp = workers[id].edsave.Front()
		if itertmp == nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get workers[id].edsave fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsave := itertmp.Value.(string)
		itertmp = workers[id].edsku1.Front()
		if itertmp == nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get workers[id].edsku1 fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsku1 := itertmp.Value.(string)
		////////
		tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
		//rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()

		pubkeyhex := hex.EncodeToString(sedpk)
		fmt.Printf("====================dcrm_genPubKey,success get pubkey = %v =====================\n",pubkeyhex)
		
		pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(sedpk), Save: sedsave, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
		epubs, err := Encode2(pubs)
		if err != nil {
			common.Debug("===============dcrm_genPubKey,encode fail=================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode PubKeyData fail in req ed pubkey", Err: err}
			ch <- res
			return
		}

		ss, err := Compress([]byte(epubs))
		if err != nil {
			common.Debug("===============dcrm_genPubKey,commpress fail=================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress PubKeyData fail in req ed pubkey", Err: err}
			ch <- res
			return
		}

		common.Debug("===============dcrm_genPubKey,start call AcceptReqAddr to update success status=================","account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
		tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
		if reply != nil {
			common.Debug("===============dcrm_genPubKey,update reqaddr status=================","err",reply,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",msgprex)
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error.")}
			ch <- res
			return
		}

		/*if !strings.EqualFold(cointype, "ALL") {
			h := coins.NewCryptocoinHandler(cointype)
			if h == nil {
				res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: fmt.Errorf("req addr fail,cointype is not supported.")}
				ch <- res
				return
			}

			ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
			if err != nil {
				res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get dcrm addr fail from pubkey:" + pubkeyhex, Err: err}
				ch <- res
				return
			}

			//add for lockout
			kd := KeyData{Key: sedpk[:], Data: ss}
			PubKeyDataChan <- kd
			/////
			LdbPubKeyData.WriteMap(string(sedpk[:]), pubs)
			////

			key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
			kd = KeyData{Key: []byte(key), Data: ss}
			PubKeyDataChan <- kd
			/////
			LdbPubKeyData.WriteMap(key, pubs)
			////
			sk := KeyData{Key: sedpk[:], Data: sedsku1}
			SkU1Chan <- sk
			sk = KeyData{Key: []byte(key), Data: sedsku1}
			SkU1Chan <- sk
		} else*/ {
			kd := KeyData{Key: sedpk[:], Data: ss}
			PubKeyDataChan <- kd
			/////
			LdbPubKeyData.WriteMap(string(sedpk[:]), pubs)
			////
			sk := KeyData{Key: sedpk[:], Data: sedsku1}
			SkU1Chan <- sk

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
				kd = KeyData{Key: []byte(key), Data: ss}
				PubKeyDataChan <- kd
				/////
				LdbPubKeyData.WriteMap(key, pubs)
				////
				sk = KeyData{Key: []byte(key), Data: sedsku1}
				SkU1Chan <- sk
			}
		}

		res := RpcDcrmRes{Ret: pubkeyhex, Tip: "", Err: nil}
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
	    //time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
	}

	if !ok {
		return
	}

	iter := workers[id].pkx.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pkx fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spkx := iter.Value.(string)
	pkx,_ := new(big.Int).SetString(spkx,10)
	iter = workers[id].pky.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get pky fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spky := iter.Value.(string)
	pky,_ := new(big.Int).SetString(spky,10)
	ys := secp256k1.S256().Marshal(pkx, pky)

	iter = workers[id].save.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get save data fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	save := iter.Value.(string)
	iter = workers[id].sku1.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sku1 fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	sku1 := iter.Value.(string)
	////////
	sk := KeyData{Key: ys, Data: sku1}
	SkU1Chan <- sk
	//save sku1
	//

	//bip32
	iter = workers[id].bip32c.Front()
	if iter == nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get c for bip32 fail in req ec2 pubkey", Err: fmt.Errorf("get c for bip32 fail in req ec2 pubkey")}
		ch <- res
		return
	}
	bip32c := iter.Value.(string)
	////////
	bip := KeyData{Key: ys, Data: bip32c}
	Bip32CChan <- bip
	//save bip32c
	//

	tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()

	pubkeyhex := hex.EncodeToString(ys)
	fmt.Printf("================ dcrm_genpubkey,pkx = %v,pky = %v,pubkeyhex = %v ==================\n",pkx,pky,pubkeyhex)
	
	pubs := &PubKeyData{Key:msgprex,Account: account, Pub: string(ys), Save: save, Nonce: nonce, GroupId: wk.groupid, LimitNum: wk.limitnum, Mode: mode,KeyGenTime:tt}
	epubs, err := Encode2(pubs)
	if err != nil {
		common.Debug("===============dcrm_genPubKey,encode fail===================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:encode PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	ss, err := Compress([]byte(epubs))
	if err != nil {
		common.Debug("===============dcrm_genPubKey,compress fail===================","err",err,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:compress PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	common.Debug("===============dcrm_genPubKey,start call AcceptReqAddr to update success status===================","account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)

	tip, reply := AcceptReqAddr("",account, cointype, wk.groupid, nonce, wk.limitnum, mode, "true", "true", "Success", pubkeyhex, "", "", nil, id,"")
	if reply != nil {
		common.Debug("===============dcrm_genPubKey,update reqaddr status===================","err",reply,"account",account,"pubkey",pubkeyhex,"nonce",nonce,"key",rk)
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update req addr status error.")}
		ch <- res
		return
	}

	/*if !strings.EqualFold(cointype, "ALL") {
		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: fmt.Errorf("req addr fail,cointype is not supported.")}
			ch <- res
			return
		}

		ctaddr, err := h.PublicKeyToAddress(pubkeyhex)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get dcrm addr fail from pubkey:" + pubkeyhex, Err: err}
			ch <- res
			return
		}

		kd := KeyData{Key: ys, Data: ss}
		PubKeyDataChan <- kd
		/////
		LdbPubKeyData.WriteMap(string(ys), pubs)
		////

		key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
		kd = KeyData{Key: []byte(key), Data: ss}
		PubKeyDataChan <- kd
		/////
		LdbPubKeyData.WriteMap(key, pubs)
		////
		sk = KeyData{Key: []byte(key), Data: sku1}
		SkU1Chan <- sk
		
		bip = KeyData{Key: []byte(key), Data: bip32c}
		Bip32CChan <- bip
	} else*/ {
		kd := KeyData{Key: ys, Data: ss}
		PubKeyDataChan <- kd
		/////
		LdbPubKeyData.WriteMap(string(ys), pubs)
		////

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
				fmt.Printf("=========dcrm_genpubkey, pubkeyhex = %v, h = %v,err = %v ===========\n",pubkeyhex,h,err)
				continue
			}

			fmt.Printf("=========dcrm_genpubkey, ctaddr = %v,pubkeyhex = %v, h = %v ===========\n",ctaddr,pubkeyhex,h)
			key := Keccak256Hash([]byte(strings.ToLower(ctaddr))).Hex()
			kd = KeyData{Key: []byte(key), Data: ss}
			PubKeyDataChan <- kd
			/////
			LdbPubKeyData.WriteMap(key, pubs)
			////
			sk = KeyData{Key: []byte(key), Data: sku1}
			SkU1Chan <- sk
			
			bip = KeyData{Key: []byte(key), Data: bip32c}
			Bip32CChan <- bip
		}
	}

	res := RpcDcrmRes{Ret: pubkeyhex, Tip: "", Err: nil}
	ch <- res
}

func GetIds(keytype string, groupid string) sortableIDSSlice {
	var ids sortableIDSSlice
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		uid := DoubleHash(node2, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)
	return ids
}

func DoubleHash(id string, keytype string) *big.Int {
	// Generate the random num

	// First, hash with the keccak256
	keccak256 := sha3.NewKeccak256()
	_,err := keccak256.Write([]byte(id))
	if err != nil {
	    return nil
	}


	digestKeccak256 := keccak256.Sum(nil)

	//second, hash with the SHA3-256
	sha3256 := sha3.New256()

	_,err = sha3256.Write(digestKeccak256)
	if err != nil {
	    return nil
	}

	if keytype == "ED25519" {
	    var digest [32]byte
	    copy(digest[:], sha3256.Sum(nil))

	    //////
	    var zero [32]byte
	    var one [32]byte
	    one[0] = 1
	    ed.ScMulAdd(&digest, &digest, &one, &zero)
	    //////
	    digestBigInt := new(big.Int).SetBytes(digest[:])
	    return digestBigInt
	}

	digest := sha3256.Sum(nil)
	// convert the hash ([]byte) to big.Int
	digestBigInt := new(big.Int).SetBytes(digest)
	return digestBigInt
}

func GetEnodesByUid(uid *big.Int, keytype string, groupid string) string {
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v) //bug??
		id := DoubleHash(node2, keytype)
		if id.Cmp(uid) == 0 {
			return v
		}
	}

	return ""
}

//ed
//msgprex = hash
//cointype == keytype    //ec || ed25519
func KeyGenerate_DEDDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker id", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	w := workers[id]
	GroupId := w.groupid
	if GroupId == "" {
		res := RpcDcrmRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return false
	}

	ns, _ := GetGroup(GroupId)
	if ns != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:the group is not ready", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan dcrmlib.Message, ns)
	endCh := make(chan edkeygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := edkeygen.NewLocalDNode(outCh,endCh,ns,w.ThresHold)
	w.DNode = keyGenDNode

	w.MsgToEnode[w.DNode.DNodeID()] = cur_enode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
		    fmt.Printf("==========ed,keygen node start err = %v, key = %v ==========\n",err,msgprex)
			close(errChan)
		}
		
		for _,v := range w.PreSaveDcrmMsg {
		    w.DcrmMsg <- v 
		}
	}()
	go ProcessInboundMessages_EDDSA(msgprex,commStopChan,&keyGenWg,ch)
	err := processKeyGen_EDDSA(msgprex,errChan, outCh, endCh)
	if err != nil {
	    fmt.Printf("==========process ed keygen err = %v, key = %v ==========\n",err,msgprex)
	    close(commStopChan)
	    res := RpcDcrmRes{Ret: "", Err: err}
	    ch <- res
	    return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	/*
	rand := cryptorand.Reader
	var seed [32]byte

	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		fmt.Println("Error: io.ReadFull(rand, seed)")
	}

	// 1.2 privateKey' = SHA512(seed)
	var sk [64]byte
	var pk [32]byte

	seedDigest := sha512.Sum512(seed[:])

	seedDigest[0] &= 248
	seedDigest[31] &= 127
	seedDigest[31] |= 64

	copy(sk[:], seedDigest[:])

	// 1.3 publicKey
	var temSk [32]byte
	copy(temSk[:], sk[:32])

	var A ed.ExtendedGroupElement
	ed.GeScalarMultBase(&A, &temSk)

	A.ToBytes(&pk)

	CPk, DPk := ed.Commit(pk)
	zkPk := ed.Prove(temSk)

	ids := GetIds(cointype, GroupId)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "EDC11"
	s1 := string(CPk[:])
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr := GetChannelValue(ch_t, w.bedc11)
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDC11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed c11 timeout.")}
		ch <- res
		return false
	}

	if w.msg_edc11.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edc11 fail", Err: fmt.Errorf("get all ed c11 fail.")}
		ch <- res
		return false
	}
	var cpks = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			cpks[cur_enode] = CPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc11.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				cpks[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDZK"
	s1 = string(zkPk[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedzk)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDZK",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed zk timeout.")}
		ch <- res
		return false
	}

	if w.msg_edzk.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get w.msg_edzk fail", Err: fmt.Errorf("get all ed zk fail.")}
		ch <- res
		return false
	}

	var zks = make(map[string][64]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			zks[cur_enode] = zkPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edzk.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				zks[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDD11"
	s1 = string(DPk[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd11)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed d11 timeout.")}
		ch <- res
		return false
	}

	if w.msg_edd11.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_edd11 fail", Err: fmt.Errorf("get all ed d11 fail.")}
		ch <- res
		return false
	}
	var dpks = make(map[string][64]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			dpks[cur_enode] = DPk
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd11.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				dpks[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	//1.4
	//fixid := []string{"36550725515126069209815254769857063254012795400127087205878074620099758462980","86773132036836319561089192108022254523765345393585629030875522375234841566222","80065533669343563706948463591465947300529465448793304408098904839998265250318"}
	var uids = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		//num,_ := new(big.Int).SetString(fixid[k],10)
		var t [32]byte
		//copy(t[:], num.Bytes())
		copy(t[:], id.Bytes())
		if len(id.Bytes()) < 32 {
			l := len(id.Bytes())
			for j := l; j < 32; j++ {
				t[j] = byte(0x00)
			}
		}
		uids[en[0]] = t
	}

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CPkFlag := ed.Verify(cpks[en[0]], dpks[en[0]])
		if !CPkFlag {
			fmt.Printf("Error: Commitment(PK) Not Pass at User: %v \n", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:commitment check fail in req ed pubkey", Err: fmt.Errorf("Commitment(PK) Not Pass at User.")}
			ch <- res
			return false
		}
	}

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		dpk := dpks[en[0]]
		var t [32]byte
		copy(t[:], dpk[32:])
		zkPkFlag := ed.Verify_zk(zks[en[0]], t)
		if !zkPkFlag {
			fmt.Printf("Error: ZeroKnowledge Proof (Pk) Not Pass at User: %v \n", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:zeroknowledge check fail", Err: fmt.Errorf("ZeroKnowledge Proof (Pk) Not Pass.")}
			ch <- res
			return false
		}
	}

	// 2.5 calculate a = SHA256(PkU1, {PkU2, PkU3})
	var a [32]byte
	var aDigest [64]byte
	var PkSet []byte

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		dpk := dpks[en[0]]
		PkSet = append(PkSet[:], (dpk[32:])...)
	}
	h := sha512.New()
	dpk := dpks[cur_enode]
	_,err := h.Write(dpk[32:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write dpk fail in calcing SHA256(PkU1, {PkU2, PkU3}", Err: fmt.Errorf("write dpk fail in calcing SHA256(PkU1, {PkU2, PkU3}.")}
	    ch <- res
	    return false
	}

	_,err = h.Write(PkSet)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write pkset fail in calcing SHA256(PkU1, {PkU2, PkU3}", Err: fmt.Errorf("write pkset fail in calcing SHA256(PkU1, {PkU2, PkU3}.")}
	    ch <- res
	    return false
	}

	h.Sum(aDigest[:0])
	ed.ScReduce(&a, &aDigest)

	// 2.6 calculate ask
	var ask [32]byte
	var temSk2 [32]byte
	copy(temSk2[:], sk[:32])
	ed.ScMul(&ask, &a, &temSk2)

	// 2.7 calculate vss
	//////

	_, cfsBBytes, shares := ed.Vss2(ask, w.ThresHold, w.NodeCnt, uids)

	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)

		if enodes == "" {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get enode by uid fail", Err: GetRetErr(ErrGetEnodeByUIdFail)}
			ch <- res
			return false
		}

		if IsCurNode(enodes, cur_enode) {
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")
		for k, v := range shares {
			if strings.EqualFold(k, en[0]) {
				s0 := "EDSHARE1"
				s1 := string(v[:])
				ss := enode + common.Sep + s0 + common.Sep + s1
				SendMsgToPeer(enodes, ss)
				break
			}
		}
	}

	_, tip, cherr = GetChannelValue(ch_t, w.bedshare1)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDSHARE1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed share1 fail.")}
		ch <- res
		return false
	}

	if w.msg_edshare1.Len() != (w.NodeCnt-1) {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edshare1 fail", Err: fmt.Errorf("get all ed share1 fail.")}
		ch <- res
		return false
	}

	var edshares = make(map[string][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			edshares[cur_enode] = shares[cur_enode]
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edshare1.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				edshares[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDCFSB"
	ss = enode + common.Sep + s0 + common.Sep
	for _, v := range cfsBBytes {
		vv := string(v[:])
		ss = ss + vv + common.Sep
	}
	ss = ss + "NULL"

	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedcfsb)
	/////////////////////////request data from dcrm group
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"EDCFSB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed cfsb timeout.")}
		ch <- res
		return false
	}

	if w.msg_edcfsb.Len() != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edcfsb fail", Err: fmt.Errorf("get all ed cfsb fail.")}
		ch <- res
		return false
	}
	var cfsbs = make(map[string][][32]byte)
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			cfsbs[cur_enode] = cfsBBytes
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edcfsb.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				mm := m[2:]
				var cfs [][32]byte
				for _, tmp := range mm {
					if tmp == "NULL" {
						break
					}
					var t [32]byte
					va := []byte(tmp)
					copy(t[:], va[:32])
					cfs = append(cfs, t)
				}
				cfsbs[en[0]] = cfs
				break
			}
			iter = iter.Next()
		}
	}

	// 3.1 verify share
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")

		shareUFlag := ed.Verify_vss(edshares[en[0]], uids[cur_enode], cfsbs[en[0]])

		if !shareUFlag {
			fmt.Printf("Error: VSS Share Verification Not Pass at User: %v \n", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:VSS Share verification fail", Err: fmt.Errorf("VSS Share Verification Not Pass.")}
			ch <- res
			return false
		}
	}

	// 3.2 verify share2
	var a2 [32]byte
	var aDigest2 [64]byte

	var PkSet2 []byte
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])
		PkSet2 = append(PkSet2[:], (temPk[:])...)
	}

	h = sha512.New()
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		_,err = h.Write(PkSet2)
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		var askBBytes [32]byte
		askB.ToBytes(&askBBytes)

		t2 := cfsbs[en[0]]
		tt := t2[0]
		if !bytes.Equal(askBBytes[:], tt[:]) {
			fmt.Printf("Error: VSS Coefficient Verification Not Pass at User: %v \n", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:VSS Coefficient verification fail", Err: fmt.Errorf("VSS Coefficient Verification Not Pass.")}
			ch <- res
			return false
		}
	}

	// 3.3 calculate tSk
	var tSk [32]byte
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		t := edshares[en[0]]
		ed.ScAdd(&tSk, &tSk, &t)
	}

	// 3.4 calculate pk
	var finalPk ed.ExtendedGroupElement
	var finalPkBytes [32]byte

	i := 0
	for _, id := range ids {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temPk [32]byte
		t := dpks[en[0]]
		copy(temPk[:], t[32:])

		h.Reset()
		_,err = h.Write(temPk[:])
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		_,err = h.Write(PkSet2)
		if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip:err.Error(), Err:err}
		    ch <- res
		    return false
		}
		h.Sum(aDigest2[:0])
		ed.ScReduce(&a2, &aDigest2)

		var askB, A ed.ExtendedGroupElement
		A.FromBytes(&temPk)
		ed.GeScalarMult(&askB, &a2, &A)

		if i == 0 {
			finalPk = askB
		} else {
			ed.GeAdd(&finalPk, &finalPk, &askB)
		}

		i++
	}

	finalPk.ToBytes(&finalPkBytes)

	//save the local db
	//sk:pk:tsk:pkfinal
	//save := string(sk[:]) + common.Sep11 + string(pk[:]) + common.Sep11 + string(tSk[:]) + common.Sep11 + string(finalPkBytes[:])
	save := "XXX" + common.Sep11 + string(pk[:]) + common.Sep11 + string(tSk[:]) + common.Sep11 + string(finalPkBytes[:])

	w.edsave.PushBack(save)
	w.edsku1.PushBack(string(sk[:]))
	w.edpk.PushBack(string(finalPkBytes[:]))
*/

	return true
}

func ReqDataFromGroup(msgprex string,wid int,datatype string,trytimes int,timeout int) bool {
	return false //tmp code

    /*w := workers[wid]
    if w == nil {
	return false
    }

    var l *list.List
    var b chan bool
    switch datatype {
	case "AcceptReqAddrRes":
	    l = w.msg_acceptreqaddrres
	    b = w.bacceptreqaddrres
	case "AcceptLockOutRes":
	    l = w.msg_acceptlockoutres
	    b = w.bacceptlockoutres
	case "SendLockOutRes":
	    l = w.msg_sendlockoutres
	    b = w.bsendlockoutres
	case "AcceptSignRes":
	    l = w.msg_acceptsignres 
	    b = w.bacceptsignres
	case "SendSignRes":
	    l = w.msg_sendsignres 
	    b = w.bsendsignres
	case "C1":
	    l = w.msg_c1
	    b = w.bc1
	case "D1":
	    l = w.msg_d1_1
	    b = w.bd1_1
	case "SHARE1":
	    l = w.msg_share1
	    b = w.bshare1
	case "NTILDEH1H2":
	    l = w.msg_zkfact
	    b = w.bzkfact
	case "ZKUPROOF":
	    l = w.msg_zku
	    b = w.bzku
	case "MTAZK1PROOF":
	    l = w.msg_mtazk1proof 
	    b = w.bmtazk1proof
	case "C11":
	    l = w.msg_c11
	    b = w.bc11
	case "KC":
	    l = w.msg_kc
	    b = w.bkc
	case "MKG":
	    l = w.msg_mkg
	    b = w.bmkg
	case "MKW":
	    l = w.msg_mkw
	    b = w.bmkw
	case "DELTA1":
	    l = w.msg_delta1
	    b = w.bdelta1
	case "D11":
	    l = w.msg_d11_1
	    b = w.bd11_1
	case "CommitBigVAB":
	    l = w.msg_commitbigvab
	    b = w.bcommitbigvab
	case "ZKABPROOF":
	    l = w.msg_zkabproof
	    b = w.bzkabproof
	case "CommitBigUT":
	    l = w.msg_commitbigut
	    b = w.bcommitbigut
	case "CommitBigUTD11":
	    l = w.msg_commitbigutd11
	    b = w.bcommitbigutd11
	case "S1":
	    l = w.msg_s1
	    b = w.bs1
	case "SS1":
	    l = w.msg_ss1
	    b = w.bss1
	case "PaillierKey":
	    l = w.msg_paillierkey
	    b = w.bpaillierkey
	case "EDC11":
	    l = w.msg_edc11
	    b = w.bedc11
	case "EDZK":
	    l = w.msg_edzk
	    b = w.bedzk
	case "EDD11":
	    l = w.msg_edd11
	    b = w.bedd11
	case "EDSHARE1":
	    l = w.msg_edshare1
	    b = w.bedshare1
	case "EDCFSB":
	    l = w.msg_edcfsb
	    b = w.bedcfsb
	case "EDC21":
	    l = w.msg_edc21
	    b = w.bedc21
	case "EDZKR":
	    l = w.msg_edzkr
	    b = w.bedzkr
	case "EDD21":
	    l = w.msg_edd21 
	    b = w.bedd21
	case "EDC31":
	    l = w.msg_edc31
	    b = w.bedc31
	case "EDD31":
	    l = w.msg_edd31
	    b = w.bedd31
	case "EDS":
	    l = w.msg_eds 
	    b = w.beds
    }

    if l == nil {
	return false
    }
   
    suss := false
    var wg sync.WaitGroup
    _, enodes := GetGroup(w.groupid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	    node2 := ParseNode(node)
	    if strings.EqualFold(cur_enode,node2) {
		continue
	    }

	    found := findmsg(l,node2)
	    if !found {
		wg.Add(1)
		go func(key string,ll *list.List,ower string,dt string,bb chan bool,times int,tt int) {
		    defer wg.Done()

		    //fmt.Printf("%v===================ReqDataFromGroup, key = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,ower,dt,times,tt)
		    i := 0
		    for i = 0;i < times; i++ {
			//fmt.Printf("%v===================ReqDataFromGroup, key = %v, round i = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,i,ower,dt,times,tt)
			
			if findmsg(ll,ower) {
			    //fmt.Printf("%v===================ReqDataFromGroup, find msg success, key = %v, round i = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,i,ower,dt,times,tt)
			    
			    _, _, err := GetChannelValue(tt, bb) //wait 20 second     //by type
			    if err == nil {
				//fmt.Printf("%v===================ReqDataFromGroup, find msg success and get all data, key = %v, round i = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,i,ower,dt,times,tt)
				suss = true
				if len(b) == 0 {
				    b <- true  //add for exiting other threads
				}
				break
			    }
			}

			//fmt.Printf("%v===================ReqDataFromGroup, no find msg, key = %v, round i = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,i,ower,dt,times,tt)
			
			//enode1 no reciv enode2 c1 data
			//key-enode1:NoReciv:enode2:C1
			noreciv := key + "-" + cur_enode + common.Sep + "NoReciv" + common.Sep + ower + common.Sep + dt   //by type
			SendMsgToDcrmGroup(noreciv, w.groupid)
			_, _, err := GetChannelValue(tt, bb) //wait 20 second     //by type
			if err == nil {
			    //fmt.Printf("%v===================ReqDataFromGroup, no find msg and get all data, key = %v, round i = %v, ower = %v,datatype = %v,times = %v,timeout = %v ========================\n",common.CurrentTime(),key,i,ower,dt,times,tt)
			    suss = true
			    if len(b) == 0 {
				b <- true  //add for exiting other threads
			    }
			    break
			}
		    }
		}(msgprex,l,node2,datatype,b,trytimes,timeout)
	    }
    }
    wg.Wait()
    //fmt.Printf("%v===================ReqDataFromGroup, finish req data, key = %v, status = %v ========================\n",common.CurrentTime(),msgprex,suss)
    return suss*/
}

//ec2
//msgprex = hash
func KeyGenerate_DECDSA(msgprex string, ch chan interface{}, id int, cointype string) bool {
	///////for test only
	/*u1,_ := new(big.Int).SetString("3334747394230983325243207970954899590842441253149295381558648242110081293330",10)
	u2,_ := new(big.Int).SetString("69039181184174029818470298267328820110013585784220774880124345655174594749061",10)
	u3,_ := new(big.Int).SetString("14867692866148859006086889155133300611365049455876397123617203957782293499325",10)
	u4,_ := new(big.Int).SetString("84793511064568272149980886713210270911035531383314504494511304398691848103881",10)
	u5,_ := new(big.Int).SetString("60841277345123397920834696016664146929546891435110670397947900149315293244142",10)

	id1,_ := new(big.Int).SetString("53618612272167874423319834687974778412293696801310558561041950376332309251074",10)
	id2,_ := new(big.Int).SetString("54921957341908846327991236707470353323420933608233375424223802952423356273424",10)
	id3,_ := new(big.Int).SetString("55554820072087080797082013913708076641941533809080830582031668626477915287514",10)
	id4,_ := new(big.Int).SetString("60318458834590464192620032882393176022119815649037676016914795650913223224233",10)
	id5,_ := new(big.Int).SetString("115787261728302521653708661579759215305126272044286142279837734005010875313981",10)

	sku1,_ := new(big.Int).SetString("31191155413895758490308293179882186383085667250661674133654187820857154180677",10)
	sku2,_ := new(big.Int).SetString("47074940619208118544250574667751837749046355150235507843803424053911198813112",10)
	sku3,_ := new(big.Int).SetString("64402190692031667657924912059763629636297143519526964063936831306627647090315",10)
	sku4,_ := new(big.Int).SetString("34772545226428570215016578677967881376777770447360028779798133967936336399940",10)
	sku5,_ := new(big.Int).SetString("79875137852131204821645001934236208017593200315324988641558008769062905261078",10)

	new1,_ := new(big.Int).SetString("90217780269633436353718649612716896878738939932682742626484292501596677805232",10)
	new2,_ := new(big.Int).SetString("93554831225468823981433198553360053376392622858513213953942577456307683005349",10)
	new3,_ := new(big.Int).SetString("67669551554355372044987661383284795264612007389379970801351296782109151089056",10)
	new4,_ := new(big.Int).SetString("109787550781396434316135992389074051324252963495214169195450555312304474730832",10)
	new5,_ := new(big.Int).SetString("48263283217198287895944974605412009346944799039902513035658396575677600708148",10)
	sk := u1
	sk = new(big.Int).Add(sk, u2)
	sk = new(big.Int).Add(sk, u3)
	sk = new(big.Int).Add(sk, u4)
	sk = new(big.Int).Add(sk, u5)
	sk = new(big.Int).Mod(sk, secp256k1.S256().N)

	shareU1 := &ec2.ShareStruct2{Id: id1, Share: sku1}
	shareU2 := &ec2.ShareStruct2{Id: id2, Share: sku2}
	shareU3 := &ec2.ShareStruct2{Id: id3, Share: sku3}
	shareU4 := &ec2.ShareStruct2{Id: id4, Share: sku4}
	shareU5 := &ec2.ShareStruct2{Id: id5, Share: sku5}

	shares := []*ec2.ShareStruct2{shareU1, shareU2, shareU3, shareU4, shareU5}
	computeSK, _ := ec2.Combine2(shares[:3])

	fmt.Println("")
	fmt.Println("[Key Generation][Test] verify vss.Combine:")
	fmt.Println(sk)
	fmt.Println(computeSK)

	//newskU1 := new(big.Int).Mod(new1, secp256k1.S256().N)
	//newskU2 := new(big.Int).Mod(new2, secp256k1.S256().N)
	//newskU3 := new(big.Int).Mod(new3, secp256k1.S256().N)
	//newskU4 := new(big.Int).Mod(new4, secp256k1.S256().N)
	//newskU5 := new(big.Int).Mod(new5, secp256k1.S256().N)
	
	shareNewSkU1 := &ec2.ShareStruct2{Id: id1, Share: new1}
	shareNewSkU2 := &ec2.ShareStruct2{Id: id2, Share: new2}
	shareNewSkU3 := &ec2.ShareStruct2{Id: id3, Share: new3}
	shareNewSkU4 := &ec2.ShareStruct2{Id: id4, Share: new4}
	shareNewSkU5 := &ec2.ShareStruct2{Id: id5, Share: new5}

	sharesNewSkU := []*ec2.ShareStruct2{shareNewSkU1, shareNewSkU2, shareNewSkU3, shareNewSkU4, shareNewSkU5}
	computeNewSK, _ := ec2.Combine2(sharesNewSkU[:4])

	fmt.Println("")
	fmt.Println("测试,新的私钥分片，合起来，是否等于原来的私钥:")
	fmt.Println(sk)
	fmt.Println(computeNewSK)*/
	////////////////////

	if id < 0 || id >= RPCMaxWorker || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return false
	}

	w := workers[id]
	if w.groupid == "" {
		///bug groupid == nil ???
		w, err := FindWorker(msgprex)
		if err != nil || w.groupid == "" {
		    res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		    ch <- res
		    return false
		}
		//////
	}

	ns, _ := GetGroup(w.groupid)
	if ns != w.NodeCnt {
		res := RpcDcrmRes{Ret: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	//ids := GetIds(cointype, w.groupid)

	//time.Sleep(time.Duration(20) * time.Second) //tmp code
	
	//taskDone := make(chan struct{})
	commStopChan := make(chan struct{})
	outCh := make(chan dcrmlib.Message, ns)
	endCh := make(chan keygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := keygen.NewLocalDNode(outCh,endCh,ns,w.ThresHold,2048)
	w.DNode = keyGenDNode
	//keyGenDNode.SetDNodeID(fmt.Sprintf("%v",DoubleHash2(cur_enode,"ECDSA")))
	//fmt.Printf("=========== keygen, node uid = %v ===========\n",keyGenDNode.DNodeID())
	
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
		
		for _,v := range w.PreSaveDcrmMsg {
		    w.DcrmMsg <- v 
		}
	}()
	go ProcessInboundMessages(msgprex,commStopChan,&keyGenWg,ch)
	err := processKeyGen(msgprex,errChan, outCh, endCh)
	if err != nil {
	    fmt.Printf("==========process keygen err = %v ==========\n",err)
	    close(commStopChan)
	    res := RpcDcrmRes{Ret: "", Err: err}
	    ch <- res
	    return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	//*******************!!!Distributed ECDSA Start!!!**********************************

	/*u1, u1Poly, u1PolyG, commitU1G, c1, _, _, commitC1G, u1PaillierPk, u1PaillierSk, status := DECDSAGenKeyRoundOne(msgprex, ch, w)
	if !status {
		return status
	}
	common.Debug("================generate key,round one finish================","key",msgprex)

	u1Shares, status := DECDSAGenKeyRoundTwo(msgprex, cointype, ch, w, u1Poly, c1,ids)
	if !status {
		return status
	}
	common.Debug("================generate key,round two finish================","key",msgprex)

	if !DECDSAGenKeyRoundThree(msgprex, cointype, ch, w, u1PolyG, commitU1G, commitC1G, ids) {
		return false
	}
	common.Debug("================generate key,round three finish================","key",msgprex)

	sstruct, ds, status := DECDSAGenKeyVerifyShareData(msgprex, cointype, ch, w, u1PolyG, u1Shares, ids)
	if !status {
		return status
	}
	common.Debug("================generate key,verify share data finish================","key",msgprex)

	cs, udecom, status := DECDSAGenKeyVerifyCommitment(msgprex, cointype, ch, w, ds, commitU1G, ids)
	if !status {
		return false
	}
	common.Debug("================generate key,verify commitment finish================","key",msgprex)

	ug, status := DECDSAGenKeyCalcPubKey(msgprex, cointype, ch, w, udecom, ids)
	if !status {
		return false
	}
	common.Debug("================generate key,calc pubkey finish================","key",msgprex)

	//bip32
	bip32udecom, status := DECDSAGenKeyVerifyCommitment_Bip32(msgprex, cointype, ch, w, cs,ds, commitC1G, ids)
	if !status {
		return false
	}
	common.Debug("================generate key,verify commitment for bip32 finish================","key",msgprex)
	
	status = DECDSAGenKeyCalcC(msgprex, cointype, ch, w, bip32udecom, ids)
	if !status {
		return false
	}
	common.Debug("================generate key,calc c for bip32 finish================","key",msgprex)
	//

	skU1, status := DECDSAGenKeyCalcPrivKey(msgprex, cointype, ch, w, sstruct, ids)
	if !status {
		return false
	}
	common.Debug("================generate key,calc privkey finish================","key",msgprex)

	u1NtildeH1H2, status := DECDSAGenKeyRoundFour(msgprex, ch, w)
	if !status {
		return false
	}
	common.Debug("================generate key,round four finish================","key",msgprex)

	if !DECDSAGenKeyRoundFive(msgprex, ch, w, u1) {
		return false
	}
	common.Debug("================generate key,round five finish================","key",msgprex)

	if !DECDSAGenKeyVerifyZKU(msgprex, cointype, ch, w, ids, ug) {
		return false
	}
	common.Debug("================generate key,verify zk of u1 finish================","key",msgprex)

	///////////check all nodes success genarate the pubkey
	if !CheckAllNodesPubKeyStatus(msgprex,ch,w) {
	    return false
	}
	///////////

	if !DECDSAGenKeySaveData(cointype, ids, w, ch, skU1, u1PaillierPk, u1PaillierSk, cs, u1NtildeH1H2) {
		return false
	}
	common.Debug("================generate key================","u1",u1,"sku1",skU1,"key",msgprex)*/
	//*******************!!!Distributed ECDSA End!!!**********************************
	return true
}

