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
	"sync"
	"time"
	"errors"
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
	Keytype   string
	GroupID   string
	ThresHold string
	Mode      string
	AcceptTimeOut      string
	TimeStamp string
	Sigs      string
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

	_, _, _, txdata, err := CheckRaw(raw)
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
			SetUpMsgList(raw, curEnode)
			return "Success", "", nil
		}
	}

	return "Failure", "accept fail", fmt.Errorf("accept fail")
}

//--------------------------------------------------------------------------------

// ReqAddrStatus keygen result
type ReqAddrStatus struct {
	Status    string
	PubKey    string
	Tip       string
	Error     string
	AllReply  []NodeReply
	TimeStamp string
}

// GetReqAddrStatus get the result of the keygen request by key
func GetReqAddrStatus(key string) (string, string, error) {
	if key == "" {
	    return "","",errors.New("param error")
	}

	exsit, da := GetPubKeyData([]byte(key))
	///////
	if !exsit || da == nil {
		common.Debug("=====================GetReqAddrStatus,key does not exsit======================", "key", key)
		return "", "smpc back-end internal error:get reqaddr accept data fail from db when GetReqAddrStatus", fmt.Errorf("get reqaddr accept data fail from db")
	}

	ac, ok := da.(*AcceptReqAddrData)
	if !ok {
		return "", "smpc back-end internal error:get reqaddr accept data error from db when GetReqAddrStatus", fmt.Errorf("get reqaddr accept data error from db")
	}

	los := &ReqAddrStatus{Status: ac.Status, PubKey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
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

			if vv.Mode == "0" && !CheckAcc(curEnode, geteracc, vv.Sigs) {
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
}

// smpcGenPubKey generate the pubkey 
// ec2
// msgprex = hash
// cointype = keytype    // EC256K1||ed25519
func smpcGenPubKey(msgprex string, account string, cointype string, ch chan interface{}, mode string, nonce string) {
	if msgprex == "" || account == "" || cointype == "" || mode == "" || nonce == "" {
	    res := RPCSmpcRes{Ret: "", Tip: "param error", Err: errors.New("param error")}
	    ch <- res
	    return
	}

	wk, err := FindWorker(msgprex)
	if err != nil || wk == nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: err}
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
			time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
		}

		if !ok2 {
			return
		}

		itertmp := workers[id].edpk.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edpk fail", Err: GetRetErr(ErrGetGenPubkeyFail)}
			ch <- res
			return
		}
		sedpk := []byte(itertmp.Value.(string))

		itertmp = workers[id].edsave.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edsave fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
			ch <- res
			return
		}

		sedsave := itertmp.Value.(string)
		itertmp = workers[id].edsku1.Front()
		if itertmp == nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get workers[id].edsku1 fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
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
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:encode PubKeyData fail in req ed pubkey", Err: err}
			ch <- res
			return
		}

		ss, err := Compress([]byte(epubs))
		if err != nil {
			common.Error("===============smpcGenPubKey,commpress fail=================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:compress PubKeyData fail in req ed pubkey", Err: err}
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
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
			ch <- res
			return
		}

		err = PutAccountDataToDb(sedpk[:], []byte(pubkeyhex))
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to db fail", Err: err}
			ch <- res
			return
		}

		err = putSkU1ToLocalDb(sedpk[:], []byte(sedsku1))
		if err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
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
				res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
				ch <- res
				return
			}

			err = PutAccountDataToDb([]byte(key), []byte(pubkeyhex))
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to db fail", Err: err}
				ch <- res
				return
			}

			err = putSkU1ToLocalDb([]byte(key), []byte(sedsku1))
			if err != nil {
				res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
				ch <- res
				return
			}
		}

		res := RPCSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
		ch <- res
		return
	}

	ok := false
	for j := 0; j < recalcTimes; j++ { //try 20 times
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
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get pkx fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spkx := iter.Value.(string)
	pkx, _ := new(big.Int).SetString(spkx, 10)
	iter = workers[id].pky.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get pky fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenPubkeyFail)}
		ch <- res
		return
	}
	spky := iter.Value.(string)
	pky, _ := new(big.Int).SetString(spky, 10)
	ys := secp256k1.S256().Marshal(pkx, pky)

	iter = workers[id].save.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get save data fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	save := iter.Value.(string)
	iter = workers[id].sku1.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sku1 fail in req ec2 pubkey", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}
	sku1 := iter.Value.(string)

	err = putSkU1ToLocalDb(ys, []byte(sku1))
	if err != nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:put sku1 to local db fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}

	//bip32
	iter = workers[id].bip32c.Front()
	if iter == nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get c for bip32 fail in req ec2 pubkey", Err: fmt.Errorf("get c for bip32 fail in req ec2 pubkey")}
		ch <- res
		return
	}
	bip32c := iter.Value.(string)
	err = putBip32cToLocalDb(ys, []byte(bip32c))
	if err != nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:put bip32c to local db fail", Err: GetRetErr(ErrGetGenSaveDataFail)}
		ch <- res
		return
	}

	tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
	rk := Keccak256Hash([]byte(strings.ToLower(account + ":" + cointype + ":" + wk.groupid + ":" + nonce + ":" + wk.limitnum + ":" + mode))).Hex()

	pubkeyhex := hex.EncodeToString(ys)
	common.Info("================ smpc_genpubkey,pubkey generated successfully ===================","pkx",pkx,"pky",pky,"pubkey hex",pubkeyhex)

	pubs := &PubKeyData{Key: msgprex, Account: account, Pub: string(ys), Save: save, Nonce: nonce, GroupID: wk.groupid, LimitNum: wk.limitnum, Mode: mode, KeyGenTime: tt}
	epubs, err := Encode2(pubs)
	if err != nil {
		common.Error("===============smpcGenPubKey,encode fail===================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", rk)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:encode PubKeyData fail in req ec2 pubkey", Err: err}
		ch <- res
		return
	}

	ss, err := Compress([]byte(epubs))
	if err != nil {
		common.Error("===============smpcGenPubKey,compress fail===================", "err", err, "account", account, "pubkey", pubkeyhex, "nonce", nonce, "key", rk)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:compress PubKeyData fail in req ec2 pubkey", Err: err}
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
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
		ch <- res
		return
	}

	err = PutAccountDataToDb(ys, []byte(pubkeyhex))
	if err != nil {
		common.Error("================================smpcGenPubKey,put account data to local db fail=========================", "err", err, "key", msgprex)
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to local db fail", Err: err}
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
			common.Error("================================dcrm_genPubKey,put pubkey data to localdb fail=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put pubkey data fail", Err: err}
			ch <- res
			return
		}

		err = PutAccountDataToDb([]byte(key), []byte(pubkeyhex))
		if err != nil {
			common.Error("================================smpcGenPubKey,put account data to localdb fail=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put account data to local db fail", Err: err}
			ch <- res
			return
		}

		err = putSkU1ToLocalDb([]byte(key), []byte(sku1))
		if err != nil {
			common.Error("================================smpcGenPubKey,put sku1 data to local db fail,=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put sku1 data fail", Err: err}
			ch <- res
			return
		}

		err = putBip32cToLocalDb([]byte(key), []byte(bip32c))
		if err != nil {
			common.Error("================================smpcGenPubKey,put bip32c to local db fail,=========================", "err", err, "key", msgprex)
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error: put bip32c fail", Err: err}
			ch <- res
			return
		}
	}

	res := RPCSmpcRes{Ret: pubkeyhex, Tip: "", Err: nil}
	ch <- res
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
	keyGenDNode := keygen.NewLocalDNode(outCh, endCh, ns, w.ThresHold, 2048)
	w.DNode = keyGenDNode
	_,UID := GetNodeUID(curEnode, "EC256K1",w.groupid)
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v", UID))
	fmt.Printf("=========== KeyGenerateDECDSA, current node uid = %v ===========\n", keyGenDNode.DNodeID())

	w.MsgToEnode[w.DNode.DNodeID()] = curEnode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
			fmt.Printf("==========KeyGenerateDECDSA, node start, key = %v, err = %v ==========\n", msgprex,err)
			close(errChan)
		}

		exsit, da := GetReqAddrInfoData([]byte(msgprex))
		common.Debug("==========KeyGenerateDECDSA, get reqaddr info from db==================","key",msgprex,"exsit",exsit)
		if exsit {
			ac, ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
				common.Debug("==========KeyGenerateDECDSA, get reqaddr info from db==================","key",msgprex,"ac",ac)
				HandleC1Data(ac, w.sid)
			}
		}
	}()
	go ProcessInboundMessages(msgprex, commStopChan, &keyGenWg, ch)
	err := processKeyGen(msgprex, errChan, outCh, endCh)
	if err != nil {
		fmt.Printf("==========KeyGenerateDECDSA,process keygen, key = %v,err = %v ==========\n", msgprex,err)
		close(commStopChan)
		res := RPCSmpcRes{Ret: "", Err: err}
		ch <- res
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
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker id", Err: GetRetErr(ErrGetWorkerIDError)}
		ch <- res
		return false
	}

	w := workers[id]
	GroupID := w.groupid
	if GroupID == "" {
		res := RPCSmpcRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return false
	}

	ns, _ := GetGroup(GroupID)
	if ns != w.NodeCnt {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:the group is not ready", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return false
	}

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan edkeygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	keyGenDNode := edkeygen.NewLocalDNode(outCh, endCh, ns, w.ThresHold)
	w.DNode = keyGenDNode
	_,UID := GetNodeUID(curEnode, "ED25519",w.groupid)
	keyGenDNode.SetDNodeID(fmt.Sprintf("%v", UID))
	w.MsgToEnode[w.DNode.DNodeID()] = curEnode

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	go func() {
		defer keyGenWg.Done()
		if err := keyGenDNode.Start(); nil != err {
			fmt.Printf("==========KeyGenerateDEDDSA,node start, key = %v, err = %v ==========\n", msgprex,err)
			close(errChan)
		}

		exsit, da := GetReqAddrInfoData([]byte(msgprex))
		common.Debug("=========================KeyGenerateDEDDSA,get reqaddr info from db===========================","key",msgprex,"exsit",exsit)
		if exsit {
			ac, ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
				common.Debug("=========================KeyGenerateDEDDSA,get reqaddr info from db===========================","key",msgprex,"ac",ac)
				HandleC1Data(ac, w.sid)
			}
		}
	}()
	go ProcessInboundMessagesEDDSA(msgprex, commStopChan, &keyGenWg, ch)
	err := processKeyGenEDDSA(msgprex, errChan, outCh, endCh)
	if err != nil {
		fmt.Printf("==========KeyGenerateDEDDSA,process ed keygen, err = %v, key = %v ==========\n", err, msgprex)
		close(commStopChan)
		res := RPCSmpcRes{Ret: "", Err: err}
		ch <- res
		return false
	}

	close(commStopChan)
	keyGenWg.Wait()

	return true
}


