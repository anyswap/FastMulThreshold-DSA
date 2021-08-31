
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
	"strings"
	"sync"
	"time"

	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"crypto/hmac"
	"crypto/sha512"
)

type SmpcAccountsBalanceRes struct {
	PubKey   string
	Balances []SubAddressBalance
}

type SubAddressBalance struct {
	Cointype string
	SmpcAddr string
	Balance  string
}

type SmpcAddrRes struct {
	Account  string
	PubKey   string
	SmpcAddr string
	Cointype string
}

type SmpcPubkeyRes struct {
	Account     string
	PubKey      string
	SmpcAddress map[string]string
}

//--------------------------------------------------------------------------

func GetPubKeyData2(key string, account string, cointype string) (string, string, error) {
	if key == "" || cointype == "" {
		return "", "smpc back-end internal error:parameter error", fmt.Errorf("get pubkey data param error.")
	}

	exsit,da := GetPubKeyData([]byte(key))
	if !exsit {
		return "", "dcrm back-end internal error:get data from db fail ", fmt.Errorf("dcrm back-end internal error:get data from db fail")
	}

	pubs,ok := da.(*PubKeyData)
	if !ok {
		return "", "dcrm back-end internal error:get data from db fail", fmt.Errorf("dcrm back-end internal error:get data from db fail")
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	var m interface{}
	if !strings.EqualFold(cointype, "ALL") {

		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
		}

		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			return "", "smpc back-end internal error:get smpc addr fail from pubkey:" + pubkey, fmt.Errorf("req addr fail.")
		}

		m = &SmpcAddrRes{Account: account, PubKey: pubkey, SmpcAddr: ctaddr, Cointype: cointype}
		b, _ := json.Marshal(m)
		return string(b), "", nil
	}

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

	m = &SmpcPubkeyRes{Account: account, PubKey: pubkey, SmpcAddress: addrmp}
	b, _ := json.Marshal(m)
	return string(b), "", nil
}

//-------------------------------------------------------------------------------------------

func GetAccountsBalance(pubkey string, geter_acc string) (interface{}, string, error) {
	keytmp, err2 := hex.DecodeString(pubkey)
	if err2 != nil {
		return nil, "decode pubkey fail", err2
	}

	ret, tip, err := GetPubKeyData2(string(keytmp), pubkey, "ALL")
	var m interface{}
	if err == nil {
		dp := SmpcPubkeyRes{}
		_ = json.Unmarshal([]byte(ret), &dp)
		balances := make([]SubAddressBalance, 0)
		var wg sync.WaitGroup
		ret  := common.NewSafeMap(10)
		for cointype, subaddr := range dp.SmpcAddress {
			wg.Add(1)
			go func(cointype, subaddr string) {
				defer wg.Done()
				balance, _, err := GetBalance(pubkey, cointype, subaddr)
				if err != nil {
					balance = "0"
				}
				ret.WriteMap(strings.ToLower(cointype),&SubAddressBalance{Cointype: cointype, SmpcAddr: subaddr, Balance: balance})
			}(cointype, subaddr)
		}
		wg.Wait()
		for _, cointype := range coins.Cointypes {
			subaddrbal,exist := ret.ReadMap(strings.ToLower(cointype))
			if exist && subaddrbal != nil {
			    subbal,ok := subaddrbal.(*SubAddressBalance)
			    if ok && subbal != nil {
				balances = append(balances, *subbal)
				ret.DeleteMap(strings.ToLower(cointype))
			    }
			}
		}
		m = &SmpcAccountsBalanceRes{PubKey: pubkey, Balances: balances}
	}

	return m, tip, err
}

//----------------------------------------------------------------------------------------------------

func GetBalance(account string, cointype string, smpcaddr string) (string, string, error) {

	if strings.EqualFold(cointype, "EVT1") || strings.EqualFold(cointype, "EVT") { ///tmp code
		return "0","",nil  //TODO
	}

	if strings.EqualFold(cointype, "EOS") {
		return "0", "", nil //TODO
	}

	if strings.EqualFold(cointype, "BEP2GZX_754") {
		return "0", "", nil //TODO
	}

	h := coins.NewCryptocoinHandler(cointype)
	if h == nil {
		return "", "coin type is not supported", fmt.Errorf("coin type is not supported")
	}

	ba, err := h.GetAddressBalance(smpcaddr, "")
	if err != nil {
		return "0","smpc back-end internal error:get smpc addr balance fail,but return 0",nil
	}

	if h.IsToken() {
	    if ba.TokenBalance.Val == nil {
		return "0", "token balance is nil,but return 0", nil
	    }

	    ret := fmt.Sprintf("%v", ba.TokenBalance.Val)
	    return ret, "", nil
	}

	if ba.CoinBalance.Val == nil {
	    return "0", "coin balance is nil,but return 0", nil
	}

	ret := fmt.Sprintf("%v", ba.CoinBalance.Val)
	return ret, "", nil
}

//----------------------------------------------------------------------------------

func GetAddr(pubkey string,cointype string) (string,string,error) {
    if pubkey == "" || cointype == "" {
	return "","param error",fmt.Errorf("param error")
    }

     h := coins.NewCryptocoinHandler(cointype)
     if h == nil {
	     return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported.")
     }

     ctaddr, err := h.PublicKeyToAddress(pubkey)
     if err != nil {
	     return "", "smpc back-end internal error:get smpc addr fail from pubkey:" + pubkey, fmt.Errorf("get smpc  addr fail.")
     }

     return ctaddr, "", nil
}

//--------------------------------------------------------------------------------

type Err struct {
	Info string
}

func (e Err) Error() string {
	return e.Info
}

type PubAccounts struct {
	Group []AccountsList
}
type AccountsList struct {
	GroupID  string
	Accounts []PubKeyInfo
}

type PubKeyInfo struct {
    PubKey string
    ThresHold string
    TimeStamp string
}

func GetAccounts(geter_acc, mode string) (interface{}, string, error) {
	gp  := common.NewSafeMap(10)
	var wg sync.WaitGroup
	iter := db.NewIterator()
	for iter.Next() {
	    key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
	    exsit,da := GetPubKeyData(key2) 
	    if !exsit || da == nil {
		continue
	    }
	    
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptReqAddrData)
		if vv == nil || !ok {
		    return
		}

		if vv.Mode == "1" {
			if !strings.EqualFold(vv.Account,geter_acc) {
			    return
			}
		}

		if vv.Mode == "0" && !CheckAcc(cur_enode,geter_acc,vv.Sigs) {
		    return
		}

		smpcpks, _ := hex.DecodeString(vv.PubKey)
		exsit,data2 := GetPubKeyData(smpcpks[:])
		if !exsit || data2 == nil {
		    return
		}

		pd,ok := data2.(*PubKeyData)
		if !ok || pd == nil {
		    return
		}

		pubkeyhex := hex.EncodeToString([]byte(pd.Pub))
		gid := pd.GroupId
		md := pd.Mode
		limit := pd.LimitNum
		if mode == md {
			al, exsit := gp.ReadMap(strings.ToLower(gid))
			if exsit && al != nil {
			    al2,ok := al.([]PubKeyInfo)
			    if ok && al2 != nil {
				tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
				al2 = append(al2, tmp)
				//gp[gid] = al
				gp.WriteMap(strings.ToLower(gid),al2)
			    }
			} else {
				a := make([]PubKeyInfo, 0)
				tmp := PubKeyInfo{PubKey:pubkeyhex,ThresHold:limit,TimeStamp:pd.KeyGenTime}
				a = append(a, tmp)
				gp.WriteMap(strings.ToLower(gid),a)
				//gp[gid] = a
			}
		}
	    }(string(key2),da)
	}
	iter.Release()
	wg.Wait()
	
	als := make([]AccountsList, 0)
	key,value := gp.ListMap()
	for j :=0;j < len(key);j++ {
	    v,ok := value[j].([]PubKeyInfo)
	    if ok {
		alNew := AccountsList{GroupID: key[j], Accounts: v}
		als = append(als, alNew)
	    }
	}

	pa := &PubAccounts{Group: als}
	return pa, "", nil
}

//-----------------------------------------------------------------------------------------

func GetBip32ChildKey(rootpubkey string,inputcode string) (string,string,error) {
    if rootpubkey == "" || inputcode == "" {
	return "","param error",fmt.Errorf("param error")
    }

    indexs := strings.Split(inputcode, "/")
    if len([]rune(rootpubkey)) != 130 || len(indexs) < 2 || indexs[0] != "m" {
	return "","param error",fmt.Errorf("param error")
    }

    smpcpks, _ := hex.DecodeString(rootpubkey)
    exsit,da := GetPubKeyData(smpcpks[:])
    if !exsit {
	common.Debug("============================get bip32 child key,not exist pubkey data===========================","pubkey",rootpubkey)
	return "","get bip32 child key,not exist pubkey data",fmt.Errorf("get bip32 child key,not exist pubkey data")
    }

    _,ok := da.(*PubKeyData)
    if !ok {
	common.Debug("============================get bip32 child key,pubkey data error==========================","pubkey",rootpubkey)
	return "","get bip32 child key,pubkey data error",fmt.Errorf("get bip32 child key,pubkey data error")
    }

    smpcpub := (da.(*PubKeyData)).Pub
    smpcpkx, smpcpky := secp256k1.S256().Unmarshal(([]byte(smpcpub))[:])

    ///sku1
    da2 := getSkU1FromLocalDb(smpcpks[:])
    if da2 == nil {
	return "","get sku1 fail",fmt.Errorf("get sku1 fail")
    }
    sku1 := new(big.Int).SetBytes(da2)
    if sku1 == nil {
	return "","get sku1 error",fmt.Errorf("get sku1 error")
    }
    //bip32c
    da3 := getBip32cFromLocalDb(smpcpks[:])
    if da3 == nil {
	return "","get bip32c fail",fmt.Errorf("get bip32c fail")
    }
    bip32c := new(big.Int).SetBytes(da3)
    if bip32c == nil {
	return "","get bip32c error",fmt.Errorf("get bip32c error")
    }

    TRb := bip32c.Bytes()
    childPKx := smpcpkx
    childPKy := smpcpky 
    childSKU1 := sku1
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
	
    ys := secp256k1.S256().Marshal(childPKx,childPKy)
    pubkeyhex := hex.EncodeToString(ys)

    ///
    pubtmp := Keccak256Hash([]byte(strings.ToLower(rootpubkey))).Hex()
    gids := GetPrePubGids(pubtmp)
    common.Debug("============================get bip32 child key==========================","get gids",gids,"pubkey",rootpubkey)
    for _,gid := range gids {
	pub := Keccak256Hash([]byte(strings.ToLower(rootpubkey + ":" + inputcode + ":" + gid))).Hex()
	//if NeedToStartPreBip32(pub) {
	    //for _,gid := range pre.SubGid {
		go func(gg string) {
		    PutPreSigal(pub,true)

		    err := SavePrekeyToDb(rootpubkey,inputcode,gg)
		    if err != nil {
			common.Error("=========================get bip32 child key,save (pubkey,inputcode,gid) to db fail.=======================","pubkey",rootpubkey,"inputcode",inputcode,"gid",gg,"err",err)
			return
		    }

		    common.Info("===================before generate pre-sign data for bip32===============","current total number of the data ",GetTotalCount(rootpubkey,inputcode,gg),"the number of remaining pre-sign data",(PreBip32DataCount-GetTotalCount(rootpubkey,inputcode,gg)),"pub",pub,"pubkey",rootpubkey,"input code",inputcode,"sub-groupid",gg)
		    for {
			    index,need := NeedPreSignForBip32(rootpubkey,inputcode,gg)
			    if need && index != -1 && GetPreSigal(pub) {
				    tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
				    nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt))).Hex()
				    ps := &PreSign{Pub:rootpubkey,InputCode:inputcode,Gid:gg,Nonce:nonce}

				    m := make(map[string]string)
				    psjson,err := ps.MarshalJSON()
				    if err == nil {
					m["PreSign"] = string(psjson) 
				    }
				    m["Type"] = "PreSign"
				    val,err := json.Marshal(m)
				    if err != nil {
					time.Sleep(time.Duration(10000000))
					continue 
				    }
				    SendMsgToSmpcGroup(string(val),gg)

				    rch := make(chan interface{}, 1)
				    SetUpMsgList3(string(val),cur_enode,rch)
				    _, _,cherr := GetChannelValue(ch_t+10,rch)
				    if cherr != nil {
					common.Error("=====================ExcutePreSignData, failed to pre-generate sign data.========================","pubkey",rootpubkey,"err",cherr,"Index",index)
				    }

				    common.Info("===================generate pre-sign data for bip32===============","current total number of the data ",GetTotalCount(rootpubkey,inputcode,gg),"the number of remaining pre-sign data",(PreBip32DataCount-GetTotalCount(rootpubkey,inputcode,gg)),"pub",pub,"pubkey",rootpubkey,"inputcode",inputcode,"sub-groupid",gg)
			    } 

			    time.Sleep(time.Duration(1000000))
		    }
		}(gid)
	    //}
	//}
    }
    //

    addr,_,err := GetSmpcAddr(pubkeyhex)
    if err != nil {
	return "","get bip32 pubkey error",fmt.Errorf("get bip32 pubkey error")
    }
    fmt.Printf("===================GetBip32ChildKey, get bip32 pubkey success, rootpubkey = %v, inputcode = %v, child pubkey = %v, addr = %v ===================\n",rootpubkey,inputcode,pubkeyhex,addr)

    return pubkeyhex,"",nil
}

