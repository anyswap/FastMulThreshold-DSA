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
	"strings"
	"sync"
	"strconv"
	"time"

	"crypto/hmac"
	"crypto/sha512"
	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
)

// AccountsBalanceRes the balance of all smpc addr by pubkey
type AccountsBalanceRes struct {
	PubKey   string
	Balances []SubAddressBalance
}

// SubAddressBalance the balance of smpc addr 
type SubAddressBalance struct {
	Cointype string
	SmpcAddr string
	Balance  string
}

// AddrRes accout ---> pubkey ---> smpc addr by special cointype
type AddrRes struct {
	Account  string
	PubKey   string
	SmpcAddr string
	Cointype string
}

// PubkeyRes account --> pubkey --> smpc addrs
type PubkeyRes struct {
	Account     string
	PubKey      string
	SmpcAddress map[string]string
}

//--------------------------------------------------------------------------

// GetPubKeyData2 get pubkey data by key/accout/contype
// pubkey data,such as : account,pubkey,smpc address,cointype 
func GetPubKeyData2(key string, account string, cointype string) (string, string, error) {
	if key == "" || cointype == "" {
		return "", "smpc back-end internal error:parameter error", fmt.Errorf("get pubkey data param error")
	}

	exsit, da := GetPubKeyData([]byte(key))
	if !exsit {
		return "", "", fmt.Errorf("get data from db fail")
	}

	pubs, ok := da.(*PubKeyData)
	if !ok {
		return "", "", fmt.Errorf("get data from db fail")
	}

	pubkey := hex.EncodeToString([]byte(pubs.Pub))
	var m interface{}
	if !strings.EqualFold(cointype, "ALL") {

		h := coins.NewCryptocoinHandler(cointype)
		if h == nil {
			return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported")
		}

		ctaddr, err := h.PublicKeyToAddress(pubkey)
		if err != nil {
			return "", "smpc back-end internal error:get smpc addr fail from pubkey:" + pubkey,err 
		}

		m = &AddrRes{Account: account, PubKey: pubkey, SmpcAddr: ctaddr, Cointype: cointype}
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

	m = &PubkeyRes{Account: account, PubKey: pubkey, SmpcAddress: addrmp}
	b, _ := json.Marshal(m)
	return string(b), "", nil
}

//-------------------------------------------------------------------------------------------

// GetAccountsBalance Obtain SMPC addresses in different currencies in pubkey, and then obtain its balance 
func GetAccountsBalance(pubkey string, geteracc string) (interface{}, string, error) {
    	if pubkey == "" || geteracc == "" {
	    return nil,"",errors.New("param error")
	}

	keytmp, err2 := hex.DecodeString(pubkey)
	if err2 != nil {
		return nil, "decode pubkey fail", err2
	}

	ret, tip, err := GetPubKeyData2(string(keytmp), pubkey, "ALL")
	var m interface{}
	if err == nil {
		dp := PubkeyRes{}
		_ = json.Unmarshal([]byte(ret), &dp)
		balances := make([]SubAddressBalance, 0)
		var wg sync.WaitGroup
		ret := common.NewSafeMap(10)
		for cointype, subaddr := range dp.SmpcAddress {
			wg.Add(1)
			go func(cointype, subaddr string) {
				defer wg.Done()
				balance, _, err := GetBalance(pubkey, cointype, subaddr)
				// if get balance fail,and set 0,and go on.
				if err != nil {
					balance = "0"
				}
				ret.WriteMap(strings.ToLower(cointype), &SubAddressBalance{Cointype: cointype, SmpcAddr: subaddr, Balance: balance})
			}(cointype, subaddr)
		}
		wg.Wait()
		for _, cointype := range coins.Cointypes {
			subaddrbal, exist := ret.ReadMap(strings.ToLower(cointype))
			if exist && subaddrbal != nil {
				subbal, ok := subaddrbal.(*SubAddressBalance)
				if ok && subbal != nil {
					balances = append(balances, *subbal)
					ret.DeleteMap(strings.ToLower(cointype))
				}
			}
		}
		m = &AccountsBalanceRes{PubKey: pubkey, Balances: balances}
	}

	return m, tip, err
}

//----------------------------------------------------------------------------------------------------

// GetBalance get the balance by smpc address
func GetBalance(account string, cointype string, smpcaddr string) (string, string, error) {
    	if account == "" || cointype == "" || smpcaddr == "" {
	    return "","",errors.New("param error")
	}

	if strings.EqualFold(cointype, "EVT1") || strings.EqualFold(cointype, "EVT") { ///tmp code
		return "0", "", nil //TODO
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
	// get smpc addr balance fail,and return 0,not return err
	if err != nil {
		return "0", "smpc back-end internal error:get smpc addr balance fail,but return 0", nil
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

// GetAddr Obtain SMPC addresses in different currencies in pubkey
func GetAddr(pubkey string, cointype string) (string, string, error) {
	if pubkey == "" || cointype == "" {
		return "", "param error", fmt.Errorf("param error")
	}

	h := coins.NewCryptocoinHandler(cointype)
	if h == nil {
		return "", "cointype is not supported", fmt.Errorf("req addr fail.cointype is not supported")
	}

	ctaddr, err := h.PublicKeyToAddress(pubkey)
	if err != nil {
		return "", "smpc back-end internal error:get smpc addr fail from pubkey:" + pubkey,err 
	}

	return ctaddr, "", nil
}

//--------------------------------------------------------------------------------

// Err error info
type Err struct {
	Info string
}

// Error error string
func (e Err) Error() string {
	return e.Info
}

// PubAccounts all accounts generate by all group
type PubAccounts struct {
	Group []AccountsList
}

// AccountsList gid --- > generated in this group
type AccountsList struct {
	GroupID  string
	Accounts []PubKeyInfo
}

// PubKeyInfo pubkey info
type PubKeyInfo struct {
	PubKey    string
	ThresHold string
	TimeStamp string
}

// GetAccounts get all accounts generated by special account
func GetAccounts(geteracc, mode string) (interface{}, string, error) {
	if accountsdb == nil {
		return nil, "", fmt.Errorf("get accounts fail")
	}

	gp := common.NewSafeMap(10)
	var wg sync.WaitGroup

	iter := accountsdb.NewIterator()
	for iter.Next() {
		k := string(iter.Key())
		v := string(iter.Value())

		wg.Add(1)
		go func(key string, value interface{}) {
			defer wg.Done()

			pubkey, ok := value.(string)
			if !ok || pubkey == "" {
				return
			}

			smpcpks, err := hex.DecodeString(pubkey)
			if err != nil {
			    return
			}

			exsit, data2 := GetPubKeyData(smpcpks[:])
			if !exsit || data2 == nil {
				return
			}

			pd, ok := data2.(*PubKeyData)
			if !ok || pd == nil {
				return
			}

			pubkeyhex := hex.EncodeToString([]byte(pd.Pub))
			gid := pd.GroupID
			md := pd.Mode
			limit := pd.LimitNum
			if mode == md {
				al, exsit := gp.ReadMap(strings.ToLower(gid))
				if exsit && al != nil {
					al2, ok := al.([]PubKeyInfo)
					if ok && al2 != nil {
						tmp := PubKeyInfo{PubKey: pubkeyhex, ThresHold: limit, TimeStamp: pd.KeyGenTime}
						al2 = append(al2, tmp)
						//gp[gid] = al
						gp.WriteMap(strings.ToLower(gid), al2)
					}
				} else {
					a := make([]PubKeyInfo, 0)
					tmp := PubKeyInfo{PubKey: pubkeyhex, ThresHold: limit, TimeStamp: pd.KeyGenTime}
					a = append(a, tmp)
					gp.WriteMap(strings.ToLower(gid), a)
					//gp[gid] = a
				}
			}
		}(k, v)
	}
	iter.Release()
	wg.Wait()

	als := make([]AccountsList, 0)
	key, value := gp.ListMap()
	for j := 0; j < len(key); j++ {
		v, ok := value[j].([]PubKeyInfo)
		if ok {
			alNew := AccountsList{GroupID: key[j], Accounts: v}
			als = append(als, alNew)
		}
	}

	pa := &PubAccounts{Group: als}
	return pa, "", nil
}

//-----------------------------------------------------------------------------------------

// GetBip32ChildKey rootpubkey is the total public key of the root node
// the inputcode format is "m / X1 / x2 /... / xn", where x1,..., xn is the index number of the child node of each level, which is in decimal format, for example: "m / 1234567890123456789012345678901234567890123456789012323455678901234" 
// the return value is the sub public key of the X1 / x2 /... / xn sub node of the total public key of the root node.  
func GetBip32ChildKey(rootpubkey string, inputcode string,keytype string,mode string) (string, string, error) {
	if rootpubkey == "" || inputcode == "" {
		return "", "param error", fmt.Errorf("param error")
	}

	indexs := strings.Split(inputcode, "/")
	if len([]rune(rootpubkey)) != 130 || len(indexs) < 2 || indexs[0] != "m" {
		return "", "param error", fmt.Errorf("param error")
	}

	smpcpks, err := hex.DecodeString(rootpubkey)
	if err != nil {
	    return "", "", err 
	}

	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit {
		common.Debug("============================get bip32 child key,not exist pubkey data===========================", "pubkey", rootpubkey)
		return "", "get bip32 child key,not exist pubkey data", fmt.Errorf("get bip32 child key,not exist pubkey data")
	}

	_, ok := da.(*PubKeyData)
	if !ok {
		common.Debug("============================get bip32 child key,pubkey data error==========================", "pubkey", rootpubkey)
		return "", "get bip32 child key,pubkey data error", fmt.Errorf("get bip32 child key,pubkey data error")
	}

	smpcpub := (da.(*PubKeyData)).Pub
	smpcpkx, smpcpky := secp256k1.S256(keytype).Unmarshal(([]byte(smpcpub))[:])

	///sku1
	da2 := getSkU1FromLocalDb(smpcpks[:])
	if da2 == nil {
		return "", "get sku1 fail", fmt.Errorf("get sku1 fail")
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		return "", "get sku1 error", fmt.Errorf("get sku1 error")
	}
	//bip32c
	da3 := getBip32cFromLocalDb(smpcpks[:])
	if da3 == nil {
		return "", "get bip32c fail", fmt.Errorf("get bip32c fail")
	}
	bip32c := new(big.Int).SetBytes(da3)
	if bip32c == nil {
		return "", "get bip32c error", fmt.Errorf("get bip32c error")
	}

	TRb := bip32c.Bytes()
	childPKx := smpcpkx
	childPKy := smpcpky
	childSKU1 := sku1
	for idxi := 1; idxi < len(indexs); idxi++ {
		h := hmac.New(sha512.New, TRb)
		_,err := h.Write(childPKx.Bytes())
		if err != nil {
		    return "","",err
		}
		_,err = h.Write(childPKy.Bytes())
		if err != nil {
		    return "","",err
		}
		_,err = h.Write([]byte(indexs[idxi]))
		if err != nil {
		    return "","",err
		}
		T := h.Sum(nil)
		TRb = T[32:]
		TL := new(big.Int).SetBytes(T[:32])

		childSKU1 = new(big.Int).Add(TL, childSKU1)
		childSKU1 = new(big.Int).Mod(childSKU1, secp256k1.S256(keytype).N1())

		TLGx, TLGy := secp256k1.S256(keytype).ScalarBaseMult(TL.Bytes())
		childPKx, childPKy = secp256k1.S256(keytype).Add(TLGx, TLGy, childPKx, childPKy)
	}

	ys := secp256k1.S256(keytype).Marshal(childPKx, childPKy)
	pubkeyhex := hex.EncodeToString(ys)

	///
	pubtmp := Keccak256Hash([]byte(strings.ToLower(rootpubkey))).Hex()
	gids := GetPrePubGids(pubtmp)
	common.Debug("============================get bip32 child key==========================", "get gids", gids, "pubkey", rootpubkey)
	for _, gid := range gids {
		pub := Keccak256Hash([]byte(strings.ToLower(rootpubkey + ":" + inputcode + ":" + gid))).Hex()
		//if NeedToStartPreBip32(pub) {
		//for _,gid := range pre.SubGid {
		go func(gg string) {
			PutPreSigal(pub, true)

			if mode != "2" {
			    err := SavePrekeyToDb(rootpubkey, inputcode, gg,keytype)
			    if err != nil {
				    common.Error("=========================get bip32 child key,save (pubkey,inputcode,gid) to db fail.=======================", "pubkey", rootpubkey, "inputcode", inputcode, "gid", gg, "err", err)
				    return
			    }
			}
			
			common.Info("===================before generate pre-sign data for bip32===============", "current total number of the data ", GetTotalCount(rootpubkey, inputcode, gg), "the number of remaining pre-sign data", (PreBip32DataCount - GetTotalCount(rootpubkey, inputcode, gg)), "pub", pub, "pubkey", rootpubkey, "input code", inputcode, "sub-groupid", gg)
			for {
				index, need := NeedPreSignForBip32(rootpubkey, inputcode, gg)
				if need && index != -1 && GetPreSigal(pub) {
					tt := fmt.Sprintf("%v", time.Now().UnixNano()/1e6)
					nonce := Keccak256Hash([]byte(strings.ToLower(pub + tt))).Hex()
					ps := &PreSign{Pub: rootpubkey, InputCode: inputcode, Gid: gg, Nonce: nonce,KeyType:keytype}

					m := make(map[string]string)
					psjson, err := ps.MarshalJSON()
					if err == nil {
						m["PreSign"] = string(psjson)
					}
					m["Type"] = "PreSign"
					val, err := json.Marshal(m)
					if err != nil {
						time.Sleep(time.Duration(10000000))
						continue
					}
					SendMsgToSmpcGroup(string(val), gg)
					//check msg
					msghash := Keccak256Hash([]byte(strings.ToLower(string(val)))).Hex()
					_,exist := MsgReceiv.ReadMap(msghash)
					if exist {
					    continue
					}

					MsgReceiv.WriteMap(msghash,NowMilliStr())

					rch := make(chan interface{}, 1)
					SetUpMsgList3(string(val), curEnode, rch)
					_, _, cherr := GetChannelValue(cht+10, rch)
					if cherr != nil {
						common.Error("=====================ExcutePreSignData, failed to pre-generate sign data.========================", "pubkey", rootpubkey, "err", cherr, "Index", index)
						time.Sleep(time.Duration(1000000))
						continue
					}

					common.Info("===================generate pre-sign data for bip32===============", "current total number of the data ", GetTotalCount(rootpubkey, inputcode, gg), "the number of remaining pre-sign data", (PreBip32DataCount - GetTotalCount(rootpubkey, inputcode, gg)), "pub", pub, "pubkey", rootpubkey, "inputcode", inputcode, "sub-groupid", gg)
				}

				time.Sleep(time.Duration(1000000))
			}
		}(gid)
		//}
		//}
	}
	//

	addr, _, err := GetSmpcAddr(pubkeyhex)
	if err != nil {
		return "", "get bip32 pubkey error",err 
	}
	fmt.Printf("===================GetBip32ChildKey, get bip32 pubkey success, rootpubkey = %v, inputcode = %v, child pubkey = %v, addr = %v ===================\n", rootpubkey, inputcode, pubkeyhex, addr)

	return pubkeyhex, "", nil
}

//--------------------------------------------------------------

var (
    keygen_num = 0
    sign_num = 0
    keygen_fail_num = 0
    sign_fail_num = 0
)

type MpcNodeInfo struct {
    GidNum int
    KeyGenNum int
    KeyGenFailNum int
    SignNum int
    SignFailNum int
}

func GetMpcNodeInfo() (string,error) {
    //group num
    gidnum := 0
    if discover.SDK_groupList != nil {
	gidnum = len(discover.SDK_groupList)
    }

    mni := &MpcNodeInfo{GidNum:gidnum,KeyGenNum:keygen_num,KeyGenFailNum:keygen_fail_num,SignNum:sign_num,SignFailNum:sign_fail_num}

    ret,err := json.Marshal(mni)
    return string(ret),err
}

func InitMpcNodeInfo() {
    //get mpc node info
    keytmp := Keccak256Hash([]byte(strings.ToLower(curEnode + ":" + "KeyGenNum"))).Hex()
    b,da := GetPubKeyData([]byte(keytmp))
    if b {
	data,ok := da.([]byte)
	if ok {
	    num,err := strconv.Atoi(string(data))
	    if err == nil {
		keygen_num = num
	    }
	}
    }

    keytmp = Keccak256Hash([]byte(strings.ToLower(curEnode + ":" + "KeyGenFailNum"))).Hex()
    b,da = GetPubKeyData([]byte(keytmp))
    if b {
	data,ok := da.([]byte)
	if ok {
	    num,err := strconv.Atoi(string(data))
	    if err == nil {
		keygen_fail_num = num
	    }
	}
    }

    keytmp = Keccak256Hash([]byte(strings.ToLower(curEnode + ":" + "SignNum"))).Hex()
    b,da = GetPubKeyData([]byte(keytmp))
    if b {
	data,ok := da.([]byte)
	if ok {
	    num,err := strconv.Atoi(string(data))
	    if err == nil {
		sign_num = num
	    }
	}
    }

    keytmp = Keccak256Hash([]byte(strings.ToLower(curEnode + ":" + "SignFailNum"))).Hex()
    b,da = GetPubKeyData([]byte(keytmp))
    if b {
	data,ok := da.([]byte)
	if ok {
	    num,err := strconv.Atoi(string(data))
	    if err == nil {
		sign_fail_num = num
	    }
	}
    }
}



