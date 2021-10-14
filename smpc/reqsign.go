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
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"

	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/keygen"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/ecdsa/signing"
	edkeygen "github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/keygen"
	edsigning "github.com/anyswap/Anyswap-MPCNode/smpc-lib/eddsa/signing"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"github.com/astaxie/beego/logs"
	"runtime/debug"
	"sync"
)

var (
	SignChan = make(chan *RpcSignData, 10000)
	mutex    sync.Mutex
)

//--------------------------------------------------------------------------------------

// GetSignNonce get sign special tx nonce
func GetSignNonce(account string) (string, string, error) {
	mutex.Lock()
	defer mutex.Unlock()
	if account == "" {
		return "", "", fmt.Errorf("invalid account.")
	}

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	exsit, da := GetPubKeyData([]byte(key))
	if !exsit {
		fmt.Printf("================GetSignNonce,key was not found. account = %v===================\n", account)
		nonce := "0"
		PutPubKeyData([]byte(key), []byte(nonce))
		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	PutPubKeyData([]byte(key), []byte(fmt.Sprintf("%v", nonce)))
	return fmt.Sprintf("%v", nonce), "", nil
}

// SetSignNonce set sign special tx nonce
func SetSignNonce(account string, nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	err := PutPubKeyData([]byte(key), []byte(nonce))
	if err != nil {
		return err.Error(), err
	}

	return "", nil
}

//------------------------------------------------------------------------------------------

// DoSign execute sign
// sbd : sign command data + key of picked pre-sign data
// workid : current worker id
// sender : send node's enodeId
// ch : the channel to save the sign result or error info.
func DoSign(sbd *SignPickData, workid int, sender string, ch chan interface{}) error {
	if sbd == nil || workid < 0 || sender == "" || sbd.Raw == "" || sbd.PickData == nil {
		res := RpcSmpcRes{Ret: "", Tip: "do sign fail.", Err: fmt.Errorf("do sign fail")}
		ch <- res
		return fmt.Errorf("do sign fail")
	}

	key, from, nonce, txdata, err := CheckRaw(sbd.Raw)
	common.Info("=====================DoSign,check raw data finish ================", "key", key, "from", from, "err", err, "raw", sbd.Raw, "tx data", txdata)
	if err != nil {
		common.Error("===============DoSign,check raw data error===================", "err ", err, "key", key, "from", from, "raw", sbd.Raw)
		res := RpcSmpcRes{Ret: "", Tip: err.Error(), Err: err}
		ch <- res
		return err
	}

	sig, ok := txdata.(*TxDataSign)
	if ok {
		exsit, _ := GetSignInfoData([]byte(key))
		if !exsit {
			ars := GetAllReplyFromGroup(workid, sig.GroupId, Rpc_SIGN, sender)
			ac := &AcceptSignData{Initiator: sender, Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId: workid}
			err = SaveAcceptSignData(ac)
			if err == nil {
				common.Info("===============DoSign,save sign accept data finish===================", "ars ", ars, "key ", key, "tx data", sig)
				w := workers[workid]
				w.sid = key
				w.groupid = sig.GroupId
				w.limitnum = sig.ThresHold
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
				}

				w.SmpcFrom = sig.PubKey // pubkey replace smpcfrom in sign

				if sig.Mode == "0" { // self-group
					var reply bool
					var tip string
					timeout := make(chan bool, 1)
					go func(wid int) {
						cur_enode = discover.GetLocalID().String() //GetSelfEnode()
						agreeWaitTime := time.Duration(WaitAgree) * time.Second
						agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

						wtmp2 := workers[wid]

						for {
							select {
							case account := <-wtmp2.acceptSignChan:
								common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
								ars := GetAllReplyFromGroup(w.id, sig.GroupId, Rpc_SIGN, sender)
								common.Info("================== DoSign, get all AcceptSignRes===============", "result ", ars, "key ", key)

								reply = true
								for _, nr := range ars {
									if !strings.EqualFold(nr.Status, "Agree") {
										reply = false
										break
									}
								}

								if !reply {
									tip = "don't accept sign"
									_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars, wid)
								} else {
									tip = ""
									_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, wid)
								}

								if err != nil {
									tip = tip + " and accept sign data fail"
								}

								timeout <- true
								return
							case <-agreeWaitTimeOut.C:
								ars := GetAllReplyFromGroup(w.id, sig.GroupId, Rpc_SIGN, sender)
								common.Info("================== DoSign, agree wait timeout=============", "ars", ars, "key ", key)
								_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars, wid)
								reply = false
								tip = "get other node accept sign result timeout"
								if err != nil {
									tip = tip + " and accept sign data fail"
								}

								timeout <- true
								return
							}
						}
					}(workid)

					if len(workers[workid].acceptWaitSignChan) == 0 {
						workers[workid].acceptWaitSignChan <- "go on"
					}

					DisAcceptMsg(sbd.Raw, workid)
					reqaddrkey := GetReqAddrKeyByOtherKey(key, Rpc_SIGN)
					if reqaddrkey == "" {
						res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
						ch <- res
						return fmt.Errorf("get reqaddr key fail")
					}

					exsit, da := GetPubKeyData([]byte(reqaddrkey))
					if !exsit {
						res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
						ch <- res
						return fmt.Errorf("get reqaddr sigs data fail")
					}

					acceptreqdata, ok := da.(*AcceptReqAddrData)
					if !ok || acceptreqdata == nil {
						common.Debug("===============DoSign, get req addr key by other key error ===================", "key ", key)
						res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
						ch <- res
						return fmt.Errorf("get reqaddr sigs data fail")
					}

					HandleC1Data(acceptreqdata, key)

					<-timeout

					if !reply {
						if tip == "get other node accept sign result timeout" {
							ars := GetAllReplyFromGroup(w.id, sig.GroupId, Rpc_SIGN, sender)
							_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars, workid)
						}

						res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
						ch <- res
						return fmt.Errorf("don't accept sign.")
					}
				} else {
					if len(workers[workid].acceptWaitSignChan) == 0 {
						workers[workid].acceptWaitSignChan <- "go on"
					}

					ars := GetAllReplyFromGroup(w.id, sig.GroupId, Rpc_SIGN, sender)
					_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "false", "true", "Pending", "", "", "", ars, workid)
					if err != nil {
						res := RpcSmpcRes{Ret: "", Tip: err.Error(), Err: err}
						ch <- res
						return err
					}
				}

				rch := make(chan interface{}, 1)
				sign(w.sid, from, sig.PubKey, sig.InputCode, sig.MsgHash, sig.Keytype, nonce, sig.Mode, sbd.PickData, rch)
				chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
				if chret != "" {
					res := RpcSmpcRes{Ret: chret, Tip: "", Err: nil}
					ch <- res
					return nil
				}

				ars := GetAllReplyFromGroup(w.id, sig.GroupId, Rpc_SIGN, sender)
				if tip == "get other node accept sign result timeout" {
					_, err = AcceptSign(sender, from, sig.PubKey, sig.MsgHash, sig.Keytype, sig.GroupId, nonce, sig.ThresHold, sig.Mode, "true", "", "Timeout", "", tip, cherr.Error(), ars, workid)
				}

				if cherr != nil {
					res := RpcSmpcRes{Ret: "", Tip: tip, Err: cherr}
					ch <- res
					return cherr
				}

				res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
				ch <- res
				return fmt.Errorf("sign fail.")
			} else {
				common.Debug("===============DoSign,save sign accept data fail==================", "key ", key, "from ", from)
			}
		} else {
			common.Info("===============DoSign, the sign has handled before==================", "key ", key, "from ", from)
		}
	}

	res := RpcSmpcRes{Ret: "", Tip: "do sign fail.", Err: fmt.Errorf("do sign fail")}
	ch <- res
	return fmt.Errorf("do sign fail")
}

//------------------------------------------------------------------------------------------------------

// RpcAcceptSign Agree to the sign request 
// raw : accept data, including the key of the sign request
func RpcAcceptSign(raw string) (string, string, error) {
	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================RpcAcceptSign,check raw data error================", "raw", raw, "err", err)
		return "Failure", err.Error(), err
	}

	if key == "" || from == "" || txdata == nil {
		return "Failure", "check accept raw data fail", fmt.Errorf("check accept raw data fail")
	}

	acceptsig, ok := txdata.(*TxDataAcceptSign)
	if !ok {
		return "Failure", "check raw fail,it is not *TxDataAcceptSign", fmt.Errorf("check raw fail,it is not *TxDataAcceptSign")
	}

	if acceptsig.Key == "" || acceptsig.Accept == "" {
		return "Failure", "check accept raw data fail", fmt.Errorf("check accept raw data fail")
	}

	exsit, da := GetSignInfoData([]byte(acceptsig.Key))
	if exsit {
		ac, ok := da.(*AcceptSignData)
		if ok && ac != nil {
			SendMsgToSmpcGroup(raw, ac.GroupId)
			SetUpMsgList(raw, cur_enode)
			return "Success", "", nil
		}
	}

	return "Failure", "accept fail", fmt.Errorf("accept fail")
}

//-------------------------------------------------------------------------------------------

type RpcSignData struct {
	Raw       string
	PubKey    string
	InputCode string
	GroupId   string
	MsgHash   []string
	Key       string
}

type TxDataSign struct {
	TxType     string
	PubKey     string
	InputCode  string
	MsgHash    []string
	MsgContext []string
	Keytype    string
	GroupId    string
	ThresHold  string
	Mode       string
	TimeStamp  string
}

// Sign execute the sign command
// raw : sign command data
func Sign(raw string) (string, string, error) {
	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================Sign,check raw data error================", "raw", raw, "err", err)
		return "", err.Error(), err
	}

	sig, ok := txdata.(*TxDataSign)
	if !ok {
		return "", "check raw fail,it is not *TxDataSign", fmt.Errorf("check raw fail,it is not *TxDataSign")
	}

	common.Debug("=====================Sign================", "key", key, "from", from, "raw", raw)

	if sig.Keytype == "ED25519" {
		SendMsgToSmpcGroup(raw, sig.GroupId)
		SetUpMsgList(raw, cur_enode)
	} else {
		rsd := &RpcSignData{Raw: raw, PubKey: sig.PubKey, InputCode: sig.InputCode, GroupId: sig.GroupId, MsgHash: sig.MsgHash, Key: key}
		SignChan <- rsd
	}
	return key, "", nil
}

// HandleRpcSign handle sign request,read sign command from the channel and do it!
func HandleRpcSign() {
	for {
		rsd := <-SignChan

		smpcpks, _ := hex.DecodeString(rsd.PubKey)
		exsit, da := GetPubKeyData(smpcpks[:])
		common.Debug("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit)
		if exsit {
			_, ok := da.(*PubKeyData)
			common.Debug("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok)
			if ok {
				var pub string
				if rsd.InputCode != "" {
					pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.InputCode + ":" + rsd.GroupId))).Hex()
				} else {
					pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.GroupId))).Hex()
				}

				bret := false
				pickdata := make([]*PickHashData, 0)
				pickhash := make([]*PickHashKey, 0)
				for _, vv := range rsd.MsgHash {
					pick := PickPreSignData(rsd.PubKey, rsd.InputCode, rsd.GroupId)
					if pick == nil {
						bret = true
						break
					}
					common.Info("========================HandleRpcSign,choose pickkey==================", "txhash", vv, "pickkey", pick.Key, "key", rsd.Key)

					ph := &PickHashKey{Hash: vv, PickKey: pick.Key}
					pickhash = append(pickhash, ph)
					phd := &PickHashData{Hash: vv, Pre: pick}
					pickdata = append(pickdata, phd)

					//check pre sigal
					if rsd.InputCode != "" {
						if GetTotalCount(rsd.PubKey, rsd.InputCode, rsd.GroupId) >= (PreBip32DataCount/2) && GetTotalCount(rsd.PubKey, rsd.InputCode, rsd.GroupId) <= PreBip32DataCount {
							PutPreSigal(pub, false)
						} else {
							PutPreSigal(pub, true)
						}
					} else {
						if GetTotalCount(rsd.PubKey, "", rsd.GroupId) >= (PrePubDataCount*3/4) && GetTotalCount(rsd.PubKey, "", rsd.GroupId) <= PrePubDataCount {
							PutPreSigal(pub, false)
						} else {
							PutPreSigal(pub, true)
						}
					}
					//
				}

				if bret {
					continue
				}

				m := make(map[string]string)
				send, err := CompressSignBrocastData(rsd.Raw, pickhash)
				if err == nil {
					m["ComSignBrocastData"] = send
				}
				m["Type"] = "ComSignBrocastData"
				val, err := json.Marshal(m)
				if err != nil {
					common.Error("=========================HandleRpcSign======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok, "bret", bret, "err", err)
					continue
				}

				SendMsgToSmpcGroup(string(val), rsd.GroupId)

				m2 := make(map[string]string)
				selfsend, err := CompressSignData(rsd.Raw, pickdata)
				if err == nil {
					m2["ComSignData"] = selfsend
				}
				m2["Type"] = "ComSignData"
				val2, err := json.Marshal(m2)
				if err != nil {
					common.Error("=========================HandleRpcSign,compress hash data.======================", "rsd.Pubkey", rsd.PubKey, "key", rsd.Key, "exsit", exsit, "ok", ok, "bret", bret, "err", err)
					continue
				}
				SetUpMsgList(string(val2), cur_enode)
			}
		}
	}
}

//-----------------------------------------------------------------------------------------------

// get_sign_hash To get the key of sign command with the hash value,we must transfer hash array to a string
func get_sign_hash(hash []string, keytype string) string {
	var ids smpclib.SortableIDSSlice
	for _, v := range hash {
		uid := DoubleHash(v, keytype)
		ids = append(ids, uid)
	}
	sort.Sort(ids)

	ret := ""
	for _, v := range ids {
		ret += fmt.Sprintf("%v", v)
		ret += ":"
	}

	ret += "NULL"
	return ret
}

//---------------------------------------------------------------------------------------------------

type SignStatus struct {
	Status    string
	Rsv       []string
	Tip       string
	Error     string
	AllReply  []NodeReply
	TimeStamp string
}

// GetSignStatus get the result of the sign request by key
func GetSignStatus(key string) (string, string, error) {
	exsit, da := GetPubKeyData([]byte(key))
	if !exsit || da == nil {
		common.Error("=================GetSignStatus,get sign accept data fail from db================", "key", key)
		return "", "smpc back-end internal error:get sign accept data fail from db when GetSignStatus", fmt.Errorf("get sign accept data fail from db")
	}

	ac, ok := da.(*AcceptSignData)
	if !ok {
		common.Info("=================GetSignStatus,get sign accept data error from db================", "key", key)
		return "", "smpc back-end internal error:get sign accept data error from db when GetSignStatus", fmt.Errorf("get sign accept data error from db")
	}

	rsvs := strings.Split(ac.Rsv, ":")
	los := &SignStatus{Status: ac.Status, Rsv: rsvs[:len(rsvs)-1], Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

//--------------------------------------------------------------------------------------------------

type SignCurNodeInfo struct {
	Key        string
	Account    string
	PubKey     string
	MsgHash    []string
	MsgContext []string
	KeyType    string
	GroupId    string
	Nonce      string
	ThresHold  string
	Mode       string
	TimeStamp  string
}

type SignCurNodeInfoSort struct {
	Info []*SignCurNodeInfo
}

// Len get the count of arrary elements
func (s *SignCurNodeInfoSort) Len() int {
	return len(s.Info)
}

// Less weather r.Info[i] < r.Info[j]
func (s *SignCurNodeInfoSort) Less(i, j int) bool {
	itime, _ := new(big.Int).SetString(s.Info[i].TimeStamp, 10)
	jtime, _ := new(big.Int).SetString(s.Info[j].TimeStamp, 10)
	return itime.Cmp(jtime) >= 0
}

// Swap swap value of r.Info[i] and r.Info[j]
func (s *SignCurNodeInfoSort) Swap(i, j int) {
	s.Info[i], s.Info[j] = s.Info[j], s.Info[i]
}

// GetCurNodeSignInfo  Get current node's sign command approval list 
func GetCurNodeSignInfo(geter_acc string) ([]*SignCurNodeInfo, string, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("GetCurNodeSignInfo Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	var ret []*SignCurNodeInfo
	data := make(chan *SignCurNodeInfo, 1000)

	var wg sync.WaitGroup
	iter := signinfodb.NewIterator()
	for iter.Next() {
		key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		exsit, val := GetSignInfoData(key2)
		if !exsit || val == nil {
			continue
		}

		wg.Add(1)
		go func(key string, value interface{}, ch chan *SignCurNodeInfo) {
			defer func() {
				if r := recover(); r != nil {
					fmt.Errorf("GetCurNodeSignInfo go Runtime error: %v\n%v", r, string(debug.Stack()))
				}
				wg.Done()
			}()

			if value == nil || key == "" {
				return
			}

			vv, ok := value.(*AcceptSignData)
			if vv == nil || !ok {
				return
			}

			common.Debug("================GetCurNodeSignInfo======================", "vv", vv, "vv.Deal", vv.Deal, "vv.Status", vv.Status, "key", key)
			if vv.Deal == "true" || vv.Status == "Success" {
				return
			}

			if vv.Status != "Pending" {
				return
			}

			if !CheckAccept(vv.PubKey, vv.Mode, geter_acc) {
				return
			}

			los := &SignCurNodeInfo{Key: key, Account: vv.Account, PubKey: vv.PubKey, MsgHash: vv.MsgHash, MsgContext: vv.MsgContext, KeyType: vv.Keytype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
			if los == nil {
				common.Error("=========================GetCurNodeSignInfo,current info is nil========================", "key", key)
				return
			}

			ch <- los
			common.Debug("================GetCurNodeSignInfo success return=======================", "key", key)
		}(string(key2), val, data)
	}
	iter.Release()
	wg.Wait()

	l := len(data)
	for i := 0; i < l; i++ {
		info := <-data
		ret = append(ret, info)
	}

	signinfosort := SignCurNodeInfoSort{Info: ret}
	sort.Sort(&signinfosort)

	var tmp []*SignCurNodeInfo
	for i := 0; i < len(signinfosort.Info); i++ {
		if signinfosort.Info[i] == nil {
			continue
		}

		tmp = append(tmp, signinfosort.Info[i])
	}

	return tmp, "", nil
}

//----------------------------------------------------------------------------------------------------------

// sign execut the sign command,including ec and ed.
// keytype : EC256K1 || ED25519
func sign(wsid string, account string, pubkey string, inputcode string, unsignhash []string, keytype string, nonce string, mode string, pickdata []*PickHashData, ch chan interface{}) {
	smpcpks, _ := hex.DecodeString(pubkey)
	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit {
		common.Debug("============================sign,not exist sign data===========================", "pubkey", pubkey, "key", wsid)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	_, ok := da.(*PubKeyData)
	if !ok {
		common.Debug("============================sign,sign data error==========================", "pubkey", pubkey, "key", wsid)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
		ch <- res
		return
	}

	save := (da.(*PubKeyData)).Save
	smpcpub := (da.(*PubKeyData)).Pub

	var smpcpkx *big.Int
	var smpcpky *big.Int
	if keytype == "EC256K1" {
		smpcpks := []byte(smpcpub)
		smpcpkx, smpcpky = secp256k1.S256().Unmarshal(smpcpks[:])
	}

	///sku1
	da2 := getSkU1FromLocalDb(smpcpks[:])
	if da2 == nil {
		res := RpcSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RpcSmpcRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	//

	var result string
	var cherrtmp error
	rch := make(chan interface{}, 1)
	if keytype == "ED25519" {
		sign_ed(wsid, unsignhash, save, sku1, smpcpub, keytype, rch)
		ret, tip, cherr := GetChannelValue(waitall, rch)
		if cherr != nil {
			res := RpcSmpcRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res
			return
		}

		result = ret
		cherrtmp = cherr
	} else {
		sign_ec(wsid, unsignhash, save, sku1, smpcpkx, smpcpky, inputcode, keytype, pickdata, rch)
		ret, tip, cherr := GetChannelValue(waitall, rch)
		common.Info("=================sign,call sign_ec finish.==============", "return result", ret, "err", cherr, "key", wsid)
		if cherr != nil {
			res := RpcSmpcRes{Ret: "", Tip: tip, Err: cherr}
			ch <- res
			return
		}

		result = ret
		cherrtmp = cherr
	}

	tmps := strings.Split(result, ":")
	for _, rsv := range tmps {

		if rsv == "NULL" {
			continue
		}

		//bug
		rets := []rune(rsv)
		if keytype != "ED25519" && len(rets) != 130 {
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:wrong rsv size", Err: GetRetErr(ErrSmpcSigWrongSize)}
			ch <- res
			return
		}
	}

	if result != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			common.Debug("==========sign,no find worker============", "err", err, "key", wsid)
			res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
			ch <- res
			return
		}

		///////TODO tmp
		//sid-enode:SendSignRes:Success:rsv
		//sid-enode:SendSignRes:Fail:err
		mp := []string{w.sid, cur_enode}
		enode := strings.Join(mp, "-")
		s0 := "SendSignRes"
		s1 := "Success"
		s2 := result
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToSmpcGroup(ss, w.groupid)
		///////////////

		common.Debug("================sign,success sign and call AcceptSign==============", "key", wsid)
		tip, reply := AcceptSign("", account, pubkey, unsignhash, keytype, w.groupid, nonce, w.limitnum, mode, "true", "true", "Success", result, "", "", nil, w.id)
		if reply != nil {
			res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update sign status error.")}
			ch <- res
			return
		}

		common.Info("================sign,the terminal sign res is success==============", "key", wsid)
		res := RpcSmpcRes{Ret: result, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherrtmp != nil {
		common.Info("================sign,the terminal sign res is failure================", "err", cherrtmp, "key", wsid)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:sign fail", Err: cherrtmp}
		ch <- res
		return
	}

	res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:sign fail", Err: fmt.Errorf("sign fail.")}
	ch <- res
}

//----------------------------------------------------------------------------------------------

type SignData struct {
	MsgPrex    string
	Key        string
	InputCodeT string
	Save       string
	Sku1       *big.Int
	Txhash     string
	GroupId    string
	NodeCnt    int
	ThresHold  int
	SmpcFrom   string
	Keytype    string
	Cointype   string
	Pkx        *big.Int
	Pky        *big.Int
	Pre        *PreSignData
}

// MarshalJSON marshal *SignData to json byte
func (sd *SignData) MarshalJSON() ([]byte, error) {
	if sd.Pre == nil {
		return nil, errors.New("get pre-sign data fail.")
	}

	s, err := sd.Pre.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return json.Marshal(struct {
		MsgPrex    string `json:"MsgPrex"`
		Key        string `json:"Key"`
		InputCodeT string `json:"InputCodeT"`
		Save       string `json:"Save"`
		Sku1       string `json:"Sku1"`
		Txhash     string `json:"Txhash"`
		GroupId    string `json:"GroupId"`
		NodeCnt    string `json:"NodeCnt"`
		ThresHold  string `json:"ThresHold"`
		SmpcFrom   string `json:"SmpcFrom"`
		Keytype    string `json:"Keytype"`
		Cointype   string `json:"Cointype"`
		Pkx        string `json:"Pkx"`
		Pky        string `json:"Pky"`
		Pre        string `json:"Pre"`
	}{
		MsgPrex:    sd.MsgPrex,
		Key:        sd.Key,
		InputCodeT: sd.InputCodeT,
		Save:       sd.Save,
		Sku1:       fmt.Sprintf("%v", sd.Sku1),
		Txhash:     sd.Txhash,
		GroupId:    sd.GroupId,
		NodeCnt:    strconv.Itoa(sd.NodeCnt),
		ThresHold:  strconv.Itoa(sd.ThresHold),
		SmpcFrom:   sd.SmpcFrom,
		Keytype:    sd.Keytype,
		Cointype:   sd.Cointype,
		Pkx:        fmt.Sprintf("%v", sd.Pkx),
		Pky:        fmt.Sprintf("%v", sd.Pky),
		Pre:        string(s),
	})
}

// UnmarshalJSON unmarshal json string to *SignData
func (sd *SignData) UnmarshalJSON(raw []byte) error {
	var si struct {
		MsgPrex    string `json:"MsgPrex"`
		Key        string `json:"Key"`
		InputCodeT string `json:"InputCodeT"`
		Save       string `json:"Save"`
		Sku1       string `json:"Sku1"`
		Txhash     string `json:"Txhash"`
		GroupId    string `json:"GroupId"`
		NodeCnt    string `json:"NodeCnt"`
		ThresHold  string `json:"ThresHold"`
		SmpcFrom   string `json:"SmpcFrom"`
		Keytype    string `json:"Keytype"`
		Cointype   string `json:"Cointype"`
		Pkx        string `json:"Pkx"`
		Pky        string `json:"Pky"`
		Pre        string `json:"Pre"`
	}
	if err := json.Unmarshal(raw, &si); err != nil {
		return err
	}

	sd.MsgPrex = si.MsgPrex
	sd.Key = si.Key
	sd.InputCodeT = si.InputCodeT
	sd.Save = si.Save
	sd.Sku1, _ = new(big.Int).SetString(si.Sku1, 10)
	sd.Txhash = si.Txhash
	sd.GroupId = si.GroupId
	sd.NodeCnt, _ = strconv.Atoi(si.NodeCnt)
	sd.ThresHold, _ = strconv.Atoi(si.ThresHold)
	sd.SmpcFrom = si.SmpcFrom
	sd.Keytype = si.Keytype
	sd.Cointype = si.Cointype
	sd.Pkx, _ = new(big.Int).SetString(si.Pkx, 10)
	sd.Pky, _ = new(big.Int).SetString(si.Pky, 10)
	pre := &PreSignData{}
	err := pre.UnmarshalJSON([]byte(si.Pre))
	if err != nil {
		return err
	}

	sd.Pre = pre
	return nil
}

//----------------------------------------------------------------------------------------------------

// sign_ec execute the sign command with ec algorithm 
func sign_ec(msgprex string, txhash []string, save string, sku1 *big.Int, smpcpkx *big.Int, smpcpky *big.Int, inputcode string, keytype string, pickdata []*PickHashData, ch chan interface{}) string {

	tmp := make([]string, 0)
	for _, v := range txhash {
		txhashs := []rune(v)
		if string(txhashs[0:2]) == "0x" {
			tmp = append(tmp, string(txhashs[2:]))
		} else {
			tmp = append(tmp, string(txhashs))
		}
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		common.Debug("==========smpc_sign,no find worker===========", "key", msgprex, "err", err)
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}

	cur_enode = GetSelfEnode()

	var wg sync.WaitGroup
	for _, v := range tmp {
		wg.Add(1)
		go func(vv string) {
			defer wg.Done()

			//get pick
			var pick *PreSignData
			for _, val := range pickdata {
				if strings.EqualFold(val.Hash, ("0x"+vv)) || strings.EqualFold(val.Hash, vv) {
					pick = val.Pre
					break
				}
			}
			if pick == nil {
				return
			}
			//

			fmt.Printf("============================sign_ec,pkx = %v,pky = %v =============================\n", smpcpkx, smpcpky)
			key := Keccak256Hash([]byte(strings.ToLower(msgprex + "-" + vv))).Hex()
			sd := &SignData{MsgPrex: msgprex, Key: key, InputCodeT: inputcode, Save: save, Sku1: sku1, Txhash: vv, GroupId: w.groupid, NodeCnt: w.NodeCnt, ThresHold: w.ThresHold, SmpcFrom: w.SmpcFrom, Keytype: keytype, Cointype: "", Pkx: smpcpkx, Pky: smpcpky, Pre: pick}

			m := make(map[string]string)
			sdjson, err := sd.MarshalJSON()
			if err == nil {
				m["SignData"] = string(sdjson)
			}
			m["Type"] = "SignData"
			val, err := json.Marshal(m)
			if err != nil {
				common.Error("======================sign_ec, marshal SignData to json fail.==================", "unsign txhash", vv, "msgprex", msgprex, "key", key, "pick key", pick.Key, "err", err)
				return
			}

			rch := make(chan interface{}, 1)
			SetUpMsgList3(string(val), cur_enode, rch)
			_, _, cherr := GetChannelValue(ch_t, rch)
			if cherr != nil {
				common.Error("======================sign_ec, sign error====================", "vv", vv, "msgprex", msgprex, "key", key, "cherr", cherr)
				return
			}
		}(v)
	}
	wg.Wait()

	common.Info("======================sign_ec, all sign finish===================", "msgprex", msgprex, "w.rsv", w.rsv)

	var ret string
	iter := w.rsv.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		ret += mdss
		ret += ":"
		iter = iter.Next()
	}

	ret += "NULL"
	tmps := strings.Split(ret, ":")
	common.Debug("======================sign_ec=====================", "return result", ret, "len(tmps)", len(tmps), "len(tmp)", len(tmp), "key", msgprex)
	if len(tmps) == (len(tmp) + 1) {
		res := RpcSmpcRes{Ret: ret, Tip: "", Err: nil}
		ch <- res
		return ""
	}

	res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error: sign fail", Err: fmt.Errorf("sign fail")}
	ch <- res
	return ""
}

//-----------------------------------------------------------------------------------------------------

// GetPaillierPkByIndexFromSaveData get paillier pubkey by index from saved data that obtained when generating pubkey
func GetPaillierPkByIndexFromSaveData(save string, index int) *ec2.PublicKey {
	if save == "" || index < 0 {
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	s := 4 + 4*index
	if len(mm) < (s + 4) {
		return nil
	}

	l := mm[s]
	n := new(big.Int).SetBytes([]byte(mm[s+1]))
	g := new(big.Int).SetBytes([]byte(mm[s+2]))
	n2 := new(big.Int).SetBytes([]byte(mm[s+3]))
	publicKey := &ec2.PublicKey{Length: l, N: n, G: g, N2: n2}

	return publicKey
}

//--------------------------------------------------------------------------------------------------

// GetCurNodeIndex get the serial number of uid of current node in group.
func GetCurNodeIndex(gid string, keytype string) int {
	if gid == "" || keytype == "" {
		return -1
	}

	uid := DoubleHash(cur_enode, keytype)

	ids := GetIds(keytype, gid)
	for k, v := range ids {
		if v.Cmp(uid) == 0 {
			return k
		}
	}

	return -1
}

//-----------------------------------------------------------------------------------------------------

// GetCurNodePaillierSkFromSaveData get current node's paillier private key from saved data that obtained when generating pubkey
// gid is not the sub-gid
func GetCurNodePaillierSkFromSaveData(save string, gid string, keytype string) *ec2.PrivateKey {
	if save == "" || gid == "" || keytype == "" {
		return nil
	}

	cur_index := GetCurNodeIndex(gid, keytype)
	publicKey := GetPaillierPkByIndexFromSaveData(save, cur_index)
	if publicKey != nil {
		mm := strings.Split(save, common.SepSave)
		if len(mm) < 4 {
			return nil
		}

		l := mm[1]
		ll := new(big.Int).SetBytes([]byte(mm[2]))
		uu := new(big.Int).SetBytes([]byte(mm[3]))
		privateKey := &ec2.PrivateKey{Length: l, PublicKey: *publicKey, L: ll, U: uu}
		return privateKey
	}

	return nil
}

//---------------------------------------------------------------------------------------------

// GetNtildeByIndexFromSaveData get ntilde data by index from saved data that obtained when generating pubkey
func GetNtildeByIndexFromSaveData(save string, index int, NodeCnt int) *ec2.NtildeH1H2 {
	if save == "" || index < 0 || NodeCnt < 0 {
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	s := 4 + 4*NodeCnt + 3*index
	if len(mm) < (s + 3) {
		return nil
	}

	ntilde := new(big.Int).SetBytes([]byte(mm[s]))
	h1 := new(big.Int).SetBytes([]byte(mm[s+1]))
	h2 := new(big.Int).SetBytes([]byte(mm[s+2]))
	ntildeh1h2 := &ec2.NtildeH1H2{Ntilde: ntilde, H1: h1, H2: h2}

	return ntildeh1h2
}

//---------------------------------------------------------------------------------------------------

// GetMsgToEnode get uid of node in group by groupid,and put it to the map.
// map: uid ----> enodeId
func GetMsgToEnode(keytype string, groupid string) map[string]string {
	msgtoenode := make(map[string]string)
	_, nodes := GetGroup(groupid)
	others := strings.Split(nodes, common.Sep2)
	for _, v := range others {
		node2 := ParseNode(v)
		uid := DoubleHash(node2, keytype)
		msgtoenode[fmt.Sprintf("%v", uid)] = node2
	}

	return msgtoenode
}

//-----------------------------------------------------------------------------------------------------

// PreSign_ec3 execute the action of generating the pre-sign data.
// msgprex = hash
//  the return value is the generated pre-sign data.
func PreSign_ec3(msgprex string, save string, sku1 *big.Int, cointype string, ch chan interface{}, id int) *PreSignData {
	if id < 0 || id >= len(workers) {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return nil
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return nil
	}

	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return nil
	}

	sd := &keygen.LocalDNodeSaveData{}
	sd.SkU1 = sku1

	smpcpks, _ := hex.DecodeString(w.SmpcFrom)
	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit || da == nil {
		res := RpcSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return nil
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupId == "" {
		res := RpcSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return nil
	}

	sd.U1PaillierSk = GetCurNodePaillierSkFromSaveData(save, pubs.GroupId, cointype)

	U1PaillierPk := make([]*ec2.PublicKey, w.NodeCnt)
	U1NtildeH1H2 := make([]*ec2.NtildeH1H2, w.NodeCnt)
	for i := 0; i < w.NodeCnt; i++ {
		U1PaillierPk[i] = GetPaillierPkByIndexFromSaveData(save, i)
		U1NtildeH1H2[i] = GetNtildeByIndexFromSaveData(save, i, w.NodeCnt)
	}
	sd.U1PaillierPk = U1PaillierPk
	sd.U1NtildeH1H2 = U1NtildeH1H2

	sd.Ids = GetIds(cointype, pubs.GroupId)
	sd.CurDNodeID = DoubleHash(cur_enode, cointype)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupId)
	kgsave := &KGLocalDBSaveData{Save: sd, MsgToEnode: msgtoenode}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	idsign := GetIds(cointype, w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData, w.ThresHold)
	finalize_endCh := make(chan *big.Int, w.ThresHold)
	errChan := make(chan struct{})
	signDNode := signing.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, false, nil, nil, finalize_endCh)
	w.DNode = signDNode
	signDNode.SetDNodeID(fmt.Sprintf("%v", sd.CurDNodeID))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			fmt.Printf("==========sign node start err = %v ==========\n", err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				HandleC1Data(acceptreqdata, w.sid)
			}
		}
	}()
	go SignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	pre, err := processSign(msgprex, kgsave.MsgToEnode, errChan, outCh, endCh)
	if err != nil || pre == nil {
		fmt.Printf("==========process sign err = %v ==========\n", err)
		close(commStopChan)
		res := RpcSmpcRes{Ret: "", Err: err}
		ch <- res
		return nil
	}

	close(commStopChan)
	signWg.Wait()

	ret := &PreSignData{Key: msgprex, K1: pre.K1, R: pre.R, Ry: pre.Ry, Sigma1: pre.Sigma1, Gid: w.groupid, Used: false, Index: -1}
	return ret
}

// Sign_ec3 execute sign with gg20 MPC algorithm
// msgprex = hash
// return value is the backup for the smpc sign
func Sign_ec3(msgprex string, message string, cointype string, save string, pkx *big.Int, pky *big.Int, ch chan interface{}, id int, pre *PreSignData) string {
	if id < 0 || id >= len(workers) {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	w := workers[id]
	fmt.Printf("==============Sign_ec3, w.groupid = %v ==============\n", w.groupid)

	gid := w.groupid

	if w.groupid == "" {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	hashBytes, err2 := hex.DecodeString(message)
	if err2 != nil {
		res := RpcSmpcRes{Ret: "", Err: err2}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	mMtA, _ := new(big.Int).SetString(message, 16)
	mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return ""
	}

	sd := &keygen.LocalDNodeSaveData{}
	sd.Pkx = pkx
	sd.Pky = pky

	ys := secp256k1.S256().Marshal(pkx, pky)
	exsit, da := GetPubKeyData(ys)
	if !exsit || da == nil {
		res := RpcSmpcRes{Ret: "", Tip: "sign get local pubkey data fail", Err: fmt.Errorf("sign get local pubkey data fail")}
		ch <- res
		return ""
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupId == "" {
		res := RpcSmpcRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
		ch <- res
		return ""
	}

	///sku1
	da2 := getSkU1FromLocalDb(ys)
	if da2 == nil {
		res := RpcSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return ""
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RpcSmpcRes{Ret: "", Tip: "sign get sku1 fail", Err: fmt.Errorf("sign get sku1 fail")}
		ch <- res
		return ""
	}
	//
	sd.SkU1 = sku1

	sd.U1PaillierSk = GetCurNodePaillierSkFromSaveData(save, pubs.GroupId, cointype)

	U1PaillierPk := make([]*ec2.PublicKey, w.NodeCnt)
	U1NtildeH1H2 := make([]*ec2.NtildeH1H2, w.NodeCnt)
	for i := 0; i < w.NodeCnt; i++ {
		U1PaillierPk[i] = GetPaillierPkByIndexFromSaveData(save, i)
		U1NtildeH1H2[i] = GetNtildeByIndexFromSaveData(save, i, w.NodeCnt)
	}
	sd.U1PaillierPk = U1PaillierPk
	sd.U1NtildeH1H2 = U1NtildeH1H2

	sd.Ids = GetIds(cointype, pubs.GroupId)
	sd.CurDNodeID = DoubleHash(cur_enode, cointype)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupId)
	kgsave := &KGLocalDBSaveData{Save: sd, MsgToEnode: msgtoenode}

	idsign := GetIds(cointype, w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData, w.ThresHold)
	finalize_endCh := make(chan *big.Int, w.ThresHold)
	errChan := make(chan struct{})
	predata := &signing.PrePubData{K1: pre.K1, R: pre.R, Ry: pre.Ry, Sigma1: pre.Sigma1}
	signDNode := signing.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, true, predata, mMtA, finalize_endCh)
	w.DNode = signDNode
	signDNode.SetDNodeID(fmt.Sprintf("%v", DoubleHash(cur_enode, "EC256K1")))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			fmt.Printf("==========sign node start err = %v ==========\n", err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				HandleC1Data(acceptreqdata, w.sid)
			}
		}
	}()
	go SignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	fmt.Printf("==============Sign_ec3, 333333  w.groupid = %v ==============\n", w.groupid)
	s, err := processSignFinalize(msgprex, kgsave.MsgToEnode, errChan, outCh, finalize_endCh, gid)
	if err != nil || s == nil {
		fmt.Printf("==========process sign err = %v ==========\n", err)
		close(commStopChan)
		res := RpcSmpcRes{Ret: "", Err: err}
		ch <- res
		return ""
	}

	close(commStopChan)
	signWg.Wait()

	// 5. calculate s
	//us1 := signing.CalcUs(mMtA, pre.K1, pre.R, pre.Sigma1)

	/*commitBigVAB1, commitbigvabs, rho1, l1 := DECDSASignRoundSeven(msgprex, pre.R, pre.Ry, us1, w, ch)
	if commitBigVAB1 == nil || commitbigvabs == nil || rho1 == nil || l1 == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round seven finish=================","key",msgprex)

	u1zkABProof, zkabproofs := DECDSASignRoundEight(msgprex, pre.R, pre.Ry, us1, l1, rho1, w, ch, commitBigVAB1)
	if u1zkABProof == nil || zkabproofs == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round eight finish=================","key",msgprex)

	commitbigcom, BigVx, BigVy := DECDSASignVerifyBigVAB(cointype, w, commitbigvabs, zkabproofs, commitBigVAB1, u1zkABProof, idSign, pre.R, pre.Ry, ch)
	if commitbigcom == nil || BigVx == nil || BigVy == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, verify BigVAB finish=================","key",msgprex)

	commitbiguts, commitBigUT1 := DECDSASignRoundNine(msgprex, cointype, w, idSign, mMtA, pre.R, pkx, pky, BigVx, BigVy, rho1, commitbigcom, l1, ch)
	if commitbiguts == nil || commitBigUT1 == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round nine finish=================","key",msgprex)

	commitbigutd11s := DECDSASignRoundTen(msgprex, commitBigUT1, w, ch)
	if commitbigutd11s == nil {
		return ""
	}
	common.Debug("=====================Sign_ec3, round ten finish=================","key",msgprex)

	if !DECDSASignVerifyBigUTCommitment(msgprex,cointype, commitbiguts, commitbigutd11s, commitBigUT1, w, idSign, ch, commitbigcom) {
		return ""
	}
	common.Debug("=====================Sign_ec3, verify BigUT commitment finish=================","key",msgprex)
	*/ //------

	//ss1s := DECDSASignRoundEleven(msgprex, cointype, w, idSign, ch, us1)
	//if ss1s == nil {
	//	return ""
	//}
	//common.Debug("=====================Sign_ec3,round eleven finish=================","key",msgprex)

	//s := Calc_s(msgprex,cointype, w, idSign, ss1s, ch)
	//if s == nil {
	//	return ""
	//}
	//common.Debug("=====================Sign_ec3,calc s finish=================","key",msgprex)

	// 3. justify the s
	bb := false
	halfN := new(big.Int).Div(secp256k1.S256().N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		bb = true
		s = new(big.Int).Sub(secp256k1.S256().N, s)
	}

	zero, _ := new(big.Int).SetString("0", 10)
	if s.Cmp(zero) == 0 {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("s == 0.")}
		ch <- res
		return ""
	}
	common.Debug("=====================Sign_ec3,justify s finish=================", "key", msgprex)

	// **[End-Test]  verify signature with MtA
	signature := new(ECDSASignature)
	signature.New()
	signature.SetR(pre.R)
	signature.SetS(s)

	invert := false
	if cointype == "ETH" && bb {
		invert = true
	}
	if cointype == "BTC" && bb {
		invert = true
	}

	recid := smpclib.DECDSA_Sign_Calc_v(pre.R, pre.Ry, pkx, pky, signature.GetR(), signature.GetS(), hashBytes, invert)
	common.Debug("=====================Sign_ec3,first get recid =================", "recid", recid, "key", msgprex)

	////check v
	ys = secp256k1.S256().Marshal(pkx, pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
		pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
	for j := 0; j < 4; j++ {
		rsvBytes2 := append(rsvBytes1, byte(j))
		pkr, e := secp256k1.RecoverPubkey(hashBytes, rsvBytes2)
		pkr2 := hex.EncodeToString(pkr)
		pbhs2 := []rune(pkr2)
		if string(pbhs2[0:2]) == "0x" {
			pkr2 = string(pbhs2[2:])
		}
		if e == nil && strings.EqualFold(pkr2, pubkeyhex) {
			recid = j
			common.Debug("=====================Sign_ec3,second get recid =================", "recid", recid, "key", msgprex)
			break
		}
	}
	/////
	signature.SetRecoveryParam(int32(recid))
	common.Debug("=====================Sign_ec3,terminal get recid =================", "recid", signature.GetRecoveryParam(), "key", msgprex)

	if !DECDSA_Sign_Verify_RSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) {
		common.Error("=================Sign_ec3,verify fail==============", "key", msgprex)
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("sign verify fail.")}
		ch <- res
		return ""
	}

	signature2 := GetSignString(signature.GetR(), signature.GetS(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	fmt.Printf("===============Sign_ec3,verify (r,s) pass,rsv str = %v, key = %v =============\n", signature2, msgprex)
	res := RpcSmpcRes{Ret: signature2, Err: nil}
	ch <- res

	return ""
}

//------------------------------------------------------------------------------------------

type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
}

// New new a *ECDSASignature
func (this *ECDSASignature) New() {
}

// GetR get r
func (this *ECDSASignature) GetR() *big.Int {
	return this.r
}

// SetR set r
func (this *ECDSASignature) SetR(r *big.Int) {
	this.r = r
}

// GetS get s
func (this *ECDSASignature) GetS() *big.Int {
	return this.s
}

// SetS set s
func (this *ECDSASignature) SetS(s *big.Int) {
	this.s = s
}

// GetRecoveryParam get v
func (this *ECDSASignature) GetRecoveryParam() int32 {
	return this.recoveryParam
}

// SetRecoveryParam set v
func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	this.recoveryParam = recoveryParam
}

//------------------------------------------------------------------------------------------

// Tool_DecimalByteSlice2HexString transfer Decimal byte to hex string
func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

// GetSignString get RSV string
func GetSignString(r *big.Int, s *big.Int, v int) string {
	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		smpclib.ReadBits(r, sigs[1:32])
		smpclib.ReadBits(s, sigs[32:64])
		sigs[64] = byte(v)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		smpclib.ReadBits(r, sigs[1:32])
		smpclib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(v)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		smpclib.ReadBits(r, sigs[0:32])
		smpclib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(v)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	smpclib.ReadBits(r, sigs[0:len(rr)])
	smpclib.ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(v)
	ret := Tool_DecimalByteSlice2HexString(sigs)

	return ret
}

// DECDSA_Sign_Verify_RSV verify RSV
func DECDSA_Sign_Verify_RSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return smpclib.Verify2(r, s, v, message, pkx, pky)
}

//--------------------------------------------------------------------------------------------------

// sign_ed execute the sign command with ed algorithm 
func sign_ed(msgprex string, txhash []string, save string, sku1 *big.Int, pk string, keytype string, ch chan interface{}) string {

	tmp := make([]string, 0)
	for _, v := range txhash {
		txhashs := []rune(v)
		if string(txhashs[0:2]) == "0x" {
			tmp = append(tmp, string(txhashs[2:]))
		} else {
			tmp = append(tmp, string(txhashs))
		}
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		logs.Debug("===========get worker fail.=============")
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	var result string
	var bak_sig string
	for _, v := range tmp {
		var ch1 = make(chan interface{}, 1)
		for i := 0; i < recalc_times; i++ {
			if len(ch1) != 0 {
				<-ch1
			}

			bak_sig = Sign_ed(msgprex, save, sku1, v, keytype, pk, ch1, id)
			ret, _, cherr := GetChannelValue(ch_t, ch1)
			if ret != "" && cherr == nil {
				result += ret
				result += ":"
				break
			}

			time.Sleep(time.Duration(3) * time.Second)
		}
	}

	result += "NULL"
	tmps := strings.Split(result, ":")
	if len(tmps) == (len(tmp) + 1) {
		res := RpcSmpcRes{Ret: result, Tip: "", Err: nil}
		ch <- res
	}

	return bak_sig
}

//-----------------------------------------------------------------------------------------------------------------

// Sign_ed execute the sign command with ed algorithm 
// msgprex = hash
// return value is the backup for the smpc sign
func Sign_ed(msgprex string, save string, sku1 *big.Int, message string, cointype string, pk string, ch chan interface{}, id int) string {
	if id < 0 || id >= len(workers) || id >= RPCMaxWorker {
		res := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return ""
	}

	w := workers[id]
	GroupId := w.groupid
	fmt.Println("========Sign_ed============", "GroupId", GroupId)
	if GroupId == "" {
		res := RpcSmpcRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	/*msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(save), &msgmap)
	if err != nil {
	    res := RpcSmpcRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return ""
	}
	kgsave := GetKGLocalDBSaveData_ed(msgmap)
	if kgsave == nil {
	    res := RpcSmpcRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return ""
	}
	sd := kgsave.Save*/

	mm := strings.Split(save, common.Sep11)
	if len(mm) == 0 {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("ed get save data fail")}
		ch <- res
		return ""
	}

	smpcpks, _ := hex.DecodeString(w.SmpcFrom)
	exsit, da := GetPubKeyData(smpcpks[:])
	if !exsit || da == nil {
		res := RpcSmpcRes{Ret: "", Tip: "ed sign get local save data fail", Err: fmt.Errorf("ed sign get local save data fail")}
		ch <- res
		return ""
	}

	pubs, ok := da.(*PubKeyData)
	if !ok || pubs.GroupId == "" {
		res := RpcSmpcRes{Ret: "", Tip: "ed sign get local save data fail", Err: fmt.Errorf("ed sign get local save data fail")}
		ch <- res
		return ""
	}

	sd := &edkeygen.LocalDNodeSaveData{}

	var sk [64]byte
	va := sku1.Bytes()
	copy(sk[:], va[:64])
	var tsk [32]byte
	va = []byte(mm[2])
	copy(tsk[:], va[:32])
	var pkfinal [32]byte
	va = []byte(mm[3])
	copy(pkfinal[:], va[:32])

	sd.Sk = sk
	sd.TSk = tsk
	sd.FinalPkBytes = pkfinal
	sd.Ids = GetIds(cointype, pubs.GroupId)
	sd.CurDNodeID = DoubleHash(cur_enode, cointype)

	msgtoenode := GetMsgToEnode(cointype, pubs.GroupId)
	kgsave := &KGLocalDBSaveData_ed{Save: sd, MsgToEnode: msgtoenode}

	idsign := GetIds(cointype, w.groupid)

	mMtA, _ := new(big.Int).SetString(message, 16)
	fmt.Printf("==============Sign_ed, w.groupid = %v, message = %v ==============\n", w.groupid, message)

	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, w.ThresHold)
	endCh := make(chan edsigning.EdSignData, w.ThresHold)
	finalize_endCh := make(chan *big.Int, w.ThresHold) //useness
	errChan := make(chan struct{})
	signDNode := edsigning.NewLocalDNode(outCh, endCh, sd, idsign, sd.CurDNodeID, w.ThresHold, PaillierKeyLength, false, nil, mMtA, finalize_endCh)
	w.DNode = signDNode
	signDNode.SetDNodeID(fmt.Sprintf("%v", DoubleHash(cur_enode, "ED25519")))

	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
			fmt.Printf("==========ed sign node start err = %v ==========\n", err)
			close(errChan)
		}

		exsit, da := GetPubKeyData([]byte(pubs.Key))
		if exsit {
			acceptreqdata, ok := da.(*AcceptReqAddrData)
			if ok && acceptreqdata != nil {
				HandleC1Data(acceptreqdata, w.sid)
			}
		}
	}()
	go EdSignProcessInboundMessages(msgprex, commStopChan, &signWg, ch)
	edrs, err := processSign_ed(msgprex, kgsave.MsgToEnode, errChan, outCh, endCh)
	if err != nil || edrs == nil {
		fmt.Printf("==========process ed sign err = %v ==========\n", err)
		close(commStopChan)
		res := RpcSmpcRes{Ret: "", Err: err}
		ch <- res
		return ""
	}

	close(commStopChan)
	signWg.Wait()

	signature := new([64]byte)
	copy(signature[:], edrs.Rx[:])
	copy(signature[32:], edrs.Sx[:])
	sig := hex.EncodeToString(signature[:])
	fmt.Printf("==================sign_ed,get the sig = %v, signature = %v ===================\n", sig, signature)
	res := RpcSmpcRes{Ret: sig, Tip: "", Err: nil}
	ch <- res
	return ""
}

//--------------------------------------------------------------------------------------------------------------------------

/*func DECDSASignRoundSeven(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, w *RPCReqWorker, ch chan interface{}) (*ec2.Commitment, []string, *big.Int, *big.Int) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitBigVAB1, rho1, l1 := signing.DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigVAB"
	s1 := string(commitBigVAB1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigVAB finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigvab)
	common.Debug("===================finish get CommitBigVAB, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigVAB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigVAB timeout.")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitbigvabs := make([]string, w.ThresHold)
	if w.msg_commitbigvab.Len() != w.ThresHold {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigVAB fail.")}
		ch <- res
		return nil, nil, nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigvab.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigvabs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitBigVAB1, commitbigvabs, rho1, l1
}

func DECDSASignRoundEight(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, l1 *big.Int, rho1 *big.Int, w *RPCReqWorker, ch chan interface{}, commitBigVAB1 *ec2.Commitment) (*ec2.ZkABProof, []string) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil || l1 == nil || rho1 == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil
	}

	// *** Round 5B
	u1zkABProof := signing.DECDSA_Sign_ZkABProve(rho1, l1, us1, []*big.Int{r, deltaGammaGy})

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "ZKABPROOF"
	dlen := len(commitBigVAB1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigVAB1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Alpha)
	s22 := strconv.Itoa(dlen)
	ss += (s22 + common.Sep)
	for _, alp := range u1zkABProof.Alpha {
		ss += string(alp.Bytes())
		ss += common.Sep
	}

	dlen = len(u1zkABProof.Beta)
	s3 := strconv.Itoa(dlen)
	ss += (s3 + common.Sep)
	for _, bet := range u1zkABProof.Beta {
		ss += string(bet.Bytes())
		ss += common.Sep
	}

	//ss = prex-enode:ZKABPROOF:dlen:d1:d2:...:dl:alplen:a1:a2:....aalp:betlen:b1:b2:...bbet:t:u:NULL
	ss += (string(u1zkABProof.T.Bytes()) + common.Sep + string(u1zkABProof.U.Bytes()) + common.Sep)
	ss = ss + "NULL"
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send ZKABPROOF finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bzkabproof)
	common.Debug("===================finish get ZKABPROOF, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKABPROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all ZKABPROOF timeout.")}
		ch <- res
		return nil, nil
	}

	zkabproofs := make([]string, w.ThresHold)
	if w.msg_zkabproof.Len() != w.ThresHold {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get all ZKABPROOF fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_zkabproof.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		zkabproofs[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return u1zkABProof, zkabproofs
}

func DECDSASignVerifyBigVAB(cointype string, w *RPCReqWorker, commitbigvabs []string, zkabproofs []string, commitBigVAB1 *ec2.Commitment, u1zkABProof *ec2.ZkABProof, idSign sortableIDSSlice, r *big.Int, deltaGammaGy *big.Int, ch chan interface{}) (map[string]*ec2.Commitment, *big.Int, *big.Int) {
	if len(commitbigvabs) == 0 || len(zkabproofs) == 0 || commitBigVAB1 == nil || u1zkABProof == nil || cointype == "" || w == nil || len(idSign) == 0 || r == nil || deltaGammaGy == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil, nil, nil
	}

	var commitbigcom = make(map[string]*ec2.Commitment)
	for _, v := range commitbigvabs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range zkabproofs {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
						ch <- res
						return nil, nil, nil
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigcom[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigcom[cur_enode] = commitBigVAB1

	var zkabproofmap = make(map[string]*ec2.ZkABProof)
	zkabproofmap[cur_enode] = u1zkABProof

	for _, vv := range zkabproofs {
		mmm := strings.Split(vv, common.Sep)
		prex2 := mmm[0]
		prexs2 := strings.Split(prex2, "-")

		//alpha
		dlen, _ := strconv.Atoi(mmm[2])
		alplen, _ := strconv.Atoi(mmm[3+dlen])
		var alp = make([]*big.Int, 0)
		l := 0
		for j := 0; j < alplen; j++ {
			l++
			if len(mmm) < (4 + dlen + l) {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			alp = append(alp, new(big.Int).SetBytes([]byte(mmm[3+dlen+l])))
		}

		//beta
		betlen, _ := strconv.Atoi(mmm[3+dlen+1+alplen])
		var bet = make([]*big.Int, 0)
		l = 0
		for j := 0; j < betlen; j++ {
			l++
			if len(mmm) < (5 + dlen + alplen + l) {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
				ch <- res
				return nil, nil, nil
			}

			bet = append(bet, new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+l])))
		}

		t := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen]))
		u := new(big.Int).SetBytes([]byte(mmm[3+dlen+1+alplen+1+betlen+1]))

		zkABProof := &ec2.ZkABProof{Alpha: alp, Beta: bet, T: t, U: u}
		zkabproofmap[prexs2[len(prexs2)-1]] = zkABProof
	}

	var BigVx, BigVy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigcom[en[0]]) {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("verify commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if !signing.DECDSA_Sign_ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("verify zkabproof fail.")}
			ch <- res
			return nil, nil, nil
		}

		if k == 0 {
			BigVx = BigVAB1[0]
			BigVy = BigVAB1[1]
			continue
		}

		BigVx, BigVy = secp256k1.S256().Add(BigVx, BigVy, BigVAB1[0], BigVAB1[1])
	}

	return commitbigcom, BigVx, BigVy
}

func DECDSASignRoundNine(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, mMtA *big.Int, r *big.Int, pkx *big.Int, pky *big.Int, BigVx *big.Int, BigVy *big.Int, rho1 *big.Int, commitbigcom map[string]*ec2.Commitment, l1 *big.Int, ch chan interface{}) ([]string, *ec2.Commitment) {
	//if len(idSign) == 0 || len(commitbigcom) == 0 || msgprex == "" || w == nil || cointype == "" || mMtA == nil || r == nil || pkx == nil || pky == nil || l1 == nil || rho1 == nil {
	//	res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
	//	ch <- res
	//	return nil, nil
	//}

	bigU1x, bigU1y := signing.DECDSA_Sign_Round_Nine(mMtA, r, pkx, pky, BigVx, BigVy, rho1)

	// bigA23 = bigA2 + bigA3
	var bigT1x, bigT1y *big.Int
	var ind int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x = BigVAB1[2]
		bigT1y = BigVAB1[3]
		ind = k
		break
	}

	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		if k == ind {
			continue
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		bigT1x, bigT1y = secp256k1.S256().Add(bigT1x, bigT1y, BigVAB1[2], BigVAB1[3])
	}

	commitBigUT1 := signing.DECDSA_Sign_Round_Nine_Commitment(bigT1x, bigT1y, l1, bigU1x, bigU1y)

	// Broadcast commitBigUT1.C
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUT"
	s1 := string(commitBigUT1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUT finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigut)
	common.Debug("===================finish get CommitBigUT, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUT",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUT timeout.")}
		ch <- res
		return nil, nil
	}

	commitbiguts := make([]string, w.ThresHold)
	if w.msg_commitbigut.Len() != w.ThresHold {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigUT fail.")}
		ch <- res
		return nil, nil
	}

	itmp := 0
	iter := w.msg_commitbigut.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbiguts[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbiguts, commitBigUT1
}

func DECDSASignRoundTen(msgprex string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, ch chan interface{}) []string {
	if msgprex == "" || commitBigUT1 == nil || w == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// *** Round 5D
	// Broadcast
	// commitBigUT1.D,  commitBigUT2.D,  commitBigUT3.D
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigUTD11"
	dlen := len(commitBigUT1.D)
	s1 := strconv.Itoa(dlen)

	ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep
	for _, d := range commitBigUT1.D {
		ss += string(d.Bytes())
		ss += common.Sep
	}
	ss = ss + "NULL"
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUTD11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigutd11)
	common.Debug("===================finish get CommitBigUTD11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUTD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	commitbigutd11s := make([]string, w.ThresHold)
	if w.msg_commitbigutd11.Len() != w.ThresHold {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_commitbigutd11.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		commitbigutd11s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	return commitbigutd11s
}

func DECDSASignVerifyBigUTCommitment(msgprex string,cointype string, commitbiguts []string, commitbigutd11s []string, commitBigUT1 *ec2.Commitment, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, commitbigcom map[string]*ec2.Commitment) bool {
	if msgprex == "" || cointype == "" || len(commitbiguts) == 0 || len(commitbigutd11s) == 0 || commitBigUT1 == nil || w == nil || len(idSign) == 0 || commitbigcom == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return false
	}

	var commitbigutmap = make(map[string]*ec2.Commitment)
	for _, v := range commitbiguts {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_commitbigut fail.")}
			ch <- res
			return false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range commitbigutd11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
				ch <- res
				return false
			}

			prex2 := mmm[0]
			prexs2 := strings.Split(prex2, "-")
			if prexs[len(prexs)-1] == prexs2[len(prexs2)-1] {
				dlen, _ := strconv.Atoi(mmm[2])
				var gg = make([]*big.Int, 0)
				l := 0
				for j := 0; j < dlen; j++ {
					l++
					if len(mmm) < (3 + l) {
						res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
						ch <- res
						return false
					}

					gg = append(gg, new(big.Int).SetBytes([]byte(mmm[2+l])))
				}

				deCommit := &ec2.Commitment{C: new(big.Int).SetBytes([]byte(mm[2])), D: gg}
				commitbigutmap[prexs[len(prexs)-1]] = deCommit
				break
			}
		}
	}

	commitbigutmap[cur_enode] = commitBigUT1

	var bigTBx, bigTBy *big.Int
	var bigUx, bigUy *big.Int
	for k, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigutmap[en[0]]) {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("verify commit big ut fail.")}
			ch <- res
			return false
		}

		_, BigUT1 := signing.DECDSA_Key_DeCommit(commitbigutmap[en[0]])
		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if k == 0 {
			bigTBx = BigUT1[2]
			bigTBy = BigUT1[3]
			bigUx = BigUT1[0]
			bigUy = BigUT1[1]
			bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
			continue
		}

		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigUT1[2], BigUT1[3])
		bigTBx, bigTBy = secp256k1.S256().Add(bigTBx, bigTBy, BigVAB1[4], BigVAB1[5])
		bigUx, bigUy = secp256k1.S256().Add(bigUx, bigUy, BigUT1[0], BigUT1[1])
	}

	if bigTBx.Cmp(bigUx) != 0 || bigTBy.Cmp(bigUy) != 0 {
		common.Debug("==============verify bigTB = BigU fails.=================","key",msgprex)
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("verify bigTB = BigU fails.")}
		ch <- res
		return false
	}

	return true
}

func DECDSASignRoundEleven(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, us1 *big.Int) map[string]*big.Int {
	if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil
	}

	// 4. Broadcast
	// s: s1, s2, s3
	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "SS1"
	s1 := string(us1.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToSmpcGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// s: s1, s2, s3
	common.Info("===================send SS1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(WaitMsgTimeGG20, w.bss1)
	common.Info("===================finish get SS1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from smpc group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout.")}
		ch <- res
		return nil
	}

	var ss1s = make(map[string]*big.Int)
	ss1s[cur_enode] = us1

	uss1s := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
		ch <- res
		return nil
	}

	itmp := 0
	iter := w.msg_ss1.Front()
	for iter != nil {
		mdss := iter.Value.(string)
		uss1s[itmp] = mdss
		iter = iter.Next()
		itmp++
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, w.groupid)
		////////bug
		if len(enodes) < 9 {
			res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil
		}
		////////
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		for _, v := range uss1s {
			mm := strings.Split(v, common.Sep)
			if len(mm) < 3 {
				res := RpcSmpcRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
				ch <- res
				return nil
			}

			prex := mm[0]
			prexs := strings.Split(prex, "-")
			if prexs[len(prexs)-1] == en[0] {
				tmp := new(big.Int).SetBytes([]byte(mm[2]))
				ss1s[en[0]] = tmp
				break
			}
		}
	}

	return ss1s
}
*/
