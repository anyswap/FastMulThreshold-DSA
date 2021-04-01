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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	//"github.com/anyswap/Anyswap-MPCNode/mpcdsa/crypto/ec2"
	//"github.com/anyswap/Anyswap-MPCNode/mpcdsa/ecdsa/signing"
	//"github.com/anyswap/Anyswap-MPCNode/mpcdsa/ecdsa/keygen"
	//"github.com/anyswap/Anyswap-MPCNode/mpcdsa/crypto/ed"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	//"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"

	"github.com/astaxie/beego/logs"
	"sync"
	//"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"container/list"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/ecdsa/signing"
	edsigning "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/eddsa/signing"
	dcrmlib "github.com/anyswap/Anyswap-MPCNode/dcrm-lib/dcrm"
	//"github.com/fsn-dev/cryptoCoins/coins"
	//"crypto/sha512"
	//"github.com/anyswap/Anyswap-MPCNode/dcrm-lib/crypto/ed"
	//"github.com/agl/ed25519"
	//"bytes"
	//bin "github.com/dfuse-io/binary"
)

var (
	signtodel = list.New()
	delsign    sync.Mutex
	count_to_del_sign = 10 
)

func GetSignNonce(account string) (string, string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit {
	    return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	return fmt.Sprintf("%v", nonce), "", nil
}

func SetSignNonce(account string,nonce string) (string, error) {
	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "Sign"))).Hex()
	kd := KeyData{Key: []byte(key), Data: nonce}
	PubKeyDataChan <- kd
	LdbPubKeyData.WriteMap(key, []byte(nonce))
	return "", nil
}

func SignInitAcceptData2(sbd *SignBrocastData,workid int,sender string,ch chan interface{}) error {
    if sbd == nil || workid < 0 || sender == "" || sbd.Raw == "" || sbd.PickHash == nil {
	res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
	ch <- res
	return fmt.Errorf("init accept data fail")
    }

    key,from,nonce,txdata,err := CheckRaw(sbd.Raw)
    common.Info("===================== SignInitAcceptData,get result from call CheckRaw ================","key",key,"from",from,"err",err,"raw",sbd.Raw,"tx data",txdata)
    if err != nil {
	common.Debug("=============== SignInitAcceptData,check raw===================","err ",err,"key",key,"from",from,"raw",sbd.Raw)
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }
    
    sig,ok := txdata.(*TxDataSign)
    if ok {
	    var pub string
	    if sig.InputCode != "" {
		pub = Keccak256Hash([]byte(strings.ToLower(sig.PubKey + ":" + sig.InputCode + ":" + sig.GroupId))).Hex()
	    } else {
		pub = Keccak256Hash([]byte(strings.ToLower(sig.PubKey + ":" + sig.GroupId))).Hex()
	    }
	   
	    if !strings.EqualFold(sender,cur_enode) {
		   DtPreSign.Lock()
		/////check pre-sign data
		for _,vv := range sbd.PickHash {
		    common.Debug("===============SignInitAcceptData,check pickkey===================","txhash",vv.Hash,"pickkey",vv.PickKey,"key",key)
		   PickPrePubDataByKey(pub,vv.PickKey)
		}
		///////
		DtPreSign.Unlock()
	   }

	common.Debug("=============== SignInitAcceptData, it is sign txdata and check sign raw success==================","key ",key,"from ",from,"nonce ",nonce)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetSignNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============SignInitAcceptData===============","sign cur_nonce_num ",cur_nonce_num,"sign new_nonce_num ",new_nonce_num,"key ",key)
	    //if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		//_, err := SetSignNonce(from,nonce)
		_, err := SetSignNonce(from,cur_nonce) //bug
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,sig.GroupId,Rpc_SIGN,sender)
		    ac := &AcceptSignData{Initiator:sender,Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
		    err = SaveAcceptSignData(ac)
		    if err == nil {
			common.Info("=============== SignInitAcceptData,save sign accept data finish===================","ars ",ars,"key ",key,"tx data",sig)
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

			w.DcrmFrom = sig.PubKey  // pubkey replace dcrmfrom in sign
			
			if sig.Mode == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := time.Duration(AgreeWait) * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptSignChan:
							common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== SignInitAcceptData, get all AcceptSignRes===============","result ",ars,"key ",key)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if !reply {
								tip = "don't accept sign"
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
							    	common.Debug("======================= SignInitAcceptData,11111111111111,set sign pending=============================","key",key)
								tip = ""
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", ars,wid)
							}

							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== SignInitAcceptData, agree wait timeout=============","ars",ars,"key ",key)
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				DisAcceptMsg(sbd.Raw,workid)
				common.Debug("===============SignInitAcceptData, call DisAcceptMsg finish===================","key ",key)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
				if reqaddrkey == "" {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr key fail") 
				}

				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("=============== SignInitAcceptData, get req addr key by other key fail ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("=============== SignInitAcceptData, get req addr key by other key error ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				common.Debug("=============== SignInitAcceptData, start call HandleC1Data===================","reqaddrkey ",reqaddrkey,"key ",key)

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				if !reply {
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,workid)
					} else {
						//sid-enode:SendSignRes:Success:rsv
						//sid-enode:SendSignRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendSignRes"
						s1 := "Fail"
						s2 := "don't accept sign."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(waitall, w.bsendsignres)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else if w.msg_sendsignres.Len() != w.ThresHold {
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendsignres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								common.Info("======================== SignInitAcceptData,get sign result==================","sign result",mdss)
								ms := strings.Split(mdss, common.Sep)
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							} else {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash,lohash, ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							}
						}
					}

					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res
					return fmt.Errorf("don't accept sign.")
				}
			} else {
				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,workid)
				if err != nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err:err}
				    ch <- res
				    return err
				}
			}

			common.Info("=============== SignInitAcceptData,begin to sign=================","sig.MsgHash ",sig.MsgHash,"sig.Mode ",sig.Mode,"key ",key)
			rch := make(chan interface{}, 1)
			sign(w.sid, from,sig.PubKey,sig.InputCode,sig.MsgHash,sig.Keytype,nonce,sig.Mode,sbd.PickHash,rch)
			chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
			common.Info("================== SignInitAcceptData,finish sig.================","return sign result ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					DeletePrePubDataBak(pub,vv.PickKey)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()
				
				res := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
			if tip == "get other node accept sign result timeout" {
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip,cherr.Error(),ars,workid)
			} else {
				//sid-enode:SendSignRes:Success:rsv
				//sid-enode:SendSignRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendSignRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(waitall, w.bsendsignres)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else if w.msg_sendsignres.Len() != w.ThresHold {
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendsignres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						common.Info("======================== SignInitAcceptData,get sign result==================","sign result",mdss)
						ms := strings.Split(mdss, common.Sep)
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}

						/////bug
						DtPreSign.Lock()
						for _,vv := range sbd.PickHash {
							DeletePrePubDataBak(pub,vv.PickKey)
							kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
							PrePubKeyDataChan <- kd
						}
						DtPreSign.Unlock()

						res := RpcDcrmRes{Ret: lohash, Tip: "", Err: nil}
						ch <- res
						return nil
						////bug

					} else {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					}
				}
			}

			if cherr != nil {
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					SetPrePubDataUseStatus(pub,vv.PickKey,false)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()

				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			DtPreSign.Lock()
			for _,vv := range sbd.PickHash {
				SetPrePubDataUseStatus(pub,vv.PickKey,false)
				kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
				PrePubKeyDataChan <- kd
			}
			DtPreSign.Unlock()

			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res
			return fmt.Errorf("sign fail.")
		    } else {
			common.Debug("=============== SignInitAcceptData, it is sign txdata,but save accept data fail==================","key ",key,"from ",from)
		    }
		} else {
			common.Debug("=============== SignInitAcceptData, it is sign txdata,but set nonce fail==================","key ",key,"from ",from)
		}
	    //}
	} else {
		common.Info("=============== SignInitAcceptData, it is sign txdata,but has handled before==================","key ",key,"from ",from)
	}
    }

    common.Debug("=============== SignInitAcceptData, it is not sign txdata and return fail ==================","key ",key,"from ",from,"nonce ",nonce)
    res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
    ch <- res
    return fmt.Errorf("init accept data fail")
}

func InitAcceptData2(sbd *SignBrocastData,workid int,sender string,ch chan interface{}) error {
    if sbd == nil || workid < 0 || sender == "" || sbd.Raw == "" || sbd.PickHash == nil {
	res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
	ch <- res
	return fmt.Errorf("init accept data fail")
    }

    key,from,nonce,txdata,err := CheckRaw(sbd.Raw)
    common.Info("=====================InitAcceptData2,get result from call CheckRaw ================","key",key,"from",from,"err",err,"raw",sbd.Raw,"tx data",txdata)
    if err != nil {
	common.Debug("===============InitAcceptData2,check raw===================","err ",err,"key",key,"from",from,"raw",sbd.Raw)
	res := RpcDcrmRes{Ret: "", Tip: err.Error(), Err: err}
	ch <- res
	return err
    }
    
    sig,ok := txdata.(*TxDataSign)
    if ok {
	    var pub string
	    if sig.InputCode != "" {
		pub = Keccak256Hash([]byte(strings.ToLower(sig.PubKey + ":" + sig.InputCode + ":" + sig.GroupId))).Hex()
	    } else {
		pub = Keccak256Hash([]byte(strings.ToLower(sig.PubKey + ":" + sig.GroupId))).Hex()
	    }
	   
	    if !strings.EqualFold(sender,cur_enode) {
		   DtPreSign.Lock()
		/////check pre-sign data
		for _,vv := range sbd.PickHash {
		    common.Debug("===============InitAcceptData2,check pickkey===================","txhash",vv.Hash,"pickkey",vv.PickKey,"key",key)
		   PickPrePubDataByKey(pub,vv.PickKey)
		}
		///////
		DtPreSign.Unlock()
	   }

	common.Debug("===============InitAcceptData2, it is sign txdata and check sign raw success==================","key ",key,"from ",from,"nonce ",nonce)
	exsit,_ := GetValueFromPubKeyData(key)
	if !exsit {
	    cur_nonce, _, _ := GetSignNonce(from)
	    cur_nonce_num, _ := new(big.Int).SetString(cur_nonce, 10)
	    new_nonce_num, _ := new(big.Int).SetString(nonce, 10)
	    common.Debug("===============InitAcceptData2===============","sign cur_nonce_num ",cur_nonce_num,"sign new_nonce_num ",new_nonce_num,"key ",key)
	    //if new_nonce_num.Cmp(cur_nonce_num) >= 0 {
		//_, err := SetSignNonce(from,nonce)
		_, err := SetSignNonce(from,cur_nonce) //bug
		if err == nil {
		    ars := GetAllReplyFromGroup(workid,sig.GroupId,Rpc_SIGN,sender)
		    ac := &AcceptSignData{Initiator:sender,Account: from, GroupId: sig.GroupId, Nonce: nonce, PubKey: sig.PubKey, MsgHash: sig.MsgHash, MsgContext: sig.MsgContext, Keytype: sig.Keytype, LimitNum: sig.ThresHold, Mode: sig.Mode, TimeStamp: sig.TimeStamp, Deal: "false", Accept: "false", Status: "Pending", Rsv: "", Tip: "", Error: "", AllReply: ars, WorkId:workid}
		    err = SaveAcceptSignData(ac)
		    if err == nil {
			common.Info("===============InitAcceptDatai2,save sign accept data finish===================","ars ",ars,"key ",key,"tx data",sig)
			///////bug
			for k,v := range workers {
			    if strings.EqualFold(v.sid, key) {
				err = SignInitAcceptData(sbd.Raw,k,sender,ch)
				v.bwire <-true //add for dcrm-lib
				return err 
			    }
			}
			//////////

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

			w.DcrmFrom = sig.PubKey  // pubkey replace dcrmfrom in sign
			
			if sig.Mode == "0" { // self-group
				////
				var reply bool
				var tip string
				timeout := make(chan bool, 1)
				go func(wid int) {
					cur_enode = discover.GetLocalID().String() //GetSelfEnode()
					agreeWaitTime := time.Duration(AgreeWait) * time.Minute
					agreeWaitTimeOut := time.NewTicker(agreeWaitTime)

					wtmp2 := workers[wid]

					for {
						select {
						case account := <-wtmp2.acceptSignChan:
							common.Debug("InitAcceptData,", "account= ", account, "key = ", key)
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== InitAcceptData2 , get all AcceptSignRes===============","result ",ars,"key ",key)
							
							//bug
							reply = true
							for _,nr := range ars {
							    if !strings.EqualFold(nr.Status,"Agree") {
								reply = false
								break
							    }
							}
							//

							if !reply {
								tip = "don't accept sign"
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Failure", "", "don't accept sign", "don't accept sign", ars,wid)
							} else {
							    	common.Debug("=======================InitAcceptData2,11111111111111,set sign pending=============================","key",key)
								tip = ""
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "", "", ars,wid)
							}

							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

							///////
							timeout <- true
							return
						case <-agreeWaitTimeOut.C:
							ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
							common.Info("================== InitAcceptData2 , agree wait timeout=============","ars",ars,"key ",key)
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "false", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,wid)
							reply = false
							tip = "get other node accept sign result timeout"
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}
							//

							timeout <- true
							return
						}
					}
				}(workid)

				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				DisAcceptMsg(sbd.Raw,workid)
				common.Debug("===============InitAcceptData2, call DisAcceptMsg finish===================","key ",key)
				reqaddrkey := GetReqAddrKeyByOtherKey(key,Rpc_SIGN)
				if reqaddrkey == "" {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get req addr key fail", Err: fmt.Errorf("get reqaddr key fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr key fail") 
				}

				exsit,da := GetValueFromPubKeyData(reqaddrkey)
				if !exsit {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("===============InitAcceptData2, get req addr key by other key fail ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				acceptreqdata,ok := da.(*AcceptReqAddrData)
				if !ok || acceptreqdata == nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					common.Debug("===============InitAcceptData2, get req addr key by other key error ===================","key ",key)
				    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get reqaddr sigs data fail", Err: fmt.Errorf("get reqaddr sigs data fail")}
				    ch <- res
				    return fmt.Errorf("get reqaddr sigs data fail") 
				}

				common.Debug("===============InitAcceptData2, start call HandleC1Data===================","reqaddrkey ",reqaddrkey,"key ",key)

				HandleC1Data(acceptreqdata,key,workid)

				<-timeout

				if !reply {
					if tip == "get other node accept sign result timeout" {
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", "get other node accept sign result timeout", "get other node accept sign result timeout", ars,workid)
					} else {
						//sid-enode:SendSignRes:Success:rsv
						//sid-enode:SendSignRes:Fail:err
						mp := []string{w.sid, cur_enode}
						enode := strings.Join(mp, "-")
						s0 := "SendSignRes"
						s1 := "Fail"
						s2 := "don't accept sign."
						ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
						SendMsgToDcrmGroup(ss, w.groupid)
						DisMsg(ss)
						_, _, err := GetChannelValue(waitall, w.bsendsignres)
						ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
						if err != nil {
							tip = "get other node terminal accept sign result timeout" ////bug
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else if w.msg_sendsignres.Len() != w.ThresHold {
							_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars,workid)
							if err != nil {
							    tip = tip + " and accept sign data fail"
							}

						} else {
							reply2 := "false"
							lohash := ""
							iter := w.msg_sendsignres.Front()
							for iter != nil {
								mdss := iter.Value.(string)
								common.Info("========================InitAcceptData2,get sign result==================","sign result",mdss)
								ms := strings.Split(mdss, common.Sep)
								if strings.EqualFold(ms[2], "Success") {
									reply2 = "true"
									lohash = ms[3]
									break
								}

								lohash = ms[3]
								iter = iter.Next()
							}

							if reply2 == "true" {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							} else {
								_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash,lohash, ars,workid)
								if err != nil {
								    tip = tip + " and accept sign data fail"
								}

							}
						}
					}

					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

					res := RpcDcrmRes{Ret:"", Tip: tip, Err: fmt.Errorf("don't accept sign.")}
					ch <- res
					return fmt.Errorf("don't accept sign.")
				}
			} else {
				if len(workers[workid].acceptWaitSignChan) == 0 {
					workers[workid].acceptWaitSignChan <- "go on"
				}

				ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"false", "true", "Pending", "", "","", ars,workid)
				if err != nil {
					DtPreSign.Lock()
					for _,vv := range sbd.PickHash {
						SetPrePubDataUseStatus(pub,vv.PickKey,false)
						kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
						PrePubKeyDataChan <- kd
					}
					DtPreSign.Unlock()

				    res := RpcDcrmRes{Ret:"", Tip: err.Error(), Err:err}
				    ch <- res
				    return err
				}
			}

			common.Info("===============InitAcceptData2,begin to sign=================","sig.MsgHash ",sig.MsgHash,"sig.Mode ",sig.Mode,"key ",key)
			rch := make(chan interface{}, 1)
			sign(w.sid, from,sig.PubKey,sig.InputCode,sig.MsgHash,sig.Keytype,nonce,sig.Mode,sbd.PickHash,rch)
			chret, tip, cherr := GetChannelValue(waitallgg20+20, rch)
			common.Info("================== InitAcceptData2,finish sig.================","return sign result ",chret,"err ",cherr,"key ",key)
			if chret != "" {
				//common.Debug("===================InitAcceptData2,DeletePrePubData,11111===============","current total number of the data ",GetTotalCount(sig.PubKey),"key",key)
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					DeletePrePubDataBak(pub,vv.PickKey)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()
				//common.Debug("===================InitAcceptData2,DeletePrePubData,22222===============","current total number of the data ",GetTotalCount(sig.PubKey),"key",key)
				
				res := RpcDcrmRes{Ret: chret, Tip: "", Err: nil}
				ch <- res
				return nil
			}

			ars := GetAllReplyFromGroup(w.id,sig.GroupId,Rpc_SIGN,sender)
			if tip == "get other node accept sign result timeout" {
				_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip,cherr.Error(),ars,workid)
			} else {
				//sid-enode:SendSignRes:Success:rsv
				//sid-enode:SendSignRes:Fail:err
				mp := []string{w.sid, cur_enode}
				enode := strings.Join(mp, "-")
				s0 := "SendSignRes"
				s1 := "Fail"
				s2 := cherr.Error()
				ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
				SendMsgToDcrmGroup(ss, w.groupid)
				DisMsg(ss)
				_, _, err := GetChannelValue(waitall, w.bsendsignres)
				if err != nil {
					tip = "get other node terminal accept sign result timeout" ////bug
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Timeout", "", tip, tip, ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else if w.msg_sendsignres.Len() != w.ThresHold {
					_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", "get other node sign result fail", "get other node sign result fail", ars, workid)
					if err != nil {
					    tip = tip + " and accept sign data fail"
					}

				} else {
					reply2 := "false"
					lohash := ""
					iter := w.msg_sendsignres.Front()
					for iter != nil {
						mdss := iter.Value.(string)
						common.Info("========================InitAcceptData2,get sign result==================","sign result",mdss)
						ms := strings.Split(mdss, common.Sep)
						if strings.EqualFold(ms[2], "Success") {
							reply2 = "true"
							lohash = ms[3]
							break
						}

						lohash = ms[3]
						iter = iter.Next()
					}

					if reply2 == "true" {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "true", "Success", lohash, " ", " ", ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					
						/////bug
						DtPreSign.Lock()
						for _,vv := range sbd.PickHash {
							DeletePrePubDataBak(pub,vv.PickKey)
							kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
							PrePubKeyDataChan <- kd
						}
						DtPreSign.Unlock()

						res := RpcDcrmRes{Ret: lohash, Tip: "", Err: nil}
						ch <- res
						return nil
						////bug

					} else {
						_,err = AcceptSign(sender,from,sig.PubKey,sig.MsgHash,sig.Keytype,sig.GroupId,nonce,sig.ThresHold,sig.Mode,"true", "", "Failure", "", lohash, lohash, ars, workid)
						if err != nil {
						    tip = tip + " and accept sign data fail"
						}
					}
				}
			}

			if cherr != nil {
				DtPreSign.Lock()
				for _,vv := range sbd.PickHash {
					SetPrePubDataUseStatus(pub,vv.PickKey,false)
					kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					PrePubKeyDataChan <- kd
				}
				DtPreSign.Unlock()

				res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
				ch <- res
				return cherr
			}

			DtPreSign.Lock()
			for _,vv := range sbd.PickHash {
				SetPrePubDataUseStatus(pub,vv.PickKey,false)
				kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
				PrePubKeyDataChan <- kd
			}
			DtPreSign.Unlock()

			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("sign fail.")}
			ch <- res
			return fmt.Errorf("sign fail.")
		    } else {
			common.Debug("===============InitAcceptData2, it is sign txdata,but save accept data fail==================","key ",key,"from ",from)
		    }
		} else {
			common.Debug("===============InitAcceptData2, it is sign txdata,but set nonce fail==================","key ",key,"from ",from)
		}
	    //}
	} else {
		common.Info("===============InitAcceptData2, it is sign txdata,but has handled before==================","key ",key,"from ",from)
	}
    }

    common.Debug("===============InitAcceptData2, it is not sign txdata and return fail ==================","key ",key,"from ",from,"nonce ",nonce)
    res := RpcDcrmRes{Ret: "", Tip: "init accept data fail.", Err: fmt.Errorf("init accept data fail")}
    ch <- res
    return fmt.Errorf("init accept data fail")
}

func RpcAcceptSign(raw string) (string, string, error) {
    common.Debug("=====================RpcAcceptSign call CheckRaw ================","raw",raw)
    _,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================RpcAcceptSign,call CheckRaw finish================","raw",raw,"err",err)
	return "Failure",err.Error(),err
    }

    acceptsig,ok := txdata.(*TxDataAcceptSign)
    if !ok {
	return "Failure","check raw fail,it is not *TxDataAcceptSign",fmt.Errorf("check raw fail,it is not *TxDataAcceptSign")
    }

    exsit,da := GetValueFromPubKeyData(acceptsig.Key)
    if exsit {
	ac,ok := da.(*AcceptSignData)
	if ok && ac != nil {
	    common.Info("=====================RpcAcceptSign,call CheckRaw finish ================","key",acceptsig.Key,"from",from,"accept",acceptsig.Accept,"raw",raw)
	    SendMsgToDcrmGroup(raw, ac.GroupId)
	    SetUpMsgList(raw,cur_enode)
	    return "Success", "", nil
	}
    }

    return "Failure","accept fail",fmt.Errorf("accept fail")
}

type TxDataSign struct {
    TxType string
    PubKey string
    InputCode string
    MsgHash []string
    MsgContext []string
    Keytype string
    GroupId string
    ThresHold string
    Mode string
    TimeStamp string
}

func Sign(raw string) (string, string, error) {
    common.Debug("=====================Sign call CheckRaw ================","raw",raw)
    key,from,_,txdata,err := CheckRaw(raw)
    if err != nil {
	common.Info("=====================Sign,call CheckRaw finish================","raw",raw,"err",err)
	return "",err.Error(),err
    }

    sig,ok := txdata.(*TxDataSign)
    if !ok {
	return "","check raw fail,it is not *TxDataSign",fmt.Errorf("check raw fail,it is not *TxDataSign")
    }

    common.Debug("=====================Sign================","key",key,"from",from,"raw",raw)

    if sig.Keytype == "ED25519" {
	common.Info("============Sign,SendMsgToDcrmGroup===============","raw ",raw,"gid ",sig.GroupId,"key ",key)
	SendMsgToDcrmGroup(raw, sig.GroupId)
	SetUpMsgList(raw,cur_enode)
    } else {
	rsd := &RpcSignData{Raw:raw,PubKey:sig.PubKey,InputCode:sig.InputCode,GroupId:sig.GroupId,MsgHash:sig.MsgHash,Key:key}
	SignChan <- rsd
    }
    return key, "", nil
}

func HandleRpcSign() {
	for {
		rsd := <-SignChan
	
		dcrmpks, _ := hex.DecodeString(rsd.PubKey)
		exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
		common.Debug("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit)
		if exsit {
			_,ok := da.(*PubKeyData)
			common.Debug("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit,"ok",ok)
			if ok {
			    var pub string
			    if rsd.InputCode != "" {
				pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.InputCode + ":" + rsd.GroupId))).Hex()
			    } else {
				pub = Keccak256Hash([]byte(strings.ToLower(rsd.PubKey + ":" + rsd.GroupId))).Hex()
			    }
			    
			    bret := false
			    pickhash := make([]*PickHashKey,0)
			    for _,vv := range rsd.MsgHash {
				    pickkey := PickPrePubData(pub)
				    if pickkey == "" {
					    bret = true
					    break
				    }

				    common.Info("========================HandleRpcSign,choose pickkey==================","txhash",vv,"pickkey",pickkey,"key",rsd.Key)
				    ph := &PickHashKey{Hash:vv,PickKey:pickkey}
				    pickhash = append(pickhash,ph)

				    //check pre sigal
				    if rsd.InputCode != "" {
					if GetTotalCount(pub) >= (PreBip32DataCount/2) && GetTotalCount(pub) <= PreBip32DataCount {
						PutPreSigal(pub,false)
					} else {
						PutPreSigal(pub,true)
					}
				    } else {
					if GetTotalCount(pub) >= (PrePubDataCount*3/4) && GetTotalCount(pub) <= PrePubDataCount {
						PutPreSigal(pub,false)
					} else {
						PutPreSigal(pub,true)
					}
				    }
				    //
			    }

			    if bret {
				    continue
			    }

			    send,err := CompressSignBrocastData(rsd.Raw,pickhash)
			    if err != nil {
				    common.Info("=========================HandleRpcSign======================","rsd.Pubkey",rsd.PubKey,"key",rsd.Key,"exsit",exsit,"ok",ok,"bret",bret,"err",err)
				    DtPreSign.Lock()
				    for _,vv := range pickhash {
					    SetPrePubDataUseStatus(pub,vv.PickKey,false)
					    kd := UpdataPreSignData{Key:[]byte(strings.ToLower(pub)),Del:true,Data:vv.PickKey}
					    PrePubKeyDataChan <- kd
				    }
				    DtPreSign.Unlock()

				    continue
			    }

			    SendMsgToDcrmGroup(send,rsd.GroupId)
			    SetUpMsgList(send,cur_enode)
			}
		}
	}
}

func get_sign_hash(hash []string,keytype string) string {
    var ids sortableIDSSlice
    for _, v := range hash {
	    uid := DoubleHash2(v, keytype)
	    ids = append(ids, uid)
    }
    sort.Sort(ids)

    ret := ""
    for _,v := range ids {
	ret += fmt.Sprintf("%v",v)
	ret += ":"
    }

    ret += "NULL"
    return ret
}

//===================================================================

type SignStatus struct {
	Status    string
	Rsv []string
	Tip       string
	Error     string
	AllReply  []NodeReply 
	TimeStamp string
}

func GetSignStatus(key string) (string, string, error) {
	exsit,da := GetValueFromPubKeyData(key)
	///////
	if !exsit || da == nil {
		common.Info("=================GetSignStatus,get sign accept data fail from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data fail from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data fail from db when GetSignStatus")
	}

	ac,ok := da.(*AcceptSignData)
	if !ok {
		common.Info("=================GetSignStatus,get sign accept data error from db================","key",key)
		return "", "dcrm back-end internal error:get sign accept data error from db when GetSignStatus", fmt.Errorf("dcrm back-end internal error:get sign accept data error from db when GetSignStatus")
	}

	rsvs := strings.Split(ac.Rsv,":")
	los := &SignStatus{Status: ac.Status, Rsv: rsvs[:len(rsvs)-1], Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret,_ := json.Marshal(los)
	return string(ret), "",nil 
}

type SignCurNodeInfo struct {
	Key       string
	Account   string
	PubKey   string
	MsgHash   []string
	MsgContext   []string
	KeyType   string
	GroupId   string
	Nonce     string
	ThresHold  string
	Mode      string
	TimeStamp string
}

func GetCurNodeSignInfo(geter_acc string) ([]*SignCurNodeInfo, string, error) {
	var ret []*SignCurNodeInfo
	var wg sync.WaitGroup
	LdbPubKeyData.RLock()
	for k, v := range LdbPubKeyData.Map {
	    wg.Add(1)
	    go func(key string,value interface{}) {
		defer wg.Done()

		vv,ok := value.(*AcceptSignData)
		if vv == nil || !ok {
		    return
		}

		common.Debug("================GetCurNodeSignInfo======================","vv",vv,"vv.Deal",vv.Deal,"vv.Status",vv.Status,"key",key)
		if vv.Deal == "true" || vv.Status == "Success" {
		    return
		}

		if vv.Status != "Pending" {
		    return
		}

		if !CheckAccept(vv.PubKey,vv.Mode,geter_acc) {
			return
		}
		
		los := &SignCurNodeInfo{Key: key, Account: vv.Account, PubKey:vv.PubKey, MsgHash:vv.MsgHash, MsgContext:vv.MsgContext, KeyType:vv.Keytype, GroupId: vv.GroupId, Nonce: vv.Nonce, ThresHold: vv.LimitNum, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
		ret = append(ret, los)
		common.Debug("================GetCurNodeSignInfo success return=======================","key",key)
	    }(k,v)
	}
	LdbPubKeyData.RUnlock()
	wg.Wait()
	return ret, "", nil
}

func sign_ed(msgprex string,txhash []string,save string, sku1 *big.Int, pk string, keytype string, ch chan interface{}) string {

    	tmp := make([]string,0)
	for _,v := range txhash {
	    txhashs := []rune(v)
	    if string(txhashs[0:2]) == "0x" {
		    tmp = append(tmp,string(txhashs[2:]))
	    } else {
		tmp = append(tmp,string(txhashs))
	    }
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		logs.Debug("===========get worker fail.=============")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: GetRetErr(ErrNoFindWorker)}
		ch <- res
		return ""
	}
	id := w.id

	cur_enode = GetSelfEnode()

	logs.Debug("===================!!!Start!!!====================")

	var result string
	var bak_sig string
	for _,v := range tmp {
	    var ch1 = make(chan interface{}, 1)
	    for i:=0;i < recalc_times;i++ {
		//fmt.Printf("%v===============sign_ed, recalc i = %v, key = %v ================\n",common.CurrentTime(),i,msgprex)
		if len(ch1) != 0 {
		    <-ch1
		}

		//w := workers[id]
		//w.Clear2()
		bak_sig = Sign_ed(msgprex, save, sku1, v, keytype, pk, ch1, id)
		ret, _, cherr := GetChannelValue(ch_t, ch1)
		if ret != "" && cherr == nil {
		    result += ret
		    result += ":"
			//res := RpcDcrmRes{Ret: ret, Tip: "", Err: cherr}
			//ch <- res
			break
		}

		time.Sleep(time.Duration(3) * time.Second) //1000 == 1s
	    }
	}

	result += "NULL"
	tmps := strings.Split(result, ":")
	if len(tmps) == (len(tmp) + 1) {
	    res := RpcDcrmRes{Ret: result, Tip: "", Err: nil}
	    ch <- res
	}

	return bak_sig
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ed(msgprex string, save string, sku1 *big.Int, message string, cointype string, pk string, ch chan interface{}, id int) string {
	logs.Debug("===================Sign_ed====================")
	if id < 0 || id >= len(workers) || id >= RPCMaxWorker {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get worker id fail", Err: GetRetErr(ErrGetWorkerIdError)}
		ch <- res
		return ""
	}

	w := workers[id]
	GroupId := w.groupid
	fmt.Println("========Sign_ed============", "GroupId", GroupId)
	if GroupId == "" {
		res := RpcDcrmRes{Ret: "", Tip: "get group id fail", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(save), &msgmap)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return "" 
	}
	kgsave := GetKGLocalDBSaveData_ed(msgmap)
	if kgsave == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "ed presign get local save data fail", Err: fmt.Errorf("ed presign get local save data fail")}
	    ch <- res
	    return ""
	}
	sd := kgsave.Save
	
	idsign := GetIdSignByGroupId_ed(sd.Ids,kgsave.MsgToEnode,w.groupid)

	mMtA, _ := new(big.Int).SetString(message, 16)
	fmt.Printf("==============Sign_ed, w.groupid = %v, message = %v ==============\n",w.groupid,message)

	commStopChan := make(chan struct{})
	outCh := make(chan dcrmlib.Message, w.ThresHold)
	endCh := make(chan edsigning.EdSignData,w.ThresHold)
	finalize_endCh := make(chan *big.Int,w.ThresHold) //useness
	errChan := make(chan struct{})
	signDNode := edsigning.NewLocalDNode(outCh,endCh,sd,idsign,sd.CurDNodeID,w.ThresHold,PaillierKeyLength,false,nil,mMtA,finalize_endCh)
	w.DNode = signDNode
	
	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
		    fmt.Printf("==========ed sign node start err = %v ==========\n",err)
			close(errChan)
		}
		
		//fmt.Printf("=================ed sign, handle save msg 111111, len w.PreSaveDcrmMsg = %v, key = %v ===================\n",len(w.PreSaveDcrmMsg),msgprex)
		for _,v := range w.PreSaveDcrmMsg {
		    fmt.Printf("=================ed sign, handle save msg, v = %v, key = %v ===================\n",v,msgprex)
		    w.DcrmMsg <- v 
		}
	}()
	go EdSignProcessInboundMessages(msgprex,commStopChan,&signWg,ch)
	edrs,err := processSign_ed(msgprex,kgsave.MsgToEnode,errChan, outCh, endCh)
	if err != nil || edrs == nil {
	    fmt.Printf("==========process ed sign err = %v ==========\n",err)
	    close(commStopChan)
	    res := RpcDcrmRes{Ret: "", Err: err}
	    ch <- res
	    return "" 
	}

	close(commStopChan)
	signWg.Wait()

	/*ids := GetIds(cointype, GroupId)
	idSign := ids[:w.ThresHold]

	m := strings.Split(save, common.Sep11)

	var sk [64]byte
	//va := []byte(m[0])
	va := sku1.Bytes()
	copy(sk[:], va[:64])
	//pk := ([]byte(m[1]))[:]
	var tsk [32]byte
	va = []byte(m[2])
	copy(tsk[:], va[:32])
	var pkfinal [32]byte
	va = []byte(m[3])
	copy(pkfinal[:], va[:32])

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

	// [Notes]
	// 1. calculate R
	var r [32]byte
	var RBytes [32]byte
	var rDigest [64]byte

	h := sha512.New()
	_,err := h.Write(sk[32:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write sk fail in caling R", Err: err}
	    ch <- res
	    return ""
	}

	_,err = h.Write([]byte(message))
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write message fail in caling R", Err: err}
	    ch <- res
	    return ""
	}

	h.Sum(rDigest[:0])
	ed.ScReduce(&r, &rDigest)

	var R ed.ExtendedGroupElement
	ed.GeScalarMultBase(&R, &r)

	// 2. commit(R)
	R.ToBytes(&RBytes)
	CR, DR := ed.Commit(RBytes)

	// 3. zkSchnorr(rU1)
	zkR := ed.Prove(r)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "EDC21"
	s1 := string(CR[:])

	ss := enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDC21==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr := GetChannelValue(ch_t, w.bedc21)
	if cherr != nil {
		logs.Debug("get w.bedc21 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed c21 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edc21.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edc21 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_edc21 fail", Err: fmt.Errorf("get all ed c21 fail.")}
		ch <- res
		return ""
	}
	var crs = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			crs[cur_enode] = CR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc21.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				crs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDZKR"
	s1 = string(zkR[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDZKR==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedzkr)
	if cherr != nil {
		logs.Debug("get w.bedzkr timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed zkr timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edzkr.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edzkr fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edzkr fail", Err: fmt.Errorf("get all ed zkr fail.")}
		ch <- res
		return ""
	}

	var zkrs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			zkrs[cur_enode] = zkR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edzkr.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				zkrs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDD21"
	s1 = string(DR[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDD21==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd21)
	if cherr != nil {
		logs.Debug("get w.bedd21 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed d21 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edd21.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edd21 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edd21 fail", Err: fmt.Errorf("get all ed d21 fail.")}
		ch <- res
		return ""
	}
	var drs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			drs[cur_enode] = DR
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd21.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				drs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CRFlag := ed.Verify(crs[en[0]], drs[en[0]])
		if !CRFlag {
			fmt.Printf("Error: Commitment(R) Not Pass at User: %v", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:commitment verification fail in ed sign", Err: fmt.Errorf("Commitment(R) Not Pass.")}
			ch <- res
			return ""
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temR [32]byte
		t := drs[en[0]]
		copy(temR[:], t[32:])

		zkRFlag := ed.Verify_zk(zkrs[en[0]], temR)
		if !zkRFlag {
			fmt.Printf("Error: ZeroKnowledge Proof (R) Not Pass at User: %v", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:zeroknowledge verification fail in ed sign", Err: fmt.Errorf("ZeroKnowledge Proof (R) Not Pass.")}
			ch <- res
			return ""
		}
	}

	var FinalR, temR ed.ExtendedGroupElement
	var FinalRBytes [32]byte
	for index, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temRBytes [32]byte
		t := drs[en[0]]
		copy(temRBytes[:], t[32:])
		temR.FromBytes(&temRBytes)
		if index == 0 {
			FinalR = temR
		} else {
			ed.GeAdd(&FinalR, &FinalR, &temR)
		}
	}
	FinalR.ToBytes(&FinalRBytes)

	// 2.6 calculate k=H(FinalRBytes||pk||M)
	var k [32]byte
	var kDigest [64]byte

	h = sha512.New()
	_,err = h.Write(FinalRBytes[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write final r fail in caling k", Err: fmt.Errorf("write final r fail in caling k")}
	    ch <- res
	    return ""
	}

	_,err = h.Write(pkfinal[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write pk fail in caling k", Err: fmt.Errorf("write pk fail in caling k")}
	    ch <- res
	    return ""
	}

	_,err = h.Write(([]byte(message))[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write message fail in caling k", Err: fmt.Errorf("write message fail in caling k")}
	    ch <- res
	    return ""
	}

	h.Sum(kDigest[:0])

	ed.ScReduce(&k, &kDigest)

	// 2.7 calculate lambda1
	var lambda [32]byte
	lambda[0] = 1
	order := ed.GetBytesOrder()

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		if IsCurNode(enodes, cur_enode) {
			continue
		}

		var time [32]byte
		t := uids[en[0]]
		tt := uids[cur_enode]
		ed.ScSub(&time, &t, &tt)
		time = ed.ScModInverse(time, order)
		ed.ScMul(&time, &time, &t)
		ed.ScMul(&lambda, &lambda, &time)
	}

	var s [32]byte
	ed.ScMul(&s, &lambda, &tsk)
	ed.ScMul(&s, &s, &k)
	ed.ScAdd(&s, &s, &r)

	// 2.9 calculate sBBytes
	var sBBytes [32]byte
	var sB ed.ExtendedGroupElement
	ed.GeScalarMultBase(&sB, &s)
	sB.ToBytes(&sBBytes)

	// 2.10 commit(sBBytes)
	CSB, DSB := ed.Commit(sBBytes)

	s0 = "EDC31"
	s1 = string(CSB[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDC31==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedc31)
	if cherr != nil {
		logs.Debug("get w.bedc31 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed c31 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edc31.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edc31 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_edc31 fail", Err: fmt.Errorf("get all ed c31 fail.")}
		ch <- res
		return ""
	}
	var csbs = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			csbs[cur_enode] = CSB
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edc31.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				csbs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	s0 = "EDD31"
	s1 = string(DSB[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDD31==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.bedd31)
	if cherr != nil {
		logs.Debug("get w.bedd31 timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed d31 timeout.")}
		ch <- res
		return ""
	}

	if w.msg_edd31.Len() != w.NodeCnt {
		logs.Debug("get w.msg_edd31 fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get all msg_edd31 fail", Err: fmt.Errorf("get all ed d31 fail.")}
		ch <- res
		return ""
	}
	var dsbs = make(map[string][64]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			dsbs[cur_enode] = DSB
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_edd31.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [64]byte
				va := []byte(m[2])
				copy(t[:], va[:64])
				dsbs[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		CSBFlag := ed.Verify(csbs[en[0]], dsbs[en[0]])
		if !CSBFlag {
			fmt.Printf("Error: Commitment(SB) Not Pass at User: %v", en[0])
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:commitment(CSB) not pass", Err: fmt.Errorf("Commitment(SB) Not Pass.")}
			ch <- res
			return ""
		}
	}

	var sB2, temSB ed.ExtendedGroupElement
	for index, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		var temSBBytes [32]byte
		t := dsbs[en[0]]
		copy(temSBBytes[:], t[32:])
		temSB.FromBytes(&temSBBytes)

		if index == 0 {
			sB2 = temSB
		} else {
			ed.GeAdd(&sB2, &sB2, &temSB)
		}
	}

	var k2 [32]byte
	var kDigest2 [64]byte

	h = sha512.New()
	_,err = h.Write(FinalRBytes[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write final r fail in caling k2", Err: fmt.Errorf("write final r fail in caling k2.")}
	    ch <- res
	    return ""
	}

	_,err = h.Write(pkfinal[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write final pk fail in caling k2", Err: fmt.Errorf("write final pk fail in caling k2.")}
	    ch <- res
	    return ""
	}

	_,err = h.Write(([]byte(message))[:])
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:write message fail in caling k2", Err: fmt.Errorf("write message fail in caling k2.")}
	    ch <- res
	    return ""
	}

	h.Sum(kDigest2[:0])

	ed.ScReduce(&k2, &kDigest2)

	// 3.6 calculate sBCal
	var FinalR2, sBCal, FinalPkB ed.ExtendedGroupElement
	FinalR2.FromBytes(&FinalRBytes)
	FinalPkB.FromBytes(&pkfinal)
	ed.GeScalarMult(&sBCal, &k2, &FinalPkB)
	ed.GeAdd(&sBCal, &sBCal, &FinalR2)

	// 3.7 verify equation
	var sBBytes2, sBCalBytes [32]byte
	sB2.ToBytes(&sBBytes2)
	sBCal.ToBytes(&sBCalBytes)

	if !bytes.Equal(sBBytes2[:], sBCalBytes[:]) {
		fmt.Printf("Error: Not Pass Verification (SB = SBCal) at User: %v \n", cur_enode)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:not pass verification (CSB == SBCal)", Err: fmt.Errorf("Error: Not Pass Verification (SB = SBCal).")}
		ch <- res
		return ""
	}

	s0 = "EDS"
	s1 = string(s[:])
	ss = enode + common.Sep + s0 + common.Sep + s1
	logs.Debug("================sign ed round one,send msg,code is EDS==================")
	SendMsgToDcrmGroup(ss, GroupId)
	DisMsg(ss)

	_, tip, cherr = GetChannelValue(ch_t, w.beds)
	if cherr != nil {
		logs.Debug("get w.beds timeout.")
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ed s timeout.")}
		ch <- res
		return ""
	}

	if w.msg_eds.Len() != w.NodeCnt {
		logs.Debug("get w.msg_eds fail.")
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get msg_eds fail", Err: fmt.Errorf("get all ed s fail.")}
		ch <- res
		return ""
	}
	var eds = make(map[string][32]byte)
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		if IsCurNode(enodes, cur_enode) {
			eds[cur_enode] = s
			continue
		}

		en := strings.Split(string(enodes[8:]), "@")

		iter := w.msg_eds.Front()
		for iter != nil {
			data := iter.Value.(string)
			m := strings.Split(data, common.Sep)
			ps := strings.Split(m[0], "-")
			if strings.EqualFold(ps[1], en[0]) {
				var t [32]byte
				va := []byte(m[2])
				copy(t[:], va[:32])
				eds[en[0]] = t
				break
			}
			iter = iter.Next()
		}
	}

	var FinalS [32]byte
	for _, id := range idSign {
		enodes := GetEnodesByUid(id, cointype, GroupId)
		en := strings.Split(string(enodes[8:]), "@")
		t := eds[en[0]]
		ed.ScAdd(&FinalS, &FinalS, &t)
	}

	inputVerify := InputVerify{FinalR: FinalRBytes, FinalS: FinalS, Message: []byte(message), FinalPk: pkfinal}

	var pass = EdVerify(inputVerify)
	common.Debug("===========ed verify============","pass",pass)

	//r
	rx := hex.EncodeToString(FinalRBytes[:])
	sx := hex.EncodeToString(FinalS[:])
	logs.Debug("========sign_ed========", "rx", rx, "sx", sx, "FinalRBytes", FinalRBytes, "FinalS", FinalS)

	//////test
	signature := new([64]byte)
	copy(signature[:], FinalRBytes[:])
	copy(signature[32:], FinalS[:])
	suss := ed25519.Verify(&pkfinal, []byte(message), signature)
	common.Debug("===========ed verify again============","pass",suss)
	//////
	*/

	signature := new([64]byte)
	copy(signature[:], edrs.Rx[:])
	copy(signature[32:], edrs.Sx[:])
	sig := hex.EncodeToString(signature[:])
	fmt.Printf("==================sign_ed,get the sig = %v, signature = %v ===================\n",sig,signature)
	res := RpcDcrmRes{Ret: sig, Tip: "", Err: nil}
	ch <- res
	return ""
}

func sign(wsid string,account string,pubkey string,inputcode string,unsignhash []string,keytype string,nonce string,mode string,pickhash []*PickHashKey ,ch chan interface{}) {
	dcrmpks, _ := hex.DecodeString(pubkey)
	exsit,da := GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	if !exsit {
	    time.Sleep(time.Duration(5000000000))
	    exsit,da = GetPubKeyDataFromLocalDb(string(dcrmpks[:]))
	}
	///////
	if !exsit {
	    common.Debug("============================sign,not exist sign data===========================","pubkey",pubkey,"key",wsid)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
	    ch <- res
	    return
	}

	_,ok := da.(*PubKeyData)
	if !ok {
	    common.Debug("============================sign,sign data error==========================","pubkey",pubkey,"key",wsid)
	    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
	    ch <- res
	    return
	}

	save := (da.(*PubKeyData)).Save
	dcrmpub := (da.(*PubKeyData)).Pub

	var dcrmpkx *big.Int
	var dcrmpky *big.Int
	if keytype == "EC256K1" {
		dcrmpks := []byte(dcrmpub)
		dcrmpkx, dcrmpky = secp256k1.S256().Unmarshal(dcrmpks[:])
	}

	///sku1
	da2 := GetSkU1FromLocalDb(string(dcrmpks[:]))
	if da2 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	sku1 := new(big.Int).SetBytes(da2)
	if sku1 == nil {
		res := RpcDcrmRes{Ret: "", Tip: "lockout get sku1 fail", Err: fmt.Errorf("lockout get sku1 fail")}
		ch <- res
		return
	}
	//

	var result string
	var cherrtmp error
	rch := make(chan interface{}, 1)
	if keytype == "ED25519" {
	    
	    //xrp test
	    /*chandler := coins.NewCryptocoinHandler("XRP")
	    if chandler == nil {
		    res := RpcDcrmRes{Ret: "", Tip: "cointype is not supported", Err: GetRetErr(ErrCoinTypeNotSupported)}
		    ch <- res
		    return
	    }
	    realdcrmfrom, err := chandler.PublicKeyToAddress(pubkey)
	    if err != nil {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:get dcrm addr error from pubkey:" + pubkey, Err: fmt.Errorf("get dcrm addr fail")}
		    ch <- res
		    return
	    }
	    amount, ok := new(big.Int).SetString("1230000", 10)
	    if !ok {
		    res := RpcDcrmRes{Ret: "", Tip: "lockout value error", Err: fmt.Errorf("lockout value error")}
		    ch <- res
		    return
	    }

	    var lockouttx interface{}
	    var digests []string
	    var buildTxErr error
	    lockouttx, digests, buildTxErr = chandler.BuildUnsignedTransaction(realdcrmfrom, pubkey, "rwybySLAzoJcqB44HQrwyk42z7jzu3GfSS", amount, "","xrp test")
	    
	    if buildTxErr != nil || lockouttx == nil || len(digests) == 0 {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:build unsign transaction fail", Err: buildTxErr}
		    ch <- res
		    return
	    }

	    sign_ed(wsid,digests,save,sku1,dcrmpub,keytype,rch)
	    ret, tip, cherr := GetChannelValue(waitall, rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr

	    if cherr == nil {
		var sigs []string
		tmps := strings.Split(result, ":")
		for _,rsv := range tmps {
		    if rsv == "NULL" {
			continue
		    }

		    sigs = append(sigs,rsv)
		}

		signedTx, err := chandler.MakeSignedTransaction(sigs, lockouttx)
		if err != nil {
			res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:new sign transaction fail", Err: err}
			ch <- res
			return
		}
		lockout_tx_hash, err := chandler.SubmitTransaction(signedTx)
		fmt.Printf("=====================ed sign,xrp test, lockout tx hash = %v, err = %v =====================\n",lockout_tx_hash,err)
	    }*/
	    ////////////xrp test

	    ////////solana test
	    /*fromaddr,err := PubkeyHexToAddress(pubkey)
	    if err != nil {
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:pubkey to dcrm addr fail", Err: err}
		ch <- res
		return
	    }

	    tx := buildUnsignedTx(fromaddr, "2z55nksdCojo3jDW5reezbZMEvBQmdgPvMa7djMn3vR4", big.NewInt(333))

	    m := tx.Message
	    buf := new(bytes.Buffer)
	    err = bin.NewEncoder(buf).Encode(m)
	    checkError(err)
	    messageCnt := buf.Bytes()
	    
	    //dig := hex.EncodeToString(messageCnt)
	    //mt,_ := new(big.Int).SetString(dig,16)
	    //mt2 := hex.EncodeToString(mt.Bytes())
	    //fmt.Printf("====================ed sign,solona dig = %v, mt2 = %v ===================\n",dig,mt2)

	    dig := hex.EncodeToString(messageCnt[:])
	    fmt.Printf("===================ed sign,solana fromaddr = %v,msg = %v, msg str = %v ======================\n",fromaddr,messageCnt,dig)

	    var digests []string
	    digests = append(digests,dig)

	    sign_ed(wsid,digests,save,sku1,dcrmpub,keytype,rch)
	    ret, tip, cherr := GetChannelValue(waitall, rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr

	    if cherr == nil {
		var sigs []string
		tmps := strings.Split(result, ":")
		for _,rsv := range tmps {
		    if rsv == "NULL" {
			continue
		    }

		    sigs = append(sigs,rsv)
		}

		rsv,_ := hex.DecodeString(sigs[0])
		var rs [64]byte
		copy(rs[:],rsv[:])
		fmt.Printf("======================ed sign,solana rsv1 = %v, sig = %v, rsv2 = %v, rs = %v ====================\n",ret,sigs[0],rsv,rs)

		signedTx := makeSignedTx(tx, rs[:])
		sendTx(signedTx)
	    }*/
	    /////////solana test
	    
	    sign_ed(wsid,unsignhash,save,sku1,dcrmpub,keytype,rch)
	    ret, tip, cherr := GetChannelValue(waitall, rch)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr
	} else {
	    sign_ec(wsid,unsignhash,save,sku1,dcrmpkx,dcrmpky,inputcode,keytype,pickhash,rch)
	    ret, tip, cherr := GetChannelValue(waitall,rch)
	    common.Info("=================sign,call sign_ec finish.==============","return result",ret,"err",cherr,"key",wsid)
	    if cherr != nil {
		    res := RpcDcrmRes{Ret: "", Tip: tip, Err: cherr}
		    ch <- res
		    return
	    }

	    result = ret
	    cherrtmp = cherr
	}

	tmps := strings.Split(result, ":")
	for _,rsv := range tmps {

	    if rsv == "NULL" {
		continue
	    }

	    //bug
	    rets := []rune(rsv)
	    if keytype != "ED25519" && len(rets) != 130 {
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:wrong rsv size", Err: GetRetErr(ErrDcrmSigWrongSize)}
		    ch <- res
		    return
	    }
	}

	if result != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
		    common.Debug("==========sign,no find worker============","err",err,"key",wsid)
		    res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("get worker error.")}
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
		SendMsgToDcrmGroup(ss, w.groupid)
		///////////////

		common.Debug("================sign,success sign and call AcceptSign==============","key",wsid)
		tip,reply := AcceptSign("",account,pubkey,unsignhash,keytype,w.groupid,nonce,w.limitnum,mode,"true", "true", "Success", result,"","",nil,w.id)
		if reply != nil {
			res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("update sign status error.")}
			ch <- res
			return
		}

		common.Info("================sign,the terminal sign res is success==============","key",wsid)
		res := RpcDcrmRes{Ret: result, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherrtmp != nil {
		common.Info("================sign,the terminal sign res is failure================","err",cherrtmp,"key",wsid)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: cherrtmp}
		ch <- res
		return
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:sign fail", Err: fmt.Errorf("sign fail.")}
	ch <- res
}

type SignData struct {
    MsgPrex string
    Key string
    InputCodeT string
    Save string
    Sku1 *big.Int
    Txhash string
    GroupId string
    NodeCnt int 
    ThresHold int
    DcrmFrom string
    Keytype string
    Cointype string
    Pkx *big.Int
    Pky *big.Int
    PickKey string
}

func sign_ec(msgprex string, txhash []string, save string, sku1 *big.Int, dcrmpkx *big.Int, dcrmpky *big.Int, inputcode string,keytype string, pickhash []*PickHashKey,ch chan interface{}) string {

    	tmp := make([]string,0)
	for _,v := range txhash {
	    txhashs := []rune(v)
	    if string(txhashs[0:2]) == "0x" {
		    tmp = append(tmp,string(txhashs[2:]))
	    } else {
		tmp = append(tmp,string(txhashs))
	    }
	}

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		common.Debug("==========dcrm_sign,no find worker===========","key",msgprex,"err",err)
		res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:no find worker", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}

	cur_enode = GetSelfEnode()

	var wg sync.WaitGroup
	for _,v := range tmp {
	    wg.Add(1)
	    go func(vv string) {
		defer wg.Done()

		//get pickkey
		pickkey := ""
		for _,val := range pickhash {
			if strings.EqualFold(val.Hash,("0x" + vv)) || strings.EqualFold(val.Hash,vv) {
				pickkey = val.PickKey
				break
			}
		}
		if pickkey == "" {
			return
		}
		//

		//tt := fmt.Sprintf("%v",time.Now().UnixNano()/1e6)
		key := Keccak256Hash([]byte(strings.ToLower(msgprex + "-" + vv))).Hex()
		sd := &SignData{MsgPrex:msgprex,Key:key,InputCodeT:inputcode,Save:save,Sku1:sku1,Txhash:vv,GroupId:w.groupid,NodeCnt:w.NodeCnt,ThresHold:w.ThresHold,DcrmFrom:w.DcrmFrom,Keytype:keytype,Cointype:"",Pkx:dcrmpkx,Pky:dcrmpky,PickKey:pickkey}
		common.Info("======================sign_ec=================","unsign txhash",vv,"msgprex",msgprex,"key",key,"pick key",pickkey)

		val,err := Encode2(sd)
		if err != nil {
		    common.Info("======================sign_ec, encode error==================","unsign txhash",vv,"msgprex",msgprex,"key",key,"pick key",pickkey,"err",err)
		    //res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error:marshal sign data error", Err: err}
		    //ch <- res
		    return 
		}
		
		common.Debug("======================sign_ec, encode success=================","vv",vv,"msgprex",msgprex,"key",key)
		rch := make(chan interface{}, 1)
		SetUpMsgList3(val,cur_enode,rch)
		_, _,cherr := GetChannelValue(waitall,rch)
		if cherr != nil {

		    common.Info("======================sign_ec, get finish error====================","vv",vv,"msgprex",msgprex,"key",key,"cherr",cherr)
		    //res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error: sign fail", Err: cherr}
		    //ch <- res
		    return 
		}
		common.Info("======================sign_ec, get finish success===================","vv",vv,"msgprex",msgprex,"key",key)
	    }(v)
	}
	wg.Wait()

	common.Info("======================sign_ec, all sign finish===================","msgprex",msgprex,"w.rsv",w.rsv)

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
	common.Debug("======================sign_ec=====================","return result",ret,"len(tmps)",len(tmps),"len(tmp)",len(tmp),"key",msgprex)
	if len(tmps) == (len(tmp) + 1) {
	    res := RpcDcrmRes{Ret: ret, Tip: "", Err: nil}
	    ch <- res
	    return ""
	}

	res := RpcDcrmRes{Ret: "", Tip: "dcrm back-end internal error: sign fail", Err: fmt.Errorf("sign fail")}
	ch <- res
	return "" 
}

/*func DECDSASignRoundSeven(msgprex string, r *big.Int, deltaGammaGy *big.Int, us1 *big.Int, w *RPCReqWorker, ch chan interface{}) (*ec2.Commitment, []string, *big.Int, *big.Int) {
	if msgprex == "" || r == nil || deltaGammaGy == nil || us1 == nil || w == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitBigVAB1, rho1, l1 := signing.DECDSA_Sign_Round_Seven(r, deltaGammaGy, us1)

	mp := []string{msgprex, cur_enode}
	enode := strings.Join(mp, "-")
	s0 := "CommitBigVAB"
	s1 := string(commitBigVAB1.C.Bytes())
	ss := enode + common.Sep + s0 + common.Sep + s1
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigVAB finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigvab)
	common.Debug("===================finish get CommitBigVAB, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigVAB",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigVAB timeout.")}
		ch <- res
		return nil, nil, nil, nil
	}

	commitbigvabs := make([]string, w.ThresHold)
	if w.msg_commitbigvab.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigVAB fail.")}
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error")}
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
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send ZKABPROOF finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bzkabproof)
	common.Debug("===================finish get ZKABPROOF, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"ZKABPROOF",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all ZKABPROOF timeout.")}
		ch <- res
		return nil, nil
	}

	zkabproofs := make([]string, w.ThresHold)
	if w.msg_zkabproof.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all ZKABPROOF fail.")}
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return nil, nil, nil
	}

	var commitbigcom = make(map[string]*ec2.Commitment)
	for _, v := range commitbigvabs {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range zkabproofs {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
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
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
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
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
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
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_zkabproof fail.")}
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return nil, nil, nil
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigcom[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commitbigvab fail.")}
			ch <- res
			return nil, nil, nil
		}

		_, BigVAB1 := signing.DECDSA_Key_DeCommit(commitbigcom[en[0]])
		if !signing.DECDSA_Sign_ZkABVerify([]*big.Int{BigVAB1[2], BigVAB1[3]}, []*big.Int{BigVAB1[4], BigVAB1[5]}, []*big.Int{BigVAB1[0], BigVAB1[1]}, []*big.Int{r, deltaGammaGy}, zkabproofmap[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify zkabproof fail.")}
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
	//	res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
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
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUT finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigut)
	common.Debug("===================finish get CommitBigUT, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUT",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUT timeout.")}
		ch <- res
		return nil, nil
	}

	commitbiguts := make([]string, w.ThresHold)
	if w.msg_commitbigut.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUT fail.")}
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
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
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	common.Debug("===================send CommitBigUTD11 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(ch_t, w.bcommitbigutd11)
	common.Debug("===================finish get CommitBigUTD11, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"CommitBigUTD11",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
		ch <- res
		return nil
	}

	commitbigutd11s := make([]string, w.ThresHold)
	if w.msg_commitbigutd11.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get all CommitBigUTD11 fail.")}
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
		ch <- res
		return false
	}

	var commitbigutmap = make(map[string]*ec2.Commitment)
	for _, v := range commitbiguts {
		mm := strings.Split(v, common.Sep)
		if len(mm) < 3 {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigut fail.")}
			ch <- res
			return false
		}

		prex := mm[0]
		prexs := strings.Split(prex, "-")
		for _, vv := range commitbigutd11s {
			mmm := strings.Split(vv, common.Sep)
			if len(mmm) < 3 {
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
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
						res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get msg_commitbigutd11 fail.")}
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
			ch <- res
			return false
		}
		////////

		en := strings.Split(string(enodes[8:]), "@")
		if !keygen.DECDSA_Key_Commitment_Verify(commitbigutmap[en[0]]) {
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify commit big ut fail.")}
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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("verify bigTB = BigU fails.")}
		ch <- res
		return false
	}

	return true
}

func DECDSASignRoundEleven(msgprex string, cointype string, w *RPCReqWorker, idSign sortableIDSSlice, ch chan interface{}, us1 *big.Int) map[string]*big.Int {
	if cointype == "" || msgprex == "" || w == nil || len(idSign) == 0 || us1 == nil {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("param error.")}
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
	SendMsgToDcrmGroup(ss, w.groupid)
	DisMsg(ss)

	// 1. Receive Broadcast
	// s: s1, s2, s3
	common.Info("===================send SS1 finish, ", "prex = ", msgprex, "", "====================")
	_, tip, cherr := GetChannelValue(WaitMsgTimeGG20, w.bss1)
	common.Info("===================finish get SS1, ", "err = ", cherr, "prex = ", msgprex, "", "====================")
	/////////////////////////request data from dcrm group
	suss := false
	if cherr != nil {
	    suss = ReqDataFromGroup(msgprex,w.id,"SS1",reqdata_trytimes,reqdata_timeout)
	} else {
	    suss = true
	}
	///////////////////////////////////

	if !suss {
		res := RpcDcrmRes{Ret: "", Tip: tip, Err: fmt.Errorf("get ss1 timeout.")}
		ch <- res
		return nil
	}

	var ss1s = make(map[string]*big.Int)
	ss1s[cur_enode] = us1

	uss1s := make([]string, w.ThresHold)
	if w.msg_ss1.Len() != w.ThresHold {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
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
			res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get enodes error")}
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
				res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get ss1 fail.")}
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

func GetIdSignByGroupId(msgtoenode map[string]string,groupid string) dcrmlib.SortableIDSSlice {
    var ids dcrmlib.SortableIDSSlice

    _, enodes := GetGroup(groupid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	for key,value := range msgtoenode {
	    if strings.EqualFold(value,node2) {
		uid,_ := new(big.Int).SetString(key,10)
		ids = append(ids,uid)
		break
	    }
	}
    }
    
    sort.Sort(ids)
    return ids
}

func GetIdSignByGroupId_ed(ids dcrmlib.SortableIDSSlice,msgtoenode map[string]string,groupid string) dcrmlib.SortableIDSSlice {
    var signids dcrmlib.SortableIDSSlice

    _, enodes := GetGroup(groupid)
    nodes := strings.Split(enodes, common.Sep2)
    for _, node := range nodes {
	node2 := ParseNode(node)
	for key,value := range msgtoenode {
	    if strings.EqualFold(value,node2) {

		for _,v := range ids {
		    var id [32]byte
		    copy(id[:],v.Bytes())
		    if strings.EqualFold(hex.EncodeToString(id[:]),key) {
			signids = append(signids,v)
			break
		    }

		}
		break
	    }
	}
    }
    
    sort.Sort(signids)
    return signids
}

//msgprex = hash
//return value is the backup for the dcrm sig
func PreSign_ec3(msgprex string, save string, sku1 *big.Int, cointype string, ch chan interface{},id int)  *PrePubData {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return nil
	}
	w := workers[id]
	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return nil
	}

	/*mm := strings.Split(save, common.SepSave)
	if len(mm) == 0 {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get save data fail")}
		ch <- res
		return nil
	}*/

	//time.Sleep(time.Duration(20) * time.Second) //tmp code
	
	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(save), &msgmap)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
	    ch <- res
	    return nil 
	}
	kgsave := GetKGLocalDBSaveData(msgmap)
	if kgsave == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
	    ch <- res
	    return nil
	}
	sd := kgsave.Save
	
	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	//ids := GetIds(cointype, w.groupid)
	//idSign := ids[:w.ThresHold]

	//common.Info("===================PreSign_ec3 start=================","index",index,"w.groupid",w.groupid,"key",msgprex)
	//*******************!!!Distributed ECDSA Sign Start!!!**********************************
	idsign := GetIdSignByGroupId(kgsave.MsgToEnode,w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan dcrmlib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData,w.ThresHold)
	finalize_endCh := make(chan *big.Int,w.ThresHold)
	errChan := make(chan struct{})
	signDNode := signing.NewLocalDNode(outCh,endCh,sd,idsign,sd.CurDNodeID,w.ThresHold,PaillierKeyLength,false,nil,nil,finalize_endCh)
	w.DNode = signDNode
	
	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
		    fmt.Printf("==========sign node start err = %v ==========\n",err)
			close(errChan)
		}
		
		for _,v := range w.PreSaveDcrmMsg {
		    w.DcrmMsg <- v 
		}
	}()
	go SignProcessInboundMessages(msgprex,commStopChan,&signWg,ch)
	pre,err := processSign(msgprex,kgsave.MsgToEnode,errChan, outCh, endCh)
	if err != nil || pre == nil {
	    fmt.Printf("==========process sign err = %v ==========\n",err)
	    close(commStopChan)
	    res := RpcDcrmRes{Ret: "", Err: err}
	    ch <- res
	    return nil 
	}

	close(commStopChan)
	signWg.Wait()

	/*skU1, w1 := MapPrivKeyShare(cointype, w, idSign, string(sku1.Bytes()))
	if skU1 == nil || w1 == nil {
	    return nil
	}

	u1K, u1Gamma, commitU1GammaG := DECDSASignRoundOne(msgprex, w, idSign, ch)
	if u1K == nil || u1Gamma == nil || commitU1GammaG == nil {
		return nil 
	}
	common.Debug("===================,PreSign_ec3,round one finish=================","key",msgprex)

	ukc, ukc2, ukc3 := DECDSASignPaillierEncrypt(cointype, save, w, idSign, u1K, ch)
	if ukc == nil || ukc2 == nil || ukc3 == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,paillier encrypt finish=================","key",msgprex)

	zk1proof, zkfactproof := DECDSASignRoundTwo(msgprex, cointype, save, w, idSign, ch, u1K, ukc2, ukc3)
	if zk1proof == nil || zkfactproof == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,round two finish================","key",msgprex)

	if !DECDSASignRoundThree(msgprex, cointype, save, w, idSign, ch, ukc) {
		return nil
	}
	common.Debug("===================PreSign_ec3,round three finish================","key",msgprex)

	if !DECDSASignVerifyZKNtilde(msgprex, cointype, save, w, idSign, ch, ukc, ukc3, zk1proof, zkfactproof) {
		return nil
	}
	common.Debug("===================PreSign_ec3,verify zk ntilde finish==================","key",msgprex)

	betaU1Star, betaU1, vU1Star, vU1 := signing.GetRandomBetaV(PaillierKeyLength, w.ThresHold)
	common.Debug("===================PreSign_ec3,get random betaU1Star/vU1Star finish================","key",msgprex)

	mkg, mkg_mtazk2, mkw, mkw_mtazk2, status := DECDSASignRoundFour(msgprex, cointype, save, w, idSign, ukc, ukc3, zkfactproof, u1Gamma, w1, betaU1Star, vU1Star,ch)
	if !status {
		return nil
	}
	common.Debug("===================PreSign_ec3,round four finish================","key",msgprex)

	if !DECDSASignVerifyZKGammaW(msgprex,cointype, save, w, idSign, ukc, ukc3, zkfactproof, mkg, mkg_mtazk2, mkw, mkw_mtazk2, ch) {
		return nil
	} 
	common.Debug("===================PreSign_ec3,verify zk gamma/w finish===================","key",msgprex)

	u1PaillierSk := GetSelfPrivKey(cointype, idSign, w, save, ch)
	if u1PaillierSk == nil {
		return nil
	}
	common.Debug("===================PreSign_ec3,get self privkey finish====================","key",msgprex)

	alpha1 := DecryptCkGamma(cointype, idSign, w, u1PaillierSk, mkg, ch)
	if alpha1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3,decrypt paillier(k)XGamma finish=================","key",msgprex)

	uu1 := DecryptCkW(cointype, idSign, w, u1PaillierSk, mkw, ch)
	if uu1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, decrypt paillier(k)Xw1 finish=================","key",msgprex)

	delta1 := CalcDelta(alpha1, betaU1, ch, w.ThresHold)
	if delta1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, calc delta finish=================","key",msgprex)

	sigma1 := CalcSigma(uu1, vU1, ch, w.ThresHold)
	if sigma1 == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, calc sigma finish=================","key",msgprex)

	deltaSum := DECDSASignRoundFive(msgprex, cointype, delta1, idSign, w, ch)
	if deltaSum == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, round five finish=================","key",msgprex)

	u1GammaZKProof := DECDSASignRoundSix(msgprex, u1Gamma, commitU1GammaG, w, ch)
	if u1GammaZKProof == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, round six finish=================","key",msgprex)

	ug := DECDSASignVerifyCommitment(cointype, w, idSign, commitU1GammaG, u1GammaZKProof, ch)
	if ug == nil {
		return nil
	}
	common.Debug("=====================PreSign_ec3, verify commitment finish=================","key",msgprex)

	r, deltaGammaGy := Calc_r(cointype, w, idSign, ug, deltaSum, ch)

	if r == nil || deltaGammaGy == nil {
		return nil
	}*/////-----

	//common.Info("=====================PreSign_ec3, calc r finish=================","key",msgprex)

	//ret := &PrePubData{Key:msgprex,K1:u1K,R:r,Ry:deltaGammaGy,Sigma1:sigma1,Gid:w.groupid,Used:false}
	ret := &PrePubData{Key:msgprex,K1:pre.K1,R:pre.R,Ry:pre.Ry,Sigma1:pre.Sigma1,Gid:w.groupid,Used:false}
	return ret
}

//msgprex = hash
//return value is the backup for the dcrm sig
func Sign_ec3(msgprex string, message string, cointype string,save string, pkx *big.Int,pky *big.Int,ch chan interface{}, id int,pre *PrePubData) string {
	if id < 0 || id >= len(workers) {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("no find worker.")}
		ch <- res
		return ""
	}
	w := workers[id]
	fmt.Printf("==============Sign_ec3, w.groupid = %v ==============\n",w.groupid)

	gid := w.groupid

	if w.groupid == "" {
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("get group id fail.")}
		ch <- res
		return ""
	}

	hashBytes, err2 := hex.DecodeString(message)
	if err2 != nil {
		res := RpcDcrmRes{Ret: "", Err: err2}
		ch <- res
		return ""
	}

	// [Notes]
	// 1. assume the nodes who take part in the signature generation as follows
	//ids := GetIds(cointype, w.groupid)
	//idSign := ids[:w.ThresHold]
	
	//time.Sleep(time.Duration(20) * time.Second) //tmp code
	
	mMtA, _ := new(big.Int).SetString(message, 16)
	//common.Info("=============Sign_ec3 start=============","w.ThresHold",w.ThresHold,"w.groupid",w.groupid,"key",msgprex)

	//*******************!!!Distributed ECDSA Sign Start!!!**********************************

	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(save), &msgmap)
	if err != nil {
	    res := RpcDcrmRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
	    ch <- res
	    return "" 
	}
	kgsave := GetKGLocalDBSaveData(msgmap)
	if kgsave == nil {
	    res := RpcDcrmRes{Ret: "", Tip: "presign get local save data fail", Err: fmt.Errorf("presign get local save data fail")}
	    ch <- res
	    return ""
	}
	sd := kgsave.Save
	
	fmt.Printf("==============Sign_ec3, 222222  w.groupid = %v ==============\n",w.groupid)
	idsign := GetIdSignByGroupId(kgsave.MsgToEnode,w.groupid)

	commStopChan := make(chan struct{})
	outCh := make(chan dcrmlib.Message, w.ThresHold)
	endCh := make(chan signing.PrePubData,w.ThresHold)
	finalize_endCh := make(chan *big.Int,w.ThresHold)
	errChan := make(chan struct{})
	predata := &signing.PrePubData{K1:pre.K1,R:pre.R,Ry:pre.Ry,Sigma1:pre.Sigma1}
	signDNode := signing.NewLocalDNode(outCh,endCh,sd,idsign,sd.CurDNodeID,w.ThresHold,PaillierKeyLength,true,predata,mMtA,finalize_endCh)
	w.DNode = signDNode
	
	var signWg sync.WaitGroup
	signWg.Add(2)
	go func() {
		defer signWg.Done()
		if err := signDNode.Start(); nil != err {
		    fmt.Printf("==========sign node start err = %v ==========\n",err)
			close(errChan)
		}
		
		for _,v := range w.PreSaveDcrmMsg {
		    fmt.Printf("============sign dnode start,handle pre-msg = %v ==============\n",v)
		    w.DcrmMsg <- v 
		}
	}()
	go SignProcessInboundMessages(msgprex,commStopChan,&signWg,ch)
	fmt.Printf("==============Sign_ec3, 333333  w.groupid = %v ==============\n",w.groupid)
	s,err := processSignFinalize(msgprex,kgsave.MsgToEnode,errChan, outCh, finalize_endCh,gid)
	if err != nil || s == nil {
	    fmt.Printf("==========process sign err = %v ==========\n",err)
	    close(commStopChan)
	    res := RpcDcrmRes{Ret: "", Err: err}
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
*///------

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
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("s == 0.")}
		ch <- res
		return ""
	}
	common.Debug("=====================Sign_ec3,justify s finish=================","key",msgprex)

	// **[End-Test]  verify signature with MtA
	signature := new(ECDSASignature)
	signature.New()
	signature.SetR(pre.R)
	signature.SetS(s)

	invert := false
	if cointype == "ETH" && bb {
		//recid ^=1
		invert = true
	}
	if cointype == "BTC" && bb {
		//recid ^= 1
		invert = true
	}

	recid := dcrmlib.DECDSA_Sign_Calc_v(pre.R, pre.Ry, pkx, pky, signature.GetR(), signature.GetS(), hashBytes, invert)
	common.Info("=====================Sign_ec3,first get recid =================","recid",recid,"key",msgprex)
	
	////check v
	ys := secp256k1.S256().Marshal(pkx,pky)
	pubkeyhex := hex.EncodeToString(ys)
	pbhs := []rune(pubkeyhex)
	if string(pbhs[0:2]) == "0x" {
	    pubkeyhex = string(pbhs[2:])
	}

	rsvBytes1 := append(signature.GetR().Bytes(), signature.GetS().Bytes()...)
	for j := 0; j < 4; j++ {
	    rsvBytes2 := append(rsvBytes1, byte(j))
	    pkr, e := secp256k1.RecoverPubkey(hashBytes,rsvBytes2)
	    pkr2 := hex.EncodeToString(pkr)
	    pbhs2 := []rune(pkr2)
	    if string(pbhs2[0:2]) == "0x" {
		pkr2 = string(pbhs2[2:])
	    }
	    if e == nil && strings.EqualFold(pkr2,pubkeyhex) {
		recid = j
		common.Info("=====================Sign_ec3,second get recid =================","recid",recid,"key",msgprex)
		break
	    }
	}
	/////
	signature.SetRecoveryParam(int32(recid))
	common.Info("=====================Sign_ec3,terminal get recid =================","recid",signature.GetRecoveryParam(),"key",msgprex)

	if !DECDSA_Sign_Verify_RSV(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), message, pkx, pky) {
		common.Debug("=================Sign_ec3,verify is false==============","key",msgprex)
		fmt.Printf("============Sign_ec3,verify is false, key = %v ==============\n",msgprex)
		res := RpcDcrmRes{Ret: "", Err: fmt.Errorf("sign verify fail.")}
		ch <- res
		return ""
	}
	common.Debug("=================Sign_ec3,verify (r,s) pass==============","key",msgprex)
	fmt.Printf("===============Sign_ec3,verify (r,s) pass, key = %v =================\n",msgprex)

	signature2 := GetSignString(signature.GetR(), signature.GetS(), signature.GetRecoveryParam(), int(signature.GetRecoveryParam()))
	rstring := "========================== r = " + fmt.Sprintf("%v", signature.GetR()) + " ========================="
	sstring := "========================== s = " + fmt.Sprintf("%v", signature.GetS()) + " =========================="
	fmt.Println(rstring)
	fmt.Println(sstring)
	common.Debug("=================Sign_ec3==============","rsv str",signature2,"key",msgprex)
	fmt.Printf("===============Sign_ec3, rsv str = %v, key = %v =============\n",signature2,msgprex)
	res := RpcDcrmRes{Ret: signature2, Err: nil}
	ch <- res

	common.Debug("=================Sign_ec3, rsv pass==============","key",msgprex)
	//*******************!!!Distributed ECDSA Sign End!!!**********************************

	return ""
}

type ECDSASignature struct {
	r               *big.Int
	s               *big.Int
	recoveryParam   int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int, s *big.Int) {
	this.r = r
	this.s = s
}

func (this *ECDSASignature) New3(r *big.Int, s *big.Int, recoveryParam int32) {
	this.r = r
	this.s = s
	this.recoveryParam = recoveryParam
}

func (this *ECDSASignature) GetRoudFiveAborted() bool {
	return this.roudFiveAborted
}

func (this *ECDSASignature) SetRoudFiveAborted(roudFiveAborted bool) {
	this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
	return this.r
}

func (this *ECDSASignature) SetR(r *big.Int) {
	this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
	return this.s
}

func (this *ECDSASignature) SetS(s *big.Int) {
	this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
	return this.recoveryParam
}

func (this *ECDSASignature) SetRecoveryParam(recoveryParam int32) {
	this.recoveryParam = recoveryParam
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
	var sa = make([]string, 0)
	for _, v := range DecimalSlice {
		sa = append(sa, fmt.Sprintf("%02X", v))
	}
	ss := strings.Join(sa, "")
	return ss
}

func GetSignString(r *big.Int, s *big.Int, v int32, i int) string {
	rr := r.Bytes()
	sss := s.Bytes()

	//bug
	if len(rr) == 31 && len(sss) == 32 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		dcrmlib.ReadBits(r, sigs[1:32])
		dcrmlib.ReadBits(s, sigs[32:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 31 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[0] = byte(0)
		sigs[32] = byte(0)
		dcrmlib.ReadBits(r, sigs[1:32])
		dcrmlib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	if len(rr) == 32 && len(sss) == 31 {
		sigs := make([]byte, 65)
		sigs[32] = byte(0)
		dcrmlib.ReadBits(r, sigs[0:32])
		dcrmlib.ReadBits(s, sigs[33:64])
		sigs[64] = byte(i)
		ret := Tool_DecimalByteSlice2HexString(sigs)
		return ret
	}
	//

	n := len(rr) + len(sss) + 1
	sigs := make([]byte, n)
	dcrmlib.ReadBits(r, sigs[0:len(rr)])
	dcrmlib.ReadBits(s, sigs[len(rr):len(rr)+len(sss)])

	sigs[len(rr)+len(sss)] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)

	return ret
}

func DECDSA_Sign_Verify_RSV(r *big.Int, s *big.Int, v int32, message string, pkx *big.Int, pky *big.Int) bool {
	return dcrmlib.Verify2(r, s, v, message, pkx, pky)
}

