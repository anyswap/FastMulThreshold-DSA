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
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/ecdsa/keygen"
	"github.com/anyswap/FastMulThreshold-DSA/smpc/tss/ecdsa/reshare"
	smpclib "github.com/anyswap/FastMulThreshold-DSA/smpc/tss/smpc"
	"github.com/fsn-dev/cryptoCoins/coins"
	"sort"
	"errors"
)

//----------------------------------------------------------------------------------------

// GetReShareNonce get reshare special tx nonce
func GetReShareNonce(account string) (string, string, error) {
    	if account == "" {
	    return "","",errors.New("param error")
	}

	key := Keccak256Hash([]byte(strings.ToLower(account + ":" + "RESHARE"))).Hex()
	exsit, da := GetPubKeyData([]byte(key))
	if !exsit {
		return "0", "", nil
	}

	nonce, _ := new(big.Int).SetString(string(da.([]byte)), 10)
	one, _ := new(big.Int).SetString("1", 10)
	nonce = new(big.Int).Add(nonce, one)
	return fmt.Sprintf("%v", nonce), "", nil
}

// SetReShareNonce set reshare special tx nonce
func SetReShareNonce(account string, nonce string) (string, error) {
    	if account == "" || nonce == "" {
	    return "",errors.New("param error")
	}

	key2 := Keccak256Hash([]byte(strings.ToLower(account + ":" + "RESHARE"))).Hex()
	err := PutPubKeyData([]byte(key2), []byte(nonce))
	if err != nil {
		return err.Error(), err
	}

	return "", nil
}

//--------------------------------------------------------------------------------

// IsValidReShareAccept is valid reshare accept??
func IsValidReShareAccept(from string, gid string) bool {
	if from == "" || gid == "" {
		return false
	}

	h := coins.NewCryptocoinHandler("FSN")
	if h == nil {
		return false
	}

	_, enodes := GetGroup(gid)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		pk := "04" + node2

		fr, err := h.PublicKeyToAddress(pk)
		if err != nil {
			return false
		}

		if strings.EqualFold(from, fr) {
			return true
		}
	}

	return false
}

//--------------------------------------------------------------------------------

// TxDataReShare the data of the special tx of reshare
type TxDataReShare struct {
	TxType    string
	Nonce    string
	PubKey    string
	GroupID   string
	TSGroupID string
	ThresHold string
	Account   string
	Mode      string
	AcceptTimeOut      string
	Sigs      string
	TimeStamp string
	FixedApprover []string
	Comment string
	Keytype string
}

// ReShare execute the reshare command
// raw : reshare command data
func ReShare(raw string) (string, string, error) {
    	if raw == "" {
	    return "","",errors.New("param error")
	}

	key, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================ReShare,check raw data error ================", "raw", raw, "err", err)
		return "", err.Error(), err
	}

	rh, ok := txdata.(*TxDataReShare)
	if !ok {
		return "", "check raw fail,it is not *TxDataReShare", fmt.Errorf("check raw data fail")
	}

	common.Debug("=====================ReShare, SendMsgToSmpcGroup ================", "raw", raw, "gid", rh.GroupID, "key", key)
	SendMsgToSmpcGroup(raw, rh.GroupID)
	SetUpMsgList(raw, curEnode)
	return key, "", nil
}

//-----------------------------------------------------------------------------------

// RPCAcceptReShare Agree to the reshare request 
// raw : accept data, including the key of the reshare request
func RPCAcceptReShare(raw string) (string, string, error) {
    	if raw == "" {
	    return "","",errors.New("param error")
	}

	_, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=====================RPCAcceptReShare,check raw data error ================", "raw", raw, "err", err)
		return "Failure", err.Error(), err
	}

	acceptrh, ok := txdata.(*TxDataAcceptReShare)
	if !ok {
		return "Failure", "check raw fail,it is not *TxDataAcceptReShare", fmt.Errorf("check raw fail,it is not *TxDataAcceptReShare")
	}

	exsit, da := GetReShareInfoData([]byte(acceptrh.Key))
	if exsit {
		ac, ok := da.(*AcceptReShareData)
		if ok && ac != nil {
			common.Debug("=====================RPCAcceptReShare, SendMsgToSmpcGroup ================", "raw", raw, "gid", ac.GroupID, "key", acceptrh.Key)
			SendMsgToSmpcGroup(raw, ac.GroupID)
			SetUpMsgList(raw, curEnode)
			return "Success", "", nil
		}
	}

	return "Failure", "accept fail", fmt.Errorf("accept fail")
}

//-------------------------------------------------------------------------------------

// ReShareStatus reshare result
type ReShareStatus struct {
	KeyID    string
	From string
	GroupID string
	ThresHold    string
	Status    string
	Pubkey    string
	Tip       string
	Error     string
	AllReply  []NodeReply
	TimeStamp string
}

// GetReShareStatus get the result of the reshare request by key
func GetReShareStatus(key string) (string, string, error) {
    	if key == "" {
	    return "","",errors.New("param error")
	}

	exsit, da := GetPubKeyData([]byte(key))
	if !exsit || da == nil {
		return "", "smpc back-end internal error:get reshare accept data fail from db when GetReShareStatus", fmt.Errorf("get reshare accept data fail from db")
	}

	ac, ok := da.(*AcceptReShareData)
	if !ok {
		return "", "smpc back-end internal error:get reshare accept data error from db when GetReShareStatus", fmt.Errorf("get reshare accept data error from db")
	}

	los := &ReShareStatus{KeyID:key,From:ac.Account,GroupID:ac.GroupID,ThresHold:ac.LimitNum,Status: ac.Status, Pubkey: ac.PubKey, Tip: ac.Tip, Error: ac.Error, AllReply: ac.AllReply, TimeStamp: ac.TimeStamp}
	ret, _ := json.Marshal(los)
	return string(ret), "", nil
}

//-------------------------------------------------------------------------------------

// ReShareCurNodeInfo the data of current node's approve list
type ReShareCurNodeInfo struct {
	Key       string
	PubKey    string
	GroupID   string
	TSGroupID string
	ThresHold string
	Account   string
	Mode      string
	TimeStamp string
}

// ReShareCurNodeInfoSort sort the info of current node's approve list
type ReShareCurNodeInfoSort struct {
	Info []*ReShareCurNodeInfo
}

// Len get the count of arrary elements
func (r *ReShareCurNodeInfoSort) Len() int {
	return len(r.Info)
}

// Less weather r.Info[i] < r.Info[j]
func (r *ReShareCurNodeInfoSort) Less(i, j int) bool {
	itime, _ := new(big.Int).SetString(r.Info[i].TimeStamp, 10)
	jtime, _ := new(big.Int).SetString(r.Info[j].TimeStamp, 10)
	return itime.Cmp(jtime) >= 0
}

// Swap swap value of r.Info[i] and r.Info[j]
func (r *ReShareCurNodeInfoSort) Swap(i, j int) {
	r.Info[i], r.Info[j] = r.Info[j], r.Info[i]
}

// GetCurNodeReShareInfo  Get current node's reshare command approval list 
func GetCurNodeReShareInfo() ([]*ReShareCurNodeInfo, string, error) {
	var ret []*ReShareCurNodeInfo
	data := make(chan *ReShareCurNodeInfo, 1000)

	var wg sync.WaitGroup
	iter := reshareinfodb.NewIterator()
	for iter.Next() {
		key2 := []byte(string(iter.Key())) //must be deep copy, Otherwise, an error will be reported: "panic: JSON decoder out of sync - data changing underfoot?"
		exsit, da := GetReShareInfoData(key2)
		if !exsit || da == nil {
			continue
		}

		wg.Add(1)
		go func(key string, value interface{}, ch chan *ReShareCurNodeInfo) {
			defer wg.Done()

			vv, ok := value.(*AcceptReShareData)
			if vv == nil || !ok {
				return
			}

			common.Debug("================GetCurNodeReShareInfo====================", "vv", vv, "vv.Deal", vv.Deal, "vv.Status", vv.Status, "key", key)
			if vv.Deal == "true" || vv.Status == "Success" {
				return
			}

			if vv.Status != "Pending" {
				return
			}

			los := &ReShareCurNodeInfo{Key: key, PubKey: vv.PubKey, GroupID: vv.GroupID, TSGroupID: vv.TSGroupID, ThresHold: vv.LimitNum, Account: vv.Account, Mode: vv.Mode, TimeStamp: vv.TimeStamp}
			ch <- los
			common.Debug("================GetCurNodeReShareInfo success return============================", "key", key)
		}(string(key2), da, data)
	}
	iter.Release()
	wg.Wait()

	l := len(data)
	for i := 0; i < l; i++ {
		info := <-data
		ret = append(ret, info)
	}

	reshareinfosort := ReShareCurNodeInfoSort{Info: ret}
	sort.Sort(&reshareinfosort)

	return reshareinfosort.Info, "", nil
}

//-----------------------------------------------------------------------------------------

// _reshare execute reshare
// param groupid is not subgroupid
// w.groupid is subgroupid
func _reshare(raw string, wsid string, initator string, groupid string, pubkey string, account string, mode string, sigs string, ch chan interface{},keytype string) {

	rch := make(chan interface{}, 1)
	smpcReshare(raw, wsid, initator, groupid, pubkey, account, mode, sigs, rch,keytype)
	ret, _, cherr := GetChannelValue(cht, rch)
	if ret != "" {
		w, err := FindWorker(wsid)
		if w == nil || err != nil {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("get worker error")}
			ch <- res
			return
		}

		//sid-enode:SendReShareRes:Success:ret
		//sid-enode:SendReShareRes:Fail:err
		mp := []string{w.sid, curEnode}
		enode := strings.Join(mp, "-")
		s0 := "SendReShareRes"
		s1 := "Success"
		s2 := ret
		ss := enode + common.Sep + s0 + common.Sep + s1 + common.Sep + s2
		SendMsgToSmpcGroup(ss, groupid)

		tip, reply := AcceptReShare("", initator, groupid, w.groupid, pubkey, w.limitnum, mode, "true", "true", "Success", ret, "", "", nil, w.id)
		if reply != nil {
			res := RPCSmpcRes{Ret: "", Tip: tip, Err: fmt.Errorf("update reshare status error")}
			ch <- res
			return
		}

		common.Info("================reshare,the terminal res is success=================", "key", wsid)
		res := RPCSmpcRes{Ret: ret, Tip: tip, Err: err}
		ch <- res
		return
	}

	if cherr != nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:reshare fail", Err: cherr}
		ch <- res
		return
	}
}

//---------------------------------------------------------------------------------------

// smpcReshare execute reshare
// ec2
// msgprex = hash
// return value is the backup for smpc sig.
func smpcReshare(raw string, msgprex string, initator string, groupid string, pubkey string, account string, mode string, sigs string, ch chan interface{},keytype string) {

	w, err := FindWorker(msgprex)
	if w == nil || err != nil {
		res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:no find worker", Err: fmt.Errorf("no find worker")}
		ch <- res
		return
	}
	id := w.id

	var ch1 = make(chan interface{}, 1)
	for i := 0; i < recalcTimes; i++ {
		if len(ch1) != 0 {
			<-ch1
		}

		ReShareEC2(raw, msgprex, initator, groupid, pubkey, account, mode, sigs, ch1, id,keytype)
		ret, _, cherr := GetChannelValue(cht, ch1)
		if ret != "" && cherr == nil {
			res := RPCSmpcRes{Ret: ret, Tip: "", Err: cherr}
			ch <- res
			break
		}

		w.Clear2()
		time.Sleep(time.Duration(1) * time.Second) //1000 == 1s
	}
}

//-------------------------------------------------------------------------------------------------------

// ReShareEC2 execute reshare
// msgprex = hash
// return value is the backup for the smpc sig
func ReShareEC2(raw string, msgprex string, initator string, groupid string, pubkey string, account string, mode string, sigs string, ch chan interface{}, id int,keytype string) {
	if id < 0 || id >= len(workers) {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("no find worker")}
		ch <- res
		return
	}

	w := workers[id]
	if w.groupid == "" {
		res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("get group id fail")}
		ch <- res
		return
	}

	ns, _ := GetGroup(groupid)
	if ns != w.NodeCnt {
		res := RPCSmpcRes{Ret: "", Err: GetRetErr(ErrGroupNotReady)}
		ch <- res
		return
	}

	smpcpks, err := hex.DecodeString(pubkey)
	if err != nil {
	    res := RPCSmpcRes{Ret: "", Err: err}
	    ch <- res
	    return
	}

	exsit, da := GetPubKeyData(smpcpks[:])
	oldnode := true
	if !exsit {
		oldnode = false
	}

	if oldnode {
		_, ok := da.(*PubKeyData)
		if !ok || (da.(*PubKeyData)).GroupID == "" {
			res := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get sign data from db fail", Err: fmt.Errorf("get sign data from db fail")}
			ch <- res
			return
		}

		save := (da.(*PubKeyData)).Save
		mm := strings.Split(save, common.SepSave)
		if len(mm) == 0 {
			res := RPCSmpcRes{Ret: "", Err: fmt.Errorf("reshare get save data fail")}
			ch <- res
			return
		}

		sd := &keygen.LocalDNodeSaveData{}
		///sku1
		da2 := getSkU1FromLocalDb(smpcpks[:])
		if da2 == nil {
			res := RPCSmpcRes{Ret: "", Tip: "reshare get sku1 fail", Err: fmt.Errorf("reshare get sku1 fail")}
			ch <- res
			return
		}
		sku1 := new(big.Int).SetBytes(da2)
		if sku1 == nil {
			res := RPCSmpcRes{Ret: "", Tip: "reshare get sku1 fail", Err: fmt.Errorf("reshare get sku1 fail")}
			ch <- res
			return
		}
		//
		sd.SkU1 = sku1
		pkx, pky := secp256k1.S256(keytype).Unmarshal(smpcpks[:])
		sd.Pkx = pkx
		sd.Pky = pky

		sd.U1PaillierSk = GetCurNodePaillierSkFromSaveData(save, (da.(*PubKeyData)).GroupID, keytype)

		U1PaillierPk := make([]*ec2.PublicKey, w.NodeCnt)
		U1NtildeH1H2 := make([]*ec2.NtildeH1H2, w.NodeCnt)
		for i := 0; i < w.NodeCnt; i++ {
			U1PaillierPk[i] = GetPaillierPkByIndexFromSaveData(save, i)
			U1NtildeH1H2[i] = GetNtildeByIndexFromSaveData(save, i, w.NodeCnt)
		}
		sd.U1PaillierPk = U1PaillierPk
		sd.U1NtildeH1H2 = U1NtildeH1H2

		sd.IDs = GetGroupNodeUIDs(keytype,groupid,groupid) // 1,2,3,4,6
		_,sd.CurDNodeID = GetNodeUID(curEnode,keytype,groupid) 

		//msgtoenode := GetMsgToEnode(smpclib.EC256K1,(da.(*PubKeyData)).GroupID,(da.(*PubKeyData)).GroupID)
		//kgsave := &KGLocalDBSaveData{Save: sd, MsgToEnode: msgtoenode}

		found := false
		ids := GetGroupNodeUIDs(keytype,groupid,w.groupid)
		_,uid := GetNodeUID(curEnode,keytype,groupid)
		for _,v := range ids {
		    if v.Cmp(uid) == 0 {
			found = true
			break
		    }
		}

		if !found {
			fmt.Printf("================= ReShareEC2,not found in old groupid, so current node is not old node. new groupid = %v, new ts groupid = %v =======================\n", groupid, w.groupid)
			oldnode = false
		}

		if oldnode {
		
			oldindex,_ := GetNodeUID(curEnode,keytype,(da.(*PubKeyData)).GroupID)
			sd.U1NtildePrivData = GetNtildePrivDataByIndexFromSaveData(save,w.NodeCnt)
			if sd.U1NtildePrivData == nil {
				res := RPCSmpcRes{Ret: "", Tip: "get ntilde priv data fail", Err: fmt.Errorf("get ntilde priv data fail")}
				ch <- res
				return
			}

			fmt.Printf("================= ReShareEC2,oldnode is true, groupid = %v, w.groupid = %v =======================\n", groupid, w.groupid)
			commStopChan := make(chan struct{})
			outCh := make(chan smpclib.Message, ns)
			endCh := make(chan keygen.LocalDNodeSaveData, ns)
			errChan := make(chan struct{})
			reshareDNode := reshare.NewLocalDNode(outCh, endCh, ns, w.ThresHold, 2048, sd, true,oldindex,keytype)
			w.DNode = reshareDNode
			_,UID := GetNodeUID(curEnode,keytype,groupid)
			reshareDNode.SetDNodeID(fmt.Sprintf("%v", UID))

			uid, _ := new(big.Int).SetString(w.DNode.DNodeID(), 10)
			w.MsgToEnode[fmt.Sprintf("%v", uid)] = curEnode

			var reshareWg sync.WaitGroup
			reshareWg.Add(2)
			go func() {
				defer reshareWg.Done()
				if err := reshareDNode.Start(); nil != err {
					fmt.Printf("==========reshare node start err = %v ==========\n", err)
					close(errChan)
				}

				HandleC1Data(nil, w.sid)
			}()
			go ReshareProcessInboundMessages(msgprex, keytype,commStopChan, errChan,&reshareWg, ch)
			newsku1, err := processReshare(raw, msgprex, groupid, pubkey, account, mode, sigs, errChan, outCh, endCh,keytype)
			if err != nil {
				fmt.Printf("==========process reshare err = %v ==========\n", err)
				close(commStopChan)

				if len(ch) == 0 {
				    res := RPCSmpcRes{Ret: "", Err: err}
				    ch <- res
				}

				return
			}

			res := RPCSmpcRes{Ret: fmt.Sprintf("%v", newsku1), Err: nil}
			ch <- res
			close(commStopChan)
			reshareWg.Wait()
			return
		}
	}

	fmt.Printf("================= ReShareEC2,oldnode is false, groupid = %v, w.groupid = %v,w.ThresHold = %v,w.sid = %v, msgprex = %v =======================\n", groupid, w.groupid, w.ThresHold, w.sid, msgprex)
	commStopChan := make(chan struct{})
	outCh := make(chan smpclib.Message, ns)
	endCh := make(chan keygen.LocalDNodeSaveData, ns)
	errChan := make(chan struct{})
	reshareDNode := reshare.NewLocalDNode(outCh, endCh, ns, w.ThresHold, 2048, nil, false,-1,keytype)
	w.DNode = reshareDNode
	_,UID := GetNodeUID(curEnode,keytype,groupid)
	reshareDNode.SetDNodeID(fmt.Sprintf("%v", UID))

	uid, _ := new(big.Int).SetString(w.DNode.DNodeID(), 10)
	w.MsgToEnode[fmt.Sprintf("%v", uid)] = curEnode

	var reshareWg sync.WaitGroup
	reshareWg.Add(2)
	go func() {
		defer reshareWg.Done()
		if err := reshareDNode.Start(); nil != err {
			fmt.Printf("==========reshare node start err = %v ==========\n", err)
			close(errChan)
		}

		HandleC1Data(nil, w.sid)
	}()
	go ReshareProcessInboundMessages(msgprex, keytype,commStopChan, errChan,&reshareWg, ch)
	newsku1, err := processReshare(raw, msgprex, groupid, pubkey, account, mode, sigs, errChan, outCh, endCh,keytype)
	if err != nil {
		fmt.Printf("==========process reshare err = %v ==========\n", err)
		close(commStopChan)

		if len(ch) == 0 {
		    res := RPCSmpcRes{Ret: "", Err: err}
		    ch <- res
		}

		return
	}

	res := RPCSmpcRes{Ret: fmt.Sprintf("%v", newsku1), Err: nil}
	ch <- res
	close(commStopChan)
	reshareWg.Wait()
}

//-------------------------------------------------------------------------------------------------------------

// GetIDReshareByGroupID get uid of node in group by groupid,and sort the uids
func GetIDReshareByGroupID(msgtoenode map[string]string, groupid string) smpclib.SortableIDSSlice {
    	if msgtoenode == nil || groupid == "" {
	    return nil
	}

	var ids smpclib.SortableIDSSlice

	_, enodes := GetGroup(groupid)

	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		for key, value := range msgtoenode {
			if strings.EqualFold(value, node2) {
				uid, _ := new(big.Int).SetString(key, 10)
				ids = append(ids, uid)
				break
			}
		}
	}

	sort.Sort(ids)
	return ids
}


