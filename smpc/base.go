
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

package smpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"os"
	"bytes"

	"github.com/fsn-dev/cryptoCoins/coins"
	cryptocoinsconfig "github.com/fsn-dev/cryptoCoins/coins/config"
	"github.com/fsn-dev/cryptoCoins/coins/eos"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	p2psmpc "github.com/anyswap/Anyswap-MPCNode/p2p/layer2"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"encoding/gob"
	"compress/zlib"
	"github.com/anyswap/Anyswap-MPCNode/crypto/sha3"
	"io"
	"github.com/anyswap/Anyswap-MPCNode/internal/common/hexutil"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"crypto/hmac"
	"crypto/sha512"
	smpclibec2 "github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ec2"
	"github.com/anyswap/Anyswap-MPCNode/smpc-lib/crypto/ed"
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"sort"
)

var (
	cur_enode  string
	init_times = 0
	recalc_times = 1 
	KeyFile    string
)

type NodeReply struct {
    Enode string
    Status string
    TimeStamp string
    Initiator string // "1"/"0"
}

type LunchParams struct {
    WaitMsg uint64
    TryTimes uint64
    PreSignNum uint64
    WaitAgree uint64
    Bip32Pre uint64
}

func Start(params *LunchParams) {
   
	cryptocoinsconfig.Init()
	coins.Init()
	
	cur_enode = p2psmpc.GetSelfID()
	
	go smpclibec2.GenRandomSafePrime()
	
	common.Info("======================smpc.Start======================","cache",cache,"handles",handles,"cur enode",cur_enode)
	err := StartSmpcLocalDb()
	if err != nil {
	    info := "======================smpc.Start," + err.Error() + ",so terminate smpc node startup"
	    common.Error(info)
	    os.Exit(1)
	    return
	}

	common.Info("======================smpc.Start,open all db success======================","cur_enode",cur_enode)
	
	PrePubDataCount = int(params.PreSignNum)
	WaitMsgTimeGG20 = int(params.WaitMsg)
	recalc_times = int(params.TryTimes)
	waitallgg20 = WaitMsgTimeGG20 * recalc_times
	WaitAgree = int(params.WaitAgree)
	PreBip32DataCount = int(params.Bip32Pre)
	
	AutoPreGenSignData()

	go HandleRpcSign()

	common.Info("================================smpc.Start,init finish.========================","cur_enode",cur_enode,"waitmsg",WaitMsgTimeGG20,"trytimes",recalc_times,"presignnum",PrePubDataCount,"bip32pre",PreBip32DataCount)
}

func InitGroupInfo(groupId string) {
	cur_enode = discover.GetLocalID().String()
}

type RpcSmpcRes struct {
	Ret string
	Tip string
	Err error
}

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

func CheckAccept(pubkey string,mode string,account string) bool {
    if pubkey == "" || mode == "" || account == "" {
	return false
    }

    smpcpks, _ := hex.DecodeString(pubkey)
    exsit,da := GetPubKeyData(smpcpks[:])
    if exsit {
	pd,ok := da.(*PubKeyData)
	if ok {
	    exsit,da2 := GetPubKeyData([]byte(pd.Key))
	    if exsit {
		ac,ok := da2.(*AcceptReqAddrData)
		if ok {
		    if ac != nil {
			if ac.Mode != mode {
			    return false
			}
			if mode == "1" && strings.EqualFold(account,ac.Account) {
			    return true
			}

			if mode == "0" && CheckAcc(cur_enode,account,ac.Sigs) {
			    return true
			}
		    }
		}
	    }
	}
    }

    return false
}

func CheckRaw(raw string) (string,string,string,interface{},error) {
    if raw == "" {
	return "","","",nil,fmt.Errorf("raw data empty")
    }
    
    tx := new(types.Transaction)
    raws := common.FromHex(raw)
    if err := rlp.DecodeBytes(raws, tx); err != nil {
	    return "","","",nil,err
    }

    signer := types.NewEIP155Signer(big.NewInt(30400)) //
    from, err := types.Sender(signer, tx)
    if err != nil {
	return "", "","",nil,err
    }

    req := TxDataReqAddr{}
    err = json.Unmarshal(tx.Data(), &req)
    if err == nil && req.TxType == "REQSMPCADDR" {
	groupid := req.GroupId 
	if groupid == "" {
		return "","","",nil,fmt.Errorf("get group id fail.")
	}

	threshold := req.ThresHold
	if threshold == "" {
		return "","","",nil,fmt.Errorf("get threshold fail.")
	}

	mode := req.Mode
	if mode == "" {
		return "","","", nil,fmt.Errorf("get mode fail.")
	}

	timestamp := req.TimeStamp
	if timestamp == "" {
		return "","","", nil,fmt.Errorf("get timestamp fail.")
	}

	nums := strings.Split(threshold, "/")
	if len(nums) != 2 {
		return "","","", nil,fmt.Errorf("tx.data error.")
	}

	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
		return "","","", nil,err
	}

	ts, err := strconv.Atoi(nums[0])
	if err != nil {
		return "","","", nil,err
	}

	if nodecnt < ts || ts < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	Nonce := tx.Nonce()

	nc,_ := GetGroup(groupid)
	if nc != nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}

	if !CheckGroupEnode(groupid) {
	    return "","","",nil,fmt.Errorf("there is same enodeID in group")
	}
	
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + req.Keytype + ":" + groupid + ":" + fmt.Sprintf("%v", Nonce) + ":" + threshold + ":" + mode))).Hex()

	common.Debug("================CheckRaw, it is reqaddr tx=================","raw ",raw,"key ",key,"req ",&req)
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&req,nil
    }
    
    sig := TxDataSign{}
    err = json.Unmarshal(tx.Data(), &sig)
    if err == nil && sig.TxType == "SIGN" {
	pubkey := sig.PubKey
	inputcode := sig.InputCode
	hash := sig.MsgHash
	keytype := sig.Keytype
	groupid := sig.GroupId
	threshold := sig.ThresHold
	mode := sig.Mode
	timestamp := sig.TimeStamp
	Nonce := tx.Nonce()

	if from.Hex() == "" || pubkey == "" || hash == nil || keytype == "" || groupid == "" || threshold == "" || mode == "" || timestamp == "" {
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
	    common.Info("==============CheckRaw, sign,check group node count error============","limit ",limit,"nodecnt ",nodecnt,"nc ",nc,"groupid ",groupid)
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

	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + fmt.Sprintf("%v", Nonce) + ":" + pubkey + ":" + get_sign_hash(hash,keytype) + ":" + keytype + ":" + groupid + ":" + threshold + ":" + mode))).Hex()
	common.Debug("=================CheckRaw, it is sign tx==================","raw ",raw,"key ",key,"sig ",&sig)
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&sig,nil
    }

    //******************//////////TODO
    pre := TxDataPreSignData{}
    err = json.Unmarshal(tx.Data(), &pre)
    if err == nil && pre.TxType == "PRESIGNDATA" {
	pubkey := pre.PubKey
	subgids := pre.SubGid
	Nonce := tx.Nonce()

	if from.Hex() == "" || pubkey == "" || subgids == nil {
		return "","","",nil,fmt.Errorf("param error from raw data.")
	}
	//

	smpcpks, _ := hex.DecodeString(pubkey)
	exsit,_ := GetPubKeyData(smpcpks[:])
	if !exsit {
		return "","","",nil,fmt.Errorf("invalid pubkey")
	}

	common.Debug("=================CheckRaw, it is presigndata tx==================","raw ",raw,"pre ",&pre)
	return "",from.Hex(),fmt.Sprintf("%v", Nonce),&pre,nil
    }

    //************************/////////////

    rh := TxDataReShare{}
    err = json.Unmarshal(tx.Data(), &rh)
    if err == nil && rh.TxType == "RESHARE" {
	if !IsValidReShareAccept(from.Hex(),rh.GroupId) {
	    return "","","",nil,fmt.Errorf("check current enode account fail from raw data")
	}

	if from.Hex() == "" || rh.PubKey == "" || rh.TSGroupId == "" || rh.ThresHold == "" || rh.Account == "" || rh.Mode == "" || rh.TimeStamp == "" {
	    return "","","",nil,fmt.Errorf("param error.")
	}

	////
	nums := strings.Split(rh.ThresHold, "/")
	if len(nums) != 2 {
	    return "","","",nil,fmt.Errorf("transacion data format error,threshold is not right")
	}
	nodecnt, err := strconv.Atoi(nums[1])
	if err != nil {
	    return "","","",nil,err
	}
	limit, err := strconv.Atoi(nums[0])
	if err != nil {
	    return "","","",nil,err
	}
	if nodecnt < limit || limit < 2 {
	    return "","","",nil,fmt.Errorf("threshold format error")
	}

	nc,_ := GetGroup(rh.GroupId)
	if nc < limit || nc > nodecnt {
	    return "","","",nil,fmt.Errorf("check group node count error")
	}
	
	key := Keccak256Hash([]byte(strings.ToLower(from.Hex() + ":" + rh.GroupId + ":" + rh.TSGroupId + ":" + rh.PubKey + ":" + rh.ThresHold + ":" + rh.Mode))).Hex()
	Nonce := tx.Nonce()
	
	return key,from.Hex(),fmt.Sprintf("%v", Nonce),&rh,nil
    }

    acceptreq := TxDataAcceptReqAddr{}
    err = json.Unmarshal(tx.Data(), &acceptreq)
    if err == nil && acceptreq.TxType == "ACCEPTREQADDR" {
	if acceptreq.Accept != "AGREE" && acceptreq.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetReqAddrInfoData([]byte(acceptreq.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept data fail from db in checking raw reqaddr accept data")
	}

	ac,ok := da.(*AcceptReqAddrData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("decode accept data fail")
	}

	///////
	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	if !CheckAcc(cur_enode,from.Hex(),ac.Sigs) {
	    return "","","",nil,fmt.Errorf("invalid accept account")
	}

	common.Debug("=================CheckRaw, it is acceptreqaddr tx====================","raw ",raw,"key ",acceptreq.Key,"acceptreq ",&acceptreq)
	return acceptreq.Key,from.Hex(),"",&acceptreq,nil
    }

    acceptsig := TxDataAcceptSign{}
    err = json.Unmarshal(tx.Data(), &acceptsig)
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
	
	if !CheckAccept(ac.PubKey,ac.Mode,from.Hex()) {
	    return "","","",nil,fmt.Errorf("invalid accepter")
	}
	
	common.Debug("=================CheckRaw, it is acceptsign tx====================","raw ",raw,"key ",acceptsig.Key,"acceptsig ",&acceptsig)
	return acceptsig.Key,from.Hex(),"",&acceptsig,nil
    }

    acceptrh := TxDataAcceptReShare{}
    err = json.Unmarshal(tx.Data(), &acceptrh)
    if err == nil && acceptrh.TxType == "ACCEPTRESHARE" {
	if acceptrh.Accept != "AGREE" && acceptrh.Accept != "DISAGREE" {
	    return "","","",nil,fmt.Errorf("transaction data format error,the lastest segment is not AGREE or DISAGREE")
	}

	exsit,da := GetReShareInfoData([]byte(acceptrh.Key))
	if !exsit {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	ac,ok := da.(*AcceptReShareData)
	if !ok || ac == nil {
	    return "","","",nil,fmt.Errorf("get accept result from db fail")
	}

	if ac.Mode == "1" {
	    return "","","",nil,fmt.Errorf("mode = 1,do not need to accept")
	}
	
	//if !IsValidReShareAccept(from.Hex(),ac.GroupId) {
	  //  return "","","",nil,fmt.Errorf("check current enode account fail from raw data")
	//}

	common.Debug("=================CheckRaw, it is acceptreshare tx=====================","raw ",raw,"key ",acceptrh.Key,"acceptrh ",&acceptrh)
	return acceptrh.Key,from.Hex(),"",&acceptrh,nil
    }

    return "","","",nil,fmt.Errorf("check fail")
}

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

func init() {
	p2psmpc.RegisterRecvCallback(Call2)
	p2psmpc.SdkProtocol_registerBroadcastInGroupCallback(Call)
	p2psmpc.RegisterCallback(Call)

	RegP2pGetGroupCallBack(p2psmpc.SdkProtocol_getGroup)
	RegP2pSendToGroupAllNodesCallBack(p2psmpc.SdkProtocol_SendToGroupAllNodes)
	RegP2pGetSelfEnodeCallBack(p2psmpc.GetSelfID)
	RegP2pBroadcastInGroupOthersCallBack(p2psmpc.SdkProtocol_broadcastInGroupOthers)
	RegP2pSendMsgToPeerCallBack(p2psmpc.SendMsgToPeer)
	RegP2pParseNodeCallBack(p2psmpc.ParseNodeID)
	RegSmpcGetEosAccountCallBack(eos.GetEosAccount)
	InitChan()
}

func Call2(msg interface{}) {
	s := msg.(string)
	SetUpMsgList2(s)
}

var parts  = common.NewSafeMap(10)

func receiveGroupInfo(msg interface{}) {
	cur_enode = p2psmpc.GetSelfID()

	m := strings.Split(msg.(string), "|")
	if len(m) != 2 {
		return
	}

	splitkey := m[1]

	head := strings.Split(splitkey, ":")[0]
	body := strings.Split(splitkey, ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "smpcslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "smpcslash")[1])
	//parts[p] = body
	parts.WriteMap(strconv.Itoa(p),body)

	if parts.MapLength() == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			da,exist := parts.ReadMap(strconv.Itoa(i))
			if exist {
			    datmp,ok := da.(string)
			    if ok {
				c += datmp
			    }
			}
		}

		time.Sleep(time.Duration(2) * time.Second) //1000 == 1s
		////
		Init(m[0])
	}
}

func Init(groupId string) {
	common.Debug("======================Init==========================","get group id",groupId,"init_times",strconv.Itoa(init_times))

	if init_times >= 1 {
		return
	}

	init_times = 1
	InitGroupInfo(groupId)
}

func SetUpMsgList2(msg string) {

	mm := strings.Split(msg, "smpcslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

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

func Encode2(obj interface{}) (string, error) {
    switch ch := obj.(type) {
	case *SendMsg:
		/*ch := obj.(*SendMsg)
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil*/

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *PubKeyData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
			return "", err1
		}
		return buff.String(), nil
	case *AcceptReqAddrData:
		ret,err := json.Marshal(ch)
		if err != nil {
		    return "",err
		}
		return string(ret),nil
	case *AcceptSignData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	case *AcceptReShareData:

		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)

		err1 := enc.Encode(ch)
		if err1 != nil {
		    return "", err1
		}
		return buff.String(), nil
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {

	if datatype == "SendMsg" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res SendMsg
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "PubKeyData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res PubKeyData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReqAddrData" {
		var m AcceptReqAddrData
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
		    return nil,err
		}

		return &m,nil
	}

	if datatype == "AcceptSignData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptSignData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	if datatype == "AcceptReShareData" {
		var data bytes.Buffer
		data.Write([]byte(s))

		dec := gob.NewDecoder(&data)

		var res AcceptReShareData
		err := dec.Decode(&res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	}

	return nil, fmt.Errorf("decode obj fail.")
}

///////

func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail.")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
		return "", err
	}

	_,err = w.Write(c)
	if err != nil {
	    return "",err
	}

	w.Close()

	s := in.String()
	return s, nil
}

func UnCompress(s string) (string, error) {

	if s == "" {
		return "", fmt.Errorf("param error.")
	}

	var data bytes.Buffer
	data.Write([]byte(s))

	r, err := zlib.NewReader(&data)
	if err != nil {
		return "", err
	}

	var out bytes.Buffer
	_,err = io.Copy(&out, r)
	if err != nil {
	    return "",err
	}

	return out.String(), nil
}

////

type SmpcHash [32]byte

func (h SmpcHash) Hex() string { return hexutil.Encode(h[:]) }

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h SmpcHash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
	    _,err := d.Write(b)
	    if err != nil {
		return h 
	    }
	}
	d.Sum(h[:0])
	return h
}

type RpcType int32

const (
    Rpc_REQADDR      RpcType = 0
    Rpc_LOCKOUT     RpcType = 1
    Rpc_SIGN      RpcType = 2
    Rpc_RESHARE     RpcType = 3
)

func GetAllReplyFromGroup(wid int,gid string,rt RpcType,initiator string) []NodeReply {
    if gid == "" {
	return nil
    }

    var ars []NodeReply
    _, enodes := GetGroup(gid)
    nodes := strings.Split(enodes, common.Sep2)
    
    if wid < 0 || wid >= len(workers) {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}

	return ars
    }

    w := workers[wid]
    if w == nil {
	return nil
    }

    if rt == Rpc_SIGN {
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
		    key2 := GetReqAddrKeyByOtherKey(key,rt)
		    exsit,da := GetPubKeyData([]byte(key2))
		    if exsit {
			ac,ok := da.(*AcceptReqAddrData)
			if ok && ac != nil {
			    ret := GetRawReply(w.msg_acceptsignres)
			    //sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			    mms := strings.Split(ac.Sigs, common.Sep)
			    for k,mm := range mms {
				if strings.EqualFold(mm,node2) {
				    reply,ok := ret[mms[k+1]]
				    if ok && reply != nil {
					common.Info("===================GetAllReplyFromGroup,it is sign=================","key",key,"from",mms[k+1],"Accept",reply.Accept,"raw",mdss)
					if reply.Accept == "true" {
					    sta = "Agree"
					} else {
					    sta = "DisAgree"
					}
					ts = reply.TimeStamp
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
    } 
    
    if rt == Rpc_RESHARE {
	for _, node := range nodes {
		node2 := ParseNode(node)
		sta := "Pending"
		ts := ""
		in := "0"
		if strings.EqualFold(initiator,node2) {
		    in = "1"
		}

		iter := w.msg_acceptreshareres.Front()
		for iter != nil {
		    mdss := iter.Value.(string)
		    _,from,_,txdata,err := CheckRaw(mdss)
		    if err != nil {
			iter = iter.Next()
			continue
		    }

		    rh,ok := txdata.(*TxDataReShare)
		    if ok {
			h := coins.NewCryptocoinHandler("FSN")
			if h == nil {
			    iter = iter.Next()
			    continue
			}
			
			pk := "04" + node2 
			fr, err := h.PublicKeyToAddress(pk)
			if err != nil {
			    iter = iter.Next()
			    continue
			}

			if strings.EqualFold(from, fr) {
			    sta = "Agree"
			    ts = rh.TimeStamp
			    break
			}
		    }

		    acceptrh,ok := txdata.(*TxDataAcceptReShare)
		    if ok {
			h := coins.NewCryptocoinHandler("FSN")
			if h == nil {
			    iter = iter.Next()
			    continue
			}
			
			pk := "04" + node2 
			fr, err := h.PublicKeyToAddress(pk)
			if err != nil {
			    iter = iter.Next()
			    continue
			}

			if strings.EqualFold(from, fr) {
			    sta = "Agree"
			    ts = acceptrh.TimeStamp
			    break
			}
		    }

		    iter = iter.Next()
		}
		
		nr := NodeReply{Enode:node2,Status:sta,TimeStamp:ts,Initiator:in}
		ars = append(ars,nr)
	}
    }
    
    if rt == Rpc_REQADDR {
	for _, node := range nodes {
	    node2 := ParseNode(node)
	    sta := "Pending"
	    ts := ""
	    in := "0"
	    if strings.EqualFold(initiator,node2) {
		in = "1"
	    }

	    iter := w.msg_acceptreqaddrres.Front()
	    if iter != nil {
		mdss := iter.Value.(string)
		common.Debug("===================== GetAllReplyFromGroup call CheckRaw,it is Rpc_REQADDR ================")
		key,_,_,_,_ := CheckRaw(mdss)
		exsit,da := GetReqAddrInfoData([]byte(key))
		if !exsit || da == nil {
		    exsit,da = GetPubKeyData([]byte(key))
		}

		if exsit {
		    ac,ok := da.(*AcceptReqAddrData)
		    if ok && ac != nil {
			ret := GetRawReply(w.msg_acceptreqaddrres)
			//sigs:  5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
			mms := strings.Split(ac.Sigs, common.Sep)
			for k,mm := range mms {
			    if strings.EqualFold(mm,node2) {
				reply,ok := ret[mms[k+1]]
				if ok && reply != nil {
				    if reply.Accept == "true" {
					sta = "Agree"
				    } else {
					sta = "DisAgree"
				    }
				    ts = reply.TimeStamp
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
    }

    return ars
}

func GetReqAddrKeyByOtherKey(key string,rt RpcType) string {
    if key == "" {
	return ""
    }

    if rt == Rpc_SIGN {
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
    }

    return ""
}

func GetChannelValue(t int, obj interface{}) (string, string, error) {
	timeout := make(chan bool, 1)
	go func() {
		time.Sleep(time.Duration(t) * time.Second) //1000 == 1s
		timeout <- true
	}()

	switch ch := obj.(type) {
	case chan interface{}:
		select {
		case v := <-ch:
			ret, ok := v.(RpcSmpcRes)
			if ok {
				return ret.Ret, ret.Tip, ret.Err
			}
		case <-timeout:
			return "", "smpc back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan string:
		select {
		case v := <-ch:
			return v, "", nil
		case <-timeout:
			return "", "smpc back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int64:
		select {
		case v := <-ch:
			return strconv.Itoa(int(v)), "", nil
		case <-timeout:
			return "", "smpc back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan int:
		select {
		case v := <-ch:
			return strconv.Itoa(v), "", nil
		case <-timeout:
			return "", "smpc back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	case chan bool:
		select {
		case v := <-ch:
			if !v {
				return "false", "", nil
			} else {
				return "true", "", nil
			}
		case <-timeout:
			return "", "smpc back-end internal error:get result from channel timeout", fmt.Errorf("get data from node fail.")
		}
	default:
		return "", "smpc back-end internal error:unknown channel type", fmt.Errorf("unknown ch type.")
	}

	return "", "smpc back-end internal error:unknown error.", fmt.Errorf("get value fail.")
}

//error type 1
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
	    key2 := []byte(string(iter.Key())) //must be deep copy,or show me the error: "panic: JSON decoder out of sync - data changing underfoot?"
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

func IsCurNode(enodes string, cur string) bool {
	if enodes == "" || cur == "" {
		return false
	}

	s := []rune(enodes)
	en := strings.Split(string(s[8:]), "@")
	return en[0] == cur
}

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

/*type sortableIDSSlice []*big.Int

func (s sortableIDSSlice) Len() int {
	return len(s)
}

func (s sortableIDSSlice) Less(i, j int) bool {
	return s[i].Cmp(s[j]) <= 0
}

func (s sortableIDSSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}*/

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

func GetIds(keytype string, groupid string) smpclib.SortableIDSSlice {
	var ids smpclib.SortableIDSSlice
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

