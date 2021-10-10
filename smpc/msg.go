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
	"container/list"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/anyswap/Anyswap-MPCNode/crypto"
	"github.com/anyswap/Anyswap-MPCNode/crypto/ecies"
	"github.com/anyswap/Anyswap-MPCNode/crypto/secp256k1"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	p2psmpc "github.com/anyswap/Anyswap-MPCNode/p2p/layer2"
	"github.com/fsn-dev/cryptoCoins/coins"
	"github.com/fsn-dev/cryptoCoins/coins/types"
	"github.com/fsn-dev/cryptoCoins/tools/rlp"
	"math/big"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

var (
	ch_t            = 300
	WaitMsgTimeGG20 = 100
	waitall         = ch_t * recalc_times
	waitallgg20     = WaitMsgTimeGG20 * recalc_times
	WaitAgree       = 120 // second
	C1Data          = common.NewSafeMap(10)

	syncpresign = true

	//callback
	GetGroup               func(string) (int, string)
	SendToGroupAllNodes    func(string, string) (string, error)
	GetSelfEnode           func() string
	BroadcastInGroupOthers func(string, string) (string, error)
	SendToPeer             func(string, string) error
	ParseNode              func(string) string
	GetEosAccount          func() (string, string, string)
)

//----------------------------------------------------------------------------------

//p2p callback
func RegP2pGetGroupCallBack(f func(string) (int, string)) {
	GetGroup = f
}

func RegP2pSendToGroupAllNodesCallBack(f func(string, string) (string, error)) {
	SendToGroupAllNodes = f
}

func RegP2pGetSelfEnodeCallBack(f func() string) {
	GetSelfEnode = f
}

func RegP2pBroadcastInGroupOthersCallBack(f func(string, string) (string, error)) {
	BroadcastInGroupOthers = f
}

func RegP2pSendMsgToPeerCallBack(f func(string, string) error) {
	SendToPeer = f
}

func RegP2pParseNodeCallBack(f func(string) string) {
	ParseNode = f
}

func RegSmpcGetEosAccountCallBack(f func() (string, string, string)) {
	GetEosAccount = f
}

//------------------------------------------------------------------------------------------

func Call2(msg interface{}) {
	s := msg.(string)
	SetUpMsgList2(s)
}

func SetUpMsgList2(msg string) {

	mm := strings.Split(msg, "smpcslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

var parts = common.NewSafeMap(10)

//smpc node receive specific msg (for example:group info) from p2p by Call2
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
	parts.WriteMap(strconv.Itoa(p), body)

	if parts.MapLength() == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			da, exist := parts.ReadMap(strconv.Itoa(i))
			if exist {
				datmp, ok := da.(string)
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

//init smpc node with the msg receive from group by Call2
func Init(groupId string) {
	common.Debug("======================Init==========================", "get group id", groupId, "init_times", strconv.Itoa(init_times))

	if init_times >= 1 {
		return
	}

	init_times = 1
	InitGroupInfo(groupId)
}

func InitGroupInfo(groupId string) {
	cur_enode = discover.GetLocalID().String()
}

//------------------------------------------------------------------------------

//brodcast msg to group
func SendMsgToSmpcGroup(msg string, groupid string) {
	common.Debug("=========SendMsgToSmpcGroup=============", "msg", msg, "groupid", groupid)
	_, err := BroadcastInGroupOthers(groupid, msg)
	if err != nil {
		common.Debug("=========SendMsgToSmpcGroup,send msg to smpc group=============", "msg", msg, "groupid", groupid, "err", err)
	}
}

//-------------------------------------------------------------------------------

func EncryptMsg(msg string, enodeID string) (string, error) {
	hprv, err1 := hex.DecodeString(enodeID)
	if err1 != nil {
		return "", err1
	}

	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(hprv) / 2
	p.X.SetBytes(hprv[:half])
	p.Y.SetBytes(hprv[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return "", fmt.Errorf("id is invalid secp256k1 curve point")
	}

	var cm []byte
	pub := ecies.ImportECDSAPublic(p)
	cm, err := ecies.Encrypt(crand.Reader, pub, []byte(msg), nil, nil)
	if err != nil {
		return "", err
	}

	return string(cm), nil
}

func DecryptMsg(cm string) (string, error) {
	nodeKey, errkey := crypto.LoadECDSA(KeyFile)
	if errkey != nil {
		return "", errkey
	}

	prv := ecies.ImportECDSA(nodeKey)
	var m []byte
	m, err := prv.Decrypt([]byte(cm), nil, nil)
	if err != nil {
		return "", err
	}

	return string(m), nil
}

func SendMsgToPeer(enodes string, msg string) {
	en := strings.Split(string(enodes[8:]), "@")
	cm, err := EncryptMsg(msg, en[0])
	if err != nil {
		return
	}

	err = SendToPeer(enodes, cm)
	if err != nil {
		return
	}
}

//-------------------------------------------------------------

func IsReshareCmd(raw string) (bool, string) {
	if raw == "" {
		return false, ""
	}

	key, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		return false, ""
	}

	_, ok := txdata.(*TxDataReShare)
	if ok {
		return true, key
	}

	return false, ""
}

func IsGenKeyCmd(raw string) (bool, string) {
	if raw == "" {
		return false, ""
	}

	key, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		return false, ""
	}

	_, ok := txdata.(*TxDataReqAddr)
	if ok {
		return true, key
	}

	return false, ""
}

func IsPreGenSignData(raw string) (string, bool) {
	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(raw), &msgmap)
	if err == nil {
		if msgmap["Type"] == "PreSign" {
			sd := &PreSign{}
			if err = sd.UnmarshalJSON([]byte(msgmap["SignData"])); err == nil {
				return sd.Nonce, true
			}
		}
	}

	return "", false
}

func IsEDSignCmd(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}

	key, _, _, txdata, err := CheckRaw(raw)
	if err != nil {
		return "", false
	}

	sig, ok := txdata.(*TxDataSign)
	if ok {
		if sig.Keytype == "ED25519" {
			return key, true
		}

		return "", false
	}

	return "", false
}

func IsSignDataCmd(raw string) (string, bool) {
	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(raw), &msgmap)

	if err == nil {
		if msgmap["Type"] == "SignData" {
			sd := &SignData{}
			if err = sd.UnmarshalJSON([]byte(msgmap["SignData"])); err == nil {
				return sd.Key, true
			}
		}
	}

	return "", false
}

func GetCmdKey(msg string) string {
	if msg == "" {
		return ""
	}

	ok, key := IsGenKeyCmd(msg)
	if ok {
		return key
	}

	ok, key = IsReshareCmd(msg)
	if ok {
		return key
	}

	key, ok = IsPreGenSignData(msg)
	if ok {
		return key
	}

	key, ok = IsEDSignCmd(msg)
	if ok {
		return key
	}

	key, ok = IsSignDataCmd(msg)
	if ok {
		return key
	}

	return ""
}

//----------------------------------------------------------------------------------------

//receive msg from p2p
func Call(msg interface{}, enode string) {
	common.Debug("====================Call===================", "get p2p msg ", msg, "sender node", enode)
	s := msg.(string)
	if s == "" {
		return
	}
	raw, err := UnCompress(s)
	if err == nil {
		s = raw
	}
	msgdata, errdec := DecryptMsg(s) //for SendMsgToPeer
	if errdec == nil {
		s = msgdata
	}

	msgmap := make(map[string]string)
	err = json.Unmarshal([]byte(s), &msgmap)
	if err == nil {
		val, ok := msgmap["Key"]
		if ok {
			w, err := FindWorker(val)
			if err == nil {
				if w.DNode != nil && w.DNode.Round() != nil {
					common.Debug("====================Call, get smpc msg,worker found.===================", "key", val, "msg", msg, "sender node", enode)
					w.SmpcMsg <- s
				} else {
					from := msgmap["FromID"]
					msgtype := msgmap["Type"]
					key := strings.ToLower(val + "-" + from + "-" + msgtype)
					C1Data.WriteMap(key, s)
					fmt.Printf("===============================Call, pre-save p2p msg, worker found, key = %v,fromId = %v,msgtype = %v, msg = %v========================\n", val, from, msgtype, s)
				}
			} else {
				from := msgmap["FromID"]
				msgtype := msgmap["Type"]
				key := strings.ToLower(val + "-" + from + "-" + msgtype)
				C1Data.WriteMap(key, s)
				fmt.Printf("===============================Call, pre-save p2p msg, worker not found, key = %v,fromId = %v,msgtype = %v, msg = %v========================\n", val, from, msgtype, s)
			}

			return
		}

		if msgmap["Type"] == "SyncPreSign" {
			sps := &SyncPreSign{}
			if err = sps.UnmarshalJSON([]byte(msgmap["SyncPreSign"])); err == nil {
				w, err := FindWorker(sps.MsgPrex)
				if err == nil {
					if w.msg_syncpresign.Len() < w.ThresHold {
						if !Find(w.msg_syncpresign, s) {
							w.msg_syncpresign.PushBack(s)
							if w.msg_syncpresign.Len() == w.ThresHold {
								w.bsyncpresign <- true
							}
						}
					}
				}
			}

			return
		}
	}

	SetUpMsgList(s, enode)
}

func SetUpMsgList(msg string, enode string) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	rch := make(chan interface{}, 1)
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

func SetUpMsgList3(msg string, enode string, rch chan interface{}) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

//-----------------------------------------------------------------

type WorkReq interface {
	Run(workid int, ch chan interface{}) bool
}

type RecvMsg struct {
	msg    string
	sender string
}

func (self *RecvMsg) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RPCMaxWorker {
		res2 := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get worker id fail", Err: fmt.Errorf("worker was not found.")}
		ch <- res2
		return false
	}

	res := self.msg
	if res == "" {
		res2 := RpcSmpcRes{Ret: "", Tip: "smpc back-end internal error:get data fail in RecvMsg.Run", Err: fmt.Errorf("worker was not found.")}
		ch <- res2
		return false
	}

	msgdata, errdec := DecryptMsg(res) //for SendMsgToPeer
	if errdec == nil {
		common.Debug("================RecvMsg.Run, decrypt msg success=================", "msg", msgdata)
		res = msgdata
	}

	/*mm := strings.Split(res, common.Sep)
	if len(mm) >= 3 {
		common.Debug("================RecvMsg.Run,begin to dis msg =================", "res", res)
		//msg:  key-enode:C1:X1:X2....:Xn
		//msg:  key-enode1:NoReciv:enode2:C1
		DisMsg(res)
		return true
	}*/

	var req SmpcReq
	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(res), &msgmap)
	if err == nil {
		if msgmap["Type"] == "SignData" || msgmap["Type"] == "PreSign" || msgmap["Type"] == "ComSignBrocastData" || msgmap["Type"] == "ComSignData" {
			req = &ReqSmpcSign{}
			return req.DoReq(res, workid, self.sender, ch)
		}
	}

	return (MsgRun(res, workid, self.sender, ch) == nil)
}

//---------------------------------------------------------------------------

func Handle(key string, c1data string) {
	w, err := FindWorker(key)
	if w == nil || err != nil {
		return
	}

	val, exist := C1Data.ReadMap(c1data)
	if exist {
		if w.DNode != nil && w.DNode.Round() != nil {
			w.SmpcMsg <- val.(string)
			go C1Data.DeleteMap(c1data)
		}
	}
}

func HandleKG(key string, uid *big.Int) {
	c1data := strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "KGRound0Message")
	Handle(key, c1data)
	c1data = strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "KGRound1Message")
	Handle(key, c1data)
}

func HandleSign(key string, uid *big.Int) {
	c1data := strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "SignRound1Message")
	Handle(key, c1data)
	c1data = strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "SignRound2Message")
	Handle(key, c1data)
}

//C1Data Key, Three formats are included:
//1.  key-enodefrom, for reshare only, enodefrom get from enodeId
//2.  key-uid-msgtype, for example: key-uid-"KGRound0Message"
//3.  key-accout,for accept reply
func HandleC1Data(ac *AcceptReqAddrData, key string) {
	w, err := FindWorker(key)
	if w == nil || err != nil {
		return
	}

	//reshare only
	if ac == nil {
		exsit, da := GetReShareInfoData([]byte(key))
		if !exsit {
			return
		}

		ac, ok := da.(*AcceptReShareData)
		if !ok || ac == nil {
			return
		}

		_, enodes := GetGroup(ac.GroupId)
		nodes := strings.Split(enodes, common.Sep2)
		for _, node := range nodes {
			node2 := ParseNode(node)
			pk := "04" + node2
			h := coins.NewCryptocoinHandler("FSN")
			if h == nil {
				continue
			}

			fr, err := h.PublicKeyToAddress(pk)
			if err != nil {
				continue
			}

			c1data := strings.ToLower(key + "-" + fr)
			c1, exist := C1Data.ReadMap(c1data)
			if exist {
				DisAcceptMsg(c1.(string), w.id)
				go C1Data.DeleteMap(c1data)
			}
		}

		return
	}
	//reshare only

	if key == "" {
		return
	}

	_, enodes := GetGroup(ac.GroupId)
	nodes := strings.Split(enodes, common.Sep2)

	for _, node := range nodes {
		node2 := ParseNode(node)
		uid := DoubleHash(node2, "EC256K1")
		HandleKG(key, uid)
		HandleSign(key, uid)
		uid = DoubleHash(node2, "ED25519")
		HandleKG(key, uid)
		HandleSign(key, uid)
	}

	mms := strings.Split(ac.Sigs, common.Sep)
	if len(mms) < 3 { //1:enodeid1:account1
		return
	}

	count := (len(mms) - 1) / 2
	for j := 0; j < count; j++ {
		from := mms[2*j+2]
		c1data := strings.ToLower(key + "-" + from)
		c1, exist := C1Data.ReadMap(c1data)
		if exist {
			DisAcceptMsg(c1.(string), w.id)
			go C1Data.DeleteMap(c1data)
		}
	}
}

//-----------------------------------------------------------------------------------

func GetRawType(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}

	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=======================GetRawType,check accept raw data error===================", "err", err)
		return "", ""
	}

	_, ok := txdata.(*TxDataReqAddr)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", key, "from", from, "txdata", txdata)
		return "REQADDR", key
	}

	_, ok = txdata.(*TxDataSign)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", key, "from", from, "txdata", txdata)
		return "SIGN", key
	}

	_, ok = txdata.(*TxDataReShare)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", key, "from", from, "txdata", txdata)
		return "RESHARE", key
	}

	acceptreq, ok := txdata.(*TxDataAcceptReqAddr)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", acceptreq.Key, "from", from, "txdata", txdata)
		return "ACCEPTREQADDR", acceptreq.Key
	}

	acceptsig, ok := txdata.(*TxDataAcceptSign)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", acceptsig.Key, "from", from, "txdata", txdata)
		return "ACCEPTSIGN", acceptsig.Key
	}

	acceptreshare, ok := txdata.(*TxDataAcceptReShare)
	if ok {
		common.Debug("=======================GetRawType,get one accept raw data===================", "raw", raw, "key", acceptreshare.Key, "from", from, "txdata", txdata)
		return "ACCEPTRESHARE", acceptreshare.Key
	}

	return "", ""
}

//---------------------------------------------------------------------------------

func DisAcceptMsg(raw string, workid int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("DisAcceptMsg Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	if raw == "" || workid < 0 || workid >= len(workers) {
		return
	}

	var req SmpcReq
	rawtype, key := GetRawType(raw)
	switch rawtype {
	case "REQADDR":
		req = &ReqSmpcAddr{}
	case "SIGN":
		req = &ReqSmpcSign{}
	case "RESHARE":
		req = &ReqSmpcReshare{}
	case "ACCEPTREQADDR":
		req = &ReqSmpcAddr{}
	case "ACCEPTSIGN":
		req = &ReqSmpcSign{}
	case "ACCEPTRESHARE":
		req = &ReqSmpcReshare{}
	}

	req.DisAcceptMsg(raw, workid, key)
}

//------------------------------------------------------------------------------------

func MsgRun(raw string, workid int, sender string, ch chan interface{}) error {
	if raw == "" || workid < 0 || sender == "" {
		res := RpcSmpcRes{Ret: "", Tip: "msg run fail.", Err: fmt.Errorf("msg run fail")}
		ch <- res
		return fmt.Errorf("msg run fail")
	}

	var req SmpcReq
	rawtype, key := GetRawType(raw)
	switch rawtype {
	case "REQADDR":
		req = &ReqSmpcAddr{}
	case "SIGN":
		req = &ReqSmpcSign{}
	case "RESHARE":
		req = &ReqSmpcReshare{}
	case "ACCEPTREQADDR":
		req = &ReqSmpcAddr{}
	case "ACCEPTSIGN":
		req = &ReqSmpcSign{}
	case "ACCEPTRESHARE":
		req = &ReqSmpcReshare{}
	default:
		return fmt.Errorf("Unsupported request type")
	}

	common.Info("=====================MsgRun,get result from GetRawType ================", "key", key, "raw", raw)
	if !req.DoReq(raw, workid, sender, ch) {
		return fmt.Errorf("msg run fail")
	}

	return nil
}

//------------------------------------------------------------------------------------

func GetGroupSigsDataByRaw(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("raw data empty")
	}

	tx := new(types.Transaction)
	raws := common.FromHex(raw)
	if err := rlp.DecodeBytes(raws, tx); err != nil {
		return "", err
	}

	signer := types.NewEIP155Signer(big.NewInt(30400)) //
	_, err := types.Sender(signer, tx)
	if err != nil {
		return "", err
	}

	var threshold string
	var mode string
	var groupsigs string
	var groupid string

	var req2 SmpcReq
	req := TxDataReqAddr{}
	err = json.Unmarshal(tx.Data(), &req)
	if err == nil && req.TxType == "REQSMPCADDR" {
		req2 = &ReqSmpcAddr{}
	} else {
		rh := TxDataReShare{}
		err = json.Unmarshal(tx.Data(), &rh)
		if err == nil && rh.TxType == "RESHARE" {
			req2 = &ReqSmpcReshare{}
		}
	}

	if req2 != nil {
		threshold, mode, groupsigs, groupid = req2.GetGroupSigs(tx.Data())
	}

	if threshold == "" || mode == "" || groupid == "" {
		return "", fmt.Errorf("raw data error,it is not REQSMPCADDR tx or RESHARE tx")
	}

	if mode == "1" {
		return "", nil
	}

	if mode == "0" && groupsigs == "" {
		return "", fmt.Errorf("raw data error,must have sigs data when mode = 0")
	}

	nums := strings.Split(threshold, "/")
	nodecnt, _ := strconv.Atoi(nums[1])
	if nodecnt <= 1 {
		return "", fmt.Errorf("threshold error")
	}

	sigs := strings.Split(groupsigs, "|")
	//SigN = enode://xxxxxxxx@ip:portxxxxxxxxxxxxxxxxxxxxxx
	_, enodes := GetGroup(groupid)
	nodes := strings.Split(enodes, common.Sep2)
	if nodecnt != len(sigs) {
		fmt.Printf("============================GetGroupSigsDataByRaw,nodecnt = %v,common.Sep2 = %v,enodes = %v,groupid = %v,sigs len = %v,groupsigs = %v========================\n", nodecnt, common.Sep2, enodes, groupid, len(sigs), groupsigs)
		return "", fmt.Errorf("group sigs error")
	}

	sstmp := strconv.Itoa(nodecnt)
	for j := 0; j < nodecnt; j++ {
		en := strings.Split(sigs[j], "@")
		for _, node := range nodes {
			node2 := ParseNode(node)
			enId := strings.Split(en[0], "//")
			if len(enId) < 2 {
				fmt.Printf("==========================GetGroupSigsDataByRaw,len enid = %v========================\n", len(enId))
				return "", fmt.Errorf("group sigs error")
			}

			if strings.EqualFold(node2, enId[1]) {
				enodesigs := []rune(sigs[j])
				if len(enodesigs) <= len(node) {
					fmt.Printf("==========================GetGroupSigsDataByRaw,node = %v,enodesigs = %v,node len = %v,enodessigs len = %v,enodes = %v,groupsigs = %v========================\n", node, enodesigs, len(node), len(enodesigs), enodes, groupsigs)
					return "", fmt.Errorf("group sigs error")
				}

				sig := enodesigs[len(node):]
				//sigbit, _ := hex.DecodeString(string(sig[:]))
				sigbit := common.FromHex(string(sig[:]))
				if sigbit == nil {
					fmt.Printf("==========================GetGroupSigsDataByRaw,node = %v,enodesigs = %v,node len = %v,enodessigs len = %v,enodes = %v,groupsigs = %v,sig = %v========================\n", node, enodesigs, len(node), len(enodesigs), enodes, groupsigs, sig)
					return "", fmt.Errorf("group sigs error")
				}

				pub, err := secp256k1.RecoverPubkey(crypto.Keccak256([]byte(node2)), sigbit)
				if err != nil {
					fmt.Printf("==========================GetGroupSigsDataByRaw,node = %v,enodesigs = %v,node len = %v,enodessigs len = %v,enodes = %v,groupsigs = %v,sig = %v,err = %v========================\n", node, enodesigs, len(node), len(enodesigs), enodes, groupsigs, sig, err)
					return "", err
				}

				h := coins.NewCryptocoinHandler("FSN")
				if h != nil {
					pubkey := hex.EncodeToString(pub)
					from, err := h.PublicKeyToAddress(pubkey)
					if err != nil {
						fmt.Printf("==========================GetGroupSigsDataByRaw,node = %v,enodesigs = %v,node len = %v,enodessigs len = %v,enodes = %v,groupsigs = %v,sig = %v,err = %v, pubkey = %v========================\n", node, enodesigs, len(node), len(enodesigs), enodes, groupsigs, sig, err, pubkey)
						return "", err
					}

					//5:eid1:acc1:eid2:acc2:eid3:acc3:eid4:acc4:eid5:acc5
					sstmp += common.Sep
					sstmp += node2
					sstmp += common.Sep
					sstmp += from
				}
			}
		}
	}

	tmps := strings.Split(sstmp, common.Sep)
	if len(tmps) == (2*nodecnt + 1) {
		return sstmp, nil
	}

	return "", fmt.Errorf("group sigs error")
}

//--------------------------------------------------------------------------------

func CheckGroupEnode(gid string) bool {
	if gid == "" {
		return false
	}

	groupenode := make(map[string]bool)
	_, enodes := GetGroup(gid)
	nodes := strings.Split(enodes, common.Sep2)
	for _, node := range nodes {
		node2 := ParseNode(node)
		_, ok := groupenode[strings.ToLower(node2)]
		if ok {
			return false
		}

		groupenode[strings.ToLower(node2)] = true
	}

	return true
}

//------------------------------------------------------------------------------

//msg: key-enode:C1:X1:X2...:Xn
//msg: key-enode1:NoReciv:enode2:C1
func DisMsg(msg string) {

	defer func() {
		if r := recover(); r != nil {
			fmt.Errorf("DisMsg Runtime error: %v\n%v", r, string(debug.Stack()))
			return
		}
	}()

	mm := strings.Split(msg, common.Sep)
	if len(mm) < 3 {
		common.Debug("======================DisMsg, < 3 for CHECKPUBKEYSTATUS================", "msg", msg, "common.Sep", common.Sep, "mm len", len(mm))
		return
	}

	mms := mm[0]
	prexs := strings.Split(mms, "-")
	if len(prexs) < 2 {
		common.Debug("======================DisMsg, < 2 for CHECKPUBKEYSTATUS================", "msg", msg, "mms", mms, "prexs len", len(prexs))
		return
	}

	//msg:  hash-enode:C1:X1:X2
	w, err := FindWorker(prexs[0])
	if err != nil || w == nil {
		mmtmp := mm[0:2]
		ss := strings.ToLower(strings.Join(mmtmp, common.Sep))
		common.Debug("===============DisMsg,pre-save the p2p msg=============", "ss", ss, "msg", msg, "key", prexs[0])
		C1Data.WriteMap(ss, msg)

		return
	}

	msgCode := mm[1]
	switch msgCode {
	case "C1":
		///bug
		if w.msg_c1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_c1, msg) {
			return
		}

		w.msg_c1.PushBack(msg)
		common.Debug("======================DisMsg, after pushback================", "w.msg_c1 len", w.msg_c1.Len(), "w.NodeCnt", w.NodeCnt, "key", prexs[0])
		if w.msg_c1.Len() == w.NodeCnt {
			common.Debug("======================DisMsg, Get All C1==================", "w.msg_c1 len", w.msg_c1.Len(), "w.NodeCnt", w.NodeCnt, "key", prexs[0])
			w.bc1 <- true
		}
	case "BIP32C1":
		///bug
		if w.msg_bip32c1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_bip32c1, msg) {
			return
		}

		w.msg_bip32c1.PushBack(msg)
		if w.msg_bip32c1.Len() == w.NodeCnt {
			w.bbip32c1 <- true
		}
	case "D1":
		///bug
		if w.msg_d1_1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_d1_1, msg) {
			return
		}

		w.msg_d1_1.PushBack(msg)
		if w.msg_d1_1.Len() == w.NodeCnt {
			w.bd1_1 <- true
		}
	case "SHARE1":
		///bug
		if w.msg_share1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_share1, msg) {
			return
		}

		w.msg_share1.PushBack(msg)
		if w.msg_share1.Len() == (w.NodeCnt - 1) {
			w.bshare1 <- true
		}
	//case "ZKFACTPROOF":
	case "NTILDEH1H2":
		///bug
		if w.msg_zkfact.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_zkfact, msg) {
			return
		}

		w.msg_zkfact.PushBack(msg)
		if w.msg_zkfact.Len() == w.NodeCnt {
			w.bzkfact <- true
		}
	case "ZKUPROOF":
		///bug
		if w.msg_zku.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_zku, msg) {
			return
		}

		w.msg_zku.PushBack(msg)
		if w.msg_zku.Len() == w.NodeCnt {
			w.bzku <- true
		}
	case "MTAZK1PROOF":
		///bug
		if w.msg_mtazk1proof.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mtazk1proof, msg) {
			return
		}

		w.msg_mtazk1proof.PushBack(msg)
		if w.msg_mtazk1proof.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MTAZK1PROOF====================", "key", prexs[0])
			w.bmtazk1proof <- true
		}
		//sign
	case "C11":
		///bug
		if w.msg_c11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_c11, msg) {
			return
		}

		common.Debug("=====================Get C11====================", "msg", msg, "key", prexs[0])
		w.msg_c11.PushBack(msg)
		if w.msg_c11.Len() == w.ThresHold {
			common.Debug("=====================Get All C11====================", "key", prexs[0])
			w.bc11 <- true
		}
	case "KC":
		///bug
		if w.msg_kc.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_kc, msg) {
			return
		}

		w.msg_kc.PushBack(msg)
		if w.msg_kc.Len() == w.ThresHold {
			common.Debug("=====================Get All KC====================", "key", prexs[0])
			w.bkc <- true
		}
	case "MKG":
		///bug
		if w.msg_mkg.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mkg, msg) {
			return
		}

		w.msg_mkg.PushBack(msg)
		if w.msg_mkg.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MKG====================", "key", prexs[0])
			w.bmkg <- true
		}
	case "MKW":
		///bug
		if w.msg_mkw.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msg_mkw, msg) {
			return
		}

		w.msg_mkw.PushBack(msg)
		if w.msg_mkw.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MKW====================", "key", prexs[0])
			w.bmkw <- true
		}
	case "DELTA1":
		///bug
		if w.msg_delta1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_delta1, msg) {
			return
		}

		w.msg_delta1.PushBack(msg)
		if w.msg_delta1.Len() == w.ThresHold {
			common.Debug("=====================Get All DELTA1====================", "key", prexs[0])
			w.bdelta1 <- true
		}
	case "D11":
		///bug
		if w.msg_d11_1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_d11_1, msg) {
			return
		}

		w.msg_d11_1.PushBack(msg)
		if w.msg_d11_1.Len() == w.ThresHold {
			common.Debug("=====================Get All D11====================", "key", prexs[0])
			w.bd11_1 <- true
		}
	case "CommitBigVAB":
		///bug
		if w.msg_commitbigvab.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigvab, msg) {
			return
		}

		w.msg_commitbigvab.PushBack(msg)
		if w.msg_commitbigvab.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigVAB====================", "key", prexs[0])
			w.bcommitbigvab <- true
		}
	case "ZKABPROOF":
		///bug
		if w.msg_zkabproof.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_zkabproof, msg) {
			return
		}

		w.msg_zkabproof.PushBack(msg)
		if w.msg_zkabproof.Len() == w.ThresHold {
			common.Debug("=====================Get All ZKABPROOF====================", "key", prexs[0])
			w.bzkabproof <- true
		}
	case "CommitBigUT":
		///bug
		if w.msg_commitbigut.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigut, msg) {
			return
		}

		w.msg_commitbigut.PushBack(msg)
		if w.msg_commitbigut.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigUT====================", "key", prexs[0])
			w.bcommitbigut <- true
		}
	case "CommitBigUTD11":
		///bug
		if w.msg_commitbigutd11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_commitbigutd11, msg) {
			return
		}

		w.msg_commitbigutd11.PushBack(msg)
		if w.msg_commitbigutd11.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigUTD11====================", "key", prexs[0])
			w.bcommitbigutd11 <- true
		}
	case "SS1":
		///bug
		if w.msg_ss1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msg_ss1, msg) {
			return
		}

		w.msg_ss1.PushBack(msg)
		if w.msg_ss1.Len() == w.ThresHold {
			common.Info("=====================Get All SS1====================", "key", prexs[0])
			w.bss1 <- true
		}
	case "PaillierKey":
		///bug
		if w.msg_paillierkey.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_paillierkey, msg) {
			return
		}

		w.msg_paillierkey.PushBack(msg)
		if w.msg_paillierkey.Len() == w.NodeCnt {
			common.Debug("=====================Get All PaillierKey====================", "key", prexs[0])
			w.bpaillierkey <- true
		}

	//////////////////ed
	case "EDC11":
		///bug
		if w.msg_edc11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc11, msg) {
			return
		}

		w.msg_edc11.PushBack(msg)
		if w.msg_edc11.Len() == w.NodeCnt {
			w.bedc11 <- true
		}
	case "EDZK":
		///bug
		if w.msg_edzk.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edzk, msg) {
			return
		}

		w.msg_edzk.PushBack(msg)
		if w.msg_edzk.Len() == w.NodeCnt {
			w.bedzk <- true
		}
	case "EDD11":
		///bug
		if w.msg_edd11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd11, msg) {
			return
		}

		w.msg_edd11.PushBack(msg)
		if w.msg_edd11.Len() == w.NodeCnt {
			w.bedd11 <- true
		}
	case "EDSHARE1":
		///bug
		if w.msg_edshare1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msg_edshare1, msg) {
			return
		}

		w.msg_edshare1.PushBack(msg)
		if w.msg_edshare1.Len() == (w.NodeCnt - 1) {
			w.bedshare1 <- true
		}
	case "EDCFSB":
		///bug
		if w.msg_edcfsb.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edcfsb, msg) {
			return
		}

		w.msg_edcfsb.PushBack(msg)
		if w.msg_edcfsb.Len() == w.NodeCnt {
			w.bedcfsb <- true
		}
	case "EDC21":
		///bug
		if w.msg_edc21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc21, msg) {
			return
		}

		w.msg_edc21.PushBack(msg)
		if w.msg_edc21.Len() == w.NodeCnt {
			w.bedc21 <- true
		}
	case "EDZKR":
		///bug
		if w.msg_edzkr.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edzkr, msg) {
			return
		}

		w.msg_edzkr.PushBack(msg)
		if w.msg_edzkr.Len() == w.NodeCnt {
			w.bedzkr <- true
		}
	case "EDD21":
		///bug
		if w.msg_edd21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd21, msg) {
			return
		}

		w.msg_edd21.PushBack(msg)
		if w.msg_edd21.Len() == w.NodeCnt {
			w.bedd21 <- true
		}
	case "EDC31":
		///bug
		if w.msg_edc31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edc31, msg) {
			return
		}

		w.msg_edc31.PushBack(msg)
		if w.msg_edc31.Len() == w.NodeCnt {
			w.bedc31 <- true
		}
	case "EDD31":
		///bug
		if w.msg_edd31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_edd31, msg) {
			return
		}

		w.msg_edd31.PushBack(msg)
		if w.msg_edd31.Len() == w.NodeCnt {
			w.bedd31 <- true
		}
	case "EDS":
		///bug
		if w.msg_eds.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msg_eds, msg) {
			return
		}

		w.msg_eds.PushBack(msg)
		if w.msg_eds.Len() == w.NodeCnt {
			w.beds <- true
		}
	default:
		fmt.Println("unkown msg code")
	}
}

//--------------------------------------------------------------------------------

func Find(l *list.List, msg string) bool {
	if l == nil || msg == "" {
		return false
	}

	var next *list.Element
	for e := l.Front(); e != nil; e = next {
		next = e.Next()

		if e.Value == nil {
			continue
		}

		s := e.Value.(string)

		if s == "" {
			continue
		}

		if strings.EqualFold(s, msg) {
			return true
		}
	}

	return false
}

//--------------------------------------------------------------------------------

func testEq(a, b []string) bool {
	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}

	return true
}
