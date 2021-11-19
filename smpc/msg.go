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
	smpclib "github.com/anyswap/Anyswap-MPCNode/smpc-lib/smpc"
	"errors"
)

var (
	cht            = 300

	// WaitMsgTimeGG20 wait msg timeout
	WaitMsgTimeGG20 = 100

	waitall         = cht * recalcTimes
	waitallgg20     = WaitMsgTimeGG20 * recalcTimes

	// WaitAgree agree timeout
	WaitAgree       = 120 // second

	// C1Data the data arrive before cmd by p2p
	C1Data          = common.NewSafeMap(10)

	syncpresign = true

	// GetGroup p2p callback
	GetGroup               func(string) (int, string)

	// SendToGroupAllNodes p2p callback
	SendToGroupAllNodes    func(string, string) (string, error)

	// GetSelfEnode p2p callback
	GetSelfEnode           func() string

	// BroadcastInGroupOthers p2p callback
	BroadcastInGroupOthers func(string, string) (string, error)

	// SendToPeer p2p callback
	SendToPeer             func(string, string) error

	// ParseNode p2p callback
	ParseNode              func(string) string

	// GetEosAccount p2p callback
	GetEosAccount          func() (string, string, string)
)

//----------------------------------------------------------------------------------

// p2p callback

// RegP2pGetGroupCallBack set p2p callback func GetGroup
func RegP2pGetGroupCallBack(f func(string) (int, string)) {
	GetGroup = f
}

// RegP2pSendToGroupAllNodesCallBack set p2p callback func SendToGroupAllNodes
func RegP2pSendToGroupAllNodesCallBack(f func(string, string) (string, error)) {
	SendToGroupAllNodes = f
}

// RegP2pGetSelfEnodeCallBack set p2p callback func GetSelfEnode
func RegP2pGetSelfEnodeCallBack(f func() string) {
	GetSelfEnode = f
}

// RegP2pBroadcastInGroupOthersCallBack set p2p callback func BroadcastInGroupOthers
func RegP2pBroadcastInGroupOthersCallBack(f func(string, string) (string, error)) {
	BroadcastInGroupOthers = f
}

// RegP2pSendMsgToPeerCallBack set p2p callback func SendToPeer
func RegP2pSendMsgToPeerCallBack(f func(string, string) error) {
	SendToPeer = f
}

// RegP2pParseNodeCallBack set p2p callback func ParseNode
func RegP2pParseNodeCallBack(f func(string) string) {
	ParseNode = f
}

// RegSmpcGetEosAccountCallBack set p2p callback func GetEosAccount
func RegSmpcGetEosAccountCallBack(f func() (string, string, string)) {
	GetEosAccount = f
}

//------------------------------------------------------------------------------------------

// Call2 use for receiving the group info from p2p
func Call2(msg interface{}) {
	s := msg.(string)
	SetUpMsgList2(s)
}

// SetUpMsgList2 receive group info
func SetUpMsgList2(msg string) {

	mm := strings.Split(msg, "smpcslash")
	if len(mm) >= 2 {
		receiveGroupInfo(msg)
		return
	}
}

var parts = common.NewSafeMap(10)

// receiveGroupInfo smpc node receive specific msg (for example:group info) from p2p by Call2
func receiveGroupInfo(msg interface{}) {
	curEnode = p2psmpc.GetSelfID()

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

//Init smpc node with the msg receive from group by Call2
func Init(groupID string) {
	common.Debug("======================Init==========================", "get group id", groupID, "initTimes", strconv.Itoa(initTimes))

	if initTimes >= 1 {
		return
	}

	initTimes = 1
	InitGroupInfo(groupID)
}

// InitGroupInfo get current node enodeID etc.
func InitGroupInfo(groupID string) {
	curEnode = discover.GetLocalID().String()
	// .......
}

//------------------------------------------------------------------------------

// SendMsgToSmpcGroup brodcast msg to group nodes by group id
func SendMsgToSmpcGroup(msg string, groupid string) {
	common.Debug("=========SendMsgToSmpcGroup=============", "msg", msg, "groupid", groupid)
	_, err := BroadcastInGroupOthers(groupid, msg)
	if err != nil {
		common.Debug("=========SendMsgToSmpcGroup,send msg to smpc group=============", "msg", msg, "groupid", groupid, "err", err)
	}
}

//-------------------------------------------------------------------------------

// EncryptMsg encrypt msg 
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

// DecryptMsg decrypt msg
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

// SendMsgToPeer send msg to special peer
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

// IsReshareCmd Judge whether it is Reshare command data 
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

// IsGenKeyCmd  Judge whether it is the command data that generating pubkey 
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

// IsPreGenSignData  Judge whether it is the command data that generating pre-sign data 
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

// IsEDSignCmd  Judge whether it is the ed sign command data 
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

// IsSignDataCmd Judge whether it is the "SignData" data struct
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

// GetCmdKey get the key of various of command datas
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

// Call receive msg from p2p
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
					fmt.Printf("===============================Call, pre-save p2p msg, worker found, key = %v,fromID = %v,msgtype = %v, c1data key = %v, c1data value = %v========================\n", val, from, msgtype, key, s)
				}
			} else {
				from := msgmap["FromID"]
				msgtype := msgmap["Type"]
				key := strings.ToLower(val + "-" + from + "-" + msgtype)
				C1Data.WriteMap(key, s)
				fmt.Printf("===============================Call, pre-save p2p msg, worker not found, key = %v,fromID = %v,msgtype = %v, c1data key = %v, c1data value = %v========================\n", val, from, msgtype, key, s)
			}

			return
		}

		if msgmap["Type"] == "SyncPreSign" {
			sps := &SyncPreSign{}
			if err = sps.UnmarshalJSON([]byte(msgmap["SyncPreSign"])); err == nil {
				w, err := FindWorker(sps.MsgPrex)
				if err == nil {
					if w.msgsyncpresign.Len() < w.ThresHold {
						if !Find(w.msgsyncpresign, s) {
							w.msgsyncpresign.PushBack(s)
							if w.msgsyncpresign.Len() == w.ThresHold {
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

// SetUpMsgList set RecvMsg data to RPCReqQueue
func SetUpMsgList(msg string, enode string) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	rch := make(chan interface{}, 1)
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

// SetUpMsgList3 set RecvMsg data to RPCReqQueue
func SetUpMsgList3(msg string, enode string, rch chan interface{}) {

	v := RecvMsg{msg: msg, sender: enode}
	//rpc-req
	req := RPCReq{rpcdata: &v, ch: rch}
	RPCReqQueue <- req
}

//-----------------------------------------------------------------

// WorkReq base type of work request
type WorkReq interface {
	Run(workid int, ch chan interface{}) bool
}

// RecvMsg msg data by channel or p2p and its sender
type RecvMsg struct {
	msg    string
	sender string
}

// Run Implement keygen/sign/reshare command and Process accept data
func (recv *RecvMsg) Run(workid int, ch chan interface{}) bool {
	if workid < 0 || workid >= RPCMaxWorker {
		res2 := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get worker id fail", Err: fmt.Errorf("worker was not found")}
		ch <- res2
		return false
	}

	res := recv.msg
	if res == "" {
		res2 := RPCSmpcRes{Ret: "", Tip: "smpc back-end internal error:get data fail in RecvMsg.Run", Err: fmt.Errorf("worker was not found")}
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

	var req CmdReq
	msgmap := make(map[string]string)
	err := json.Unmarshal([]byte(res), &msgmap)
	if err == nil {
		if msgmap["Type"] == "SignData" || msgmap["Type"] == "PreSign" || msgmap["Type"] == "ComSignBrocastData" || msgmap["Type"] == "ComSignData" {
			req = &ReqSmpcSign{}
			return req.DoReq(res, workid, recv.sender, ch)
		}
	}

	return (MsgRun(res, workid, recv.sender, ch) == nil)
}

//---------------------------------------------------------------------------

// Handle send pre-save msg to SmpcMsg channel
// delete pre-save msg from C1Data map
func Handle(key string, c1data string) {
	w, err := FindWorker(key)
	if w == nil || err != nil {
		return
	}

	val, exist := C1Data.ReadMap(c1data)
	if exist {
		common.Debug("==============================Handle,exsit c1data========================","key",key,"c1data key",c1data)
		if w.DNode != nil && w.DNode.Round() != nil {
			common.Info("==============================Handle,put c1data to w.SmpcMsg channel success.========================","key",key,"c1data key",c1data,"c1data value",val.(string))
			w.SmpcMsg <- val.(string)
			go C1Data.DeleteMap(c1data)
		}
	}
}

// HandleKG Process pre-save msg for keygen
func HandleKG(key string, uid *big.Int) {
	c1data := strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "KGRound0Message")
	Handle(key, c1data)
	c1data = strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "KGRound1Message")
	Handle(key, c1data)
}

// HandleSign Process pre-save msg for sign 
func HandleSign(key string, uid *big.Int) {
	c1data := strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "SignRound1Message")
	Handle(key, c1data)
	c1data = strings.ToLower(key + "-" + fmt.Sprintf("%v", uid) + "-" + "SignRound7Message")
	Handle(key, c1data)
}

//HandleC1Data C1Data Key, Three formats are included:
// 1.  key-enodefrom, for reshare only, enodefrom get from enodeID
// 2.  key-uid-msgtype, for example: key-uid-"KGRound0Message"
// 3.  key-accout,for accept reply
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

		_, enodes := GetGroup(ac.GroupID)
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

	_, enodes := GetGroup(ac.GroupID)
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

// GetRawType get special tx data type and key from command data or accept data
func GetRawType(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}

	key, from, _, txdata, err := CheckRaw(raw)
	if err != nil {
		common.Error("=======================GetRawType,check accept raw data error===================","raw",raw,"err", err)
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

// DisAcceptMsg  Collect accept data of nodes in the group, after collection, continue the MPC process 
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

	var req CmdReq
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

// MsgRun  1.Parse the command data and implement the process 2.analyze the accept data   
func MsgRun(raw string, workid int, sender string, ch chan interface{}) error {
	if raw == "" || workid < 0 || sender == "" {
		res := RPCSmpcRes{Ret: "", Tip: "msg run fail.", Err: fmt.Errorf("msg run fail")}
		ch <- res
		return fmt.Errorf("msg run fail")
	}

	var req CmdReq
	rawtype, _ := GetRawType(raw)
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

	if !req.DoReq(raw, workid, sender, ch) {
		return fmt.Errorf("msg run fail")
	}

	return nil
}

//------------------------------------------------------------------------------------

// GetGroupSigsDataByRaw get account sigs data from special tx data(raw data)
// account sigs data:  Signatures generated by respective accounts,the signature object is the pubkey of eNode,that is,enodeID.
// account sigs data: sig1 | sig2 | ... | sigN   (N is the count of nodes in group.)
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

	var req2 CmdReq
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
			enID := strings.Split(en[0], "//")
			if len(enID) < 2 {
				fmt.Printf("==========================GetGroupSigsDataByRaw,len enid = %v========================\n", len(enID))
				return "", fmt.Errorf("group sigs error")
			}

			if strings.EqualFold(node2, enID[1]) {
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

// CheckGroupEnode Judge whether there is same enodeID in group 
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

//DisMsg msg: key-enode:C1:X1:X2...:Xn
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
		if w.msgc1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgc1, msg) {
			return
		}

		w.msgc1.PushBack(msg)
		common.Debug("======================DisMsg, after pushback================", "w.msgc1 len", w.msgc1.Len(), "w.NodeCnt", w.NodeCnt, "key", prexs[0])
		if w.msgc1.Len() == w.NodeCnt {
			common.Debug("======================DisMsg, Get All C1==================", "w.msgc1 len", w.msgc1.Len(), "w.NodeCnt", w.NodeCnt, "key", prexs[0])
			w.bc1 <- true
		}
	case "BIP32C1":
		///bug
		if w.msgbip32c1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgbip32c1, msg) {
			return
		}

		w.msgbip32c1.PushBack(msg)
		if w.msgbip32c1.Len() == w.NodeCnt {
			w.bbip32c1 <- true
		}
	case "D1":
		///bug
		if w.msgd1d1.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgd1d1, msg) {
			return
		}

		w.msgd1d1.PushBack(msg)
		if w.msgd1d1.Len() == w.NodeCnt {
			w.bd1d1 <- true
		}
	case "SHARE1":
		///bug
		if w.msgshare1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msgshare1, msg) {
			return
		}

		w.msgshare1.PushBack(msg)
		if w.msgshare1.Len() == (w.NodeCnt - 1) {
			w.bshare1 <- true
		}
	//case "ZKFACTPROOF":
	case "NTILDEH1H2":
		///bug
		if w.msgzkfact.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgzkfact, msg) {
			return
		}

		w.msgzkfact.PushBack(msg)
		if w.msgzkfact.Len() == w.NodeCnt {
			w.bzkfact <- true
		}
	case "ZKUPROOF":
		///bug
		if w.msgzku.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgzku, msg) {
			return
		}

		w.msgzku.PushBack(msg)
		if w.msgzku.Len() == w.NodeCnt {
			w.bzku <- true
		}
	case "MTAZK1PROOF":
		///bug
		if w.msgmtazk1proof.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msgmtazk1proof, msg) {
			return
		}

		w.msgmtazk1proof.PushBack(msg)
		if w.msgmtazk1proof.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MTAZK1PROOF====================", "key", prexs[0])
			w.bmtazk1proof <- true
		}
		//sign
	case "C11":
		///bug
		if w.msgc11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgc11, msg) {
			return
		}

		common.Debug("=====================Get C11====================", "msg", msg, "key", prexs[0])
		w.msgc11.PushBack(msg)
		if w.msgc11.Len() == w.ThresHold {
			common.Debug("=====================Get All C11====================", "key", prexs[0])
			w.bc11 <- true
		}
	case "KC":
		///bug
		if w.msgkc.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgkc, msg) {
			return
		}

		w.msgkc.PushBack(msg)
		if w.msgkc.Len() == w.ThresHold {
			common.Debug("=====================Get All KC====================", "key", prexs[0])
			w.bkc <- true
		}
	case "MKG":
		///bug
		if w.msgmkg.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msgmkg, msg) {
			return
		}

		w.msgmkg.PushBack(msg)
		if w.msgmkg.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MKG====================", "key", prexs[0])
			w.bmkg <- true
		}
	case "MKW":
		///bug
		if w.msgmkw.Len() >= (w.ThresHold - 1) {
			return
		}
		///
		if Find(w.msgmkw, msg) {
			return
		}

		w.msgmkw.PushBack(msg)
		if w.msgmkw.Len() == (w.ThresHold - 1) {
			common.Debug("=====================Get All MKW====================", "key", prexs[0])
			w.bmkw <- true
		}
	case "DELTA1":
		///bug
		if w.msgdelta1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgdelta1, msg) {
			return
		}

		w.msgdelta1.PushBack(msg)
		if w.msgdelta1.Len() == w.ThresHold {
			common.Debug("=====================Get All DELTA1====================", "key", prexs[0])
			w.bdelta1 <- true
		}
	case "D11":
		///bug
		if w.msgd11d1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgd11d1, msg) {
			return
		}

		w.msgd11d1.PushBack(msg)
		if w.msgd11d1.Len() == w.ThresHold {
			common.Debug("=====================Get All D11====================", "key", prexs[0])
			w.bd11d1 <- true
		}
	case "CommitBigVAB":
		///bug
		if w.msgcommitbigvab.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgcommitbigvab, msg) {
			return
		}

		w.msgcommitbigvab.PushBack(msg)
		if w.msgcommitbigvab.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigVAB====================", "key", prexs[0])
			w.bcommitbigvab <- true
		}
	case "ZKABPROOF":
		///bug
		if w.msgzkabproof.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgzkabproof, msg) {
			return
		}

		w.msgzkabproof.PushBack(msg)
		if w.msgzkabproof.Len() == w.ThresHold {
			common.Debug("=====================Get All ZKABPROOF====================", "key", prexs[0])
			w.bzkabproof <- true
		}
	case "CommitBigUT":
		///bug
		if w.msgcommitbigut.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgcommitbigut, msg) {
			return
		}

		w.msgcommitbigut.PushBack(msg)
		if w.msgcommitbigut.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigUT====================", "key", prexs[0])
			w.bcommitbigut <- true
		}
	case "CommitBigUTD11":
		///bug
		if w.msgcommitbigutd11.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgcommitbigutd11, msg) {
			return
		}

		w.msgcommitbigutd11.PushBack(msg)
		if w.msgcommitbigutd11.Len() == w.ThresHold {
			common.Debug("=====================Get All CommitBigUTD11====================", "key", prexs[0])
			w.bcommitbigutd11 <- true
		}
	case "SS1":
		///bug
		if w.msgss1.Len() >= w.ThresHold {
			return
		}
		///
		if Find(w.msgss1, msg) {
			return
		}

		w.msgss1.PushBack(msg)
		if w.msgss1.Len() == w.ThresHold {
			common.Info("=====================Get All SS1====================", "key", prexs[0])
			w.bss1 <- true
		}
	case "PaillierKey":
		///bug
		if w.msgpaillierkey.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgpaillierkey, msg) {
			return
		}

		w.msgpaillierkey.PushBack(msg)
		if w.msgpaillierkey.Len() == w.NodeCnt {
			common.Debug("=====================Get All PaillierKey====================", "key", prexs[0])
			w.bpaillierkey <- true
		}

	//////////////////ed
	case "EDC11":
		///bug
		if w.msgedc11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedc11, msg) {
			return
		}

		w.msgedc11.PushBack(msg)
		if w.msgedc11.Len() == w.NodeCnt {
			w.bedc11 <- true
		}
	case "EDZK":
		///bug
		if w.msgedzk.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedzk, msg) {
			return
		}

		w.msgedzk.PushBack(msg)
		if w.msgedzk.Len() == w.NodeCnt {
			w.bedzk <- true
		}
	case "EDD11":
		///bug
		if w.msgedd11.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedd11, msg) {
			return
		}

		w.msgedd11.PushBack(msg)
		if w.msgedd11.Len() == w.NodeCnt {
			w.bedd11 <- true
		}
	case "EDSHARE1":
		///bug
		if w.msgedshare1.Len() >= (w.NodeCnt - 1) {
			return
		}
		///
		if Find(w.msgedshare1, msg) {
			return
		}

		w.msgedshare1.PushBack(msg)
		if w.msgedshare1.Len() == (w.NodeCnt - 1) {
			w.bedshare1 <- true
		}
	case "EDCFSB":
		///bug
		if w.msgedcfsb.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedcfsb, msg) {
			return
		}

		w.msgedcfsb.PushBack(msg)
		if w.msgedcfsb.Len() == w.NodeCnt {
			w.bedcfsb <- true
		}
	case "EDC21":
		///bug
		if w.msgedc21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedc21, msg) {
			return
		}

		w.msgedc21.PushBack(msg)
		if w.msgedc21.Len() == w.NodeCnt {
			w.bedc21 <- true
		}
	case "EDZKR":
		///bug
		if w.msgedzkr.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedzkr, msg) {
			return
		}

		w.msgedzkr.PushBack(msg)
		if w.msgedzkr.Len() == w.NodeCnt {
			w.bedzkr <- true
		}
	case "EDD21":
		///bug
		if w.msgedd21.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedd21, msg) {
			return
		}

		w.msgedd21.PushBack(msg)
		if w.msgedd21.Len() == w.NodeCnt {
			w.bedd21 <- true
		}
	case "EDC31":
		///bug
		if w.msgedc31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedc31, msg) {
			return
		}

		w.msgedc31.PushBack(msg)
		if w.msgedc31.Len() == w.NodeCnt {
			w.bedc31 <- true
		}
	case "EDD31":
		///bug
		if w.msgedd31.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgedd31, msg) {
			return
		}

		w.msgedd31.PushBack(msg)
		if w.msgedd31.Len() == w.NodeCnt {
			w.bedd31 <- true
		}
	case "EDS":
		///bug
		if w.msgeds.Len() >= w.NodeCnt {
			return
		}
		///
		if Find(w.msgeds, msg) {
			return
		}

		w.msgeds.PushBack(msg)
		if w.msgeds.Len() == w.NodeCnt {
			w.beds <- true
		}
	default:
		fmt.Println("unkown msg code")
	}
}

//--------------------------------------------------------------------------------

// Find find msg in list
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

// testEq  Judge whether a and B are equal 
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

//----------------------------------------------------------------

// for p2p msg sig

func getNodePrivate(keyfile string) (*ecdsa.PrivateKey,error) {
    if keyfile == "" {
	return nil,errors.New("key file is invalid")
    }

    nodeKey, err := crypto.LoadECDSA(keyfile)
    if err != nil {
	fmt.Printf("====================getNodePrivate,err = %v=======================\n",err)
	return nil,err
    }
    
    //enodeID := discover.PubkeyID(&nodeKey.PublicKey).String()
    //fmt.Printf("======================getNodePrivate,enodeID = %v,cur_enode = %v===================\n",enodeID,curEnode)

    return nodeKey,nil
}

func getUnSignMsgByte(msg smpclib.Message) ([]byte,error) {
    if msg == nil {
	return nil,errors.New("msg error")
    }
    
    s, err := json.Marshal(msg)
    if err != nil {
	fmt.Printf("====================getUnSignMsgByte,err = %v=======================\n",err)
	    return nil,err
    }

    hash := crypto.Keccak256(s)
    return hash,nil
}

func sigP2pMsg(msg smpclib.Message,enodeID string) ([]byte,error) {
    if msg == nil || enodeID == "" {
	return nil,errors.New("param error")
    }

    priv,err := getNodePrivate(KeyFile)
    if err != nil {
	return nil,errors.New("get private fail")
    }

    hash,err := getUnSignMsgByte(msg)
    if err != nil {
	return nil,err
    }

    if len(hash) != 32 {
	return nil,errors.New("hash len != 32")
    }

    sig,err := crypto.Sign(hash,priv)
    if err != nil {
	fmt.Printf("====================sigP2pMsg,err = %v=======================\n",err)
	return nil,err
    }

    if !checkP2pSig(sig,msg,enodeID) {
	return nil,errors.New("check sig error")
    }

    return sig,nil
}

func checkP2pSig(sig []byte,msg smpclib.Message,enodeID string) bool {
    if sig == nil || msg == nil || enodeID == "" {
	return false
    }
    
    hash,err := getUnSignMsgByte(msg)
    if err != nil {
	return false 
    }

    public,err := crypto.SigToPub(hash,sig)
    if err != nil {
	fmt.Printf("====================checkP2pSig,err = %v=======================\n",err)
	return false
    }

    pub := secp256k1.S256().Marshal(public.X,public.Y) 
    pub2 := hex.EncodeToString(pub) // 04.....
    s := []rune(pub2) // 04.....
    ss := string(s[2:])
    // pub2: 04730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf56bdbc2d86cb5f89c8e90d0
    // ss: 730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf56bdbc2d86cb5f89c8e90d0
    // enodeID: 730c8fc7142d15669e8329138953d9484fd4cce0c690e35e105a9714deb741f10b52be1c5d49eeeb6f00aab8f3d2dec4e3352d0bf56bdbc2d86cb5f89c8e90d0
    if ss == enodeID {
	return true
    }

    //fmt.Printf("====================checkP2pSig, check fail,recover pubkey = %v,enodeID = %v=======================\n",ss,enodeID)
    return false
}


