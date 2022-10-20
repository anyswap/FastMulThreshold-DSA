/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  huangweijun@anyswap.exchange
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

package discover

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anyswap/FastMulThreshold-DSA/crypto"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/anyswap/FastMulThreshold-DSA/ethdb"
)

var (
	setgroupNumber = 0
	setgroup       = 0
	Smpcdelimiter  = "smpcmsg"
	Smpc_groupList *Group
	Xp_groupList   *Group
	tmpsmpcmsg     = &getsmpcmessage{Number: [3]byte{0, 0, 0}, Msg: ""}
	setlocaliptrue = false
	LocalIP        string
	RemoteIP       net.IP
	RemotePort     = uint16(0)
	RemoteUpdate   = false
	SelfEnode      = ""
	SelfIPPort     = ""
	changed        = 0
	Xp_changed     = 0
	connectOk bool = false

	SDK_groupList map[NodeID]*Group = make(map[NodeID]*Group)
	GroupSDK      sync.Mutex
	groupSDKList  []*Node

	groupDbLock      sync.Mutex
	sequenceLock     sync.Mutex
	sequenceDone     sync.Map
	sequenceDoneRecv sync.Map
	Sequence         = uint64(1)
	SelfID           = ""
	SelfNodeID       NodeID
	p2pSuffix                                 = "p2p"
	p2pDir                                    = ""
	nodeOnline       map[NodeID]*OnLineStatus = make(map[NodeID]*OnLineStatus)

	updateGroupsNode  bool           = false // update node dynamically
	addNodes          map[NodeID]int = make(map[NodeID]int)
	addNodesLock      sync.Mutex
	loadedSeeds       map[NodeID]int = make(map[NodeID]int)
	loadedDone        bool           = false
	checkNetworkChan  chan int       = make(chan int, 1)
)
var (
	Smpc_groupMemNum = 0
	Xp_groupMemNum   = 0
	SDK_groupNum     = 0
)

type OnLineStatus struct {
	Status bool
	Lock   sync.Mutex
}

const (
	SendWaitTime = 1 * time.Minute
	checkNetworkConnectTime = 10 * time.Second
	pingCount    = 10

	Smpcprotocol_type = iota + 1
	Xprotocol_type
	Sdkprotocol_type

	Smpc_findGroupPacket = iota + 10 + neighborsPacket //14
	Xp_findGroupPacket
	Sdk_findGroupPacket
	Smpc_groupPacket
	Sdk_groupPacket
	Xp_groupPacket
	Smpc_groupInfoPacket
	Sdk_groupStatusPacket
	PeerMsgPacket
	getSmpcPacket
	getSdkPacket
	Xp_getCCPacket
	getXpPacket
	gotSmpcPacket
	gotSdkPacket
	gotXpPacket
	msgBroadcastPacket // use udp.send when peer.send failed
	Smpc_MsgSplitPacket
	Smpc_MsgSplitAckPacket
	Smpc_BroadcastMsgPacket

	Ack_Packet
)

///get mpc node info
var (
    giddb    *ethdb.LDBDatabase
)

// GetSmpcGidDb open database for group db
func GetSmpcGidDb(eid string) error {
	if eid == "" {
		return errors.New("enode id error")
	}

	if giddb != nil {
		return nil
	}

	dir := common.DefaultDataDir()
	if setgroup != 0 {
		dir = filepath.Join(dir, p2pSuffix, "bootnode-"+eid)
	} else {
		dir = filepath.Join(dir, p2pSuffix, eid)
	}
	common.Debug("==== GetSmpcGidDb ====", "dir", dir)
	db, err := ethdb.NewLDBDatabase(dir, 76, 512)
	if err != nil {
		common.Error("======================GetSmpcGidDb,open giddb fail======================", "err", err, "dir", dir)
		return err
	}

	giddb = db
	return nil
}

///

type (
	findgroup struct {
		ID         NodeID
		P2pType    byte
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	Ack struct {
		Sequence   uint64
		Expiration uint64
	}

	Group struct {
		sync.Mutex
		ID NodeID
		//Gname      string
		Mode string // 2/3
		msg  string
		//status        string
		count   int
		P2pType byte
		Nodes   []RpcNode
		Type    string // group type: 1+2, 1+1+1
		//userID      []string
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	GroupSDKList struct {
		Nodes []*Node
	}

	message struct {
		//sync.Mutex
		Msg        string
		Expiration uint64
	}

	messageBroadcast struct {
		//sync.Mutex
		Msg        string
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	getsmpcmessage struct {
		//sync.Mutex
		Number     [3]byte
		P2pType    byte
		Target     NodeID // doesn't need to be an actual public key
		Msg        string
		Sequence   uint64
		Expiration uint64
	}

	smpcmessage struct {
		//sync.Mutex
		Number     [3]byte
		Target     NodeID // doesn't need to be an actual public key
		P2pType    byte
		Msg        string
		Sequence   uint64
		Expiration uint64
	}
)

func InitP2pDir() {
	p2pDir = common.DefaultDataDir()
}

func (req *findgroup) name() string { return "FINDGROUP/v4" }

func getGroupList(gid NodeID, p2pType int) *Group { //nooo
	switch p2pType {
	case Sdkprotocol_type:
		return getGroupSDK(gid)
	case Smpcprotocol_type:
		return Smpc_groupList
	case Xprotocol_type:
		return Xp_groupList
	}
	return nil
}

func getGroupSDK(gid NodeID) *Group { //nooo
	for id, g := range SDK_groupList {
		//if g.status != "SUCCESS" {
		//	continue
		//}
		index := id.String()
		gf := gid.String()
		common.Debug("==== getGroupSDK() ====", "id", id, "gid", gid)
		if index[:8] == gf[:8] {
			return g
		}
	}
	return nil
}

func getGroupChange(p2pType int) *int {
	switch p2pType {
	case Smpcprotocol_type:
		return &changed
	case Xprotocol_type:
		return &Xp_changed
	}
	return nil
}

func getCCPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return getSdkPacket
	case Smpcprotocol_type:
		return getSmpcPacket
	case Xprotocol_type:
		return Xp_getCCPacket
	}
	return 0
}
func getGroupPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return Sdk_groupPacket
	case Smpcprotocol_type:
		return Smpc_groupPacket
	case Xprotocol_type:
		return Xp_groupPacket
	}
	return 0
}

func getFindGroupPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return Sdk_findGroupPacket
	case Smpcprotocol_type:
		return Smpc_findGroupPacket
	case Xprotocol_type:
		return Xp_findGroupPacket
	}
	return 0
}

func getGroupMemNum(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return SDK_groupNum
	case Smpcprotocol_type:
		return Smpc_groupMemNum
	case Xprotocol_type:
		return Xp_groupMemNum
	}
	return 0
}

func getGotPacket(p2pType int) int {
	switch p2pType {
	case Sdkprotocol_type:
		return gotSdkPacket
	case Smpcprotocol_type:
		return gotSmpcPacket
	case Xprotocol_type:
		return gotXpPacket
	}
	return 0
}

// findgroup sends a findgroup request to the bootnode and waits until
// the node has sent up to a group.
func (t *udp) findgroup(gid, toid NodeID, toaddr *net.UDPAddr, target NodeID, p2pType int) ([]*Node, error) { //nooo
	//log.Debug("====  (t *udp) findgroup()  ====", "gid", gid, "p2pType", p2pType)
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	groupPacket := getGroupPacket(p2pType)
	findgroupPacket := getFindGroupPacket(p2pType)
	groupMemNum := getGroupMemNum(p2pType)
	errc := t.pending(toid, byte(groupPacket), func(r interface{}) bool {
		reply := r.(*Group)
		//log.Debug("findgroup", "reply", reply, "r", r)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rpcNode(rn))
			if err != nil {
				common.Debug("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		//log.Debug("findgroup", "return nodes", nodes)
		return nreceived >= groupMemNum
	})
	//log.Debug("findgroup, t.send", "toaddr", toaddr, "gid", gid, "p2pType", p2pType, "send packet", byte(findgroupPacket), "p2ptype", byte(p2pType))
	_, errs := t.send(toaddr, byte(findgroupPacket), &findgroup{
		ID:         gid,
		P2pType:    byte(p2pType),
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if errs != nil {
		common.Debug("==== (t *udp) sendMsgToPeer ====", "errs", errs)
		return nil,errs
	}
	err := <-errc
	return nodes, err
}

func (req *findgroup) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//log.Debug("====  (req *findgroup) handle()  ====", "from", from, "fromID", fromID)
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.db.hasBond(fromID) {
		// No bond exists, we don't process the packet. This prevents
		// an attack vector where the discovery protocol could be used
		// to amplify traffic in a DDOS attack. A malicious actor
		// would send a findnode request with the IP address and UDP
		// port of the target as the source address. The recipient of
		// the findnode packet would then send a neighbors packet
		// (which is a much bigger packet than findnode) to the victim.
		return errUnknownNode
	}
	groupPacket := getGroupPacket(int(req.P2pType))
	if p := getGroupInfo(req.ID, int(req.P2pType)); p != nil {
		//log.Debug("====  (req *findgroup) handle()  ====", "getGroupInfo", p)
		_, errs := t.send(from, byte(groupPacket), p)
		if errs != nil {
			common.Debug("==== (t *udp) sendMsgToPeer ====", "errs", errs)
			return errs
		}
	}
	return nil
}

func (req *getsmpcmessage) name() string { return "GETSMPCMSG/v4" }
func (req *smpcmessage) name() string    { return "SMPCMSG/v4" }

var number [3]byte

func SendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
	return Table4group.net.sendToGroupCC(toid, toaddr, msg, p2pType)
}

func (t *udp) udpSendMsg(toid NodeID, toaddr *net.UDPAddr, msg string, number [3]byte, p2pType int, ret bool) (string, error) {
	sequenceLock.Lock()
	s := Sequence
	Sequence += 1
	sequenceLock.Unlock()

	getPacket := 0
	if ret == true {
		getPacket = getGotPacket(p2pType)
	} else {
		getPacket = getCCPacket(p2pType)
	}
	reqGet := &getsmpcmessage{
		Target:   toid,
		Number:   number,
		P2pType:  byte(p2pType),
		Msg:      msg,
		Sequence: s,
	}
	req := &smpcmessage{
		Target:     toid,
		Number:     number,
		P2pType:    byte(p2pType),
		Msg:        msg,
		Sequence:   s,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	timeout := false
	go func() {
		msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
		go func() {
			SendWaitTimeOut := time.NewTicker(SendWaitTime)
			select {
			case <-SendWaitTimeOut.C:
				timeout = true
			}
		}()
		for {
			if timeout == true {
				common.Info("====  (t *udp) udpSendMsg()  ====", "send toaddr", toaddr, "err", "timeout")
				break
			}
			errc := t.pending(toid, byte(Ack_Packet), func(r interface{}) bool {
				common.Info("recv ack ====  (t *udp) udpSendMsg()  ====", "from", toaddr, "sequence", s, "ackSequence", r.(*Ack).Sequence)
				return true
			})
			var errs error
			if ret == true {
				req.Expiration = uint64(time.Now().Add(expiration).Unix())
				_, errs = t.send(toaddr, byte(getPacket), req)
				common.Debug("==== (t *udp) udpSendMsg()  ==== p2pBroatcast", "send toaddr", toaddr, "sequence", s, "errs", errs, "msgHash", msgHash)
			} else {
				reqGet.Expiration = uint64(time.Now().Add(expiration).Unix())
				_, errs = t.send(toaddr, byte(getPacket), reqGet)
				common.Debug("==== (t *udp) udpSendMsg()  ==== p2pBroatcast", "send toaddr", toaddr, "sequence", s, "msgHash", msgHash)
			}
			time.Sleep(time.Duration(5) * time.Second)
			err := <-errc
			if errs != nil || err != nil {
				continue
			}
			common.Info("====  (t *udp) udpSendMsg()  ====", "send toaddr", toaddr, "SUCCESS", "")
			break

		}
	}()
	if timeout == true {
		return "", errors.New("timeout")
	}
	return "", nil
}

func (req *Ack) name() string { return "ACK/v4" }
func (req *Ack) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, byte(Ack_Packet), req) {
		common.Debug("====  (t *udp) udpSendMsg()  ====", "handleReply, toaddr", from)
	}
	return nil
}

// sendgroup sends to group smpc and waits until
// the node has reply.
func (t *udp) sendToGroupCC(toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) (string, error) {
	var err error = nil
	retmsg := ""
	number[0]++
	if len(msg) <= 800 {
		number[1] = 1
		number[2] = 1
		_, err = t.udpSendMsg(toid, toaddr, msg, number, p2pType, false)
		if err != nil {
			common.Debug("==== (t *udp) sendMsgToPeer ====", "err", common.CurrentTime(), err)
			return "",err
		}
	} else if len(msg) > 800 && len(msg) < 1600 {
		number[1] = 1
		number[2] = 2
		_, err = t.udpSendMsg(toid, toaddr, msg[0:800], number, p2pType, false)
		if err != nil {
			common.Debug("=== (t *udp) sendMsgToPeer ====, err: %v\n", err)
			return "",err
		} else {
			number[1] = 2
			number[2] = 2
			_, err = t.udpSendMsg(toid, toaddr, msg[800:], number, p2pType, false)
			if err != nil {
				common.Debug("==== (t *udp) sendMsgToPeer ====", "eer", err)
				return "",err
			}
		}
	} else {
		return "", errors.New("send fail, msg size > 1600")
	}
	return retmsg, err
}

func (req *getsmpcmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//if expired(req.Expiration) {
	//	return errExpired
	//}
	common.Debug("send ack ==== (req *getsmpcmessage) handle() ====", "to", from, "squencencen", req.Sequence)
	_,err := t.send(from, byte(Ack_Packet), &Ack{
		Sequence:   req.Sequence,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if err != nil {
	    return err
	}

	ss := fmt.Sprintf("get-%v-%v", fromID, req.Sequence)
	common.Debug("==== (req *getsmpcmessage) handle() ====", "from", from, "sequence", req.Sequence)
	sequenceLock.Lock()
	if _, ok := sequenceDoneRecv.Load(ss); ok {
		common.Debug("==== (req *getsmpcmessage) handle() ====", "from", from, "req.Sequence", from, req.Sequence)
		sequenceLock.Unlock()
		return nil
	}
	sequenceDoneRecv.Store(ss, 1)
	sequenceLock.Unlock()

	msgp := req.Msg
	num := req.Number
	if num[2] > 1 {
		if tmpsmpcmsg.Number[0] == 0 || num[0] != tmpsmpcmsg.Number[0] {
			tmpsmpcmsg = &(*req)
			return nil
		}
		if tmpsmpcmsg.Number[1] == num[1] {
			return nil
		}
		var buffer bytes.Buffer
		if tmpsmpcmsg.Number[1] < num[1] {
			buffer.WriteString(tmpsmpcmsg.Msg)
			buffer.WriteString(req.Msg)
		} else {
			buffer.WriteString(req.Msg)
			buffer.WriteString(tmpsmpcmsg.Msg)
		}
		msgp = buffer.String()
	}

	go func() {
		msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(msgp))).Hex()
		common.Debug("==== (req *getsmpcmessage) handle() ==== p2pBroatcast", "recv from target", fromID, "from", from, "msgHash", msgHash)
		msgc := callMsgEvent(msgp, int(req.P2pType), fromID.String())
		msg := <-msgc
		_, err := t.udpSendMsg(fromID, from, msg, number, int(req.P2pType), true)
		if err != nil {
			common.Debug("smpc handle", "send to target", fromID, "from", from, "msg(len", len(msg), "err", err)
			return
		}
	}()
	return nil
}

func RemoveSequenceDoneRecv(id string) {
	sequenceLock.Lock()
	defer sequenceLock.Unlock()
	sequenceDoneRecv.Range(func(k, v interface{}) bool {
		kid := k.(string)
		kslice := strings.Split(kid, "-")
		if kslice[0] == id {
			sequenceDoneRecv.Delete(k)
		}
		return true
	})
}

func (req *smpcmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	//if expired(req.Expiration) {
	//        return errExpired
	//}
	msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(req.Msg))).Hex()
	common.Debug("==== (req *smpcmessage) handle() ==== p2pBroatcast", "recv from target", fromID, "from", from, "msgHash", msgHash)
	common.Debug("send ack ==== (req *smpcmessage) handle() ====", "to", from, "msg", req.Msg)
	_,err := t.send(from, byte(Ack_Packet), &Ack{
		Sequence:   req.Sequence,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if err != nil {
	    return err
	}

	ss := fmt.Sprintf("%v-%v", fromID, req.Sequence)
	common.Debug("==== (req *smpcmessage) handle() ====", "recvMsg", ss)
	sequenceLock.Lock()
	if _, ok := sequenceDoneRecv.Load(ss); ok {
		common.Debug("==== (req *smpcmessage) handle() ====", "from", from, "exist req.Sequence", req.Sequence)
		sequenceLock.Unlock()
		return nil
	}
	sequenceDoneRecv.Store(ss, 1)
	sequenceLock.Unlock()
	common.Debug("==== (req *smpcmessage) handle() ==== p2pBroatcast callback callCCReturn", "recv from target", fromID, "from", from, "msgHash", msgHash)
	go callCCReturn(req.Msg, int(req.P2pType), fromID.String())
	return nil
}

func getGroupInfo(gid NodeID, p2pType int) *Group { //nooo
	groupList := getGroupList(gid, p2pType)
	common.Debug("getGroupInfo", "gid", gid, "groupList", groupList, "setgroup", setgroup, "p2pType", p2pType)
	if /*setgroup == 1 &&*/ groupList != nil /*&& groupList.count == groupMemNum*/ {
		groupList.Lock()
		defer groupList.Unlock()
		p := groupList
		p.P2pType = byte(p2pType)
		p.Expiration = uint64(time.Now().Add(expiration).Unix())
		return p
	}
	return nil
}

func InitGroup() {
	//	GroupSDK.Lock()
	//	defer GroupSDK.Unlock()
	setgroup = 1
	//	setgroupNumber = groupsNum
	//SDK_groupNum = nodesNum
	//	Smpc_groupMemNum = nodesNum
	//	Xp_groupMemNum   = nodesNum
	//	Smpc_groupList = &Group{msg: "smpc", count: 0, Expiration: ^uint64(0)}
	//	Xp_groupList = &Group{msg: "smpc", count: 0, Expiration: ^uint64(0)}
	//	RecoverGroupSDKList()// List
	//	RecoverGroupAll(SDK_groupList)// Group
	//	for i, g := range SDK_groupList {
	//		fmt.Printf("InitGroup, SDK_groupList gid: %v, g: %v\n", i, g)
	//		sendGroupInfo(g, int(g.P2pType))
	//	}
}

func SendToGroup(gid NodeID, msg string, allNodes bool, p2pType int, gg []*Node) (string, error) {
	common.Info("==== SendToGroup() ====", "gid", gid, "allNodes", allNodes, "p2pType", p2pType)
	//gg := getGroupSDK(gid)
	groupMemNum := 0
	g := make([]*Node, 0, bucketSize)
	if gg != nil {
		//for _, rn := range gg.Nodes {
		//	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
		//	err := n.validateComplete()
		//	if err != nil {
		//		fmt.Printf("Invalid neighbor node received, ip: %v, err: %v\n", rn.IP, err)
		//		continue
		//	}
		//	g = append(g, n)
		//}
		g = gg
		groupMemNum = len(gg)
	} else {
		common.Debug("from local, from bootnodei", "Not found gid", gid)
		bn := Table4group.nursery[0]
		if bn == nil {
			return "", errors.New("SendToGroup, bootnode is nil")
		}
		ipa := &net.UDPAddr{IP: bn.IP, Port: int(bn.UDP)}
		g = GetGroup(gid, bn.ID, ipa, bn.ID, p2pType)
		groupMemNum := getGroupMemNum(p2pType)
		if g == nil || len(g) != groupMemNum {
			common.Debug("SendToGroup()", "group is nil or wrong len", "")
			return "", errors.New("SendToGroup(), group is nil or wrong len")
		}
	}

	sent := make([]int, groupMemNum+1)
	retMsg := ""
	count := 0
	for i := 1; i <= groupMemNum; {
		rand.Seed(time.Now().UnixNano())
		r := rand.Intn(groupMemNum) % groupMemNum
		j := 1
		for ; j < i; j++ {
			if r+1 == sent[j] {
				break
			}
		}
		if j < i {
			continue
		}
		sent[i] = r + 1
		i += 1
		n := g[r]
		if n.ID.String() == GetLocalID().String() {
			go SendToMyselfAndReturn(n.ID.String(), msg, p2pType)
		} else {
			ipa := &net.UDPAddr{IP: n.IP, Port: int(n.UDP)}
			_, err := Table4group.net.sendToGroupCC(n.ID, ipa, msg, p2pType)
			if err != nil {
				common.Debug("SendToGroup", "sendToGroupCC(n.ID", n.ID, "ipa", ipa, ") error", err)
				retMsg = fmt.Sprintf("%v; SendToGroup, sendToGroupCC(n.ID: %v, ipa: %v) error", retMsg, n.ID, ipa)
				return "", errors.New(retMsg)
			} else {
				retMsg = fmt.Sprintf("%v; sendToGroupCC(n.ID: %v, ipa: %v) Success", retMsg, n.ID, ipa)
			}
		}
		count += 1
		if allNodes == false {
			break
		}
	}
	if (allNodes == false && count == 1) || (allNodes == true && count == groupMemNum) {
		return retMsg, nil
	}
	fmt.Println(retMsg)
	return "", errors.New(retMsg)
}

func PingNode(id NodeID, ip net.IP, port int) error {
	n := NewNode(id, ip, uint16(port), uint16(port))
	err := n.validateComplete()
	if err != nil {
		return err
	}
	ipa := &net.UDPAddr{IP: ip, Port: port}
	return Table4group.net.ping(id, ipa)
}

func GetGroup(gid, id NodeID, addr *net.UDPAddr, target NodeID, p2pType int) []*Node {
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	if SDK_groupList != nil && SDK_groupList[gid] != nil {
		nodes := make([]*Node, 0, bucketSize)
		for _, rn := range SDK_groupList[gid].Nodes {
			n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
			err := n.validateComplete()
			if err != nil {
				common.Debug("Invalid neighbor node received", "ip", rn.IP, "addr", addr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		return nodes
	}
	g, _ := Table4group.net.findgroup(gid, id, addr, target, p2pType)
	return g
}

func setGroup(n *Node, replace string) {
	if setgroupNumber == 0 {
		setGroupSDK(n, replace, Sdkprotocol_type)
		return
	} else if setgroupNumber == 1 {
		setGroupCC(n, replace, Xprotocol_type) // same nodes
	} else {
		groupChanged := getGroupChange(Smpcprotocol_type)
		if *groupChanged == 2 {
			setGroupCC(n, replace, Xprotocol_type) // deferent nodes
		}
	}
	setGroupCC(n, replace, Smpcprotocol_type)
}

func sendpeer(gid, toid NodeID, ipa *net.UDPAddr,p2pType int) {
    err := SendToPeer(gid, toid, ipa, "", p2pType)
    if err != nil {
	return 
    }
}

func sendGroupToNode(groupList *Group, p2pType int, node *Node) { //nooo
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	go sendpeer(groupList.ID, node.ID, ipa, p2pType)
	if p2pType == Smpcprotocol_type || p2pType == Sdkprotocol_type {
		var tmp int = 0
		for i := 0; i < groupList.count; i++ {
			n := groupList.Nodes[i]
			tmp++
			if n.ID != node.ID {
				continue
			}
			cDgid := fmt.Sprintf("%v", groupList.ID) + "|" + "1smpcslash1:" + strconv.Itoa(tmp) + "#" + "Init"
			common.Debug("==== sendGroupToNode() ====", "cDgid", cDgid)
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			err := SendMsgToNode(node.ID, ipa, cDgid)
			if err != nil {
			    return
			}

			break
		}
	}
}

func sendGroupInfo(gid NodeID, nodes []RpcNode, p2pType int) { //nooo
	common.Debug("==== sendGroupInfo() ====", "gid", gid, "nodes", nodes)
	for i := 0; i < len(nodes); i++ {
		common.Debug("==== sendGroupInfo() ====", "gid", gid, "node", nodes[i])
		node := nodes[i]
		//e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
		//if e == SelfEnode {
		//	go callGroupEvent(req.ID, req.Mode, nodes, int(req.P2pType), req.Type)
		//}
		ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
		go sendpeer(gid, node.ID, ipa, p2pType)
	}
}

func sendGroupInit2Node(gid NodeID, node RpcNode, i int) {
	cDgid := fmt.Sprintf("%v", gid) + "|" + "1smpcslash1:" + strconv.Itoa(i) + "#" + "Init"
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	err := SendMsgToNode(node.ID, ipa, cDgid)
	if err != nil {
	    return
	}
}

func sendGroupInit(groupList *Group, p2pType int) { //nooo
	//enodes := fmt.Sprintf("%v,%v,%v", groupList.ID, count, enode)
	if p2pType == Smpcprotocol_type || p2pType == Sdkprotocol_type {
		for i := 0; i < groupList.count; i++ {
			node := groupList.Nodes[i]
			gid := groupList.ID
			tmpi := i
			go sendGroupInit2Node(gid, node, tmpi)
		}
	}
}

func addGroupSDK(n *Node, p2pType int) { //nooo
	groupTmp := new(Group)
	groupTmp.Nodes = make([]RpcNode, SDK_groupNum)
	for i, node := range groupSDKList {
		groupTmp.Nodes[i] = RpcNode(nodeToRPC(node))
		groupTmp.count++
	}
	groupTmp.Nodes[len(groupSDKList)] = RpcNode(nodeToRPC(n))
	groupTmp.count++
	groupTmp.ID = n.ID
	groupTmp.Mode = fmt.Sprintf("%v/%v", groupTmp.count, groupTmp.count)
	groupTmp.P2pType = byte(p2pType)
	groupTmp.Type = "1+2"
	SDK_groupList[groupTmp.ID] = groupTmp
}

func StartCreateSDKGroup(gid NodeID, threshold string, enode []*Node, Type string, exist bool, subGroup bool) string {
	common.Debug("==== StartCreateSDKGroup() ====", "gid", gid)
	buildSDKGroup(gid, threshold, enode, Type, exist, subGroup)
	return ""
}

func buildSDKGroup(gid NodeID, threshold string, enode []*Node, Type string, exist bool, subGroup bool) {
	es := strings.Split(threshold, "/")
	if len(es) != 2 {
		common.Info("args threshold format is wrong", "threshold", threshold)
		return
	}
	nodeNum0, _ := strconv.Atoi(es[0])
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	common.Debug("==== buildSDKGroup() ====", "gid", gid, "enode", enode)
	groupTmp := new(Group)
	groupTmp.Mode = threshold
	groupTmp.Type = Type
	cnodes := len(enode)
	if subGroup {
		cnodes = nodeNum0
	}
	groupTmp.Nodes = make([]RpcNode, cnodes)
	tmpNodes := make([]RpcNode, len(enode))
	for i, node := range enode {
		tmpNodes[i] = RpcNode(nodeToRPC(node))
		common.Debug("==== buildSDKGroup() ====", "tmpNodes", tmpNodes,"i",i,"node",tmpNodes[i],"enode",*node)
		if subGroup {
			if i >= nodeNum0 {
				continue
			}
		}
		groupTmp.Nodes[i] = RpcNode(nodeToRPC(node))
		groupTmp.count++
	}
	groupTmp.ID = gid
	SDK_groupList[groupTmp.ID] = groupTmp
	common.Debug("==== buildSDKGroup() ====", "gid", gid, "group", groupTmp)
	if exist != true {
		sendGroupInit(SDK_groupList[gid], Sdkprotocol_type)
	}
	sendGroupInfo(gid, tmpNodes, Sdkprotocol_type)
}

func updateGroup(n *Node, p2pType int) { //nooo
	for _, g := range SDK_groupList {
		for i, node := range g.Nodes {
			if node.ID == n.ID {
				g.Nodes = append(g.Nodes[:i], g.Nodes[i+1:]...)
				g.Nodes = append(g.Nodes, RpcNode(nodeToRPC(n)))
				sendGroupInfo(g.ID, g.Nodes, p2pType)
				sendGroupInit(g, p2pType)
				err := StoreGroupToDb(g)
				if err != nil {
				    return
				}

				break
			}
		}
	}
}

func updateGroupNode(n *Node, p2pType int) {
	for _, g := range SDK_groupList {
		for _, node := range g.Nodes {
			if node.ID == n.ID {
				sendGroupToNode(g, p2pType, n)
				break
			}
		}
	}
}

func checkNodeIDExist(n *Node) (bool, bool) { //exist, update //nooo
	groupTmp := SDK_groupList[n.ID]
	for _, node := range groupTmp.Nodes {
		if node.ID == n.ID {
			if string(node.IP) != string(n.IP) || node.UDP != n.UDP {
				return true, true
			}
			return true, false
		}
	}
	return false, true
}

func UpdateGroupSDKNode(nodeID NodeID, ipport net.Addr) {
	n, err := ParseNode(fmt.Sprintf("enode://%v@%v", nodeID, ipport))
	if err == nil {
		GroupSDK.Lock()
		defer GroupSDK.Unlock()
		updateGroupSDKNode(n, Sdkprotocol_type)
		common.Debug("==== UpdateGroupSDKNode() ====", "nodeID", nodeID, "ipport", ipport)
	}
}

func updateGroupSDKNode(nd *Node, p2pType int) { //nooo
	n := RpcNode(nodeToRPC(nd))
	for gid, g := range SDK_groupList {
		for i, node := range g.Nodes {
			if node.ID == n.ID {
				ipp1 := fmt.Sprintf("%v:%v", node.IP, node.UDP)
				ipp2 := fmt.Sprintf("%v:%v", n.IP, n.UDP)
				common.Debug("==== updateGroupSDKNode() ====", "nodeID", n.ID, "ip2", ipp2, "ip2", ipp1)
				if ipp1 != ipp2 {
					common.Debug("==== updateGroupSDKNode() ====", "ip2", ipp2, "ip1", ipp1)
					g.Nodes[i] = n
					common.Debug("==== updateGroupSDKNode() ====", "update group(gid", gid, ") enode", node, "->", n)
					//sendGroupInfo(g, p2pType)
					sendGroupInit(g, p2pType)
					err := StoreGroupToDb(g)
					if err != nil {
					    return
					}

					break
				}
				//ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
				//go SendToPeer(gid, node.ID, ipa, "", Sdkprotocol_type)
				tmpi := i
				go sendGroupInit2Node(gid, node, tmpi)
				break
			}
		}
	}
}

func checkGroupSDKListExist(n *Node) (bool, bool) { //return: exist, update //nooo
	for i, node := range groupSDKList {
		if node.ID == n.ID {
			ip1 := fmt.Sprintf("%v", node.IP)
			ip2 := fmt.Sprintf("%v", n.IP)
			if ip1 != ip2 || node.UDP != n.UDP {
				common.Debug("==== checkGroupSDKListExist() ====", "string(node.IP)", ip1, "string(n.IP)", ip2, "node.UDP", node.UDP, "n.UDP", n.UDP)
				common.Debug("==== checkGroupSDKListExist() ====", "enode", groupSDKList[i], "->", n)
				groupSDKList[i] = n
				return true, true
			}
			return true, false
		}
	}
	return false, true
}

func setGroupSDK(n *Node, replace string, p2pType int) {
	GroupSDK.Lock()
	defer GroupSDK.Unlock()
	common.Debug("==== setGroupSDK() ====", "node", n, "add/replace", replace)
	if replace == "add" {
		if setgroup == 0 {
			//check 1+1+1 group
			updateGroupSDKNode(n, p2pType)
			return
		} else {
			return // not auto create group for bootnode
		}
		et, ut := checkGroupSDKListExist(n)
		if et == true {
			if ut == true {
				go updateGroup(n, p2pType)
			} else {
				go updateGroupNode(n, p2pType)
			}
			return
		}
		common.Debug("==== setGroupSDK() ====", "len(groupSDKList)", len(groupSDKList), "SDK_groupNum", SDK_groupNum)
		if len(groupSDKList) == (SDK_groupNum - 1) {
			if SDK_groupList[n.ID] == nil { // not exist group
				addGroupSDK(n, p2pType)
			} else {
				et, up := checkNodeIDExist(n)
				if et == true && up == true {
					if SDK_groupList[n.ID] != nil { // exist group
						delete(SDK_groupList, n.ID)
					}
					addGroupSDK(n, p2pType)
				}
			}
			common.Debug("==== setGroupSDK() ====", "nodeID", n.ID, "group", SDK_groupList[n.ID])
			sendGroupInfo(n.ID, SDK_groupList[n.ID].Nodes, p2pType)
			sendGroupInit(SDK_groupList[n.ID], p2pType)
			err := StoreGroupToDb(SDK_groupList[n.ID])
			if err != nil {
			    return
			}
		} else { // add self node
			if len(groupSDKList) < SDK_groupNum {
				//e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
				groupSDKList = append(groupSDKList, n)
				common.Debug("==== setGroupSDK() ====", "len(groupSDKList)", len(groupSDKList))
				if len(groupSDKList) == (SDK_groupNum - 1) {
				    err := StoreGroupSDKListToDb()
				    if err != nil {
					return
				    }
				}
			}
		}
	} else {
		if setgroup == 1 {
			common.Debug("==== setGroupSDK() ====", "node", n, "add/replace", replace)
		}
		//if SDK_groupList[n.ID] != nil { // exist group
		//	delete(SDK_groupList, n.ID)
		//}
	}
}

//send group info
func setGroupCC(n *Node, replace string, p2pType int) {
	groupList := getGroupList(NodeID{}, p2pType)
	groupChanged := getGroupChange(p2pType)
	groupMemNum := getGroupMemNum(p2pType)

	if setgroup == 0 {
		return
	}
	groupList.Lock()
	defer groupList.Unlock()
	if *groupChanged == 2 {
		if replace == "add" {
			count := 0
			enode := ""
			for i := 0; i < groupList.count; i++ {
				count++
				node := groupList.Nodes[i]
				if enode != "" {
					enode += Smpcdelimiter
				}
				e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
				enode += e
				if bytes.Equal(n.IP, node.IP) == true && n.UDP == node.UDP {
					ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
					go sendpeer(NodeID{}, node.ID, ipa, p2pType)
				}
			}
			enodes := fmt.Sprintf("%v,%v", count, enode)
			if p2pType == Smpcprotocol_type {
				go callPrivKeyEvent(enodes)
			}
		}
		return
	}

	if replace == "add" {
		if groupList.count >= groupMemNum {
			groupList.count = groupMemNum
			return
		}
		groupList.Nodes = append(groupList.Nodes, RpcNode(nodeToRPC(n)))
		groupList.count++
		if *groupChanged == 0 {
			*groupChanged = 1
		}
	} else if replace == "remove" {
		if groupList.count <= 0 {
			groupList.count = 0
			return
		}
		for i := 0; i < groupList.count; i++ {
			if groupList.Nodes[i].ID == n.ID {
				groupList.Nodes = append(groupList.Nodes[:i], groupList.Nodes[i+1:]...)
				groupList.count--
				if *groupChanged == 0 {
					*groupChanged = 1
				}
				break
			}
		}
	}
	if groupList.count == groupMemNum && *groupChanged == 1 {
		count := 0
		enode := ""
		for i := 0; i < groupList.count; i++ {
			count++
			node := groupList.Nodes[i]
			if enode != "" {
				enode += Smpcdelimiter
			}
			e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
			enode += e
			ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
			go sendpeer(NodeID{}, node.ID, ipa, p2pType)
		}
		enodes := fmt.Sprintf("%v,%v", count, enode)
		if p2pType == Smpcprotocol_type {
			go callPrivKeyEvent(enodes)
		}
		*groupChanged = 2
	}
}

//send group info
func SendMsgToNode(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	if msg == "" {
		return nil
	}
	return Table4group.net.sendMsgToPeer(toid, toaddr, msg)
}

/////////ack for sending msg with udp

var (
    SmpcCall      func(interface{}, string)
    Msg2Peer = common.NewSafeMap(10)
    MsgAckMap  = common.NewSafeMap(10)
    resend = 3
    splitlen = 1200
    repeat = 1 
)

func getFullLen(str []string) int {
    n := 0
    for _,v := range str {
	if v != "" {
	    n++
	}
    }

    return n
}

func MergeSplitMsg(ms *MsgSend) string {
    if ms == nil {
	return ""
    }

    total,err := strconv.Atoi(ms.Num)
    if err != nil {
	return ""
    }
    pos,err := strconv.Atoi(ms.Pos)
    if err != nil {
	return ""
    }

    if pos >= total || pos < 0 {
	common.Error("====================MergeSplitMsg,get split msg pos error====================","msg hash",ms.MsgHash,"pos",pos,"total",total)
	return ""
    }

    val,exist := Msg2Peer.ReadMap(ms.MsgHash)
    if !exist {
	tmp := make([]string,total)
	tmp[pos] = ms.SplitMsg
	Msg2Peer.WriteMap(ms.MsgHash,tmp)
	if getFullLen(tmp) == total {
	    var s string
	    for _,v := range tmp {
		s += v
	    }

	    common.Debug("====================MergeSplitMsg,get msg====================","msg hash",ms.MsgHash,"pos",pos,"total",total)
	    return s
	}

	return ""
    }

    tmp,ok := val.([]string)
    if !ok {
	return ""
    }

    tmp[pos] = ms.SplitMsg
    Msg2Peer.WriteMap(ms.MsgHash,tmp)
    if getFullLen(tmp) == total {
	var s string
	for _,v := range tmp {
	    s += v
	}

	common.Debug("====================MergeSplitMsg,get msg====================","msg hash",ms.MsgHash,"pos",pos,"total",total)
	return s
    }

    return ""
}

type MsgSend struct {
   MsgHash string
   Pos string
   Num string
   PacketType string
   SplitMsg string
}

func sendSplitMsg(t *udp,msg string,ptype int,toaddr *net.UDPAddr,toid NodeID) error {

    if msg == "" || t == nil || toaddr == nil {
	return errors.New("param error")
    }

    num := getSplitMsgNum(msg)
    if num <= 0 {
	return errors.New("split msg num error")
    }

    msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
    common.Debug("==============sendSplitMsg,broadcast msg to group===================","orig msg hash",msghash,"send to node.ID",toid,"send to node.IP",toaddr.IP,"send to node.UDP",toaddr.Port,"split len",splitlen,"orig msg len",len(msg),"split msg num",num)

    msgs := []rune(msg)
    for i:=0;i<num;i++ {
	ms := &MsgSend{}
	ms.MsgHash = msghash
	ms.Pos = strconv.Itoa(i) 
	ms.Num = strconv.Itoa(num)
	ms.PacketType = strconv.Itoa(ptype)

	if i == (int(num)-1) {
	    ms.SplitMsg = string(msgs[splitlen*i:])
	} else {
	    ms.SplitMsg = string(msgs[splitlen*i:(i+1)*splitlen])
	}

	for j:=0;j<repeat;j++ {
	    errc := t.pending(toid, byte(Smpc_MsgSplitPacket), func(r interface{}) bool {
		    return true
	    })

	    if errc == nil {
		break
	    }
	    
	    time.Sleep(time.Duration(20) * time.Millisecond)
	}

	for j:=0;j<repeat;j++ {
	    _, errt := t.send(toaddr, byte(Smpc_MsgSplitPacket),ms)
	    if errt == nil {
		break
	    }
	    
	    common.Debug("====================sendSplitMsg,udp send msg fail=====================","j",j,"err",errt)
	    time.Sleep(time.Duration(20) * time.Millisecond)
	}
	
	//err := <-errc
	//return err
	
	time.Sleep(time.Duration(20) * time.Millisecond)
    }

    return nil
}

func getReqObject(ptype int) packet {
    switch ptype {
    case Smpc_groupInfoPacket:
	return new(Group)
    case Smpc_BroadcastMsgPacket:
	return new(SmpcBroadcastMsg)
    default:
	return nil
    }

    return nil
}

func (ms *MsgSend) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
    common.Debug("=====================MsgSend.handle,get msg========================","fromID",fromID,"msghash",ms.MsgHash,"from node.IP",from.IP,"from node.UDP",from.Port)
    s := MergeSplitMsg(ms)
    if s == "" {
	return nil
    }

    msghash := crypto.Keccak256Hash([]byte(strings.ToLower(s))).Hex()
    if !strings.EqualFold(msghash,ms.MsgHash) {
	return nil
    }
    
    common.Debug("=====================MsgSend.handle,get orig msg success========================","fromID",fromID,"orig msghash",ms.MsgHash,"from node.IP",from.IP,"from node.UDP",from.Port)
   
    ptype,err := strconv.Atoi(ms.PacketType)
    if err != nil {
	return err
    }

    req := getReqObject(ptype)
    if req == nil {
	return errors.New("get req object fail")
    }

    err = json.Unmarshal([]byte(s), req)
    if err != nil {
	common.Debug("=====================MsgSend.handle,unmarshal orig msg to UDP Object error========================","fromID",fromID,"msghash",ms.MsgHash,"err",err,"from node.IP",from.IP,"from node.UDP",from.Port)
	return err
    }

    err = req.handle(t,from,fromID,mac)
    if err != nil {
	common.Error("=====================MsgSend.handle,call packet handle(such as Call/recvGroupInfo) fail========================","fromID",fromID,"from node.IP",from.IP,"from node.UDP",from.Port,"msghash",ms.MsgHash,"req",req,"err",err)
	return err
    }

    common.Debug("=====================MsgSend.handle,call packet handle(such as Call/recvGroupInfo) success and send orig msg ack========================","fromID",fromID,"from node.IP",from.IP,"from node.UDP",from.Port,"msghash",ms.MsgHash)
    Msg2Peer.DeleteMap(ms.MsgHash)
    SendMsgAck(t,msghash,from,fromID)
    return nil
}

func (ms *MsgSend) name() string {
    return "MSGSEND/v4"
}

//-----------------------------------

type MsgAck struct {
    MsgHash string
    Flag string
}

func SendMsgAck(t *udp,msghash string,from *net.UDPAddr,fromid NodeID) {
    if t == nil || msghash == "" || from == nil {
	return
    }

    ma := &MsgAck{}
    ma.MsgHash = msghash
    ma.Flag = "Msg Ack"

    for i:=0;i<repeat;i++ {
	errc := t.pending(fromid, byte(Smpc_MsgSplitAckPacket), func(r interface{}) bool {
		return true
	})
	if errc == nil {
	    break
	}
	
	time.Sleep(time.Duration(20) * time.Millisecond)
    }

    for i:=0;i<repeat;i++ {
	_, errt := t.send(from, byte(Smpc_MsgSplitAckPacket),ma)
	if errt == nil {
	    break
	}
	
	time.Sleep(time.Duration(20) * time.Millisecond)
    }
    
    common.Debug("=================SendMsgAck,send msg ack success==================","send msg ack to node.ID",fromid,"orig msg hash",msghash,"send msg ack to node.IP",from.IP,"send msg ack to node.UDP",from.Port)
}

func (ms *MsgAck) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
    msghash2 := crypto.Keccak256Hash([]byte(strings.ToLower(ms.MsgHash + ":" + fromID.String()))).Hex()
    tmp,exist := MsgAckMap.ReadMap(msghash2)
    if !exist {
	return nil
    }

    ack,ok := tmp.(chan bool)
    if !ok {
	return errors.New("msg ack data error")
    }

    ack <-true
    common.Debug("================MsgAck.handle,get msg ack=================","orig msg hash",ms.MsgHash,"fromid",fromID,"node.IP",from.IP,"node.UDP",from.Port)
    return nil
}

func (ms *MsgAck) name() string {
    return "MSGACK/v4"
}

//-------------------------------------

func checkMsgStatus(t *udp,msghash string,msg string,ptype int,toaddr *net.UDPAddr,toid NodeID) {
    msghash2 := crypto.Keccak256Hash([]byte(strings.ToLower(msghash + ":" + toid.String()))).Hex()
    ack := make(chan bool, 1)
    MsgAckMap.WriteMap(msghash2,ack)

    for i:=0;i<resend;i++ {
	ackWaitTime := 10 * time.Second
	ackWaitTimeOut := time.NewTicker(ackWaitTime)

	select {
	case <-ack:
	    common.Debug("=================checkMsgStatus,get msg ack success===========================","i",i,"orig msg hash",msghash,"send to node",toaddr)
		MsgAckMap.DeleteMap(msghash2)
		return
	case <-ackWaitTimeOut.C:
	    common.Debug("=================checkMsgStatus,get msg ack timeout===========================","i",i,"orig msg hash",msghash,"send to node",toaddr)
		sendSplitMsg(t,msg,ptype,toaddr,toid)
		break
	}
    }

    common.Debug("=================checkMsgStatus,get msg ack fail===========================","orig msg hash",msghash,"send to node",toaddr)
    MsgAckMap.DeleteMap(msghash2)
}

func getSplitMsgNum(msg string) int {
    l := len(msg)
    a := l%splitlen
    b := l/splitlen
    if a != 0 {
	b++
    }

    return b
}

func (t *udp) sendMsgSplitToPeerWithUDP(toid NodeID, toaddr *net.UDPAddr, packet []byte, p2pType int,ptype int) error {
    if packet == nil || len(packet) == 0 {
	return errors.New("packet error")
    }

    err := sendSplitMsg(t,string(packet),ptype,toaddr,toid)
    if err != nil {
	return err
    }

    msghash := crypto.Keccak256Hash([]byte(strings.ToLower(string(packet)))).Hex()
    go checkMsgStatus(t,msghash,string(packet),ptype,toaddr,toid)

    return err
}

//send any object with udp
//split msg
func SendMsgSplitToPeerWithUDP(toid NodeID, toaddr *net.UDPAddr, req interface{}, p2pType int,ptype int) error {
    if req == nil {
	return errors.New("msg error")
    }
    
    packet, err := json.Marshal(req)
    if err != nil {
	common.Error("=====================SendMsgToPeerWithUDP,marshal error====================","err",err)
	return err
    }

    return Table4group.net.sendMsgSplitToPeerWithUDP(toid,toaddr,packet,p2pType,ptype)
}

type SmpcBroadcastMsg struct {
    Data string
}

func (sbm *SmpcBroadcastMsg) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
    if sbm.Data == "" {
	return errors.New("data error")
    }

    if SmpcCall == nil {
	return errors.New("call back function nil")
    }

    go SmpcCall(sbm.Data,fromID.String())
    return nil
}

func (sbm *SmpcBroadcastMsg) name() string {
    return "SMPCBROADCASTMSG/v4"
}

/////////end

func SendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
	common.Debug("==== SendToPeer() ====", "toaddr", toaddr, "msg", msg)
	return Table4group.net.sendToPeer(gid, toid, toaddr, msg, p2pType)
}

func (t *udp) sendToPeer(gid, toid NodeID, toaddr *net.UDPAddr, msg string, p2pType int) error {
	req := getGroupInfo(gid, p2pType)
	common.Debug("====  (t *udp) sendToPeer()  ====", "toaddr", toaddr, "groupInfo", req)
	if req == nil {
		return nil
	}

	packet, err := json.Marshal(req)
	if err != nil {
	    common.Error("=====================udp.sendToPeer,marshal group info error====================","err",err)
	    return err
	}
	err = sendSplitMsg(t,string(packet),Smpc_groupInfoPacket,toaddr,toid)
	if err != nil {
	    return err
	}

	msghash := crypto.Keccak256Hash([]byte(strings.ToLower(string(packet)))).Hex()
	go checkMsgStatus(t,msghash,string(packet),Smpc_groupInfoPacket,toaddr,toid)
	////////////////

	/*_, errt := t.send(toaddr, byte(Smpc_groupInfoPacket), req)
	if errt != nil {
		common.Debug("====  (t *udp) sendToPeer()  ====", "t.send, toaddr", toaddr, "err", errt)
		return errt
	} else {
		common.Debug("====  (t *udp) sendToPeer()  ====", "t.send, toaddr", toaddr, "groupInfo", req, "SUCCESS", "")
	}*/
	//err = <-errc
	return err
}

func (req *Group) name() string { return "GROUPMSG/v4" }
func (req *Group) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	nodes := make([]*Node, 0)
	for _, rn := range req.Nodes {
		common.Debug("==== (req *Group) handle() ====", "Node", rn)
		n, err := t.nodeFromRPC(from, rpcNode(rn))
		if err != nil {
			common.Debug("==== (req *Group) handle() ====", "gid", req.ID, "Node", rn, "Group p2perror", err)
			return err
		}
		common.Debug("==== (req *Group) handle() ====", "append Node", rn)
		nodes = append(nodes, n)
	}

	common.Debug("==== (req *Group) handle() ====, callGroupEvent", "from", from, "gid", req.ID, "req.Nodes", nodes)
	go callGroupEvent(req.ID, req.Mode, nodes, int(req.P2pType), req.Type)
	return nil
}

//send msg
func (t *udp) sendMsgToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	errc := t.pending(toid, PeerMsgPacket, func(r interface{}) bool {
		return true
	})
	_, errs := t.send(toaddr, PeerMsgPacket, &message{
		Msg:        msg,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if errs != nil {
		common.Debug("==== (t *udp) sendMsgToPeer ====", "errs", errs)
		return errs
	}
	err := <-errc
	return err
}
func (req *message) name() string { return "MESSAGE/v4" }

func (req *message) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	common.Debug("====  (req *message) handle()  ====", "from", from, "fromID", fromID)
	if expired(req.Expiration) {
		return errExpired
	}
	go callPriKeyEvent(req.Msg)
	return nil
}

//send msg to broadcast node after peer.send failed
var broadcastNodeCallback func(interface{}, string)

func RegisterBroadcastNodeCallback(callbackfunc func(interface{}, string)) {
	broadcastNodeCallback = callbackfunc
}

func callMsgBroadcastEvent(msg string, fromID string) {
	if broadcastNodeCallback != nil {
		broadcastNodeCallback(msg, fromID)
	}
}

func SendMsgToBroadcastNode(node *Node, msg string) error {
	if msg == "" {
		return nil
	}
	toid := node.ID
	toaddr := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	return Table4group.net.sendMsgToBroadcastNode(toid, toaddr, msg)
}

func (t *udp) sendMsgToBroadcastNode(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	common.Debug("sendMsgToBroadcastNode","toid",toid,"toaddr",toaddr,"msgHash",msgHash, "len", len(msg))
	errc := t.pending(toid, msgBroadcastPacket, func(r interface{}) bool {
		return true
	})
	_, errs := t.send(toaddr, msgBroadcastPacket, &messageBroadcast{
		Msg:        msg,
		Expiration: uint64(time.Now().Add(expirationBroadcast).Unix()),
	})
	if errs != nil {
		common.Debug("==== (t *udp) sendMsgToBroadcastNode ====", "errs", errs, "toid",toid,"toaddr",toaddr,"msgHash",msgHash, "len", len(msg))
		return errs
	}
	err := <-errc
	common.Debug("sendMsgToBroadcastNode success","toid",toid,"toaddr",toaddr,"msgHash",msgHash)
	return err
}
func (req *messageBroadcast) name() string { return "MESSAGEBROADCAST/v4" }

func (req *messageBroadcast) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	msgHash := crypto.Keccak256Hash([]byte(strings.ToLower(req.Msg))).Hex()
	common.Debug("(sendMsgToBroadcastNode) handle()", "from", from, "fromID", fromID, "msgHash", msgHash, "len", len(req.Msg))
	if expired(req.Expiration) {
		return errExpired
	}
	go callMsgBroadcastEvent(req.Msg, fromID.String())
	return nil
}
//end

var groupcallback func(NodeID, string, interface{}, int, string)

func RegisterGroupCallback(callbackfunc func(NodeID, string, interface{}, int, string)) {
	groupcallback = callbackfunc
}

func callGroupEvent(gid NodeID, mode string, n []*Node, p2pType int, Type string) {
	if groupcallback != nil {
		common.Debug("==== callGroupEvent() ====", "gid", gid, "mode", mode, "n", n, "p2pType", p2pType, "Type", Type)
		groupcallback(gid, mode, n, p2pType, Type)
	}
}

var prikeycallback func(interface{})

func RegisterPriKeyCallback(callbackfunc func(interface{})) {
	prikeycallback = callbackfunc
}

func callPriKeyEvent(msg string) {
	if prikeycallback != nil {
		prikeycallback(msg)
	}
}

func callMsgEvent(e interface{}, p2pType int, fromID string) <-chan string {
	switch p2pType {
	case Sdkprotocol_type:
		if sdkcallback != nil {
			return sdkcallback(e, fromID)
		} else {
			common.Debug("==== callMsgEvent() ====", "error", "callback func is nil, RegisterSdkMsgCallback not called")
			ch := make(chan string)
			ch <- "RegisterSdkMsgCallback not called"
			return ch
		}
	case Smpcprotocol_type:
		return smpccallback(e)
	case Xprotocol_type:
		return xpcallback(e)
	}
	ch := make(chan string)
	ch <- "p2pType invalid"
	return ch
}

var sdkcallback func(interface{}, string) <-chan string

func RegisterSdkMsgCallback(sdkbackfunc func(interface{}, string) <-chan string) {
	sdkcallback = sdkbackfunc
}
func callsdkEvent(e interface{}, fromID string) <-chan string {
	return sdkcallback(e, fromID)
}

//peer(of SMPC group) receive other peer msg to run smpc
var smpccallback func(interface{}) <-chan string

func RegisterSmpcMsgCallback(callbackfunc func(interface{}) <-chan string) {
	smpccallback = callbackfunc
}
func callsmpcEvent(e interface{}) <-chan string {
	return smpccallback(e)
}

var sdkretcallback func(interface{}, string)

func RegisterSdkMsgRetCallback(sdkbackfunc func(interface{}, string)) {
	sdkretcallback = sdkbackfunc
}
func callsdkReturn(e interface{}, fromID string) {
	if sdkretcallback != nil {
		sdkretcallback(e, fromID)
	}
}

//return
var smpcretcallback func(interface{})

func RegisterSmpcMsgRetCallback(callbackfunc func(interface{})) {
	smpcretcallback = callbackfunc
}
func callsmpcReturn(e interface{}) {
	smpcretcallback(e)
}

//peer(of Xp group) receive other peer msg to run dccp
var xpcallback func(interface{}) <-chan string

func RegisterXpMsgCallback(callbackfunc func(interface{}) <-chan string) {
	xpcallback = callbackfunc
}
func callxpEvent(e interface{}) <-chan string {
	return xpcallback(e)
}

//return
var xpretcallback func(interface{})

func RegisterXpMsgRetCallback(callbackfunc func(interface{})) {
	xpretcallback = callbackfunc
}
func callxpReturn(e interface{}) {
	xpretcallback(e)
}

func callCCReturn(e interface{}, p2pType int, fromID string) {
	switch p2pType {
	case Sdkprotocol_type:
		callsdkReturn(e, fromID)
	case Smpcprotocol_type:
		callsmpcReturn(e)
	case Xprotocol_type:
		callxpReturn(e)
	}
}

//get private Key
var privatecallback func(interface{})

func RegisterSendCallback(callbackfunc func(interface{})) {
	privatecallback = callbackfunc
}

func callPrivKeyEvent(e string) {
	if privatecallback != nil {
		privatecallback(e)
	}
}

func ParseNodes(n []*Node) (int, string) {
	i := 0
	enode := ""
	for _, e := range n {
		if enode != "" {
			enode += Smpcdelimiter
		}
		i++
		enode += e.String()
	}
	return i, enode
}

func GetLocalIP() string {
	return LocalIP
}

func GetRemoteIP() net.IP {
	return RemoteIP
}

func GetRemotePort() uint16 {
	if RemotePort == 0 {
		RemotePort = Table4group.self.UDP
	}
	return RemotePort
}

func GetLocalID() NodeID {
	return SelfNodeID
}

func GetEnode() string {
	return SelfEnode
}


// GetPublicIP returns your public IP address
func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip := string(body)
	return ip, nil
}

func CheckNetwokConnect() {
	go func() {
		time.Sleep(time.Duration(60) * time.Second)
		for {
			ip, err := getPublicIP()
			if err == nil {
				updateRemoteIP(parseIP(ip), RemotePort)
				return
			}
			time.Sleep(time.Duration(1) * time.Second)
		}
	}()
	go func() {
		<-checkNetworkChan
		connectOk = true
	}()
	go func() {
		for {
			SendWaitTimeOut := time.NewTicker(checkNetworkConnectTime)
			select {
			case <-SendWaitTimeOut.C:
				if connectOk {
					common.Info("CheckNetworkConnect success", "ip", RemoteIP, "port", RemotePort)
					return
				} else {
					common.Info("CheckNetwokConnect failed, Please check network: port or bootnode")
				}
			}
		}
	}()
}

func updateRemoteIP(ip net.IP, port uint16) {
	if setgroup == 0 && RemoteUpdate == false {
		RemoteUpdate = true
		updateIPPort(ip, port)
		checkNetworkChan <- 1
	}
}

func UpdateMyselfIP() {
	for {
		if connectOk {
			break
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
	enode := fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
	n, _ := ParseNode(enode)
	setGroup(n, "add")
}

func updateIPPort(ip net.IP, port uint16) {
	//fmt.Printf("updateRemoteIP, IP:port = %v:%v\n\n", ip, port)
	common.Info("============= updateRemoteIP() ============", "IP", ip, "port", port)
	RemoteIP = ip
	RemotePort = port
	SelfEnode = fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
	SelfIPPort = fmt.Sprintf("%v:%v", RemoteIP, RemotePort)
	common.Info("updateRemoteIP", "myselfEnode", SelfEnode)
}

func SendToMyselfAndReturn(selfID, msg string, p2pType int) {
	msgc := callMsgEvent(msg, p2pType, selfID)
	msgr := <-msgc
	callCCReturn(msgr, p2pType, selfID)
}

func UpdateGroupNodesNumber(number, p2pType int) {
	switch p2pType {
	case Sdkprotocol_type:
		if SDK_groupNum == 0 {
			SDK_groupNum = number
		}
		break
	case Smpcprotocol_type:
		if Smpc_groupMemNum == 0 {
			Smpc_groupMemNum = number
		}
		break
	case Xprotocol_type:
		if Xp_groupMemNum == 0 {
			Xp_groupMemNum = number
		}
		break
	}
}

func GetEnodeStatus(enode string) (string, error) {
	n, err := ParseNode(enode)
	if err != nil || n.validateComplete() != nil {
		common.Debug("GetEnodeStatus ParseNode", "err", enode)
		return "", errors.New("enode wrong format")
	}
	selfid := fmt.Sprintf("%v", GetLocalID())
	common.Debug("GetEnodeStatus", "selfid", selfid, "node.ID", n.ID)
	if n.ID.String() == selfid {
		return "OnLine", nil
	} else {
		return getOnLine(n.ID), nil
	}
	return "OffLine", nil
}

func StoreGroupToDb(groupInfo *Group) error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	// fix bug:resource temporarily unavailable
	if giddb == nil {
		dir := getGroupDir()
		//db, err := leveldb.OpenFile(dir, nil)
		db, err := ethdb.NewLDBDatabase(dir, 76, 512)
		if err != nil {
		    common.Error("===================StoreGroupToDb,init group db fail=====================","dir",dir,"err",err)
		   return err
		}
		giddb = db
	}

	//dir := getGroupDir()
	//db, err := leveldb.OpenFile(dir, nil)
	//if err != nil {
	 //   common.Error("===================StoreGroupToDb=====================","err",err)
	 //   return err
	//}
	// fix bug:resource temporarily unavailable

	key := crypto.Keccak256Hash([]byte(strings.ToLower(fmt.Sprintf("%v", groupInfo.ID)))).Hex()
	ac := new(Group)
	ac.ID = groupInfo.ID
	ac.Mode = groupInfo.Mode
	ac.P2pType = groupInfo.P2pType
	ac.Type = groupInfo.Type
	ac.Nodes = make([]RpcNode, 0)
	for _, n := range groupInfo.Nodes {
		ac.Nodes = append(ac.Nodes, n)
	}
	alos, err := Encode2(ac)
	if err != nil {
		//db.Close()
		//giddb.Close()
		common.Error("===================StoreGroupToDb,encode fail=====================","err",err)
		return err
	}
	ss, err := Compress([]byte(alos))
	if err != nil {
		//db.Close()
		//giddb.Close()
		common.Error("===================StoreGroupToDb,compress fail=====================","err",err)
		return err
	}

	//err = db.Put([]byte(key), []byte(ss), nil)
	err = giddb.Put([]byte(key), []byte(ss))
	if err != nil {
	    //db.Close()
	    //giddb.Close()
	    common.Error("===================StoreGroupToDb,put data to db fail=====================","err",err)
	    return err
	}

	//db.Close()
	//giddb.Close()
	common.Debug("================ StoreGroupInfo,success save the group info ================ ")
	return nil
}

func RecoverGroupByGID(gid NodeID) (*Group, error) {
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	if giddb == nil {
		dir := getGroupDir()
		db, err := ethdb.NewLDBDatabase(dir, 76, 512)
		//db, err := leveldb.OpenFile(dir, nil)
		if err != nil {
			common.Error("======RecoverGroupByGID=======","open db error",err)
			return nil, err
		}
		giddb = db
	}

	key := crypto.Keccak256Hash([]byte(strings.ToLower(fmt.Sprintf("%v", gid)))).Hex()
	//da, err := db.Get([]byte(key), nil)
	da, err := giddb.Get([]byte(key))
	if err == nil {
		ds, err := UnCompress(string(da))
		if err != nil {
			//db.Close()
			return nil, err
		}

		dss, err := Decode2(ds, "Group")
		if err != nil {
			common.Debug("==== GetGroupInfo() ====", "error", "decode group data fail")
			//db.Close()
			return nil, err
		}

		ac := dss.(*Group)
		common.Debug("==== GetGroupInfo() ====", "ac", ac)
		//db.Close()
		return ac, nil
	}
	//db.Close()
	return nil, err
}

func StoreGroupSDKListToDb() error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupSDKListDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return err
	}

	key := crypto.Keccak256Hash([]byte("groupsdklist")).Hex()
	ac := new(GroupSDKList)
	ac.Nodes = make([]*Node, 0)
	for _, n := range groupSDKList {
		ac.Nodes = append(ac.Nodes, n)
	}
	alos, err := Encode2(ac)
	if err != nil {
		db.Close()
		return err
	}
	ss, err := Compress([]byte(alos))
	if err != nil {
		db.Close()
		return err
	}

	common.Debug("==== StoreGroupSDKListToDb() ==== new", "groupSDKList", ac)
	err = db.Put([]byte(key), []byte(ss), nil)
	if err != nil {
	    db.Close()
		return err
	}

	db.Close()
	return nil
}

func RecoverGroupSDKList() error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	dir := getGroupSDKListDir()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	key := crypto.Keccak256Hash([]byte("groupsdklist")).Hex()
	da, err := db.Get([]byte(key), nil)
	if err == nil {
		ds, err := UnCompress(string(da))
		if err != nil {
			return err
		}

		dss, err := Decode2(ds, "GroupSDKList")
		if err != nil {
			common.Debug("==== RecoverGroupSDKList() ====", "error", "decode group data fail")
			return err
		}

		ac := dss.(*GroupSDKList)
		common.Debug("==== RecoverGroupSDKList() ====", "groupSDKList", ac)
		for _, n := range ac.Nodes {
			groupSDKList = append(groupSDKList, n)
		}
		return nil
	}
	return err
}

func GetGroupDir() string {
	return getGroupDir()
}

func getGroupDir() string {
	dir := common.DefaultDataDir()
	if setgroup != 0 {
		dir = filepath.Join(dir, p2pSuffix, "bootnode-"+SelfID)
	} else {
		dir = filepath.Join(dir, p2pSuffix, SelfID)
	}
	common.Debug("==== getGroupDir() ====", "dir", dir)
	return dir
}

func getGroupSDKListDir() string {
	if setgroup == 0 {
		return ""
	}
	dir := filepath.Join(p2pDir, p2pSuffix, "SDKList-"+SelfID)
	common.Debug("==== getGroupSDKListDir() ====", "dir", dir)
	return dir
}

func Encode2(obj interface{}) (string, error) {
	switch obj.(type) {
	case *Group:
		ch := obj.(*Group)
		ret, err := json.Marshal(ch)
		if err != nil {
			return "", err
		}
		return string(ret), nil
	case *GroupSDKList:
		ch := obj.(*GroupSDKList)
		ret, err := json.Marshal(ch)
		if err != nil {
			return "", err
		}
		return string(ret), nil
	default:
		return "", fmt.Errorf("encode obj fail.")
	}
}

func Decode2(s string, datatype string) (interface{}, error) {
	if datatype == "GroupSDKList" {
		var m GroupSDKList
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
			return nil, err
		}
		return &m, nil
	}
	if datatype == "Group" {
		var m Group
		err := json.Unmarshal([]byte(s), &m)
		if err != nil {
			return nil, err
		}
		return &m, nil
	}
	return nil, fmt.Errorf("decode obj fail.")
}

func Compress(c []byte) (string, error) {
	if c == nil {
		return "", fmt.Errorf("compress fail.")
	}

	var in bytes.Buffer
	w, err := zlib.NewWriterLevel(&in, zlib.BestCompression-1)
	if err != nil {
	    return "", err
	}

	_,err2 := w.Write(c)
	if err2 != nil {
	    return "", err2
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
	_,err2 := io.Copy(&out, r)
	if err2 != nil {
	    return "", err2
	}

	return out.String(), nil
}

func RecoverGroupAll(SdkGroup map[NodeID]*Group) error { //nooo
	groupDbLock.Lock()
	defer groupDbLock.Unlock()

	if giddb == nil {
		dir := getGroupDir()
		common.Debug("==== getGroupFromDb() ====", "dir", dir)
		//db, err := leveldb.OpenFile(dir, nil)
		db, err := ethdb.NewLDBDatabase(dir, 76, 512)
		if err != nil {
			common.Debug("==== getGroupFromDb() ====", "db open err", err)
			return err
		}
		giddb = db
	}

	//iter := db.NewIterator(nil, nil)
	iter := giddb.NewIterator()
	for iter.Next() {
		value := string(iter.Value())
		ss, err := UnCompress(value)
		if err != nil {
			common.Debug("==== getGroupFromDb() ====", "UnCompress err", err)
			continue
		}

		g, err := Decode2(ss, "Group")
		if err != nil {
			common.Debug("==== getGroupFromDb() ====", "Decode2 err", err)
			continue
		}

		gm := g.(*Group)
		groupTmp := NewGroup()
		groupTmp.Mode = gm.Mode
		groupTmp.P2pType = gm.P2pType
		groupTmp.Type = gm.Type
		groupTmp.ID = gm.ID
		SdkGroup[gm.ID] = groupTmp
		groupTmp.Nodes = make([]RpcNode, 0)
		for _, node := range gm.Nodes {
			groupTmp.Nodes = append(groupTmp.Nodes, node)
		}
		common.Debug("==== getGroupFromDb() ====", "nodes", groupTmp.Nodes)
		common.Debug("==== getGroupFromDb() ====", "SdkGroup", SdkGroup[gm.ID])
	}
	//db.Close()
	return nil
}

func NewGroup() *Group {
	return &Group{}
}

func UpdateOnLine(nodeID NodeID, online bool) {
	if nodeOnline[nodeID] == nil {
		nodeOnline[nodeID] = new(OnLineStatus)
	}
	nodeOnline[nodeID].Lock.Lock()
	nodeOnline[nodeID].Status = online
	nodeOnline[nodeID].Lock.Unlock()
	common.Debug("==== UpdateOnLine() ====", "nodeid", nodeID, "status", online)
}

func getOnLine(nodeID NodeID) string {
	if nodeOnline[nodeID] != nil {
		nodeOnline[nodeID].Lock.Lock()
		online := nodeOnline[nodeID].Status
		nodeOnline[nodeID].Lock.Unlock()
		if online == true {
			return "OnLine"
		}
	}
	return "OffLine"
}

func PrintBucketNodeInfo(id NodeID) {
	Table4group.mutex.Lock()
	defer Table4group.mutex.Unlock()

	findNode := false
	for i := range Table4group.buckets {
		if findNode == true {
			break
		}
		findReplacements := true
		b := Table4group.buckets[i]
		for j, n := range b.entries { // live entries, sorted by time of last contact
			if id == n.ID {
				common.Debug("==== PrintBucketNodeInfo() ====", "buckets", i, "entries", j, "IP", n.IP, "UDP", n.UDP)
				findNode = true
				findReplacements = false
				break
			}
		}
		if findReplacements == true {
			for j, n := range b.replacements { // live entries, sorted by time of last contact
				if id == n.ID {
					common.Debug("==== PrintBucketNodeInfo() ====", "replacements", j, "IP", n.IP, "UDP", n.UDP)
					findNode = true
					break
				}
			}
		}
	}
	if findNode != true {
		common.Debug("==== PrintfBucketNodeInfo() ====", "not exist int bucket fail id", id)
	}
}

func Remove(n *Node) {
	common.Debug("==== remove() ====", "n", n)
	Table4group.delete(n)
}

func checkUpdateNode(n *Node) {
	if setgroup == 1 {
		return
	}
	if updateGroupsNode == true {
		return
	}
	updateGroupsNode = true
	if setgroup == 0 && n.ID != SelfNodeID && checkAddNodes(n.ID) == true {
		if ok := checkSeeds(n.ID); ok == false {
			setGroup(n, "add")
		}
	}
	updateGroupsNode = false
}

func loadedSeed(seeds []*Node) {
	if loadedDone == false {
		loadedDone = true
		for i := range seeds {
			loadedSeeds[seeds[i].ID] = 1
		}
	}
}

func AddNodes(nid NodeID) {
	addNodesLock.Lock()
	defer addNodesLock.Unlock()
	addNodes[nid] = 1
}

func checkAddNodes(nid NodeID) bool {
	addNodesLock.Lock()
	defer addNodesLock.Unlock()
	if addNodes[nid] == 1 {
		delete(addNodes, nid)
		return true
	}
	return false
}

func checkSeeds(nid NodeID) bool {
	if loadedSeeds[nid] == 1 {
		return true
	}
	return false
}

func InitIP(ip string, port uint16) {
	LocalIP = ip
	RemoteIP = parseIP(ip)
	RemotePort = port
	SelfEnode = fmt.Sprintf("enode://%v@%v:%v", GetLocalID(), RemoteIP, RemotePort)
	common.Info("==== InitIP() ====", "IP", RemoteIP)
}

func parseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		common.Debug("parseIP", "invalid", s)
		return net.IP{}
	}
	return ip
}
