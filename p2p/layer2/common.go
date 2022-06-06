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

package layer2

import (
	"errors"
	"fmt"
	//"sync"
	"strings"
	"net"
	"time"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/rlp"
	mapset "github.com/deckarep/golang-set"
	"github.com/anyswap/FastMulThreshold-DSA/crypto"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"encoding/json"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	//cdLen := getCDLen(msg)
	//common.Debug("==== BroadcastToGroup() ====", "gid", gid, "msg", msg[:cdLen])
	xvcGroup, msgCode := getGroupAndCode(gid, p2pType)
	if xvcGroup == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		common.Debug("==== BroadcastToGroup ====", "p2pType", p2pType, "is not exist", "")
		return "", errors.New(e)
	}
	groupTmp := *xvcGroup
	go func() {
	    //p2pBroatcastPeers(msg,msgCode,myself)
	    p2pBroatcast(&groupTmp, msg, msgCode, myself)
	}()
	
	return "BroadcastToGroup send end", nil
}

//------------------------------------------------------

var (
    MsgAckMap  = common.NewSafeMap(10)
    resend = 60
    splitlen = 1200 
)

type MsgSend struct {
   MsgHash string
   Pos int
   Num int
   SplitMsg string
}

type MsgAck struct {
    MsgHash string
    Flag string
}

func SendMsgAck(msghash string,eID string) {
    if eID == "" || msghash == "" {
	return
    }

    enode := "0x" + eID
    nodeid,err := discover.HexID(enode)
    if err != nil {
	return
    }
    
    ma := &MsgAck{}
    ma.MsgHash = msghash
    ma.Flag = "Msg Ack"
    s, err := json.Marshal(ma)
    if err != nil {
	return
    }

    //log.Debug("=================SendMsgAck==================","send msg ack to node.ID",eID,"orig msg hash",msghash)
    sendMsgToBroadcastNode(nodeid,string(s))
}

func SetMsgStatus(msghash string,enode string) {
    if msghash == "" || enode == "" {
	return
    }

    msghash2 := crypto.Keccak256Hash([]byte(strings.ToLower(msghash + ":" + enode))).Hex()
    tmp,exist := MsgAckMap.ReadMap(msghash2)
    if !exist {
	return
    }

    ack,ok := tmp.(chan bool)
    if !ok {
	return
    }

    //log.Debug("================SetMsgStatus,get msg ack=================","orig msg hash",msghash,"enode",enode)
    ack <-true
}

func checkMsgStatus(msghash string,msg string,node discover.RpcNode,msgCode uint64) {
    if msghash == "" || msg == "" {
	return
    }

    ack := make(chan bool, 1)
    msghash2 := crypto.Keccak256Hash([]byte(strings.ToLower(msghash + ":" + node.ID.String()))).Hex()
    MsgAckMap.WriteMap(msghash2,ack)

    for i:=0;i<resend;i++ {
	ackWaitTime := 10 * time.Second
	ackWaitTimeOut := time.NewTicker(ackWaitTime)

	select {
	case <-ack:
	    log.Debug("=================checkMsgStatus,get msg ack success(send msg success)===========================","i",i,"orig msg hash",msghash,"send to node.ID",node.ID)
		MsgAckMap.DeleteMap(msghash2)
		return
	case <-ackWaitTimeOut.C:
		//log.Debug("=================checkMsgStatus,get msg ack timeout===========================","i",i,"orig msg hash",msghash,"send to node.ID",node.ID)
		SplitMsg(msg,node,int(msgCode))
		break	
	}
    }
    
    log.Debug("=================checkMsgStatus,get msg ack fail(maybe send msg fail)===========================","orig msg hash",msghash,"send to node.ID",node.ID)
    MsgAckMap.DeleteMap(msghash2)
}

func SplitMsg(msg string,node discover.RpcNode,msgCode int) error {
    if msg == "" {
	return errors.New("msg error")
    }

    msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
    log.Debug("==============SplitMsg,broadcast msg to group===================","orig msg hash",msghash,"send to node.IP",node.IP,"send to node.UDP",node.UDP,"send to node.ID",node.ID,"split len",splitlen,"orig msg len",len(msg))

    var err error
    var s []byte
    success := false
    
    //try tcp first
    /*emitter.Lock()
    p := emitter.peers[node.ID]
    emitter.Unlock()
    
    if p != nil {
	splitlen = 60000 
	l := len(msg)
	a := l%splitlen
	b := l/splitlen
	if a != 0 {
	    b++
	}

	msgs := []rune(msg)
	for i:=0;i<b;i++ {
	    ms := &MsgSend{}
	    ms.MsgHash = msghash
	    ms.Pos = i
	    ms.Num = b

	    if i == (b-1) {
		ms.SplitMsg = string(msgs[splitlen*i:])
	    } else {
		ms.SplitMsg = string(msgs[splitlen*i:(i+1)*splitlen])
	    }
	    
	    s, err = json.Marshal(ms)
	    if err != nil {
		    log.Debug("=========SplitMsg,marshal error=============", "err",err)
		    success = false
		    break
	    }
	    
	    for i:=0;i<20;i++ {
		err = p2p.Send(p.ws, uint64(msgCode),string(s))
		if err == nil {
		    success = true
		    break
		}
		
		if i == 19 {
		    success = false
		    break
		}

		time.Sleep(time.Duration(100) * time.Millisecond)
	    }

	    if !success {
		break
	    }

	    time.Sleep(time.Duration(100) * time.Millisecond)
	}
    }*/

    //try udp
    if !success {
	l := len(msg)
	a := l%splitlen
	b := l/splitlen
	if a != 0 {
	    b++
	}

	msgs := []rune(msg)
	//var wg sync.WaitGroup
	for i:=0;i<b;i++ {
	    //wg.Add(1)
	    //go func(index int) {
		//defer wg.Done()
		ms := &MsgSend{}
		ms.MsgHash = msghash
		ms.Pos = i
		ms.Num = b

		if i == (b-1) {
		    ms.SplitMsg = string(msgs[splitlen*i:])
		} else {
		    ms.SplitMsg = string(msgs[splitlen*i:(i+1)*splitlen])
		}
		
		s, err = json.Marshal(ms)
		if err != nil {
			log.Debug("=========SplitMsg,marshal error=============", "i",i,"err",err)
			return err
		}
		
		//splitmsghash := crypto.Keccak256Hash([]byte(strings.ToLower(string(s)))).Hex()
		//log.Debug("=========SplitMsg,send split msg to node=============", "node.ID",node.ID,"split msg hash",splitmsghash,"orig msg hash",msghash)

		sendMsgToBroadcastNode(node.ID,string(s))

		time.Sleep(time.Duration(80) * time.Millisecond)
	    //}(i)
	}
	//wg.Wait()
    }

    return err 
}

//-----------------------------------------------------------------------------

func P2pBroatcastPeers(msg string,myself bool) int {
    return p2pBroatcastPeers(msg,Sdk_msgCode,false)
}

func p2pBroatcastPeers(msg string, msgCode int, myself bool) int {
    if msg == "" {
	return 0
    }

    msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
    for eID,p := range emitter.peers {
	if eID.String() == "" || p == nil {
	    continue
	}
	
	if selfid == eID {
	    if myself == true {
		    common.Debug("============= p2pBroatcastPeers,send to myself =============", "msg hash", msghash)
		    go callEvent(msg, eID.String())
	    }
	    continue
	}
	
	for i:=0;i<20;i++ {
	    emitter.Lock()
	    if err := p2p.Send(p.ws, uint64(msgCode), msg); err != nil {
		//common.Error("============ p2pBroatcastPeers =============", "i",i,"send to peer eID", eID.String(), "msg hash", msghash,"err",err)
		if i == 19 {
			common.Error("============ p2pBroatcastPeers,send msg to peer terminal fail =============", "i",i,"send to peer eID", eID.String(), "send msg hash", msghash,"err",err)
		}

	    } else {
		    common.Info("============ p2pBroatcastPeers,send msg to peer terminal success =============", "i",i,"send to peer eID", eID.String(), "send msg hash", msghash)
		    emitter.Unlock()
		    break 
	    }
	    
	    emitter.Unlock()

	    //err = sendMsgToBroadcastNode(node.ID, msg)
	    //if err == nil {
		//break
	    //}

	    //time.Sleep(time.Duration(1) * time.Second)
	    time.Sleep(time.Duration(1000) * time.Millisecond)
	}
	
	time.Sleep(time.Duration(100) * time.Millisecond)
    }

    return 1
}

//--------------------------------------------------------

func p2pBroatcast(dccpGroup *discover.Group, msg string, msgCode int, myself bool) int {
    	if msg == "" {
	    return 0
	}
	msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()

	//cdLen := getCDLen(msg)
	//common.Debug("==== p2pBroatcast() ====", "group", dccpGroup, "msg", msg[:cdLen])
	if dccpGroup == nil {
		//common.Debug("==== p2pBroatcast() ====", "group", "nil", "msg", msg[:cdLen])
		common.Error("============== p2pBroatcast,get group fail ================", "orig msg hash", msghash)
		return 0
	}

	/*pi := p2pServer.PeersInfo()
	for _, pinfo := range pi {
		common.Debug("==== p2pBroatcast() ====", "peers.Info", pinfo)
	}*/

	var ret int = 0
	//wg := &sync.WaitGroup{}
	//wg.Add(len(dccpGroup.Nodes))
	for _, node := range dccpGroup.Nodes {
		//common.Debug("==== p2pBroatcast() ====", "nodeID", node.ID, "len", len(msg), "group", dccpGroup, "msg", msg[:cdLen])
		if selfid == node.ID {
			if myself == true {
				//common.Debug("==== p2pBroatcast() ====", "myself, group", dccpGroup, "msg", msg[:cdLen])
				go callEvent(msg, node.ID.String())
			}
			//wg.Done()
			continue
		}

		//go func(node discover.RpcNode) {
		//	defer wg.Done()
		//common.Debug("==== p2pBroatcast() ====", "call p2pSendMsg, group", dccpGroup, "msg", msg[:cdLen])
		//TODO, print node info from tab
		discover.PrintBucketNodeInfo(node.ID)
		//err := p2pSendMsg(node, uint64(msgCode), msg)
		err := SplitMsg(msg,node,msgCode)
		if err != nil {
			common.Error("============== p2pBroatcast,send msg to group node terminal fail ================", "orig msg hash",msghash,"send to node.IP",node.IP,"send to node.UDP",node.UDP,"send to node.ID",node.ID,"err",err,"msg len",len(msg))
			continue
		}
	
		go checkMsgStatus(msghash,msg,node,uint64(msgCode))

		//common.Debug("============== p2pBroatcast,send msg to group node terminal success ================", "orig msg hash", msghash,"send to node.IP",node.IP,"send to node.UDP",node.UDP,"send to node.ID",node.ID,"msg len",len(msg))
		//}(node)

		time.Sleep(time.Duration(80) * time.Millisecond)
	}

	//wg.Wait()
	return ret
}

func p2pSendMsg(node discover.RpcNode, msgCode uint64, msg string) error {
	//cdLen := getCDLen(msg)
	if msg == "" {
		common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID, "msg", "nil p2perror")
		return errors.New("p2pSendMsg msg is nil")
	}
	
	msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	//common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen])
	err := errors.New("p2pSendMsg err")
	countSendFail := 0
	for {
		/*emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
				common.Error("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen],"send", "fail waitting resend")
				//common.Error("================== p2pSendMsg,send fail =================", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg hash",msghash,"err",err)
				//emitter.Unlock()
				//return err
			} else {
				emitter.Unlock()
				//common.Debug("================== p2pSendMsg,send success with tcp =================", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg hash",msghash)
				//common.Info("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "countSend", countSendFail, "msg", msg[:cdLen], "send", "success")
				return nil
			}
		} else {
			common.Error("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID,"peer", "not exist p2perror continue")
			//common.Error("================== p2pSendMsg,not exist peer =================", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg hash",msghash)
		}

		emitter.Unlock()*/

		err = sendMsgToBroadcastNode(node.ID, msg)
		if err == nil {
			common.Debug("================== p2pSendMsg,send success with udp =================", "send to node.IP", node.IP, "send to node.UDP", node.UDP, "send to node.ID", node.ID, "send msg hash",msghash,"msg len",len(msg))
			return nil
		}

		countSendFail += 1
		if countSendFail >= 20 {
			//common.Error("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "terminal send", "fail p2perror", "sendCount", countSendFail)
			break
		}
		if countSendFail == 1 || countSendFail%5 == 0 {
			//common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "send", "fail p2perror", "sendCount", countSendFail)
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
	return err
}

func sendMsgToBroadcastNode(nid discover.NodeID, msg string) error {
	//msghash := crypto.Keccak256Hash([]byte(strings.ToLower(msg))).Hex()
	node := p2p.GetStaticNode(nid)
	if node == nil {
		common.Warn("sendMsgToBroadcastNode p2p.GetStaticNode node not exist","nodeid", nid)
		//common.Error("======================sendMsgToBroadcastNode, p2p.GetStaticNode node not exist==================","nodeid", nid,"msg hash",msghash)
		return  errors.New("GetStaticNode node not exist")
	}
	//common.Debug("sendMsgToBroadcastNode","nodeid", nid, "node", node)
	return discover.SendMsgToBroadcastNode(node, msg)

}

func getGroupAndCode(gid discover.NodeID, p2pType int) (*discover.Group, int) {
	msgCode := peerMsgCode
	var xvcGroup *discover.Group = nil
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if SdkGroup != nil {
			_, xvcGroup = getGroupSDK(gid)
			msgCode = Sdk_msgCode
		}
		break
	case SmpcProtocol_type:
		if dccpGroup != nil {
			xvcGroup = dccpGroup
			msgCode = Smpc_msgCode
		}
		break
	case Xprotocol_type:
		if xpGroup != nil {
			xvcGroup = xpGroup
			msgCode = Xp_msgCode
		}
		break
	default:
		return nil, msgCode
	}
	return xvcGroup, msgCode
}

func GetGroupSDKAll() []*discover.Group { //nooo
	var groupTmp []*discover.Group
	for _, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		groupTmp = append(groupTmp, g)
	}
	return groupTmp
}

func getGroupSDK(gid discover.NodeID) (discover.NodeID, *discover.Group) { //nooo
	for id, g := range SdkGroup {
		if g.Type != "1+1+1" && g.Type != "1+2" {
			continue
		}
		index := id.String()
		gf := gid.String()
		if index[:8] == gf[:8] {
			return id, g
		}
	}
	return discover.NodeID{}, nil
}

func init() {
	emitter = NewEmitter()
	discover.RegisterGroupCallback(recvGroupInfo)
}
func NewEmitter() *Emitter {
	return &Emitter{peers: make(map[discover.NodeID]*peer)}
}

// update p2p
func (e *Emitter) addPeer(p *p2p.Peer, ws p2p.MsgReadWriter) {
	e.Lock()
	defer e.Unlock()
	common.Info("=============== addPeer() ================", "id", p.ID().String()[:8])
	discover.RemoveSequenceDoneRecv(p.ID().String())
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}, knownTxs: mapset.NewSet()}
	enode := fmt.Sprintf("enode://%v@%v", p.ID().String(), p.RemoteAddr())
	node, _ := discover.ParseNode(enode)
	p2pServer.AddTrustedPeer(node)
	discover.UpdateOnLine(p.ID(), true)
	discover.AddNodes(p.ID())
}

func (e *Emitter) removePeer(p *p2p.Peer) {
	e.Lock()
	defer e.Unlock()
	discover.UpdateOnLine(p.ID(), false)
	common.Info("=============== removePeer() ================", "id", p.ID().String()[:8])
	return
	//enode := fmt.Sprintf("enode://%v@%v", p.ID().String(), p.RemoteAddr())
	//node, _ := discover.ParseNode(enode)
	//p2pServer.RemoveTrustedPeer(node)
	//discover.Remove(node)
	//delete(e.peers, p.ID())
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	emitter.addPeer(peer, rw)
	//go discover.UpdateGroupSDKNode(peer.ID(), peer.RemoteAddr())
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			common.Debug("==== handle() ====", "peerID", peer.ID(), "w.ReadMsg err", err)
			rw = emitter.peers[peer.ID()].ws
			time.Sleep(time.Duration(1) * time.Second)
			//continue
			//emitter.removePeer(peer)
			return err
		}
		switch msg.Code {
		case peerMsgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Debug("==== handle() ==== p2pBroatcast", "Err: decode msg err", err)
				return err
			} else {
				common.Debug("==== handle() ==== p2pBroatcast", "Recv callEvent(), peerMsgCode fromID", peer.ID().String(), "msg", string(recv))
				go callEvent(string(recv), peer.ID().String())
			}
			break
		case Sdk_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Debug("==== handle() ==== p2pBroatcast", "Err: decode sdk msg err", err)
				return err
			} else {
				cdLen := getCDLen(string(recv))
				common.Debug("==== handle() ==== p2pBroatcast", "Recv Sdk_callEvent(), Sdk_msgCode fromID", peer.ID().String(), "msg", string(recv)[:cdLen])
				go Sdk_callEvent(string(recv), peer.ID().String())
			}
			break
		case Smpc_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Info("Err: decode msg", "err", err)
				return err
			} else {
				go Smpc_callEvent(string(recv))
			}
			break
		case Xp_msgCode:
			var recv []byte
			err := rlp.Decode(msg.Payload, &recv)
			if err != nil {
				common.Debug("Err: decode msg", "err", err)
				return err
			} else {
				go Xp_callEvent(string(recv))
			}
			break
		default:
			common.Debug("unkown msg code", "", "")
			break
		}
	}
	return nil
}

// receive message form peers
func RegisterCallback(recvFunc func(interface{}, string)) {
	callback = recvFunc
}
func callEvent(msg, fromID string) {
	common.Debug("==== callEvent() ====", "fromID", fromID, "msg", msg)
	callback(msg, fromID)
}

func GetSelfID() string {
	return discover.GetLocalID().String()
}

func GetEnode() string {
	return discover.GetEnode()
}

func getGroup(gid discover.NodeID, p2pType int) (int, string) {
	var xvcGroup *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		discover.GroupSDK.Lock()
		defer discover.GroupSDK.Unlock()
		if SdkGroup != nil {
			_, xvcGroup = getGroupSDK(gid)
		}
		break
	case SmpcProtocol_type:
		if dccpGroup == nil {
			return 0, ""
		}
		xvcGroup = dccpGroup
		break
	case Xprotocol_type:
		if xpGroup == nil {
			return 0, ""
		}
		xvcGroup = xpGroup
		break
	default:
		return 0, ""
	}
	enode := ""
	count := 0
	if xvcGroup == nil {
		return count, enode
	}
	for _, e := range xvcGroup.Nodes {
		if enode != "" {
			enode += discover.Smpcdelimiter
		}
		enode += fmt.Sprintf("enode://%v@%v:%v", e.ID, e.IP, e.UDP)
		count++
	}
	return count, enode
}

func recvGroupInfo(gid discover.NodeID, mode string, req interface{}, p2pType int, Type string) {
	common.Info("================ recvGroupInfo() =================", "gid", gid, "req", req)
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	var xvcGroup *discover.Group
	switch p2pType {
	case Sdkprotocol_type:
		if SdkGroup[gid] != nil {
			//TODO: check IP,UDP
			_, groupTmp := getGroupSDK(gid)
			idcount := 0
			for _, enode := range req.([]*discover.Node) {
				node, _ := discover.ParseNode(enode.String())
				for _, n := range groupTmp.Nodes {
					if node.ID == n.ID {
						ipp1 := fmt.Sprintf("%v:%v", node.IP, node.UDP)
						ipp2 := fmt.Sprintf("%v:%v", n.IP, n.UDP)
						if ipp1 == ipp2 {
							idcount += 1
							break
						}
						break
					}
				}
			}
			if idcount == len(req.([]*discover.Node)) {
				common.Debug("==== recvGroupInfo() ====", "exist gid", gid)
				return
			}
		}
		groupTmp := discover.NewGroup()
		groupTmp.ID = gid
		groupTmp.Mode = mode
		groupTmp.P2pType = byte(p2pType)
		groupTmp.Type = Type
		SdkGroup[gid] = groupTmp
		xvcGroup = groupTmp
		break
	case SmpcProtocol_type:
		dccpGroup = discover.NewGroup()
		xvcGroup = dccpGroup
		break
	case Xprotocol_type:
		xpGroup = discover.NewGroup()
		xvcGroup = xpGroup
		break
	default:
		return
	}
	updateGroupNodesNumber(len(req.([]*discover.Node)), p2pType)
	xvcGroup.Nodes = make([]discover.RpcNode, 0)
	for _, enode := range req.([]*discover.Node) {
		node, _ := discover.ParseNode(enode.String())
		xvcGroup.Nodes = append(xvcGroup.Nodes, discover.RpcNode{ID: node.ID, IP: node.IP, UDP: node.UDP, TCP: node.UDP})
		if node.ID != selfid {
			go p2pServer.AddPeer(node)
			go p2pServer.AddTrustedPeer(node)
		}
	}
	common.Debug("==== recvGroupInfo() ====", "Store Group", xvcGroup)
	err := discover.StoreGroupToDb(xvcGroup)
	if err != nil {
	    return
	}

	err = discover.RecoverGroupAll(SdkGroup)
	if err != nil {
	    return
	}

	if false {
		var testGroup map[discover.NodeID]*discover.Group = make(map[discover.NodeID]*discover.Group) //TODO delete
		err = discover.RecoverGroupAll(testGroup)
		if err != nil {
		    return
		}

		common.Debug("==== recvGroupInfo() ====", "Recov test Group", testGroup)
		for i, g := range testGroup {
			common.Debug("testGroup", "i", i, "g", g)
		}
	}
	err = discover.RecoverGroupAll(discover.SDK_groupList) // Group
	if err != nil {
	    return
	}
}

func Broadcast(msg string) {
	if msg == "" || emitter == nil {
		return
	}
	emitter.Lock()
	defer emitter.Unlock()
	func() {
		for _, p := range emitter.peers {
			if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
				continue
			}
		}
	}()
}

func SendMsgToPeer(enode string, msg string) error {
	node, _ := discover.ParseNode(enode)
	countSendFail := 0
	for {
		emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err := p2p.Send(p.ws, peerMsgCode, msg); err != nil {
				common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "p2perror", err, "countSend", countSendFail)
				return err
			} else {
				common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "SUCCESS, countSend", countSendFail)
				emitter.Unlock()
				return nil
			}
		}
		emitter.Unlock()

		countSendFail += 1
		if countSendFail > 3000 {
			common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "msg", msg, "timeout fail", "")
			break
		}
		if countSendFail <= 1 || countSendFail%100 == 0 {
			common.Debug("==== SendMsgToPeer() ====", "send to node", node.ID, "fail, countSend", countSendFail)
		}
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
	return errors.New(retMsg)
}

func SendToMyself(enode, msg string, p2pType int) error {
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	if _, err := discover.SendToGroupCC(node.ID, ipa, msg, p2pType); err == nil {
		return err
	}
	return nil
}

func SendToPeer(enode string, msg string) {
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	err := discover.SendMsgToNode(node.ID, ipa, msg)
	if err != nil {
	    return
	}
}

// broadcastInGroup will propagate a batch of message to all peers which are not known to
// already have the given message.
func (e *Emitter) broadcastInGroup(tx Transaction) {
	e.Lock()
	defer e.Unlock()

	var txset = make(map[*peer][]Transaction)

	// Broadcast message to a batch of peers not knowing about it
	peers := e.peersWithoutTx(tx.hash(), true)
	for _, peer := range peers {
		txset[peer] = append(txset[peer], tx)
	}

	for peer, txs := range txset {
		peer.sendTx(txs)
	}
}

// group: true, in group
//        false, peers
func (e *Emitter) peersWithoutTx(hash common.Hash, group bool) []*peer {
	list := make([]*peer, 0, len(e.peers))
	if group == true {
		if dccpGroup == nil || len(dccpGroup.Nodes) == 0 {
			return list
		}
		for _, n := range dccpGroup.Nodes {
			if n.ID == selfid {
				continue
			}
			p := e.peers[n.ID]
			if p != nil && !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	} else {
		for _, p := range e.peers {
			if !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	}
	return list
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *peer) sendTx(txs []Transaction) {
	for _, tx := range txs {
		if err := p2p.Send(p.ws, Smpc_msgCode, string(tx.Payload)); err != nil {
			if len(p.queuedTxs) >= maxKnownTxs {
				p.knownTxs.Pop()
			}
			p.knownTxs.Add(tx.hash())
		}
	}
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) hash() common.Hash {
	if hash := tx.Hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx.Payload)
	var tmp common.Hash
	if v == tmp {
	    return tmp
	}

	tx.Hash.Store(v)
	return v
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	err := rlp.Encode(hw, x)
	if err != nil {
	    return
	}

	hw.Sum(h[:0])
	return h
}

func updateGroupNodesNumber(number, p2pType int) {
	discover.UpdateGroupNodesNumber(number, p2pType)
}

func InitSelfNodeID(nodeid string) {
	sid, _ := HexID(nodeid)
	discover.SelfNodeID = sid
	common.Info("==== InitSelfNodeID() ====", "SelfNodeID", sid)
}

func InitP2pDir() {
	discover.InitP2pDir()
}

func InitServer(nodeserv interface{}) {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	selfid = discover.GetLocalID()
	p2pServer = nodeserv.(p2p.Server)
	err := discover.RecoverGroupAll(SdkGroup)
	if err != nil {
	    return
	}

	for i, g := range SdkGroup {
		common.Debug("==== InitServer() ====", "GetGroupFromDb, g", g)
		for _, node := range g.Nodes {
			common.Debug("==== InitServer() ====", "gid", i, "node", node)
			if node.ID != selfid {
				err = discover.PingNode(node.ID, node.IP, int(node.UDP))
				if err != nil {
				    return
				}
				en := discover.NewNode(node.ID, node.IP, node.UDP, node.TCP)
				go p2pServer.AddPeer(en)
				go p2pServer.AddTrustedPeer(en)
			}
		}
	}
	err = discover.RecoverGroupAll(discover.SDK_groupList) // Group
	if err != nil {
	    return
	}
	common.Debug("InitServer", "init Group info", "finished")
	go discover.UpdateMyselfIP()
}

func getCDLen(msg string) int {
	if len(msg) > 214 {
		return 214
	}
	return len(msg)
}
