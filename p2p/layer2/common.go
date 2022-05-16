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
	"net"
	"time"

	"github.com/anyswap/FastMulThreshold-DSA/crypto/sha3"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
	"github.com/anyswap/FastMulThreshold-DSA/p2p"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/discover"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/rlp"
	mapset "github.com/deckarep/golang-set"
	"github.com/anyswap/FastMulThreshold-DSA/log"
	"github.com/onrik/ethrpc"
	"path/filepath"
	"os"
	"strings"
	"io/ioutil"
	"strconv"
	"encoding/json"
)

var (
	statDir = "stat"
)

func BroadcastToGroup(gid discover.NodeID, msg string, p2pType int, myself bool) (string, error) {
	cdLen := getCDLen(msg)
	common.Debug("==== BroadcastToGroup() ====", "gid", gid, "msg", msg[:cdLen])
	xvcGroup, msgCode := getGroupAndCode(gid, p2pType)
	if xvcGroup == nil {
		e := fmt.Sprintf("BroadcastToGroup p2pType=%v is not exist", p2pType)
		common.Debug("==== BroadcastToGroup ====", "p2pType", p2pType, "is not exist", "")
		return "", errors.New(e)
	}
	groupTmp := *xvcGroup
	go p2pBroatcast(&groupTmp, msg, msgCode, myself)
	return "BroadcastToGroup send end", nil
}

// StoreRPCPort save rpc port
func StoreRPCPort(pubdir string, rpcport int) {
	UpdateRPCPort(pubdir, fmt.Sprintf("%v", rpcport))
}

// DeleteRPCPort delete rpc port
func DeleteRPCPort(pubdir string) {
	UpdateRPCPort(pubdir, "")
}

// UpdateRPCPort update rpc port
func UpdateRPCPort(pubdir, rpcport string) {
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
	    err := os.MkdirAll(dir, os.ModePerm)
	    if err != nil {
		return
	    }
	}
	rpcfile := filepath.Join(dir, "rpcport")
	fmt.Printf("==== updateRPCPort() ====, rpcfile: %v, rpcport: %v\n", rpcfile, rpcport)
	f, err := os.Create(rpcfile)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		_, err = f.Write([]byte(rpcport))
		if err != nil {
		    return
		}
	}
}

// GetRPCPort get rpc port
func GetRPCPort(pubdir string) int {
	fmt.Printf("==== GetRPCPort() ====, pubdir: %v\n", pubdir)
	portDir := common.DefaultDataDir()
	dir := filepath.Join(portDir, statDir, pubdir)
	if common.FileExist(dir) != true {
		return 0
	}
	rpcfile := filepath.Join(dir, "rpcport")
	if common.FileExist(rpcfile) != true {
		return 0
	}

	port, err := ioutil.ReadFile(rpcfile)
	if err == nil {
		pp := strings.Split(string(port), "\n")
		p, err := strconv.Atoi(pp[0])
		fmt.Printf("==== GetRPCPort() ====, p: %v, err: %v\n", p, err)
		if err == nil {
			return p
		}
	}
	return 0
}

type response struct {
	Status string      `json:"Status"`
	Tip    string      `json:"Tip"`
	Error  string      `json:"Error"`
	Data   interface{} `json:"Data"`
}
type dataResult struct {
	Result string `json:"result"`
}
type dataEnode struct {
	Enode string `json:"Enode"`
}

// getJSONResult parse result from rpc return data
func getJSONResult(successResponse json.RawMessage) (string, error) {
	var data dataResult
	repData, err := getJSONData(successResponse)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(repData, &data); err != nil {
		fmt.Println("getJSONResult Unmarshal json fail:", err)
		return "", err
	}
	return data.Result, nil
}

func getJSONData(successResponse json.RawMessage) ([]byte, error) {
	var rep response
	if err := json.Unmarshal(successResponse, &rep); err != nil {
		fmt.Println("getJSONData Unmarshal json fail:", err)
		return nil, err
	}
	if rep.Status != "Success" {
		return nil, errors.New(rep.Error)
	}
	repData, err := json.Marshal(rep.Data)
	if err != nil {
		fmt.Println("getJSONData Marshal json fail:", err)
		return nil, err
	}
	return repData, nil
}

func GetEnodeList(url []string) []string {
    if len(url) == 0 {
	return nil
    }

    enodeList := make([]string, len(url))
    for i := 0; i < len(url); i++ {
	    client := ethrpc.New(url[i])
	    if client == nil {
		return nil
	    }

	    enodeRep, err := client.Call("smpc_getEnode")
	    if err != nil {
		log.Error("==================GetEnodeList,call error,try again====================", "i",i,"url",url[i],"err",err)
		vv := strings.Split(url[i],":")
		if len(vv) < 3 {
		    return nil
		}

		_,err = strconv.Atoi(vv[2])
		if err != nil {
		    log.Error("==================GetEnodeList====================", "i",i,"url",url[i],"err",err)
		   return nil 
		}

		tmpurl := "http://127.0.0.1:" + vv[2] 
		client = ethrpc.New(tmpurl)
		if client == nil {
		    return nil
		}
		
		enodeRep, err = client.Call("smpc_getEnode")
		if err != nil {
		    log.Error("==================GetEnodeList====================", "i",i,"url",url[i],"err",err)
		    return nil
		}
	    }

	    var enodeJSON dataEnode
	    enodeData, _ := getJSONData(enodeRep)
	    if err := json.Unmarshal(enodeData, &enodeJSON); err != nil {
		log.Error("==================GetEnodeList,unmarshal fail====================", "i",i,"url",url[i],"err",err)
		return nil
	    }

	    enodeList[i] = enodeJSON.Enode
	    log.Info("==================GetEnodeList====================", "i",i,"url",url[i],"enode",enodeList[i])
    }

    return enodeList
}

func SaveGroupRPCPort(url []string) {
    enodes := GetEnodeList(url)
    
    //save the rpc port
    // http://IP:RPCPORT
    for k,v := range url {
	vv := strings.Split(v,":")
	if len(vv) < 3 {
	    continue
	}

	rpcport,err := strconv.Atoi(vv[2])
	if err != nil {
	    log.Error("==================SaveGroupRPCPort====================", "k",k,"url",v,"err",err)
	    continue
	}

	nodeid, err := discover.ParseNode(enodes[k])
	if err != nil {
	    log.Error("==================SaveGroupRPCPort====================", "k",k,"url",v,"err",err)
		continue
	}

	log.Info("==================SaveGroupRPCPort====================", "k",k,"url",v,"enodeID",nodeid.ID.String(),"rpcport",rpcport)
	StoreRPCPort(nodeid.ID.String(), rpcport)
    }
    //
}

func p2pBroatcast(dccpGroup *discover.Group, msg string, msgCode int, myself bool) int {
	cdLen := getCDLen(msg)
	common.Debug("==== p2pBroatcast() ====", "group", dccpGroup, "msg", msg[:cdLen])
	if dccpGroup == nil {
		common.Debug("==== p2pBroatcast() ====", "group", "nil", "msg", msg[:cdLen])
		return 0
	}
	pi := p2pServer.PeersInfo()
	for _, pinfo := range pi {
		common.Debug("==== p2pBroatcast() ====", "peers.Info", pinfo)
	}
	var ret int = 0
	//wg := &sync.WaitGroup{}
	//wg.Add(len(dccpGroup.Nodes))
	for _, node := range dccpGroup.Nodes {
		common.Debug("==== p2pBroatcast() ====", "nodeID", node.ID, "len", len(msg), "group", dccpGroup, "msg", msg[:cdLen])
		if selfid == node.ID {
			if myself == true {
				common.Debug("==== p2pBroatcast() ====", "myself, group", dccpGroup, "msg", msg[:cdLen])
				go callEvent(msg, node.ID.String())
			}
			//wg.Done()
			continue
		}
		//go func(node discover.RpcNode) {
		//	defer wg.Done()
		common.Debug("==== p2pBroatcast() ====", "call p2pSendMsg, group", dccpGroup, "msg", msg[:cdLen])
		//TODO, print node info from tab
		discover.PrintBucketNodeInfo(node.ID)
		err := p2pSendMsg(node, uint64(msgCode), msg)
		if err != nil {
			//
			self := fmt.Sprintf("%v",selfid)
			enodeID := fmt.Sprintf("%v",node.ID)
			nodeIP := fmt.Sprintf("%v",node.IP)
			nodePort := fmt.Sprintf("%v",node.UDP)
			rpc := GetRPCPort(enodeID)
			if rpc == 0 {
				log.Error("=====================p2pBroatcast,send fail,get rpc port fail==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort)
			    continue
			}

			rpcstr := strconv.Itoa(rpc)
			if rpcstr == "" {
				log.Error("=====================p2pBroatcast,send fail,get rpc port fail==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort,"rpcport",rpc)
			    continue
			}

			log.Debug("=====================p2pBroatcast,send fail,resend with rpc==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort,"Rpc",rpcstr)
			url := "http://" + nodeIP + ":" + rpcstr
			client := ethrpc.New(url)
			if client != nil {
				_, err = client.Call("smpc_callPeer", msg, self)
				if err != nil {
					log.Error("=====================p2pBroatcast,send fail,resend with rpc==================","err",err)
					url = "http://127.0.0.1:" + rpcstr
					client = ethrpc.New(url)
					if client != nil {
						_, err = client.Call("smpc_callPeer", msg, self)
						if err != nil {
							log.Error("=====================p2pBroatcast,try again send fail,resend with rpc==================","err",err)
							continue
						}
					}

					continue
				}
			}
			//

			continue
		}
		//}(node)
		time.Sleep(time.Duration(100) * time.Millisecond)
	}
	//wg.Wait()
	return ret
}

func p2pSendMsg(node discover.RpcNode, msgCode uint64, msg string) error {
	cdLen := getCDLen(msg)
	if msg == "" {
		common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID, "msg", "nil p2perror")
		return errors.New("p2pSendMsg msg is nil")
	}
	common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen])
	err := errors.New("p2pSendMsg err")
	countSendFail := 0
	for {
		emitter.Lock()
		p := emitter.peers[node.ID]
		if p != nil {
			if err = p2p.Send(p.ws, msgCode, msg); err != nil {
				common.Error("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "send", "fail waitting resend")
				//emitter.Unlock()
				//return err
			} else {
				emitter.Unlock()
				common.Info("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "countSend", countSendFail, "msg", msg[:cdLen], "send", "success")
				return nil
			}
		} else {
			common.Error("==== p2pSendMsg() ==== p2pBroatcast", "nodeID", node.ID, "peer", "not exist p2perror continue")
		}

		/*ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
		err := discover.SendMsgToNode(node.ID, ipa, msg)
		if err == nil {
		    emitter.Unlock()
		    common.Info("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "countSend", countSendFail, "msg", msg[:cdLen], "send", "success")
		    return nil
		}
		common.Error("====================p2pSendMsg()=================","send msg to node error",err)*/

		emitter.Unlock()

		countSendFail += 1
		if countSendFail >= 30 {
			common.Error("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "terminal send", "fail p2perror", "sendCount", countSendFail)
			break
		}
		if countSendFail == 1 || countSendFail%5 == 0 {
			common.Debug("==== p2pSendMsg() ==== p2pBroatcast", "node.IP", node.IP, "node.UDP", node.UDP, "node.ID", node.ID, "msg", msg[:cdLen], "send", "fail p2perror", "sendCount", countSendFail)
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
	return err
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
				//return err
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

	//
	self := fmt.Sprintf("%v",selfid)
	enodeID := fmt.Sprintf("%v",node.ID)
	nodeIP := fmt.Sprintf("%v",node.IP)
	nodePort := fmt.Sprintf("%v",node.UDP)
	rpc := GetRPCPort(enodeID)
	if rpc == 0 {
	    log.Error("=====================SendMsgToPeer,send fail,get rpc port fail==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort)
	    retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
	    return errors.New(retMsg)
	}

	rpcstr := strconv.Itoa(rpc)
	if rpcstr == "" {
	    log.Error("=====================SendMsgToPeer,send fail,get rpc port fail==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort,"rpcport",rpc)
	    retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
	    return errors.New(retMsg)
	}

	log.Debug("=====================SendMsgToPeer,send fail,resend with rpc==================","enodeID",enodeID,"IP",nodeIP,"Port",nodePort,"Rpc",rpcstr)
	url := "http://" + nodeIP + ":" + rpcstr
	client := ethrpc.New(url)
	if client != nil {
	    _, err := client.Call("smpc_callPeer", msg, self)
		if err != nil {
			log.Error("=====================SendMsgToPeer,send fail,resend with rpc==================","err",err)
			url = "http://127.0.0.1:" + rpcstr
			client = ethrpc.New(url)
			if client != nil {
				_, err = client.Call("smpc_callPeer", msg, self)
				if err != nil {
				    log.Error("=====================SendMsgToPeer,try again send fail,resend with rpc==================","err",err)
				    retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
				    return errors.New(retMsg)
				}

				return nil
			}
			
			retMsg := fmt.Sprintf("==== SendMsgToPeer() ====, send msg: %v to node: %v timeout err", msg, node.ID)
			return errors.New(retMsg)
		}

		return nil
	}
	//
	
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
	discover.SDK_groupListChan <- 1
}

func getCDLen(msg string) int {
	if len(msg) > 214 {
		return 214
	}
	return len(msg)
}
