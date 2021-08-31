/*
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019  huangweijun@anyswap.exchange
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
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/anyswap/Anyswap-MPCNode/crypto"
	"github.com/anyswap/Anyswap-MPCNode/internal/common"
	"github.com/anyswap/Anyswap-MPCNode/p2p"
	"github.com/anyswap/Anyswap-MPCNode/p2p/discover"
	"github.com/anyswap/Anyswap-MPCNode/rpc"
)

// txs start
func SmpcProtocol_sendToGroupOneNode(msg string) (string, error) {
	return discover.SendToGroup(discover.NodeID{}, msg, false, SmpcProtocol_type, nil)
}

// broadcast
// to group's nodes
func SmpcProtocol_broadcastInGroupAll(msg string) { // within self
	BroadcastToGroup(discover.NodeID{}, msg, SmpcProtocol_type, true)
}

func SmpcProtocol_broadcastInGroupOthers(msg string) { // without self
	BroadcastToGroup(discover.NodeID{}, msg, SmpcProtocol_type, false)
}

// unicast
// to anyone
func SmpcProtocol_sendMsgToNode(toid discover.NodeID, toaddr *net.UDPAddr, msg string) error {
	fmt.Printf("==== SendMsgToNode() ====\n")
	return discover.SendMsgToNode(toid, toaddr, msg)
}

// to peers
func SmpcProtocol_sendMsgToPeer(enode string, msg string) error {
	return SendMsgToPeer(enode, msg)
}

// callback
// receive private key
func SmpcProtocol_registerPriKeyCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegisterPriKeyCallback(recvPrivkeyFunc)
}

func Sdk_callEvent(msg string, fromID string) {
	common.Debug("Sdk_callEvent", "", "")
	Sdk_callback(msg, fromID)
}

// receive message form peers
func SmpcProtocol_registerRecvCallback(recvSmpcFunc func(interface{}) <-chan string) {
	Smpc_callback = recvSmpcFunc
}
func Smpc_callEvent(msg string) {
	Smpc_callback(msg)
}

// receive message from dccp
func SmpcProtocol_registerMsgRecvCallback(smpccallback func(interface{}) <-chan string) {
	discover.RegisterSmpcMsgCallback(smpccallback)
}

// receive message from dccp result
func SmpcProtocol_registerMsgRetCallback(smpccallback func(interface{})) {
	discover.RegisterSmpcMsgRetCallback(smpccallback)
}

// get info
func SmpcProtocol_getGroup() (int, string) {
	return getGroup(discover.NodeID{}, SmpcProtocol_type)
}

func (smpc *SmpcAPI) Version(ctx context.Context) (v string) {
	return ProtocolVersionStr
}
func (smpc *SmpcAPI) Peers(ctx context.Context) []*p2p.PeerInfo {
	var ps []*p2p.PeerInfo
	for _, p := range smpc.smpc.peers {
		ps = append(ps, p.peer.Info())
	}

	return ps
}

// Protocols returns the whisper sub-protocols ran by this particular client.
func (smpc *Smpc) Protocols() []p2p.Protocol {
	return []p2p.Protocol{smpc.protocol}
}

// p2p layer 2
// New creates a Whisper client ready to communicate through the Ethereum P2P network.
func SmpcNew(cfg *Config) *Smpc {
	smpc := &Smpc{
		peers: make(map[discover.NodeID]*peer),
		quit:  make(chan struct{}),
		cfg:   cfg,
	}

	// p2p smpc sub protocol handler
	smpc.protocol = p2p.Protocol{
		Name:    ProtocolName,
		Version: ProtocolVersion,
		Length:  NumberOfMessageCodes,
		Run:     HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version": ProtocolVersionStr,
			}
		},
		PeerInfo: func(id discover.NodeID) interface{} {
			if p := emitter.peers[id]; p != nil {
				return p.peerInfo
			}
			return nil
		},
	}

	return smpc
}

// other
// Start implements node.Service, starting the background data propagation thread
// of the Whisper protocol.
func (smpc *Smpc) Start(server *p2p.Server) error {
	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (smpc *Smpc) Stop() error {
	return nil
}

// APIs returns the RPC descriptors the Whisper implementation offers
func (smpc *Smpc) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: ProtocolName,
			Version:   ProtocolVersionStr,
			Service:   &SmpcAPI{smpc: smpc},
			Public:    true,
		},
	}
}

func SmpcProtocol_getEnodes() (int, string) {
	return getGroup(discover.NodeID{}, SmpcProtocol_type)
}

//=============================== SMPC =================================
func SendMsg(msg string) {
	//BroadcastToGroup(discover.NodeID{}, msg, SmpcProtocol_type)
	SmpcProtocol_broadcastInGroupOthers(msg)
}

func SendToSmpcGroupAllNodes(msg string) (string, error) {
	return discover.SendToGroup(discover.NodeID{}, msg, true, SmpcProtocol_type, nil)
}

func RegisterRecvCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegisterPriKeyCallback(recvPrivkeyFunc)
}

func RegisterSmpcCallback(smpccallback func(interface{}) <-chan string) {
	discover.RegisterSmpcMsgCallback(smpccallback)
	SmpcProtocol_registerRecvCallback(smpccallback)
}

func RegisterSmpcRetCallback(smpccallback func(interface{})) {
	discover.RegisterSmpcMsgRetCallback(smpccallback)
}

func GetGroup() (int, string) {
	return SmpcProtocol_getGroup()
}

func GetEnodes() (int, string) {
	return GetGroup()
}

func RegisterSendCallback(callbackfunc func(interface{})) {
	discover.RegisterSendCallback(callbackfunc)
}

func ParseNodeID(enode string) string {
	node, err := discover.ParseNode(enode)
	if err != nil {
		common.Info("==== ParseNodeID() ====", "enode", enode, "error", err.Error())
		return ""
	}
	return node.ID.String()
}

func HexID(gID string) (discover.NodeID, error) {
	return discover.HexID(gID)
}

//================   API   SDK    =====================
func SdkProtocol_sendToGroupOneNode(gID, msg string) (string, error) {
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		common.Debug("sendToGroupOneNode", "not exist group gid", gid)
		return "", errors.New("sendToGroupOneNode, gid not exist")
	}
	g := getSDKGroupNodes(gid)
	return discover.SendToGroup(gid, msg, false, Sdkprotocol_type, g)
}

func getSDKGroupNodes(gid discover.NodeID) []*discover.Node {
	g := make([]*discover.Node, 0)
	_, xvcGroup := getGroupSDK(gid)
	if xvcGroup == nil {
		return g
	}
	for _, rn := range xvcGroup.Nodes {
		n := discover.NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
		g = append(g, n)
	}
	return g
}

func SdkProtocol_SendToGroupAllNodes(gID, msg string) (string, error) {
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("SendGroupAllNodes, group gid: %v not exist", gid)
		common.Debug("SendGroupAllNodes", "not exist group gid", gid)
		return "", errors.New(e)
	}
	g := getSDKGroupNodes(gid)
	return discover.SendToGroup(gid, msg, true, Sdkprotocol_type, g)
}

func SdkProtocol_broadcastInGroupOthers(gID, msg string) (string, error) { // without self
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("broadcastInGroupOthers, group gid: %v not exist", gid)
		common.Debug("broadcastInGroupOthers", "not exist group gid", gid)
		return "", errors.New(e)
	}
	return BroadcastToGroup(gid, msg, Sdkprotocol_type, false)
}

func SdkProtocol_broadcastInGroupAll(gID, msg string) (string, error) { // within self
	gid, _ := discover.HexID(gID)
	if checkExistGroup(gid) == false {
		e := fmt.Sprintf("broadcastInGroupAll, group gid: %v not exist", gid)
		common.Debug("broadcastInGroupAll", "not exist group gid", gid)
		return "", errors.New(e)
	}
	return BroadcastToGroup(gid, msg, Sdkprotocol_type, true)
}

func SdkProtocol_getGroup(gID string) (int, string) {
	gid, err := discover.HexID(gID)
	if err != nil || checkExistGroup(gid) == false {
		common.Debug("broadcastInGroupAll", "not exist group gID", gID, "hexid-gid", gid)
		return 0, ""
	}
	return getGroup(gid, Sdkprotocol_type)
}

func checkExistGroup(gid discover.NodeID) bool {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	if SdkGroup[gid] != nil {
		if SdkGroup[gid].Type == "1+2" || SdkGroup[gid].Type == "1+1+1" {
			return true
		}
	}
	return false
}

//  ---------------------   API  callback   ----------------------
// recv from broadcastInGroup...
func SdkProtocol_registerBroadcastInGroupCallback(recvSdkFunc func(interface{}, string)) {
	Sdk_callback = recvSdkFunc
}

// recv from sendToGroup...
func SdkProtocol_registerSendToGroupCallback(sdkcallback func(interface{}, string) <-chan string) {
	discover.RegisterSdkMsgCallback(sdkcallback)
}

// recv return from sendToGroup...
func SdkProtocol_registerSendToGroupReturnCallback(sdkcallback func(interface{}, string)) {
	discover.RegisterSdkMsgRetCallback(sdkcallback)
}

// 1 + 1 + 1
func CreateSDKGroup(threshold string, enodes []string, subGroup bool) (string, int, string) {
	es := strings.Split(threshold, "/")
	if len(es) != 2 {
		msg := fmt.Sprintf("args threshold(%v) format is wrong", threshold)
		return "", 0, msg
	}
	nodeNum0, _ := strconv.Atoi(es[0])
	count := len(enodes)
	enode := []*discover.Node{}
	var tmpEnodes []string
	for i, e := range enodes {
		node, err := discover.ParseNode(e)
		if err != nil {
			common.Info("CreateSDKGroup", "parse err", e)
			return "", 0, "enode wrong format"
		}
		enode = append(enode, node)
		if subGroup {
			if i >= nodeNum0 {
				continue
			}
		}
		tmpEnodes = append(tmpEnodes, e)
	}
	gid, err := getGIDFromEnodes(tmpEnodes)
	common.Debug("CreateSDKGroup", "gid <- id", gid, "err", err)
	discover.GroupSDK.Lock()
	exist := false
	for i := range SdkGroup {
		if i == gid {
			exist = true
			break
		}
	}
	discover.GroupSDK.Unlock()
	retErr := discover.StartCreateSDKGroup(gid, threshold, enode, "1+1+1", exist, subGroup)
	return gid.String(), count, retErr
}

func GetGIDFromEnodes(enodes []string) (string, error) {
	gid, err := getGIDFromEnodes(enodes)
	if err != nil {
		return "", err
	}
	return gid.String(), err
}

func getGIDFromEnodes(enodes []string) (discover.NodeID, error) {
	sort.Sort(sort.StringSlice(enodes))
	id := []byte("")
	for _, un := range enodes {
		common.Debug("CreateSDKGroup", "for enode", un)
		node, err := discover.ParseNode(un)
		if err != nil {
			common.Debug("CreateSDKGroup", "parse err", un)
			return discover.NodeID{}, err
		}
		common.Debug("CreateSDKGroup", "for selfid", selfid, "node.ID", node.ID)
		n := fmt.Sprintf("%v", node.ID)
		common.Debug("CreateSDKGroup", "n", n)
		if len(id) == 0 {
			id = crypto.Keccak512([]byte(node.ID.String()))
		} else {
			id = crypto.Keccak512(id, []byte(node.ID.String()))
		}
	}
	return discover.BytesID(id)
}

func GetEnodeStatus(enode string) (string, error) {
	return discover.GetEnodeStatus(enode)
}

func CheckAddPeer(threshold string, enodes []string, subGroup bool) (bool, error) {
	thshall := false
	es := strings.Split(threshold, "/")
	if len(es) != 2 {
		msg := fmt.Sprintf("args threshold(%v) format is wrong", threshold)
		return thshall, errors.New(msg)
	}
	nodeNum0, _ := strconv.Atoi(es[0])
	nodeNum1, _ := strconv.Atoi(es[1])
	if len(enodes) < nodeNum0 || len(enodes) > nodeNum1 {
		msg := fmt.Sprintf("args threshold(%v) and enodes(%v) not match", threshold, enodes)
		return thshall, errors.New(msg)
	}
	if nodeNum0 == nodeNum1 {
		thshall = true
	}
	if subGroup {// sub group
		if len(enodes) != nodeNum1 {
			msg := fmt.Sprintf("args threshold(%v) and enodes(%v) not match subGroup", threshold, enodes)
			return thshall, errors.New(msg)
		}
	}
	var nodeid map[discover.NodeID]int = make(map[discover.NodeID]int, len(enodes))
	defer func() {
		for k := range nodeid {
			delete(nodeid, k)
		}
	}()
	selfEnodeExist := false
	wg := &sync.WaitGroup{}
	for _, enode := range enodes {
		node, err := discover.ParseNode(enode)
		if err != nil {
			msg := fmt.Sprintf("CheckAddPeer, parse err enode: %v", enode)
			return thshall, errors.New(msg)
		}
		if nodeid[node.ID] == 1 {
			msg := fmt.Sprintf("CheckAddPeer, enode: %v, err: repeated", enode)
			return thshall, errors.New(msg)
		}
		nodeid[node.ID] = 1
		if selfid == node.ID {
			selfEnodeExist = true
			continue
		}

		go func(node *discover.Node) {
			wg.Add(1)
			defer wg.Done()
			p2pServer.AddPeer(node)
			p2pServer.AddTrustedPeer(node)
		}(node)
	}
	wg.Wait()
	if selfEnodeExist != true {
		msg := fmt.Sprintf("CheckAddPeer, slefEnode: %v, err: selfEnode not exist", discover.GetEnode())
		return thshall, errors.New(msg)
	}
	return thshall, nil
}

func InitIPPort(port int) {
	discover.InitIP(getLocalIP(), uint16(port))
}

func getLocalIP() string {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		common.Debug("getLocalIP", "net.Interfaces failed, err", err.Error())
		return ""
	}

	internetIP := ""
	wlanIP := ""
	loopIP := ""
	for i, iface := range netInterfaces {
		var ip net.IP
		if (iface.Flags & net.FlagUp) != 0 {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip != nil {
					if ip.To4() != nil {
						if iface.Name == "WLAN" {
							wlanIP = ip.String()
						} else if ip.IsLoopback() {
							loopIP = ip.String()
						}else {
							if internetIP == "" {
								internetIP = ip.String()
							}
						}
						common.Debug("==== getLocalIP() ====", "i", i, "iface", iface, "ip", ip)
					}
				}
			}
		}
	}
	common.Debug("==== getLocalIP() ====", "internetIP", internetIP, "wlanIP", "wlanIP, (loopIP)", loopIP)
	if internetIP != "" {
		//fmt.Printf("\nip: %v\n", internetIP)
		return internetIP
	} else if wlanIP != "" {
		//fmt.Printf("\nip: %v\n", wlanIP)
		return wlanIP
	} else if loopIP != "" {
		//fmt.Printf("\nip: %v\n", loopIP)
		return loopIP
	}
	common.Debug("getLocalIP()", "ip", "is nil")
	return ""
}

func GetGroupList() map[discover.NodeID]*discover.Group {
	discover.GroupSDK.Lock()
	defer discover.GroupSDK.Unlock()
	return discover.SDK_groupList
}

func GetSelfDir() string {
	return discover.GetGroupDir()
}

