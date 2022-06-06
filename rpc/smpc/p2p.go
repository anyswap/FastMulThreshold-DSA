/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  huangweijun@anyswap.exchange
 *
 *  this library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  this library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package smpc P2P rpc interface
package smpc

import (
	"fmt"

	"github.com/anyswap/FastMulThreshold-DSA/internal/params"
	"github.com/anyswap/FastMulThreshold-DSA/p2p/layer2"
	"github.com/anyswap/FastMulThreshold-DSA/internal/common"
)

// RPCTEST test
var RPCTEST bool = false
const maxGroupMember int = 100

const (
    	// SUCCESS success 
	SUCCESS string = "Success"

	// FAIL fail
	FAIL    string = "Error"

	// NULLRET retur nil
	NULLRET string = "Null"

	// REPEAT repeat
	REPEAT  string = "Repeat"

	// PENDING pending
	PENDING string = "Pending"
)

// Result rpc result
type Result struct {
	Status string // Success, Error, Null, Repeat, Pending
	Tip    string
	Error  string
	Data   interface{}
}

// Enode enode
type Enode struct {
	Enode string
}

// Version version info
type Version struct {
	Version string
	Commit  string
	Date    string
}

// EnodeStatus the status of enode
type EnodeStatus struct {
	Enode  string
	Status string
}

func packageResult(status, tip, errors string, msg interface{}) map[string]interface{} {
	return map[string]interface{}{
		"Status": status,
		"Tip":    tip,
		"Error":  errors,
		"Data":   msg,
	}
}

// GetVersion get gsmpc version
func (service *Service) GetVersion() map[string]interface{} {
	v, c, d := params.GetVersion()
	common.Debug("==== GetVersion() ====", "version", v, "commit", c, "date", d)
	retv := &Version{Version: v, Commit: c, Date: d}
	return packageResult(SUCCESS, "", "", retv)
}

// GetEnode get gsmpc node enodeId
func (service *Service) GetEnode() map[string]interface{} {
	//fmt.Printf("==== GetEnode() ====\n")
	en := layer2.GetEnode()
	reten := &Enode{Enode: en}
	//fmt.Printf("==== GetEnode() ====, en: %v, ret: %v\n", en, reten)
	common.Debug("==== GetEnode() ====","en",en,"ret",reten)
	return packageResult(SUCCESS, "", "", reten)
}

// GroupID group id
type GroupID struct {
	Gid  string
	Sgid string
}

// GroupInfo group info
type GroupInfo struct {
	Gid    string
	Count  int
	Enodes []string
}

// ReshareGroup create reshare group
func (service *Service) ReshareGroup(threshold string, enodes []string) map[string]interface{} {
	if len(enodes) > maxGroupMember {
		ret := &GroupID{}
		common.Debug("==== ReshareSDKGroup() ====", "threshold", threshold, "len(enodes)", len(enodes), "enodes", "parameter error")
		return packageResult(FAIL, "enodes parameter error", "", ret)
	}
	common.Debug("==== ReshareSDKGroup() ====", "threshold", threshold, "len(enodes)", len(enodes))
	all, err := layer2.CheckAddPeer(threshold, enodes, true)
	if err != nil {
		ret := &GroupID{}
		common.Debug("==== ReshareSDKGroup() ====", "CheckAddPeer", "error")
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, false)
	if retErr != "" {
		status := FAIL
		common.Debug("==== ReshareSDKGroup() ====", "CreateSDKGroup", "error")
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	sgid := ""
	if all != true {
		sid, _, retErrs := layer2.CreateSDKGroup(threshold, enodes, true)
		if retErrs != "" {
			status := FAIL
			common.Debug("==== ReshareSDKGroup() ====", "CreateSDKGroup sub", "error")
			ret := &GroupID{Sgid: sid}
			return packageResult(status, retErr, retErr, ret)
		}
		sgid = sid
		fmt.Printf("==== ReshareSDKGroup() ====, gid: %v, sgid: %v, count: %v\n", gid, sid, count)
	}
	ret := &GroupID{Gid: gid, Sgid: sgid}
	return packageResult(SUCCESS, "", "", ret)
}

// CreateGroup create group 
func (service *Service) CreateGroup(threshold string, enodes []string) map[string]interface{} {
	return service.CreateSDKGroup(threshold, enodes, false)
}

// CreateSDKGroup create group
func (service *Service) CreateSDKGroup(threshold string, enodes []string, subGroup bool) map[string]interface{} {
	if len(enodes) > maxGroupMember {
		ret := &GroupID{}
		common.Debug("==== CreateSDKGroup() ====", "threshold", threshold, "len(enodes)", len(enodes), "enodes", "parameter error")
		return packageResult(FAIL, "enodes parameter error", "", ret)
	}
	_, err := layer2.CheckAddPeer(threshold, enodes, subGroup)
	if err != nil {
		ret := &GroupID{}
		common.Debug("==== CreateSDKGroup() ====", "CheckAddPeer", "error")
		return packageResult(FAIL, err.Error(), err.Error(), ret)
	}
	gid, count, retErr := layer2.CreateSDKGroup(threshold, enodes, subGroup)
	if retErr != "" {
		status := FAIL
		common.Debug("==== CreateSDKGroup() ====", "CreateSDKGroup", "error")
		ret := &GroupID{Gid: gid}
		return packageResult(status, retErr, retErr, ret)
	}
	common.Debug("==== CreateSDKGroup() ====","gid",gid,"count",count)
	ret := &GroupID{Gid: gid}
	return packageResult(SUCCESS, "", "", ret)
}

type sdkGroupInfo struct {
	Enode     string
	GroupList []GroupInfo
}

// GetGroupByID get group by gid
func (service *Service) GetGroupByID(gid string) map[string]interface{} {
	common.Debug("==== GetGroupByID() ====", "gid", gid)
	return getGroupByID(gid)
}

// GetSDKGroup get sdk group 
func (service *Service) GetSDKGroup(enode string) map[string]interface{} {
	return getSDKGroup(enode, "1+1+1")
}

// GetSDKGroup4Smpc get group for smpc
func (service *Service) GetSDKGroup4Smpc() map[string]interface{} {
	enode := layer2.GetEnode()
	return getSDKGroup(enode, "")
}

// GetSDKGroupPerson get person group
func (service *Service) GetSDKGroupPerson(enode string) map[string]interface{} {
	return getSDKGroup(enode, "1+2")
}

// getGroupByID get group info by group id
func getGroupByID(gID string) map[string]interface{} {
	gid, _ := layer2.HexID(gID)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for id, g := range layer2.GetGroupList() {
		enodes := make([]string, 0)
		if id == gid {
			for _, en := range g.Nodes {
				enode := fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP)
				enodes = append(enodes, enode)
				addGroupChanged = true
			}
			ret := &GroupInfo{Gid: gID, Count: len(g.Nodes), Enodes: enodes}
			common.Debug("==== getGroupByID() ====", "gid", gid, "len(enodes)", len(enodes))
			return packageResult(stat, tip, tip, ret)
		}
	}
	if !addGroupChanged {
		stat = NULLRET
		tip = "group is null"
	}
	ret := &GroupInfo{Gid: gID}
	return packageResult(stat, tip, tip, ret)
}

func getSDKGroup(enode, groupType string) map[string]interface{} {
	group := make([]GroupInfo, 0)
	common.Debug("==== getSDKGroup() ====", "enode", enode)
	nodeid := layer2.ParseNodeID(enode)
	stat := SUCCESS
	tip := ""
	addGroupChanged := false
	for gid, g := range layer2.GetGroupList() {
		addGroup := false
		fmt.Printf("g: %v\n", gid, g)
		enodes := make([]string, 0)
		if g.Type == groupType {
			for _, en := range g.Nodes {
				enodes = append(enodes, fmt.Sprintf("enode://%v@%v:%v", en.ID, en.IP, en.UDP))
				if en.ID.String() == nodeid {
					addGroup = true
					addGroupChanged = true
				}
			}
		}
		if addGroup {
			ret := &GroupInfo{Gid: gid.String(), Count: len(g.Nodes), Enodes: enodes}
			group = append(group, *ret)
		}
	}
	if !addGroupChanged {
		stat = NULLRET
		tip = "group is null"
	}
	sgi := &sdkGroupInfo{Enode: enode, GroupList: group}
	return packageResult(stat, tip, tip, sgi)
}

// GetEnodeStatus get enode status
func (service *Service) GetEnodeStatus(enode string) map[string]interface{} {
	es := &EnodeStatus{Enode: enode}
	status := SUCCESS
	stat, err := layer2.GetEnodeStatus(enode)
	common.Debug("==== GetEnodeStatus() ====", "enode", enode, "stat", stat)
	if stat == "" {
		status = FAIL
	}
	es.Status = stat

	errString := ""
	if err != nil {
		errString = fmt.Sprintf("%v", err.Error())
	}
	return packageResult(status, errString, errString, es)
}

// GetSDKGroupAll for test
func (service *Service) GetSDKGroupAll() map[string]interface{} {
	common.Debug("==== GetSDKGroupAll() ====")
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg := layer2.GetGroupSDKAll()
	return packageResult(SUCCESS, "", "", retMsg)
}

// BroadcastInSDKGroupAll broacast msg to all nodes in group by gid
func (service *Service) BroadcastInSDKGroupAll(gid, msg string) map[string]interface{} {
	common.Debug("==== BroadcastInSDKGroupAll() ====", "gid", gid)
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg, err := layer2.SdkProtocol_broadcastInGroupAll(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	return packageResult(status, "", retMsg, msg)
}

// SendToGroupAllNodes send msg to all nodes in group by gid
func (service *Service) SendToGroupAllNodes(gid, msg string) map[string]interface{} {
	common.Debug("==== SendToGroupAllNodes() ====", "gid", gid)
	if RPCTEST == false {
		return packageResult(FAIL, "", "RPCTEST == false", "")
	}
	retMsg, err := layer2.SdkProtocol_SendToGroupAllNodes(gid, msg)
	status := SUCCESS
	if err != nil {
		status = FAIL
	}
	return packageResult(status, "", retMsg, msg)
}
