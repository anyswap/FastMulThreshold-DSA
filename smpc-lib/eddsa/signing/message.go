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

package signing

import (
	"strings"
	"encoding/hex"
	"strconv"
)

// SignRoundMessage base type of sign round message
type SignRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
}

// SetFromID set sending nodes's ID
func (srm *SignRoundMessage) SetFromID(id string) {
	srm.FromID = id
}

// SetFromIndex set sending nodes's serial number in group
func (srm *SignRoundMessage) SetFromIndex(index int) {
	srm.FromIndex = index
}

// AppendToID get the ID of nodes that the message will broacast to
func (srm *SignRoundMessage) AppendToID(toid string) {
	srm.ToID = append(srm.ToID, toid)
}

// SignRound1Message  Round 1 sending message 
type SignRound1Message struct {
	*SignRoundMessage
	CR [32]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound1Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound1Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound1Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound1Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound1Message to map
func (srm *SignRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound1Message"

	cr := hex.EncodeToString(srm.CR[:])
	m["CR"] = cr

	return m
}

// GetMsgType get msg type
func (srm *SignRound1Message) GetMsgType() string {
	return "SignRound1Message"
}

// SignRound2Message  Round 2 sending message 
type SignRound2Message struct {
	*SignRoundMessage
	ZkR [64]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound2Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound2Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound2Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound2Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound2Message to map
func (srm *SignRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound2Message"

	zkr := hex.EncodeToString(srm.ZkR[:])
	m["ZkR"] = zkr

	return m
}

// GetMsgType get msg type
func (srm *SignRound2Message) GetMsgType() string {
	return "SignRound2Message"
}

// SignRound3Message  Round 3 sending message 
type SignRound3Message struct {
	*SignRoundMessage
	DR [64]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound3Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound3Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound3Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound3Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound3Message to map
func (srm *SignRound3Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound3Message"

	dr := hex.EncodeToString(srm.DR[:])
	m["DR"] = dr

	return m
}

// GetMsgType get msg type
func (srm *SignRound3Message) GetMsgType() string {
	return "SignRound3Message"
}

// SignRound4Message  Round 4 sending message 
type SignRound4Message struct {
	*SignRoundMessage
	CSB [32]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound4Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound4Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound4Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound4Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound4Message to map
func (srm *SignRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message"

	csb := hex.EncodeToString(srm.CSB[:])
	m["CSB"] = csb

	return m
}

// GetMsgType get msg type
func (srm *SignRound4Message) GetMsgType() string {
	return "SignRound4Message"
}

// SignRound5Message  Round 5 sending message 
type SignRound5Message struct {
	*SignRoundMessage
	DSB [64]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound5Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound5Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound5Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound5Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound5Message to map
func (srm *SignRound5Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound5Message"

	dsb := hex.EncodeToString(srm.DSB[:])
	m["DSB"] = dsb

	return m
}

// GetMsgType get msg type
func (srm *SignRound5Message) GetMsgType() string {
	return "SignRound5Message"
}

// SignRound6Message  Round 6 sending message 
type SignRound6Message struct {
	*SignRoundMessage
	S [32]byte
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound6Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound6Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound6Message) GetToID() []string {
	return srm.ToID
}

// IsBroadcast weather broacast the message
func (srm *SignRound6Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound6Message to map
func (srm *SignRound6Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound6Message"

	s := hex.EncodeToString(srm.S[:])
	m["S"] = s

	return m
}

// GetMsgType get msg type
func (srm *SignRound6Message) GetMsgType() string {
	return "SignRound6Message"
}

