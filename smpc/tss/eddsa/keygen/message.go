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

package keygen

import (
	"strings"
	"encoding/hex"
	"strconv"
)

// KGRoundMessage base type of sign round message
type KGRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
	TeeValidateData string `json:"TeeValidateData"`
}

// SetFromID set sending nodes's ID
func (kg *KGRoundMessage) SetFromID(id string) {
	kg.FromID = id
}

// SetFromIndex set sending nodes's serial number in group
func (kg *KGRoundMessage) SetFromIndex(index int) {
	kg.FromIndex = index
}

// AppendToID get the ID of nodes that the message will broacast to
func (kg *KGRoundMessage) AppendToID(toid string) {
	kg.ToID = append(kg.ToID, toid)
}

// SetTeeValidateData set sending nodes's tee validate data
func (kg *KGRoundMessage) SetTeeValidateData(data string) {
	kg.TeeValidateData = data
}

// KGRound0Message  Round 0 sending message 
type KGRound0Message struct {
	*KGRoundMessage
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound0Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound0Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound0Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound0Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound0Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound0Message to map
func (kg *KGRound0Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["Type"] = "KGRound0Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound0Message) GetMsgType() string {
	return "KGRound0Message"
}

// KGRound1Message  Round 1 sending message 
type KGRound1Message struct {
	*KGRoundMessage

	CPk [32]byte
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound1Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound1Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound1Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound1Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound1Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound1Message to map
func (kg *KGRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	cpk := hex.EncodeToString(kg.CPk[:])
	m["CPk"] = cpk

	m["Type"] = "KGRound1Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound1Message) GetMsgType() string {
	return "KGRound1Message"
}

// KGRound2Message  Round 2 sending message 
type KGRound2Message struct {
	*KGRoundMessage

	ZkPk [64]byte
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound2Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound2Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound2Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound2Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound2Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound2Message to map
func (kg *KGRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	zkpk := hex.EncodeToString(kg.ZkPk[:])
	m["ZkPk"] = zkpk

	m["Type"] = "KGRound2Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound2Message) GetMsgType() string {
	return "KGRound2Message"
}

// KGRound3Message  Round 3 sending message 
type KGRound3Message struct {
	*KGRoundMessage

	DPk [64]byte
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound3Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound3Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound3Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound3Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound3Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound3Message to map
func (kg *KGRound3Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	dpk := hex.EncodeToString(kg.DPk[:])
	m["DPk"] = dpk

	m["Type"] = "KGRound3Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound3Message) GetMsgType() string {
	return "KGRound3Message"
}

// KGRound4Message  Round 4 sending message 
type KGRound4Message struct {
	*KGRoundMessage

	Share [32]byte
	ShareEnc string
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound4Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound4Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound4Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound4Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound4Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *KGRound4Message to map
func (kg *KGRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = strings.Join(kg.ToID, ":")

	shares := hex.EncodeToString(kg.Share[:])
	m["Share"] = shares
	m["ShareEnc"] = kg.ShareEnc
	m["Type"] = "KGRound4Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound4Message) GetMsgType() string {
	return "KGRound4Message"
}

// KGRound5Message  Round 5 sending message 
type KGRound5Message struct {
	*KGRoundMessage

	CfsBBytes [][32]byte
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound5Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound5Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound5Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound5Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound5Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound5Message to map
func (kg *KGRound5Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""

	tmp := make([]string, len(kg.CfsBBytes))
	for k, v := range kg.CfsBBytes {
		vv := hex.EncodeToString(v[:])
		tmp[k] = vv
	}
	s := strings.Join(tmp, ":")
	m["CfsBBytes"] = s

	m["Type"] = "KGRound5Message"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound5Message) GetMsgType() string {
	return "KGRound5Message"
}

