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

package reshare

import (
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"math/big"
	"strconv"
	"strings"
)

// ReRoundMessage base type of sign round message
type ReRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
	TeeValidateData string `json:"TeeValidateData"`
}

// SetFromID set sending nodes's ID
func (re *ReRoundMessage) SetFromID(id string) {
	re.FromID = id
}

// SetFromIndex set sending nodes's serial number in group
func (re *ReRoundMessage) SetFromIndex(index int) {
	re.FromIndex = index
}

// AppendToID get the ID of nodes that the message will broacast to
func (re *ReRoundMessage) AppendToID(toid string) {
	re.ToID = append(re.ToID, toid)
}

// SetTeeValidateData set sending nodes's tee validate data
func (re *ReRoundMessage) SetTeeValidateData(data string) {
	re.TeeValidateData = data
}

// ReRound0Message  Round 0 sending message 
type ReRound0Message struct {
	*ReRoundMessage
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound0Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound0Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound0Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound0Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound0Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound0Message to map
func (re *ReRound0Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""
	m["Type"] = "ReRound0Message"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound0Message) GetMsgType() string {
	return "ReRound0Message"
}

// ReRound1Message  Round 1 sending message 
type ReRound1Message struct {
	*ReRoundMessage
	ComC *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound1Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound1Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound1Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound1Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound1Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound1Message to map
func (re *ReRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""
	m["ComC"] = fmt.Sprintf("%v", re.ComC)
	m["Type"] = "ReRound1Message"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound1Message) GetMsgType() string {
	return "ReRound1Message"
}

// ReRound2Message  Round 2 sending message 
type ReRound2Message struct {
	*ReRoundMessage

	ID    *big.Int
	Share *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound2Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound2Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound2Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound2Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound2Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *ReRound2Message to map
func (re *ReRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = strings.Join(re.ToID, ":")
	m["ID"] = fmt.Sprintf("%v", re.ID)
	m["Share"] = fmt.Sprintf("%v", re.Share)
	m["Type"] = "ReRound2Message"
	m["TeeValidateData"] = re.TeeValidateData
	fmt.Printf("\n===========ReRound2Message.OutMap, re.ID = %v,re.Share = %v, FromID = %v ==========\n", m["ID"], m["Share"], m["FromID"])
	return m
}

// GetMsgType get msg type
func (re *ReRound2Message) GetMsgType() string {
	return "ReRound2Message"
}

// ReRound2Message1  Round 2 sending message 
type ReRound2Message1 struct {
	*ReRoundMessage

	ComD      []*big.Int
	SkP1PolyG [][]*big.Int
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound2Message1) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound2Message1) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound2Message1) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound2Message1) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound2Message1) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound2Message1 to map
func (re *ReRound2Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""

	tmp := make([]string, len(re.ComD))
	for k, v := range re.ComD {
		tmp[k] = fmt.Sprintf("%v", v)
	}
	m["ComD"] = strings.Join(tmp, ":")

	tmp3 := make([][]string, len(re.SkP1PolyG))
	for k, v := range re.SkP1PolyG {
		tmp4 := make([]string, len(v))
		for kk, vv := range v {
			tmp4[kk] = fmt.Sprintf("%v", vv)
		}

		tmp3[k] = tmp4
	}
	tmp5 := make([]string, len(tmp3))
	for k, v := range tmp3 {
		vv := strings.Join(v, ":")
		tmp5[k] = vv
	}
	m["SkP1PolyG"] = strings.Join(tmp5, "|")

	m["Type"] = "ReRound2Message1"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound2Message1) GetMsgType() string {
	return "ReRound2Message1"
}

// ReRound3Message  Round 3 sending message 
type ReRound3Message struct {
	*ReRoundMessage
	U1PaillierPk *ec2.PublicKey
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound3Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound3Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound3Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound3Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound3Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound3Message to map
func (re *ReRound3Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""

	pk, err := re.U1PaillierPk.MarshalJSON()
	if err != nil {
	    return nil
	}
	
	m["U1PaillierPk"] = string(pk)
	m["Type"] = "ReRound3Message"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound3Message) GetMsgType() string {
	return "ReRound3Message"
}

// ReRound4Message  Round 4 sending message 
type ReRound4Message struct {
	*ReRoundMessage
	U1NtildeH1H2 *ec2.NtildeH1H2

	//add for ntilde zk
	NtildeProof1 *ec2.NtildeProof
	NtildeProof2 *ec2.NtildeProof
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound4Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound4Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound4Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound4Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound4Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound4Message to map
func (re *ReRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""

	nt, err := re.U1NtildeH1H2.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["U1NtildeH1H2"] = string(nt)

	pf1, err := re.NtildeProof1.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["NtildeProof1"] = string(pf1)

	pf2, err := re.NtildeProof2.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["NtildeProof2"] = string(pf2)

	m["Type"] = "ReRound4Message"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound4Message) GetMsgType() string {
	return "ReRound4Message"
}

// ReRound5Message  Round 5 sending message 
type ReRound5Message struct {
	*ReRoundMessage
	NewSkOk string
}

// GetFromID get the ID of sending nodes in the group
func (re *ReRound5Message) GetFromID() string {
	return re.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (re *ReRound5Message) GetFromIndex() int {
	return re.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (re *ReRound5Message) GetToID() []string {
	return re.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (re *ReRound5Message) GetTeeValidateData() string {
	return re.TeeValidateData
}

// IsBroadcast weather broacast the message
func (re *ReRound5Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *ReRound5Message to map
func (re *ReRound5Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = re.FromID
	m["FromIndex"] = strconv.Itoa(re.FromIndex)
	m["ToID"] = ""
	m["NewSkOk"] = re.NewSkOk
	m["Type"] = "ReRound4Message"
	m["TeeValidateData"] = re.TeeValidateData
	return m
}

// GetMsgType get msg type
func (re *ReRound5Message) GetMsgType() string {
	return "ReRound5Message"
}

