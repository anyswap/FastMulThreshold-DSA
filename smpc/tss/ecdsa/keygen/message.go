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
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"math/big"
	"strconv"
	"strings"
)

// KGRoundMessage base type of kg round message
type KGRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
	//Sig []byte `json:"Sig"`
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

	ComC       *big.Int `json:"ComC"`
	ComCBip32 *big.Int `json:"ComCBip32"`

	U1PaillierPk *ec2.PublicKey `json:"U1PaillierPk"`
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
	m["TeeValidateData"] = kg.TeeValidateData
	m["ComC"] = fmt.Sprintf("%v", kg.ComC)
	m["ComC_bip32"] = fmt.Sprintf("%v", kg.ComCBip32)

	pk, err := kg.U1PaillierPk.MarshalJSON()
	if err != nil {
	    return nil 
	}

	m["U1PaillierPk"] = string(pk)
	m["Type"] = "KGRound1Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound1Message) GetMsgType() string {
	return "KGRound1Message"
}

// KGRound2Message  Round 2 sending message 
type KGRound2Message struct {
	*KGRoundMessage

	ID    *big.Int
	Share *big.Int
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
	return false
}

// OutMap transfer *KGRound2Message to map
func (kg *KGRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = strings.Join(kg.ToID, ":")
	m["TeeValidateData"] = kg.TeeValidateData
	m["ID"] = fmt.Sprintf("%v", kg.ID)
	if kg.Share != nil {
	    m["Share"] = fmt.Sprintf("%v", kg.Share)
	}
	m["Type"] = "KGRound2Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound2Message) GetMsgType() string {
	return "KGRound2Message"
}

//-------------------------------------------------------

// KGRound2Message1  Round 2 sending message 
type KGRound2Message1 struct {
	*KGRoundMessage

	C1 *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound2Message1) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound2Message1) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound2Message1) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound2Message1) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound2Message1) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound2Message1 to map
func (kg *KGRound2Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData
	m["C1"] = fmt.Sprintf("%v", kg.C1)
	m["Type"] = "KGRound2Message1"
	return m
}

// GetMsgType get msg type
func (kg *KGRound2Message1) GetMsgType() string {
	return "KGRound2Message1"
}

//-----------------------------------------------------------

// KGRound2Message2  Round 2 sending message2 
type KGRound2Message2 struct {
	*KGRoundMessage
	Num *big.Int
	SfPf *ec2.SquareFreeProof
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound2Message2) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound2Message2) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound2Message2) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound2Message2) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound2Message2) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound2Message1 to map
func (kg *KGRound2Message2) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData
	
	if kg.SfPf == nil {
	    return nil
	}
	sf,err := kg.SfPf.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["SfPf"] = string(sf)

	m["Num"] = fmt.Sprintf("%v",kg.Num)
	m["Type"] = "KGRound2Message2"
	
	return m
}

// GetMsgType get msg type
func (kg *KGRound2Message2) GetMsgType() string {
	return "KGRound2Message2"
}

//------------------------------------------------------------

// KGRound3Message  Round 3 sending message 
type KGRound3Message struct {
	*KGRoundMessage
	ComU1GD  []*big.Int
	ComC1GD  []*big.Int
	U1PolyGG [][]*big.Int
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
	m["TeeValidateData"] = kg.TeeValidateData

	tmp := make([]string, len(kg.ComU1GD))
	for k, v := range kg.ComU1GD {
		tmp[k] = fmt.Sprintf("%v", v)
	}
	m["ComU1GD"] = strings.Join(tmp, ":")

	tmp2 := make([]string, len(kg.ComC1GD))
	for k, v := range kg.ComC1GD {
		tmp2[k] = fmt.Sprintf("%v", v)
	}
	m["ComC1GD"] = strings.Join(tmp2, ":")

	tmp3 := make([][]string, len(kg.U1PolyGG))
	for k, v := range kg.U1PolyGG {
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
	m["U1PolyGG"] = strings.Join(tmp5, "|")
	m["Type"] = "KGRound3Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound3Message) GetMsgType() string {
	return "KGRound3Message"
}

//--------------------------------------------------------------

// KGRound3Message1  Round 3 sending message1 
type KGRound3Message1 struct {
	*KGRoundMessage
	Y *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound3Message1) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound3Message1) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound3Message1) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound3Message1) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound3Message1) IsBroadcast() bool {
	return false
}

// OutMap transfer *KGRound3Message1 to map
func (kg *KGRound3Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = strings.Join(kg.ToID, ":")
	m["Y"] = fmt.Sprintf("%v", kg.Y)
	m["Type"] = "KGRound3Message1"
	m["TeeValidateData"] = kg.TeeValidateData
	return m
}

// GetMsgType get msg type
func (kg *KGRound3Message1) GetMsgType() string {
	return "KGRound3Message1"
}

//----------------------------------------------------------------

// KGRound4Message  Round 4 sending message 
type KGRound4Message struct {
	*KGRoundMessage
	U1NtildeH1H2 *ec2.NtildeH1H2

	//add for ntilde zk
	NtildeProof1 *ec2.NtildeProof
	NtildeProof2 *ec2.NtildeProof

	// add for xi commitment
	ComXiC *big.Int
	
	//pubkey
	PubKeyX *big.Int
	PubKeyY *big.Int
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
	return true
}

// OutMap transfer *KGRound4Message to map
func (kg *KGRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData

	nt, err := kg.U1NtildeH1H2.MarshalJSON()
	if err != nil {
	    return nil 
	}
	m["U1NtildeH1H2"] = string(nt)

	pf1, err := kg.NtildeProof1.MarshalJSON()
	if err != nil {
	    return nil 
	}
	m["NtildeProof1"] = string(pf1)

	pf2, err := kg.NtildeProof2.MarshalJSON()
	if err != nil {
	    return nil 
	}
	m["NtildeProof2"] = string(pf2)

	m["ComXiC"] = fmt.Sprintf("%v",kg.ComXiC)
	m["PubKeyX"] = fmt.Sprintf("%v",kg.PubKeyX)
	m["PubKeyY"] = fmt.Sprintf("%v",kg.PubKeyY)
	m["Type"] = "KGRound4Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound4Message) GetMsgType() string {
	return "KGRound4Message"
}

// KGRound5Message  Round 5 sending message 
type KGRound5Message struct {
	*KGRoundMessage
	ComXiGD  []*big.Int
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
	m["TeeValidateData"] = kg.TeeValidateData

	tmp := make([]string, len(kg.ComXiGD))
	for k, v := range kg.ComXiGD {
		tmp[k] = fmt.Sprintf("%v", v)
	}
	m["ComXiGD"] = strings.Join(tmp, ":")

	m["Type"] = "KGRound5Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound5Message) GetMsgType() string {
	return "KGRound5Message"
}

//------------------------------------------------------------

// KGRound5Message1  Round 5-1 sending message 
type KGRound5Message1 struct {
	*KGRoundMessage

	Num *big.Int
	HvPf *ec2.HvProof
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound5Message1) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound5Message1) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound5Message1) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound5Message1) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound5Message1) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound5Message1 to map
func (kg *KGRound5Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData
	
	if kg.HvPf == nil {
	    return nil
	}
	hv,err := kg.HvPf.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["HvPf"] = string(hv)

	m["Num"] = fmt.Sprintf("%v",kg.Num)
	m["Type"] = "KGRound5Message1"
	
	return m
}

// GetMsgType get msg type
func (kg *KGRound5Message1) GetMsgType() string {
	return "KGRound5Message1"
}

//-----------------------------------------------------------------

// KGRound5Message2  Round 5 sending message2 
type KGRound5Message2 struct {
	*KGRoundMessage
	Num *big.Int
	SfPf *ec2.SquareFreeProof
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound5Message2) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound5Message2) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound5Message2) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound5Message2) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound5Message2) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound5Message2 to map
func (kg *KGRound5Message2) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData
	
	if kg.SfPf == nil {
	    return nil
	}
	sf,err := kg.SfPf.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["SfPf"] = string(sf)

	m["Num"] = fmt.Sprintf("%v",kg.Num)
	m["Type"] = "KGRound5Message2"
	
	return m
}

// GetMsgType get msg type
func (kg *KGRound5Message2) GetMsgType() string {
	return "KGRound5Message2"
}

//-----------------------------------------------------------------

// KGRound6Message  Round 6 sending message 
type KGRound6Message struct {
	*KGRoundMessage
	U1zkXiProof *ec2.ZkXiProof
	CheckPubkeyStatus bool
}

// GetFromID get the ID of sending nodes in the group
func (kg *KGRound6Message) GetFromID() string {
	return kg.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (kg *KGRound6Message) GetFromIndex() int {
	return kg.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (kg *KGRound6Message) GetToID() []string {
	return kg.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (kg *KGRound6Message) GetTeeValidateData() string {
	return kg.TeeValidateData
}

// IsBroadcast weather broacast the message
func (kg *KGRound6Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound6Message to map
func (kg *KGRound6Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = kg.FromID
	m["FromIndex"] = strconv.Itoa(kg.FromIndex)
	m["ToID"] = ""
	m["TeeValidateData"] = kg.TeeValidateData

	zk, err := kg.U1zkXiProof.MarshalJSON()
	if err != nil {
	    return nil 
	}
	m["U1zkXiProof"] = string(zk)

	if kg.CheckPubkeyStatus {
		m["CheckPubkeyStatus"] = "true"
	} else {
		m["CheckPubkeyStatus"] = "false"
	}

	m["Type"] = "KGRound6Message"
	return m
}

// GetMsgType get msg type
func (kg *KGRound6Message) GetMsgType() string {
	return "KGRound6Message"
}

//----------------------------------------------

