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
	"fmt"
	"github.com/anyswap/FastMulThreshold-DSA/tss-lib/ec2"
	"math/big"
	"strconv"
	"strings"
)

// SignRoundMessage base type of sign round message
type SignRoundMessage struct {
	FromID    string   `json:"FromID"` //DNodeID
	FromIndex int      `json:"FromIndex"`
	ToID      []string `json:"ToID"`
	TeeValidateData string `json:"TeeValidateData"`
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

// SetTeeValidateData set sending nodes's tee validate data
func (srm *SignRoundMessage) SetTeeValidateData(data string) {
	srm.TeeValidateData = data
}

//-----------------------------------------------------------------------

// SignRound1Message  Round 1 sending message 
type SignRound1Message struct {
	*SignRoundMessage

	C11 *big.Int
	ComWiC *big.Int
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound1Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound1Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *KGRound5Message to map
func (srm *SignRound1Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound1Message"
	m["C11"] = fmt.Sprintf("%v", srm.C11)
	m["ComWiC"] = fmt.Sprintf("%v", srm.ComWiC)
	m["TeeValidateData"] = srm.TeeValidateData

	return m
}

// GetMsgType get msg type
func (srm *SignRound1Message) GetMsgType() string {
	return "SignRound1Message"
}

// SignRound2Message  Round 2 sending message 
type SignRound2Message struct {
	*SignRoundMessage

	U1u1MtAZK1Proof *ec2.MtARangeProof
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound2Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound2Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound2Message to map
func (srm *SignRound2Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound2Message"
	m["TeeValidateData"] = srm.TeeValidateData

	proof, err := srm.U1u1MtAZK1Proof.MarshalJSON()
	if err != nil {
	    return nil
	}

	m["U1u1MtAZK1Proof"] = string(proof)

	return m
}

// GetMsgType get msg type
func (srm *SignRound2Message) GetMsgType() string {
	return "SignRound2Message"
}

// SignRound3Message  Round 3 sending message 
type SignRound3Message struct {
	*SignRoundMessage
	Kc *big.Int
	ComWiD   []*big.Int
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound3Message) GetTeeValidateData() string {
	return srm.TeeValidateData
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
	m["Kc"] = fmt.Sprintf("%v", srm.Kc)
	m["TeeValidateData"] = srm.TeeValidateData

	dtmp := make([]string, len(srm.ComWiD))
	for k, v := range srm.ComWiD {
		dtmp[k] = fmt.Sprintf("%v", v)
	}

	m["ComWiD"] = strings.Join(dtmp, ":")

	return m
}

// GetMsgType get msg type
func (srm *SignRound3Message) GetMsgType() string {
	return "SignRound3Message"
}

// SignRound4Message  Round 4 sending message 
type SignRound4Message struct {
	*SignRoundMessage
	U1KGamma1Cipher *big.Int
	U1u1MtAZK2Proof *ec2.MtARespZKProof
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound4Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound4Message) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound4Message to map
func (srm *SignRound4Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message"
	m["TeeValidateData"] = srm.TeeValidateData

	proof, err := srm.U1u1MtAZK2Proof.MarshalJSON()
	if err != nil {
	    return nil
	}

	m["U1u1MtAZK2Proof"] = string(proof)
	m["U1KGamma1Cipher"] = fmt.Sprintf("%v", srm.U1KGamma1Cipher)

	return m
}

// GetMsgType get msg type
func (srm *SignRound4Message) GetMsgType() string {
	return "SignRound4Message"
}

// SignRound4Message1  Round 5 sending message 
type SignRound4Message1 struct {
	*SignRoundMessage
	U1Kw1Cipher     *big.Int
	U1u1MtAZK3Proof *ec2.MtAwcRespZKProof
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound4Message1) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound4Message1) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound4Message1) GetToID() []string {
	return srm.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound4Message1) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound4Message1) IsBroadcast() bool {
	return false
}

// OutMap transfer *SignRound4Message1 to map
func (srm *SignRound4Message1) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = strings.Join(srm.ToID, ":")
	m["Type"] = "SignRound4Message1"
	m["TeeValidateData"] = srm.TeeValidateData

	proof, err := srm.U1u1MtAZK3Proof.MarshalJSON()
	if err != nil {
	    return nil
	}

	m["U1u1MtAZK3Proof"] = string(proof)
	m["U1Kw1Cipher"] = fmt.Sprintf("%v", srm.U1Kw1Cipher)

	return m
}

// GetMsgType get msg type
func (srm *SignRound4Message1) GetMsgType() string {
	return "SignRound4Message1"
}

// SignRound5Message  Round 5 sending message 
type SignRound5Message struct {
	*SignRoundMessage
	Delta1 *big.Int
	T1X *big.Int
	T1Y *big.Int
	Tpf *ec2.TProof
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound5Message) GetTeeValidateData() string {
	return srm.TeeValidateData
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
	m["TeeValidateData"] = srm.TeeValidateData

	m["Delta1"] = fmt.Sprintf("%v", srm.Delta1)
	m["T1X"] = fmt.Sprintf("%v", srm.T1X)
	m["T1Y"] = fmt.Sprintf("%v", srm.T1Y)

	proof, err := srm.Tpf.MarshalJSON()
	if err != nil {
	    return nil
	}

	m["Tpf"] = string(proof) 
	return m
}

// GetMsgType get msg type
func (srm *SignRound5Message) GetMsgType() string {
	return "SignRound5Message"
}

// SignRound6Message  Round 6 sending message 
type SignRound6Message struct {
	*SignRoundMessage
	CommU1D        []*big.Int
	U1GammaZKProof *ec2.ZkUProof
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

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound6Message) GetTeeValidateData() string {
	return srm.TeeValidateData
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
	m["TeeValidateData"] = srm.TeeValidateData

	proof, err := srm.U1GammaZKProof.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["U1GammaZKProof"] = string(proof)

	dtmp := make([]string, len(srm.CommU1D))
	for k, v := range srm.CommU1D {
		dtmp[k] = fmt.Sprintf("%v", v)
	}

	m["CommU1D"] = strings.Join(dtmp, ":")

	return m
}

// GetMsgType get msg type
func (srm *SignRound6Message) GetMsgType() string {
	return "SignRound6Message"
}

// SignRound7Message  Round 7 sending message 
type SignRound7Message struct {
	*SignRoundMessage
	K1RX *big.Int
	K1RY *big.Int
	PdlwSlackPf *ec2.PDLwSlackProof
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound7Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound7Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound7Message) GetToID() []string {
	return srm.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound7Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound7Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound7Message to map
func (srm *SignRound7Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound7Message"
	m["TeeValidateData"] = srm.TeeValidateData

	m["K1RX"] = fmt.Sprintf("%v", srm.K1RX)
	m["K1RY"] = fmt.Sprintf("%v", srm.K1RY)

	proof, err := srm.PdlwSlackPf.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["PdlwSlackPf"] = string(proof)

	return m
}

// GetMsgType get msg type
func (srm *SignRound7Message) GetMsgType() string {
	return "SignRound7Message"
}

// SignRound8Message  Round 8 sending message 
type SignRound8Message struct {
	*SignRoundMessage
	S1X *big.Int
	S1Y *big.Int
	STpf *ec2.STProof
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound8Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound8Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound8Message) GetToID() []string {
	return srm.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound8Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound8Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound8Message to map
func (srm *SignRound8Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound8Message"
	m["TeeValidateData"] = srm.TeeValidateData

	m["S1X"] = fmt.Sprintf("%v", srm.S1X)
	m["S1Y"] = fmt.Sprintf("%v", srm.S1Y)

	proof, err := srm.STpf.MarshalJSON()
	if err != nil {
	    return nil
	}
	m["STpf"] = string(proof)

	return m
}

// GetMsgType get msg type
func (srm *SignRound8Message) GetMsgType() string {
	return "SignRound8Message"
}

// SignRound9Message  Round 9 sending message 
type SignRound9Message struct {
	*SignRoundMessage
	Us1 *big.Int
}

// GetFromID get the ID of sending nodes in the group
func (srm *SignRound9Message) GetFromID() string {
	return srm.FromID
}

// GetFromIndex get the Serial number of sending nodes in the group 
func (srm *SignRound9Message) GetFromIndex() int {
	return srm.FromIndex
}

// GetToID get the ID of the node that broacasting message to
func (srm *SignRound9Message) GetToID() []string {
	return srm.ToID
}

// GetTeeValidateData get the tee validate Data of sending nodes 
func (srm *SignRound9Message) GetTeeValidateData() string {
	return srm.TeeValidateData
}

// IsBroadcast weather broacast the message
func (srm *SignRound9Message) IsBroadcast() bool {
	return true
}

// OutMap transfer *SignRound9Message to map
func (srm *SignRound9Message) OutMap() map[string]string {
	m := make(map[string]string)
	m["FromID"] = srm.FromID
	m["FromIndex"] = strconv.Itoa(srm.FromIndex)
	m["ToID"] = ""
	m["Type"] = "SignRound9Message"
	m["TeeValidateData"] = srm.TeeValidateData

	m["Us1"] = fmt.Sprintf("%v", srm.Us1)
	return m
}

// GetMsgType get msg type
func (srm *SignRound9Message) GetMsgType() string {
	return "SignRound9Message"
}

